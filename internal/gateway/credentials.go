package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

// IssueRequest 是凭证签发请求。
type IssueRequest struct {
	Username   string
	Attributes map[string]string
}

// IssueResult 是签发/续期结果。
type IssueResult struct {
	Token     string
	JTI       string
	SessionID string
	ExpiresAt time.Time
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand 失败属于环境性故障，直接 panic 安全失败优于继续签发弱标识。
		panic(fmt.Errorf("gateway: cannot read random bytes: %w", err))
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func mergeAttrs(base, extra map[string]string, maxAttrs int) (map[string]string, bool) {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	if maxAttrs > 0 && len(out) > maxAttrs {
		return nil, false
	}
	return out, true
}

// recordAudit 写入一条不含敏感内容的审计记录。
func (g *Gateway) recordAudit(e audit.Event) error {
	_, err := g.aud.Append(e)
	return err
}

// signNew 用当前 active 密钥为会话签发一张新凭证。
func (g *Gateway) signNew(sess *store.Session, attrs map[string]string, issuedAt, expiresAt time.Time) (string, token.Claims, error) {
	kid, secret, err := g.store.ActiveSigningKey()
	if err != nil {
		return "", token.Claims{}, err
	}
	signer := token.NewSigner(kid, secret, g.cfg.Issuer)
	claims := token.Claims{
		Subject:    sess.Username,
		IssuedAt:   issuedAt.Unix(),
		Expires:    expiresAt.Unix(),
		JTI:        sess.CurrentJTI,
		SessionID:  sess.ID,
		Attributes: attrs,
	}
	raw, err := signer.Sign(claims)
	if err != nil {
		return "", token.Claims{}, err
	}
	return raw, claims, nil
}

// Issue 为目录中的用户签发新凭证并创建会话。
//
// 顺序：校验主体 -> 审计落盘 -> 建会话 -> 签发。
// 任何一步失败都向上游返回错误且不产生有效凭证；若审计已落盘但会话创建失败，
// 会尽力回滚审计之前的状态（会话本来就未创建），失败被显式暴露而不被吞掉。
func (g *Gateway) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}
	if req.Username == "" {
		return IssueResult{}, fmt.Errorf("%w: empty username", errBadRequest())
	}
	user, err := g.store.GetUser(req.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return IssueResult{}, withReason(errBadRequest(), ReasonUserNotFound)
		}
		return IssueResult{}, err
	}
	if g.cfg.MaxAttrCount > 0 && len(req.Attributes) > g.cfg.MaxAttrCount {
		return IssueResult{}, withReason(errBadRequest(), ReasonTooManyAttributes)
	}

	now := g.now()
	expiresAt := now.Add(g.cfg.TokenTTL)
	sessionID := newID("sess")
	jti := newID("jti")
	attrs := mergeAttrsForUser(user, req.Attributes)

	sess := &store.Session{
		ID:          sessionID,
		Username:    user.Name,
		CurrentJTI:  jti,
		CredVersion: 1,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		Attributes:  attrs,
	}

	// 先确认当前签发密钥存在（只记录其 kid 元数据，绝不记录密钥明文）。
	kid, _, err := g.store.ActiveSigningKey()
	if err != nil {
		return IssueResult{}, mapWrappedStoreError(err)
	}

	// 先落审计（敏感操作必须留痕）。审计不可写时拒绝签发。
	if err := g.recordAudit(audit.Event{
		Actor:     user.Name,
		Operation: "issue",
		Result:    "success",
		Reason:    ReasonOK,
		JTI:       jti,
		SessionID: sessionID,
		Detail: map[string]string{
			"roles": joinNonEmpty(user.Roles),
			"kid":   kid,
		},
	}); err != nil {
		return IssueResult{}, withReason(errAudit(), ReasonAuditFailure)
	}

	// 再创建会话；失败时不会有可用于鉴权的状态残留（凭证尚未签发）。
	if err := g.store.CreateSession(*sess); err != nil {
		return IssueResult{}, mapWrappedStoreError(err)
	}

	raw, _, err := g.signNew(sess, attrs, now, expiresAt)
	if err != nil {
		// 签名失败：删除刚创建的会话，避免遗留不可用的占用名额。
		_ = g.store.DeleteSession(sessionID)
		return IssueResult{}, mapWrappedStoreError(err)
	}
	return IssueResult{Token: raw, JTI: jti, SessionID: sessionID, ExpiresAt: expiresAt}, nil
}

func joinNonEmpty(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func mergeAttrsForUser(user store.User, extra map[string]string) map[string]string {
	attrs, ok := mergeAttrs(user.Attributes, extra, 0)
	if !ok {
		attrs = map[string]string{}
	}
	return attrs
}

// CheckResult 是凭证校验结果。
type CheckResult struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason"`
	Subject   string `json:"subject"`
	SessionID string `json:"session_id"`
	JTI       string `json:"jti"`
}

// Verify 只做凭证校验（签名/签发者/有效期/会话状态/凭证版本），不做授权。
// 无论成功失败都写审计，但审计中只记录 jti，绝不记录凭证本体。
func (g *Gateway) Verify(ctx context.Context, raw string) CheckResult {
	claims, sess, reason := g.verifyAndLoad(raw)
	res := CheckResult{Reason: reason}
	if reason == ReasonOK {
		res.Valid = true
		res.Subject = claims.Subject
		res.SessionID = sess.ID
		res.JTI = claims.JTI
	}
	result := "success"
	if !res.Valid {
		result = "denied"
	}
	jti, sid := "", ""
	if claims != nil {
		jti, sid = claims.JTI, claims.SessionID
	}
	_ = g.recordAudit(audit.Event{
		Actor:     safeSubject(claims),
		Operation: "verify",
		Result:    result,
		Reason:    reason,
		JTI:       jti,
		SessionID: sid,
	})
	return res
}

func safeSubject(c *token.Claims) string {
	if c == nil {
		return "anonymous"
	}
	return c.Subject
}

// Renew 用有效且未被取代的凭证换取新凭证。
//
// 并发安全：新凭证先在锁外签名（无状态），再通过存储层 CAS 原子切换会话的
// JTI 与版本号。CAS 失败意味着已有并发续期/撤销发生，本次返回
// credential_superseded，调用方必须持新凭证重试或重新登录；
// 旧凭证绝不会因为并发而重新变为当前凭证。
func (g *Gateway) Renew(ctx context.Context, raw string) (IssueResult, error) {
	if err := ctx.Err(); err != nil {
		return IssueResult{}, err
	}
	claims, sess, reason := g.verifyAndLoad(raw)
	if reason != ReasonOK {
		_ = g.recordAudit(audit.Event{
			Actor: safeSubject(claims), Operation: "renew", Result: "denied",
			Reason: reason, JTI: jtiOf(claims), SessionID: sidOf(claims),
		})
		return IssueResult{}, withReason(errDenied(), reason)
	}

	now := g.now()
	if g.cfg.RenewWindow > 0 {
		windowStart := sess.ExpiresAt.Add(-g.cfg.RenewWindow)
		if now.Before(windowStart) {
			_ = g.recordAudit(audit.Event{
				Actor: claims.Subject, Operation: "renew", Result: "denied",
				Reason: ReasonRenewTooEarly, JTI: claims.JTI, SessionID: sess.ID,
			})
			return IssueResult{}, withReason(errDenied(), ReasonRenewTooEarly)
		}
	}

	newJTI := newID("jti")
	newExpiry := now.Add(g.cfg.TokenTTL)
	newSess := *sess
	newSess.CurrentJTI = newJTI
	newSess.ExpiresAt = newExpiry

	signed, _, err := g.signNew(&newSess, sess.Attributes, now, newExpiry)
	if err != nil {
		return IssueResult{}, mapWrappedStoreError(err)
	}

	// CAS：只有仍持有旧 (jti, version) 才能提交。
	if err := g.store.RenewSessionCAS(sess.ID, claims.JTI, sess.CredVersion, newJTI, newExpiry); err != nil {
		mapped := mapStoreError(err)
		_ = g.recordAudit(audit.Event{
			Actor: claims.Subject, Operation: "renew", Result: "denied",
			Reason: mapped, JTI: claims.JTI, SessionID: sess.ID,
		})
		return IssueResult{}, withReason(errDenied(), mapped)
	}

	if err := g.recordAudit(audit.Event{
		Actor: claims.Subject, Operation: "renew", Result: "success",
		Reason: ReasonOK, JTI: newJTI, SessionID: sess.ID,
		Detail: map[string]string{"superseded_jti": claims.JTI},
	}); err != nil {
		// CAS 已提交而审计失败：凭证已切换，无法回滚；这属于必须暴露的运维错误。
		return IssueResult{}, withReason(errAudit(), ReasonAuditFailure)
	}
	return IssueResult{Token: signed, JTI: newJTI, SessionID: sess.ID, ExpiresAt: newExpiry}, nil
}

func jtiOf(c *token.Claims) string {
	if c == nil {
		return ""
	}
	return c.JTI
}

func sidOf(c *token.Claims) string {
	if c == nil {
		return ""
	}
	return c.SessionID
}
