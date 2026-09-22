// Package service 是授权网关的编排层：把凭证(token)、存储(store)、
// 授权判定(authz)与审计(audit)组合成统一入口，保证 HTTP/CLI 等所有入口
// 走同一份判定与生命周期逻辑，结论一致且每次都留下可解释的审计记录。
//
// 失败策略（fail-closed）：任何环节出现“无法确定是否允许”的情况（存储失败、
// 审计写入失败、达到上限等），一律按拒绝处理并返回错误，绝不放行。
package service

import (
	"errors"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/authz"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

// Config 是服务配置（各类上限与凭证有效期）。
type Config struct {
	Issuer        string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	StoreLimits   store.Limits
	DecisionCache int // 判定缓存条目上限，<=0 禁用
	AuditCapacity int // 审计记录上限，<=0 不允许写入
	Now           func() time.Time
}

// VerifyReason 在 token 层原因之上补充服务级原因，保持全部拒绝原因可区分。
type VerifyReason string

const (
	VROK               VerifyReason = "ok"
	VRMalformed        VerifyReason = "malformed_token"
	VRUnsupportedAlg   VerifyReason = "unsupported_alg"
	VRUnknownKey       VerifyReason = "unknown_key"
	VRBadSignature     VerifyReason = "bad_signature"
	VRIssuerMismatch   VerifyReason = "issuer_mismatch"
	VRNotYetValid      VerifyReason = "not_before_valid"
	VRExpired          VerifyReason = "expired"
	VRKeyRevoked       VerifyReason = "signing_key_revoked"
	VRWrongTokenType   VerifyReason = "wrong_token_type"
	VRSessionNotFound  VerifyReason = "session_not_found"
	VRSessionRevoked   VerifyReason = "session_revoked"
	VRStaleVersion     VerifyReason = "credential_version_stale"
	VRUserNotFound     VerifyReason = "user_not_found"
	VRResourceNotFound VerifyReason = "resource_not_found"
)

// VerifyError 携带可区分的拒绝原因。
type VerifyError struct {
	Reason VerifyReason
	Inner  error
}

func (e *VerifyError) Error() string { return string(e.Reason) }
func (e *VerifyError) Unwrap() error { return e.Inner }

// IssueResult 是登录/续期后签发的两张凭证。
type IssueResult struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	AccessExp    time.Time
	RefreshExp   time.Time
}

// AuthorizeResult 是一次授权判定的结果。
type AuthorizeResult struct {
	Decision authz.Decision
	Reason   authz.DecisionReason
	Trace    *authz.Trace
	Subject  string
	Resource string
	Action   string
}

// Service 编排全部组件。
type Service struct {
	cfg      Config
	st       *store.Store
	ev       *authz.Evaluator
	auditLog *audit.Log
}

// New 创建服务并引导一把初始签名密钥。
func New(cfg Config, initialKeyID string, initialSecret []byte) (*Service, error) {
	if cfg.Issuer == "" {
		return nil, ErrBadConfig("empty issuer")
	}
	if cfg.AccessTTL <= 0 || cfg.RefreshTTL <= 0 || cfg.RefreshTTL < cfg.AccessTTL {
		return nil, ErrBadConfig("access/refresh ttl must be positive and refresh >= access")
	}
	if cfg.AuditCapacity < 0 {
		return nil, ErrBadConfig("audit capacity must be >= 0")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	st := store.New(cfg.StoreLimits)
	if initialKeyID != "" {
		if err := st.AddKey(store.SigningKey{
			ID: initialKeyID, Secret: append([]byte(nil), initialSecret...),
			State: store.KeyActive, CreatedAt: cfg.Now(),
		}); err != nil {
			return nil, err
		}
	}
	return &Service{
		cfg:      cfg,
		st:       st,
		ev:       authz.NewEvaluator(cfg.DecisionCache),
		auditLog: audit.New(cfg.AuditCapacity),
	}, nil
}

// ErrBadConfig 表示服务配置不合法。
type ErrBadConfig string

func (e ErrBadConfig) Error() string { return "service: bad config: " + string(e) }

// Store 暴露存储以便引导测试数据/CLI 装配（管理面操作仍经服务方法）。
func (s *Service) Store() *store.Store { return s.st }

// Audit 暴露审计日志以便核验/导出。
func (s *Service) Audit() *audit.Log { return s.auditLog }

func (s *Service) now() time.Time { return s.cfg.Now() }

func tokenReasonToVR(r token.Reason) VerifyReason {
	switch r {
	case token.ReasonOK:
		return VROK
	case token.ReasonMalformed:
		return VRMalformed
	case token.ReasonUnsupportedAlg:
		return VRUnsupportedAlg
	case token.ReasonUnknownKey:
		return VRUnknownKey
	case token.ReasonBadSignature:
		return VRBadSignature
	case token.ReasonIssuerMismatch:
		return VRIssuerMismatch
	case token.ReasonNotYetValid:
		return VRNotYetValid
	case token.ReasonExpired:
		return VRExpired
	default:
		return VRMalformed
	}
}

// keyFor 提供验签密钥：未知 kid 返回 found=false（由 token 层给出 unknown_key）；
// revoked 密钥也返回其密钥材料让签名验证继续，但随后服务层依据状态给出
// 独立的 signing_key_revoked 原因（签名错误与密钥撤销可区分）。
func (s *Service) keyFor(kid string) ([]byte, bool) {
	k, err := s.st.VerifyKeySecret(kid)
	if err != nil {
		return nil, false
	}
	return k.Secret, true
}

// verifyClaims 是 access/refresh 共用的纯凭证校验链：
// 结构/算法/签名/签发者/时效 -> 密钥状态 -> 会话存在性/撤销/版本/用户。
// 任何一步失败都返回可区分原因，绝不降级放行。
func (s *Service) verifyClaims(raw string, wantType token.Type) (*token.Claims, *store.User, error) {
	c, reason := token.Verify(raw, s.cfg.Issuer, s.now(), s.keyFor)
	if reason != token.ReasonOK {
		return nil, nil, &VerifyError{Reason: tokenReasonToVR(reason)}
	}
	if c.TokenType != wantType {
		return nil, nil, &VerifyError{Reason: VRWrongTokenType}
	}
	// 密钥状态：revoked 的密钥即使签名正确也立即拒绝。
	if k, err := s.st.VerifyKeySecret(c.KeyID); err == nil && k.State == store.KeyRevoked {
		return nil, nil, &VerifyError{Reason: VRKeyRevoked}
	}
	u, sess, err := s.st.ValidateSessionAccess(c.SessionID)
	if err != nil {
		return nil, nil, mapStoreVerifyError(err)
	}
	// 凭证必须是会话当前有效的那一张：续期旋转后旧 jti 立即失效。
	if wantType == token.TypeAccess {
		if _, err := s.st.CheckAccessJTI(c.SessionID, c.TokenID); err != nil {
			return nil, nil, mapStoreVerifyError(err)
		}
	} else {
		if _, err := s.st.CheckRefreshJTI(c.SessionID, c.TokenID); err != nil {
			return nil, nil, mapStoreVerifyError(err)
		}
	}
	// 凭证签发时刻早于用户撤销水位线 => 签发后发生过权限/角色变更或撤销。
	if !sess.UserVersion.Equal(u.RevokeBefore) || c.IssuedAt < u.RevokeBefore.Unix() {
		return nil, nil, &VerifyError{Reason: VRStaleVersion}
	}
	return c, u, nil
}

func mapStoreVerifyError(err error) error {
	switch {
	case errors.Is(err, store.ErrSessionRevoked):
		return &VerifyError{Reason: VRSessionRevoked, Inner: err}
	case errors.Is(err, store.ErrStaleVersion):
		return &VerifyError{Reason: VRStaleVersion, Inner: err}
	case errors.Is(err, store.ErrNotFound):
		return &VerifyError{Reason: VRSessionNotFound, Inner: err}
	default:
		return &VerifyError{Reason: VRSessionNotFound, Inner: err}
	}
}

// ---- 管理面 ----
//
// 所有变更遵循“先改存储、成功后再失效判定缓存并写审计”的顺序；
// 存储失败直接返回错误，不动缓存；审计失败按 fail-closed 向调用方暴露，
// 但已提交的存储变更不回滚（审计容量需在容量规划中预留，见 README）。

// mutate 执行一个存储变更，成功后失效判定缓存并写一条审计。
func (s *Service) mutate(action, actor string, detail map[string]string, fn func() error) error {
	if err := fn(); err != nil {
		s.audit("system", "", action, "", audit.DecisionError, err.Error(), detail)
		return err
	}
	s.ev.Invalidate() // 任何主体/资源/策略变更后，旧判定结论一律不再使用
	return s.audit(actor, "", action, "", audit.DecisionAllow, "committed", detail)
}

// UpsertUser 新增或全量替换用户（角色/属性动态变更）。
// 注意：替换用户对象时保留服务端维护的撤销水位线，避免管理面写入把它清零
// 导致已撤销凭证“复活”。
func (s *Service) UpsertUser(u store.User) error {
	return s.mutate("admin.upsert_user", "admin", map[string]string{"user_id": u.ID}, func() error {
		if existing, err := s.st.GetUser(u.ID); err == nil {
			u.RevokeBefore = existing.RevokeBefore
			return s.st.UpdateUser(u)
		}
		return s.st.CreateUser(u)
	})
}

// UpsertResource 新增或替换资源。
func (s *Service) UpsertResource(r store.Resource) error {
	return s.mutate("admin.upsert_resource", "admin", map[string]string{"resource_id": r.ID, "kind": r.Kind}, func() error {
		if _, err := s.st.GetResource(r.ID); err == nil {
			return s.st.ReplaceResource(r)
		}
		return s.st.CreateResource(r)
	})
}

// CreateRole 登记角色。
func (s *Service) CreateRole(id string) error {
	return s.mutate("admin.create_role", "admin", map[string]string{"role_id": id}, func() error {
		return s.st.CreateRole(id)
	})
}

// PutPolicy 新增或替换策略。
func (s *Service) PutPolicy(p store.Policy) error {
	return s.mutate("admin.put_policy", "admin",
		map[string]string{"policy_id": p.ID, "effect": string(p.Effect)}, func() error {
			return s.st.PutPolicy(p)
		})
}

// DeletePolicy 删除策略。
func (s *Service) DeletePolicy(id string) error {
	return s.mutate("admin.delete_policy", "admin", map[string]string{"policy_id": id}, func() error {
		return s.st.DeletePolicy(id)
	})
}

// AddKey 登记一把新密钥（轮换并存期：新老密钥同时可验证）。
func (s *Service) AddKey(k store.SigningKey) error {
	detail := map[string]string{"key_id": k.ID, "state": string(k.State)}
	return s.mutate("admin.add_key", "admin", detail, func() error {
		return s.st.AddKey(k)
	})
}

// RotateKey 原子轮换：新密钥必须已 AddKey；轮换后旧 active 全部退役(只验不签)。
func (s *Service) RotateKey(newKeyID string) error {
	return s.mutate("admin.rotate_key", "admin", map[string]string{"new_key_id": newKeyID}, func() error {
		_, err := s.st.RotateActiveKey(newKeyID)
		return err
	})
}

// RetireKey 将密钥置为退役（只验不签）。
func (s *Service) RetireKey(id string) error {
	return s.mutate("admin.retire_key", "admin", map[string]string{"key_id": id}, func() error {
		return s.st.RetireKey(id)
	})
}

// RevokeKey 撤销密钥：该 kid 全部凭证立即失效（下一次校验即拒绝）。
func (s *Service) RevokeKey(id string) error {
	return s.mutate("admin.revoke_key", "admin", map[string]string{"key_id": id}, func() error {
		return s.st.RevokeKey(id)
	})
}

// RevokeUser 立即撤销用户全部存量凭证：水位线前推 + 会话标记，
// 双管齐下保证撤销即刻生效，不等待任何凭证自然过期。
func (s *Service) RevokeUser(userID string) error {
	return s.mutate("admin.revoke_user", "admin", map[string]string{"user_id": userID}, func() error {
		if err := s.st.RevokeUserCredentials(userID, s.now()); err != nil {
			return err
		}
		_ = s.st.RevokeAllUserSessions(userID)
		return nil
	})
}

// RevokeSessionByToken 撤销给定凭证所属会话（登出）。只读取凭证元信息定位会话，
// 不要求凭证仍有效（过期凭证也应能登出）；无法定位时返回错误且不做任何变更。
func (s *Service) RevokeSessionByToken(raw string) error {
	meta, ok := token.DecodePayloadOnly(raw)
	if !ok {
		return &VerifyError{Reason: VRMalformed}
	}
	if err := s.st.RevokeSessionByJTI(meta.TokenID); err != nil {
		_ = s.audit(meta.Subject, meta.SessionID, "logout", "", audit.DecisionDeny, err.Error(), nil)
		return err
	}
	return s.audit(meta.Subject, meta.SessionID, "logout", "", audit.DecisionAllow, "session_revoked", nil)
}

// audit 写入一条审计；返回错误供调用方按 fail-closed 处理。
// 任何形如凭证/密钥的字段在 audit 包内都会被脱敏。
func (s *Service) audit(actor, sid, action, resource string, d audit.Decision, reason string, detail map[string]string) error {
	_, err := s.auditLog.Append(audit.AppendInput{
		Actor: actor, SessionID: sid, Action: action, Resource: resource,
		Decision: d, Reason: reason, Detail: detail, Time: s.now(),
	})
	return err
}

// ---- 身份面 ----

// issue 用当前 active 密钥签发一对凭证并在存储中原子登记会话。
// 若密钥/存储/审计任一步失败，返回错误且不产生会话；签名发生在登记之前，
// 失败时未登记的凭证不可用（无法通过会话校验），无残留可用状态。
func (s *Service) issue(userID, sessionID string, createdAt time.Time) (*IssueResult, error) {
	u, err := s.st.GetUser(userID)
	if err != nil {
		return nil, err
	}
	key, err := s.st.ActiveKey()
	if err != nil {
		return nil, err
	}
	accessExp := createdAt.Add(s.cfg.AccessTTL)
	refreshExp := createdAt.Add(s.cfg.RefreshTTL)
	accessJTI := token.NewID()
	refreshJTI := token.NewID()

	accessClaims := &token.Claims{
		Issuer: s.cfg.Issuer, Subject: userID, SessionID: sessionID,
		TokenID: accessJTI, TokenType: token.TypeAccess,
		IssuedAt: createdAt.Unix(), ExpiresAt: accessExp.Unix(),
		Roles: append([]string(nil), u.Roles...), Attrs: cloneStringMap(u.Attrs),
	}
	refreshClaims := &token.Claims{
		Issuer: s.cfg.Issuer, Subject: userID, SessionID: sessionID,
		TokenID: refreshJTI, TokenType: token.TypeRefresh,
		IssuedAt: createdAt.Unix(), ExpiresAt: refreshExp.Unix(),
	}
	accessRaw, err := token.Sign(accessClaims, key.ID, key.Secret)
	if err != nil {
		return nil, err
	}
	refreshRaw, err := token.Sign(refreshClaims, key.ID, key.Secret)
	if err != nil {
		return nil, err
	}
	if _, err := s.st.CreateSession(store.CreateSessionInput{
		ID: sessionID, UserID: userID, RefreshJTI: refreshJTI, AccessJTI: accessJTI,
		CreatedAt: createdAt, UserVersion: u.RevokeBefore,
	}); err != nil {
		return nil, err
	}
	res := &IssueResult{
		AccessToken: accessRaw, RefreshToken: refreshRaw, SessionID: sessionID,
		AccessExp: accessExp, RefreshExp: refreshExp,
	}
	return res, nil
}

// Login 以已认证用户身份签发凭证（本地演示：直接以用户 ID 登录）。
func (s *Service) Login(userID string) (*IssueResult, error) {
	if _, err := s.st.GetUser(userID); err != nil {
		_ = s.audit(userID, "", "login", "", audit.DecisionDeny, err.Error(), nil)
		return nil, err
	}
	res, err := s.issue(userID, token.NewID(), s.now())
	if err != nil {
		_ = s.audit(userID, "", "login", "", audit.DecisionError, err.Error(), nil)
		return nil, err
	}
	// 审计只记录元信息，绝不记录原始凭证；access_token 等键名也会被脱敏。
	if err := s.audit(userID, res.SessionID, "login", "", audit.DecisionAllow, "issued",
		map[string]string{"key_id": s.mustActiveKeyID()}); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) mustActiveKeyID() string {
	k, err := s.st.ActiveKey()
	if err != nil {
		return ""
	}
	return k.ID
}

// Authorize 校验访问凭证并做授权判定。任何异常路径均拒绝并审计，绝不放行。
// 返回错误表示“无法/不得授权”，调用方必须按拒绝处理；
// 正常返回时结论可能是 permit 或 deny(默认拒绝/显式拒绝)。
func (s *Service) Authorize(rawAccessToken, action, resourceID string) (*AuthorizeResult, error) {
	claims, user, verr := s.verifyClaims(rawAccessToken, token.TypeAccess)
	if verr != nil {
		reason := verr.Error()
		// 拒绝也必须留痕；actor 能解出就记录，解不出标记 unknown。
		actor := "unknown"
		if c, ok := token.DecodePayloadOnly(rawAccessToken); ok {
			actor = c.Subject
		}
		_ = s.audit(actor, "", "authorize", resourceID, audit.DecisionDeny, reason,
			map[string]string{"action": action})
		return nil, verr
	}

	var resource *store.Resource
	if resourceID != "" {
		r, err := s.st.GetResource(resourceID)
		if err != nil {
			_ = s.audit(claims.Subject, claims.SessionID, "authorize", resourceID,
				audit.DecisionDeny, string(VRResourceNotFound), map[string]string{"action": action})
			return nil, &VerifyError{Reason: VRResourceNotFound, Inner: err}
		}
		resource = r
	}
	policies := s.st.ListPolicies()
	tr := s.ev.Evaluate(user, action, resource, policies)

	out := &AuthorizeResult{
		Decision: tr.Decision, Reason: tr.Reason, Trace: tr,
		Subject: claims.Subject, Resource: resourceID, Action: action,
	}
	dec := audit.DecisionDeny
	if tr.Decision == authz.DecisionPermit {
		dec = audit.DecisionAllow
	}
	detail := map[string]string{
		"action":          action,
		"decision_reason": string(tr.Reason),
		"from_cache":      boolString(tr.FromCache),
		"roles_evaluated": joinStrings(user.Roles),
		"rules_evaluated": intString(len(tr.Rules)),
	}
	if err := s.audit(claims.Subject, claims.SessionID, "authorize", resourceID,
		dec, string(tr.Reason), detail); err != nil {
		// 审计失败：fail-closed，即使判定为 permit 也不放行。
		return nil, err
	}
	return out, nil
}

// Refresh 用 refresh 凭证换新凭证对；refresh 一次性、原子旋转。
// 重复使用同一 refresh（并发重放）只有一个请求成功，其余因旧 jti 已摘除而被拒绝；
// 续期后旧 access 同样即刻失效（jti 已旋转）。
func (s *Service) Refresh(rawRefreshToken string) (*IssueResult, error) {
	claims, user, verr := s.verifyClaims(rawRefreshToken, token.TypeRefresh)
	if verr != nil {
		actor := "unknown"
		if c, ok := token.DecodePayloadOnly(rawRefreshToken); ok {
			actor = c.Subject
		}
		_ = s.audit(actor, "", "refresh", "", audit.DecisionDeny, verr.Error(), nil)
		return nil, verr
	}

	key, err := s.st.ActiveKey()
	if err != nil {
		_ = s.audit(claims.Subject, claims.SessionID, "refresh", "", audit.DecisionError, err.Error(), nil)
		return nil, err
	}
	now := s.now()
	newAccessJTI := token.NewID()
	newRefreshJTI := token.NewID()
	accessExp := now.Add(s.cfg.AccessTTL)
	refreshExp := now.Add(s.cfg.RefreshTTL)

	accessClaims := &token.Claims{
		Issuer: s.cfg.Issuer, Subject: user.ID, SessionID: claims.SessionID,
		TokenID: newAccessJTI, TokenType: token.TypeAccess,
		IssuedAt: now.Unix(), ExpiresAt: accessExp.Unix(),
		Roles: append([]string(nil), user.Roles...), Attrs: cloneStringMap(user.Attrs),
	}
	refreshClaims := &token.Claims{
		Issuer: s.cfg.Issuer, Subject: user.ID, SessionID: claims.SessionID,
		TokenID: newRefreshJTI, TokenType: token.TypeRefresh,
		IssuedAt: now.Unix(), ExpiresAt: refreshExp.Unix(),
	}
	accessRaw, err := token.Sign(accessClaims, key.ID, key.Secret)
	if err != nil {
		return nil, err
	}
	refreshRaw, err := token.Sign(refreshClaims, key.ID, key.Secret)
	if err != nil {
		return nil, err
	}

	// 原子“校验旧 refresh jti + 旋转”：消除先查后改的 TOCTOU 竞态。
	// 并发重放同一 refresh 时只有一个调用能成功；旧 jti 摘除与新 jti 登记同临界区。
	if _, err := s.st.RotateSessionTokensIfRefreshJTI(
		claims.SessionID, claims.TokenID, newRefreshJTI, newAccessJTI, user.RevokeBefore); err != nil {
		// 旋转阶段的并发重放/撤销同样归一化为可区分的凭证级拒绝原因，
		// 保证 HTTP 与其他入口拿到的原因字符串稳定一致。
		mapped := mapStoreVerifyError(err)
		_ = s.audit(claims.Subject, claims.SessionID, "refresh", "", audit.DecisionDeny, mapped.Error(), nil)
		return nil, mapped
	}
	res := &IssueResult{
		AccessToken: accessRaw, RefreshToken: refreshRaw, SessionID: claims.SessionID,
		AccessExp: accessExp, RefreshExp: refreshExp,
	}
	if err := s.audit(claims.Subject, claims.SessionID, "refresh", "", audit.DecisionAllow,
		"rotated", map[string]string{"key_id": key.ID}); err != nil {
		return nil, err
	}
	return res, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func joinStrings(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}

// VerifyAccessToken 仅做凭证校验（不授权），供需要身份而非权限的入口复用。
func (s *Service) VerifyAccessToken(raw string) (*token.Claims, *store.User, error) {
	return s.verifyClaims(raw, token.TypeAccess)
}
