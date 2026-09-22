package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/authz"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

// AuthorizeRequest 是带凭证的授权请求。
type AuthorizeRequest struct {
	Token      string
	Resource   string
	Action     string
	Attributes map[string]string // 随请求附加的主体属性（ABAC 补充）
}

// AuthorizeResult 是授权结论与解释。
type AuthorizeResult struct {
	Allowed      bool           `json:"allowed"`
	Decision     authz.Decision `json:"decision"`
	Reason       string         `json:"reason"`
	MatchedDeny  []string       `json:"matched_deny"`
	MatchedAllow []string       `json:"matched_allow"`
	Subject      string         `json:"subject"`
	SessionID    string         `json:"session_id"`
	JTI          string         `json:"jti"`
}

func (g *Gateway) invalidateSessionCache(sessionID string) {
	prefix := sessionID + "|"
	g.cache.InvalidateIf(func(k string) bool {
		return strings.HasPrefix(k, prefix) || k == sessionID
	})
}

func (g *Gateway) denyResult(reason string, claimsSubj, sessionID, jti string) AuthorizeResult {
	return AuthorizeResult{
		Allowed: false, Decision: authz.Deny, Reason: reason,
		Subject: claimsSubj, SessionID: sessionID, JTI: jti,
	}
}

// Authorize 完成“校验凭证 -> 组装主体/资源视图 -> 策略判定 -> 审计”的完整入口。
//
// 一致性保证：
//   - 撤销立即生效：凭证校验强制 JTI 等于会话当前 JTI，且判定缓存条目绑定
//     授权版本号；撤销/角色/策略任何变更都会推进版本号，旧缓存条目视为失效。
//   - 默认拒绝：用户不存在、资源不存在、无匹配策略等全部落入 Deny。
//   - 显式拒绝优先：由无状态 authz.Engine 在全量策略快照上保证顺序无关。
func (g *Gateway) Authorize(ctx context.Context, req AuthorizeRequest) AuthorizeResult {
	if err := ctx.Err(); err != nil {
		return g.denyResult(ReasonStorageFault, "", "", "")
	}
	if req.Resource == "" || req.Action == "" {
		return g.denyResult(ReasonBadRequest, "", "", "")
	}
	if g.cfg.MaxAttrCount > 0 && len(req.Attributes) > g.cfg.MaxAttrCount {
		r := g.denyResult(ReasonTooManyAttributes, "", "", "")
		g.auditAuthorize(r, "")
		return r
	}

	claims, sess, reason := g.verifyAndLoad(req.Token)
	if reason != ReasonOK {
		r := g.denyResult(reason, subjectFromClaims(claims), sidFromClaims(claims), jtiFromClaims(claims))
		g.auditAuthorize(r, "")
		return r
	}

	// 资源必须存在；不存在的资源默认拒绝（防止对未登记对象意外放行）。
	res, err := g.store.GetResource(req.Resource)
	if err != nil {
		r := g.denyResult(ReasonResourceNotFound, claims.Subject, sess.ID, claims.JTI)
		g.auditAuthorize(r, "")
		return r
	}

	user, err := g.store.GetUser(sess.Username)
	if err != nil {
		r := g.denyResult(ReasonUserNotFound, claims.Subject, sess.ID, claims.JTI)
		g.auditAuthorize(r, "")
		return r
	}

	version := g.store.AuthzVersion()
	cacheKey := fmt.Sprintf("%s|%s|%s", sess.ID, req.Resource, req.Action)
	now := g.now().Unix()
	if hit, ok := g.cache.Get(cacheKey, now); ok && hit.version == version {
		r := AuthorizeResult{
			Allowed: hit.allowed, Decision: hit.decision, Reason: hit.reason,
			MatchedDeny: hit.deny, MatchedAllow: hit.allow,
			Subject: claims.Subject, SessionID: sess.ID, JTI: claims.JTI,
		}
		g.auditAuthorize(r, "cache")
		return r
	}

	policies, err := g.store.ListPolicies()
	if err != nil {
		r := g.denyResult(ReasonStorageFault, claims.Subject, sess.ID, claims.JTI)
		g.auditAuthorize(r, "")
		return r
	}

	subjectAttrs, _ := mergeAttrs(user.Attributes, sess.Attributes, 0)
	subjectAttrs, _ = mergeAttrs(subjectAttrs, claims.Attributes, 0)
	subjectAttrs, ok := mergeAttrs(subjectAttrs, req.Attributes, g.cfg.MaxAttrCount)
	if !ok {
		r := g.denyResult(ReasonTooManyAttributes, claims.Subject, sess.ID, claims.JTI)
		g.auditAuthorize(r, "")
		return r
	}
	// 注入内置属性，供 ABAC 条件使用。
	subjectAttrs["subject"] = user.Name
	resAttrs := mergeWithBuiltins(res, user.Name)

	authReq := authz.Request{
		Subject:       user.Name,
		Roles:         user.Roles,
		SubjectAttrs:  subjectAttrs,
		Resource:      res.Name,
		ResourceKind:  res.Kind,
		ResourceOwner: res.Owner,
		ResourceAttrs: resAttrs,
		Action:        req.Action,
	}
	expl := g.eng.Evaluate(authReq, policies)
	r := AuthorizeResult{
		Allowed:      expl.Decision == authz.Allow,
		Decision:     expl.Decision,
		Reason:       expl.Reason,
		MatchedDeny:  expl.MatchedDeny,
		MatchedAllow: expl.MatchedAllow,
		Subject:      claims.Subject,
		SessionID:    sess.ID,
		JTI:          claims.JTI,
	}
	// 只缓存正面结论且绑定当前授权版本与 TTL；任何变更都会使版本失配。
	if r.Allowed {
		g.cache.Add(cacheKey, cacheEntry{
			allowed: true, decision: r.Decision, reason: r.Reason,
			deny: r.MatchedDeny, allow: r.MatchedAllow,
			version: version, expireAt: g.now().Add(g.cfg.DecisionTTL).Unix(),
		}, g.now().Add(g.cfg.DecisionTTL).Unix())
	}
	g.auditAuthorize(r, "evaluated")
	return r
}

func mergeWithBuiltins(res store.Resource, subject string) map[string]string {
	out := make(map[string]string, len(res.Attributes)+3)
	for k, v := range res.Attributes {
		out[k] = v
	}
	out["owner"] = res.Owner
	out["kind"] = res.Kind
	out["name"] = res.Name
	return out
}

func (g *Gateway) auditAuthorize(r AuthorizeResult, source string) {
	result := "success"
	if !r.Allowed {
		result = "denied"
	}
	detail := map[string]string{}
	if source != "" {
		detail["source"] = source
	}
	_ = g.recordAudit(audit.Event{
		Actor:     orAnonymous(r.Subject),
		Operation: "authorize",
		Result:    result,
		Reason:    r.Reason,
		JTI:       r.JTI,
		SessionID: r.SessionID,
		Subject:   r.Subject,
		Matched:   joinIDs(r.MatchedDeny, r.MatchedAllow),
		Detail:    detail,
	})
}

func joinIDs(deny, allow []string) string {
	parts := make([]string, 0, len(deny)+len(allow))
	for _, d := range deny {
		parts = append(parts, "deny:"+d)
	}
	for _, a := range allow {
		parts = append(parts, "allow:"+a)
	}
	return strings.Join(parts, ",")
}

func orAnonymous(s string) string {
	if s == "" {
		return "anonymous"
	}
	return s
}

// 下列辅助在凭证非法（claims 为 nil）时安全返回空串，避免解引用空指针。
func subjectFromClaims(c *token.Claims) string {
	if c == nil {
		return ""
	}
	return c.Subject
}

func jtiFromClaims(c *token.Claims) string {
	if c == nil {
		return ""
	}
	return c.JTI
}

func sidFromClaims(c *token.Claims) string {
	if c == nil {
		return ""
	}
	return c.SessionID
}
