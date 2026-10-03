// Package gateway 编排凭证生命周期与授权判定：
// 签发、校验、续期、撤销、密钥轮换、策略管理、判定与审计。
//
// 所有敏感路径共享同一把存储锁与单调授权版本号，从而保证：
// 权限撤销立即生效（每次判定都重新核对会话状态，且撤销提升版本号使缓存失效）；
// 续期采用 CAS，并发续期不会重复计数或让旧凭证复活；
// 密钥轮换原子可见，轮换后旧密钥仅可验签、不可签发。
package gateway

import (
	"errors"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/authz"
	"github.com/highcumontoa/authz-gateway-go/internal/cache"
	"github.com/highcumontoa/authz-gateway-go/internal/config"
	"github.com/highcumontoa/authz-gateway-go/internal/evidence"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

// 拒绝/失败原因码（对各入口统一、可区分）。
const (
	ReasonOK                 = "ok"
	ReasonUserNotFound       = "user_not_found"
	ReasonTokenMalformed     = "token_malformed"
	ReasonBadSignature       = "bad_signature"
	ReasonUnknownKey         = "unknown_signing_key"
	ReasonIssuerMismatch     = "issuer_mismatch"
	ReasonTokenExpired       = "token_expired"
	ReasonTokenNotValidYet   = "token_not_valid_yet"
	ReasonSessionRevoked     = "session_revoked"
	ReasonSessionMissing     = "session_missing"
	ReasonCredentialStale    = "credential_superseded"
	ReasonNoMatchingPolicy   = "no_matching_policy"
	ReasonExplicitDeny       = "explicit_deny"
	ReasonResourceNotFound   = "resource_not_found"
	ReasonTooManyAttributes  = "too_many_attributes"
	ReasonRuleSetTooLarge    = "rule_set_too_large"
	ReasonLimitExceeded      = "limit_exceeded"
	ReasonStorageFault       = "storage_failure"
	ReasonAuditFailure       = "audit_failure"
	ReasonKeyRetired         = "signing_key_retired"
	ReasonRenewTooEarly      = "renew_outside_window"
	ReasonBadRequest         = "bad_request"
	ReasonExportInvalidRange = "export_invalid_range"
	ReasonExportUnavailable  = "export_range_unavailable"
	ReasonExportTooMany      = "export_too_many_records"
	ReasonExportTooLarge     = "export_too_large"
)

// Gateway 是服务的核心编排器。
type Gateway struct {
	cfg      config.Config
	store    *store.Store
	eng      *authz.Engine
	aud      *audit.Log
	cache    *cache.LRU[string, cacheEntry]
	exporter *evidence.Exporter
	evKey    *evidence.ExportKey
	now      func() time.Time
}

type cacheEntry struct {
	allowed  bool
	decision authz.Decision
	reason   string
	deny     []string
	allow    []string
	version  int64
	expireAt int64
}

// New 构造网关并装配存储、引擎、审计与判定缓存。
func New(cfg config.Config) *Gateway {
	cfg = cfg.MergeDefaults()
	st := store.NewBounded(cfg.MaxUsers, cfg.MaxResources, cfg.MaxPolicies,
		cfg.MaxSessions, cfg.MaxKeys)
	aud := audit.New(cfg.AuditCapacity)
	now := time.Now
	st.SetClock(now)
	aud.SetClock(now)
	// 导出证据签名密钥：优先使用注入种子，否则随机生成。
	evKey := newEvidenceKey(cfg.AuditEvidenceKeySeed)
	g := &Gateway{
		cfg:   cfg,
		store: st,
		eng:   authz.NewEngine(cfg.MaxRuleCount),
		aud:   aud,
		cache: cache.NewLRU[string, cacheEntry](cfg.DecisionCache),
		exporter: evidence.NewExporter(aud, evKey, evidence.Limits{
			MaxRecords: cfg.AuditExportMaxRecords,
			MaxBytes:   cfg.AuditExportMaxBytes,
		}),
		evKey: evKey,
		now:   now,
	}
	return g
}

// newEvidenceKey 从可选种子构造导出密钥；种子非法或未提供时退回随机密钥，
// 随机生成也失败（极不可能）时返回 nil，导出将明确报未初始化而非崩溃。
func newEvidenceKey(seed []byte) *evidence.ExportKey {
	if len(seed) > 0 {
		if k, err := evidence.ExportKeyFromSeed(seed); err == nil {
			return k
		}
	}
	k, err := evidence.NewExportKey()
	if err != nil {
		return nil
	}
	return k
}

// SetClock 注入统一时间源（测试用），存储与审计同步使用。
func (g *Gateway) SetClock(f func() time.Time) {
	g.now = f
	g.store.SetClock(f)
	g.aud.SetClock(f)
}

// Store 暴露底层存储，供引导装配使用。
func (g *Gateway) Store() *store.Store { return g.store }

// AuditLog 暴露审计日志。
func (g *Gateway) AuditLog() *audit.Log { return g.aud }

// AuditSince 返回 ID 大于 afterID 的审计记录。
func (g *Gateway) AuditSince(afterID int64) ([]audit.Event, error) {
	return g.aud.Since(afterID)
}

// mapTokenError 把 token 包哨兵错误映射为统一原因码。
func mapTokenError(err error) string {
	switch {
	case errors.Is(err, token.ErrMalformed):
		return ReasonTokenMalformed
	case errors.Is(err, token.ErrBadSignature):
		return ReasonBadSignature
	case errors.Is(err, token.ErrUnknownKey):
		return ReasonUnknownKey
	case errors.Is(err, token.ErrIssuerMismatch):
		return ReasonIssuerMismatch
	case errors.Is(err, token.ErrExpired):
		return ReasonTokenExpired
	case errors.Is(err, token.ErrNotValidYet):
		return ReasonTokenNotValidYet
	default:
		return ReasonTokenMalformed
	}
}

// mapStoreError 把存储错误映射为统一原因码。
func mapStoreError(err error) string {
	switch {
	case errors.Is(err, store.ErrLimitExceeded):
		return ReasonLimitExceeded
	case errors.Is(err, store.ErrStorageFault):
		return ReasonStorageFault
	case errors.Is(err, store.ErrConflict):
		return ReasonCredentialStale
	case errors.Is(err, store.ErrKeyRetired):
		return ReasonKeyRetired
	case errors.Is(err, store.ErrNotFound):
		return ReasonSessionMissing
	default:
		return ReasonStorageFault
	}
}

// verifyAndLoad 是所有入口共享的凭证校验路径：
// 结构 -> kid 存在性 -> 签名/签发者/时间窗 -> 会话存在 -> 未撤销 -> JTI 为当前版本。
// 任何一步异常都返回确定的原因码，绝不放行。
func (g *Gateway) verifyAndLoad(raw string) (*token.Claims, *store.Session, string) {
	h, err := token.PeekHeader(raw)
	if err != nil {
		return nil, nil, mapTokenError(err)
	}
	secret, _, err := g.store.GetKeySecret(h.Kid)
	if err != nil {
		// kid 不存在（可能密钥已彻底退役），按未知密钥拒绝。
		return nil, nil, ReasonUnknownKey
	}
	claims, err := token.Verify(raw, h.Kid, secret, g.cfg.Issuer, g.now())
	if err != nil {
		return nil, nil, mapTokenError(err)
	}
	sess, err := g.store.GetSession(claims.SessionID)
	if err != nil {
		return nil, nil, ReasonSessionMissing
	}
	if sess.Revoked {
		return nil, nil, ReasonSessionRevoked
	}
	if sess.CurrentJTI == "" || sess.CurrentJTI != claims.JTI {
		// 凭证已被续期取代：旧凭证不得复活为有效凭证。
		return nil, nil, ReasonCredentialStale
	}
	if !g.now().Before(sess.ExpiresAt) {
		return nil, nil, ReasonTokenExpired
	}
	c := claims
	return &c, &sess, ReasonOK
}
