package gateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

// Revoke 立即撤销会话：撤销在存储临界区内原子完成并提升授权版本，
// 因而该会话的所有凭证（包括最新 JTI）在下一次任何入口的判定中立即失效，
// 不必等待凭证自然过期。
func (g *Gateway) Revoke(ctx context.Context, sessionID, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sessionID == "" {
		return fmt.Errorf("%w: empty session id", errBadRequest())
	}
	// 先审计再变更：审计不可写则不执行敏感撤销。
	if err := g.recordAudit(audit.Event{
		Actor:     actor,
		Operation: "revoke",
		Result:    "success",
		Reason:    ReasonOK,
		SessionID: sessionID,
	}); err != nil {
		return withReason(errAudit(), ReasonAuditFailure)
	}
	if err := g.store.RevokeSession(sessionID, g.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return withReason(errBadRequest(), ReasonSessionMissing)
		}
		return mapWrappedStoreError(err)
	}
	// 撤销已经提升了存储授权版本；再显式清空与该会话相关的判定缓存，
	// 使旧结论立即不可见。
	g.invalidateSessionCache(sessionID)
	return nil
}

// RevokeByToken 撤销凭证所属会话。凭证必须先通过结构与签名校验，
// 避免仅凭任意字符串就能驱动撤销；但已过期的凭证仍可用于定位会话并撤销。
func (g *Gateway) RevokeByToken(ctx context.Context, raw, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := token.PeekHeader(raw)
	if err != nil {
		return withReason(errBadRequest(), ReasonTokenMalformed)
	}
	secret, _, err := g.store.GetKeySecret(h.Kid)
	if err != nil {
		return withReason(errDenied(), ReasonUnknownKey)
	}
	// 允许过期错误：过期凭证依然可以被管理员用来定位并撤销会话。
	claims, err := token.Verify(raw, h.Kid, secret, g.cfg.Issuer, g.now())
	if err != nil && !errors.Is(err, token.ErrExpired) {
		return withReason(errDenied(), mapTokenError(err))
	}
	// token.Verify 在过期时仍返回解析好的 claims。
	if claims.SessionID == "" {
		return withReason(errBadRequest(), ReasonTokenMalformed)
	}
	return g.Revoke(ctx, claims.SessionID, actor)
}
