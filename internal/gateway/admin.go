package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

// PolicyInput 是管理入口的策略输入。
type PolicyInput struct {
	ID         string
	Deny       bool
	Roles      []string
	Users      []string
	Resources  []string
	Actions    []string
	Conditions map[string]string
}

// KeyInfoResult 是密钥元数据视图（绝不包含密钥明文）。
type KeyInfoResult struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// auditAdmin 记录一次管理操作（只记元数据，不记密钥/凭证内容）。
func (g *Gateway) auditAdmin(actor, op, result, reason, target string, detail map[string]string) error {
	return g.recordAudit(audit.Event{
		Actor:     actor,
		Operation: op,
		Result:    result,
		Reason:    reason,
		Resource:  target,
		Detail:    detail,
	})
}

// UpsertPolicy 创建或更新一条授权规则。任何成功变更都让授权版本前进一步，
// 因而新判定立刻遵循新规则（旧正面结论因版本失配而失效）。
func (g *Gateway) UpsertPolicy(ctx context.Context, in PolicyInput, actor string) (store.Policy, error) {
	if err := ctx.Err(); err != nil {
		return store.Policy{}, err
	}
	if in.ID == "" {
		return store.Policy{}, fmt.Errorf("%w: empty policy id", errBadRequest())
	}
	existing, err := g.store.GetPolicy(in.ID)
	version := int64(1)
	if err == nil {
		version = existing.Version + 1
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Policy{}, mapWrappedStoreError(err)
	}
	p := store.Policy{
		ID:         in.ID,
		Version:    version,
		Deny:       in.Deny,
		Roles:      in.Roles,
		Users:      in.Users,
		Resources:  in.Resources,
		Actions:    in.Actions,
		Conditions: in.Conditions,
	}
	saved, err := g.store.PutPolicy(p)
	if err != nil {
		return store.Policy{}, mapWrappedStoreError(err)
	}
	if err := g.auditAdmin(actor, "admin_policy_upsert", "success", ReasonOK, in.ID,
		map[string]string{"version": fmt.Sprint(saved.Version), "deny": fmt.Sprint(in.Deny)}); err != nil {
		return store.Policy{}, withReason(errAudit(), ReasonAuditFailure)
	}
	return saved, nil
}

// DeletePolicy 移除一条规则；变更后立即生效。
func (g *Gateway) DeletePolicy(ctx context.Context, id, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.store.DeletePolicy(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return withReason(errBadRequest(), ReasonBadRequest)
		}
		return mapWrappedStoreError(err)
	}
	return g.auditAdmin(actor, "admin_policy_delete", "success", ReasonOK, id, nil)
}

// ListPolicies 返回策略快照。
func (g *Gateway) ListPolicies(ctx context.Context) ([]store.Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return g.store.ListPolicies()
}

// AssignRoles 覆盖式设置用户角色，变更立即影响后续判定（版本号推进）。
func (g *Gateway) AssignRoles(ctx context.Context, username string, roles []string, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if username == "" {
		return fmt.Errorf("%w: empty username", errBadRequest())
	}
	u, err := g.store.GetUser(username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return withReason(errBadRequest(), ReasonUserNotFound)
		}
		return mapWrappedStoreError(err)
	}
	u.Roles = roles
	if err := g.store.PutUser(u); err != nil {
		return mapWrappedStoreError(err)
	}
	g.cache.InvalidateIf(func(string) bool { return true })
	return g.auditAdmin(actor, "admin_assign_roles", "success", ReasonOK, username,
		map[string]string{"roles": joinNonEmpty(roles)})
}

// PrepareKey 登记“下一任”密钥。该密钥立即可以验签（轮换期间新旧并存），
// 但在 Rotate 之前不能用于签发。
func (g *Gateway) PrepareKey(ctx context.Context, kid string, secret []byte, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if kid == "" || len(secret) == 0 {
		return fmt.Errorf("%w: empty kid or secret", errBadRequest())
	}
	if err := g.store.PutKeySecret(kid, secret, store.KeyNext); err != nil {
		return mapWrappedStoreError(err)
	}
	return g.auditAdmin(actor, "admin_key_prepare", "success", ReasonOK, kid, nil)
}

// BootstrapSigningKey 登记系统的第一把签发密钥（仅在尚无 active 密钥时）。
func (g *Gateway) BootstrapSigningKey(ctx context.Context, kid string, secret []byte, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, _, err := g.store.ActiveSigningKey(); err == nil {
		return fmt.Errorf("%w: active key already exists", errBadRequest())
	}
	if err := g.store.PutKeySecret(kid, secret, store.KeyActive); err != nil {
		return mapWrappedStoreError(err)
	}
	return g.auditAdmin(actor, "admin_key_bootstrap", "success", ReasonOK, kid, nil)
}

// Rotate 原子完成密钥轮换：指定的 next 密钥成为唯一签发密钥，
// 原 active 密钥转为 retired（仍可验签旧凭证，但永不再用于签发）。
// 轮换后新签发的凭证使用新 kid；既有凭证因旧密钥保留验签能力而继续可用。
func (g *Gateway) Rotate(ctx context.Context, nextKID, actor string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	newActive, err := g.store.RotateKeys(nextKID)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", withReason(errBadRequest(), ReasonKeyRetired)
		}
		return "", mapWrappedStoreError(err)
	}
	if err := g.auditAdmin(actor, "admin_key_rotate", "success", ReasonOK, newActive,
		map[string]string{"new_active_kid": newActive}); err != nil {
		return "", withReason(errAudit(), ReasonAuditFailure)
	}
	return newActive, nil
}

// RetireKey 将历史密钥彻底退役：之后该 kid 的凭证连验签都不再被接受。
func (g *Gateway) RetireKey(ctx context.Context, kid, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.store.RetireKey(kid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return withReason(errBadRequest(), ReasonUnknownKey)
		}
		return mapWrappedStoreError(err)
	}
	return g.auditAdmin(actor, "admin_key_retire", "success", ReasonOK, kid, nil)
}

// ListKeys 返回不含明文的密钥元数据。
func (g *Gateway) ListKeys(ctx context.Context) ([]KeyInfoResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	infos, err := g.store.ListKeys()
	if err != nil {
		return nil, mapWrappedStoreError(err)
	}
	out := make([]KeyInfoResult, 0, len(infos))
	for _, k := range infos {
		out = append(out, KeyInfoResult{ID: k.ID, State: k.State.String(),
			CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt})
	}
	return out, nil
}
