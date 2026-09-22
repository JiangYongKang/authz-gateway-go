package gateway

import (
	"context"
	"fmt"

	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

// UserInput 是目录用户的写入视图。
type UserInput struct {
	Name       string            `json:"name"`
	Roles      []string          `json:"roles"`
	Attributes map[string]string `json:"attributes"`
}

// ResourceInput 是资源的写入视图。
type ResourceInput struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Owner      string            `json:"owner"`
	Attributes map[string]string `json:"attributes"`
}

// PutUser 登记或更新主体；容量超限时返回 limit_exceeded。
func (g *Gateway) PutUser(ctx context.Context, in UserInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.Name == "" {
		return fmt.Errorf("%w: empty name", errBadRequest())
	}
	return mapWrappedStoreError(g.store.PutUser(store.User{
		Name:       in.Name,
		Roles:      in.Roles,
		Attributes: in.Attributes,
	}))
}

// PutResource 登记或更新受保护资源。
func (g *Gateway) PutResource(ctx context.Context, in ResourceInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.Name == "" {
		return fmt.Errorf("%w: empty name", errBadRequest())
	}
	return mapWrappedStoreError(g.store.PutResource(store.Resource{
		Name:       in.Name,
		Kind:       in.Kind,
		Owner:      in.Owner,
		Attributes: in.Attributes,
	}))
}
