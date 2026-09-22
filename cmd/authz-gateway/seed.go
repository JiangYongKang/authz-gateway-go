package main

import (
	"context"

	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
)

// seed 装配本地演示数据：初始密钥、两个用户、一个资源与三条策略
// （含一条演示“显式拒绝优先”的冲突规则目标，可按需启用）。
func seed(gw *gateway.Gateway) error {
	ctx := context.Background()

	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("local-demo-master-key"), "bootstrap"); err != nil {
		return err
	}

	if err := gw.PutUser(ctx, gateway.UserInput{
		Name:       "alice",
		Roles:      []string{"reader", "editor"},
		Attributes: map[string]string{"dept": "engineering"},
	}); err != nil {
		return err
	}
	if err := gw.PutUser(ctx, gateway.UserInput{
		Name:       "bob",
		Roles:      []string{"reader"},
		Attributes: map[string]string{"dept": "sales"},
	}); err != nil {
		return err
	}

	if err := gw.PutResource(ctx, gateway.ResourceInput{
		Name:       "doc-1",
		Kind:       "doc",
		Owner:      "alice",
		Attributes: map[string]string{"classification": "internal"},
	}); err != nil {
		return err
	}

	policies := []gateway.PolicyInput{
		{
			ID:        "p-readers-read",
			Roles:     []string{"reader"},
			Resources: []string{"*"},
			Actions:   []string{"read"},
		},
		{
			ID:        "p-editors-write-doc1",
			Roles:     []string{"editor"},
			Resources: []string{"doc-1"},
			Actions:   []string{"write"},
		},
	}
	for _, p := range policies {
		if _, err := gw.UpsertPolicy(ctx, p, "bootstrap"); err != nil {
			return err
		}
	}
	return nil
}
