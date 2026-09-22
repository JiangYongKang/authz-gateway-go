// Command authz-gateway 在本地启动一个授权判定与凭证生命周期管理服务。
//
// 启动时会引导一组演示数据（用户/角色/资源/策略/初始签名密钥），
// 随后监听 HTTP 接口；也会在日志中打印一组可直接复制的 curl 调用顺序。
package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/httpapi"
	"github.com/highcumontoa/authz-gateway-go/internal/service"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

func main() {
	initialSecret := make([]byte, 32)
	if _, err := rand.Read(initialSecret); err != nil {
		log.Fatalf("生成初始密钥失败: %v", err)
	}

	cfg := service.Config{
		Issuer:        "https://authz.local",
		AccessTTL:     30 * time.Minute,
		RefreshTTL:    8 * time.Hour,
		StoreLimits:   store.DefaultLimits(),
		DecisionCache: 256,
		AuditCapacity: 10000,
	}
	svc, err := service.New(cfg, "k-initial", initialSecret)
	if err != nil {
		log.Fatalf("初始化服务失败: %v", err)
	}
	seed(svc)

	addr := "127.0.0.1:8080"
	srv := http.Server{Addr: addr, Handler: httpapi.New(svc).Handler()}

	log.Printf("authz-gateway 监听 http://%s", addr)
	log.Printf("快速验证:")
	log.Printf("  curl -s -XPOST %s/v1/login -d '{\"user_id\":\"alice\"}'", "http://"+addr)
	log.Printf("  curl -s -XPOST %s/v1/authorize -H 'Authorization: Bearer <access_token>' -d '{\"action\":\"read\",\"resource_id\":\"doc-1\"}'", "http://"+addr)
	log.Printf("  curl -s %s/v1/audit", "http://"+addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务退出: %v", err)
	}
}

// seed 引导演示模型：
//   - 角色 reader / editor；
//   - 用户 alice(reader, team=platform)、bob(editor)；
//   - 资源 doc-1(owner_team=platform)、secret-1；
//   - 策略：reader 可读 doc-1(ABAC 同团队)；editor 可写；secret-1 全局显式拒绝。
func seed(svc *service.Service) {
	must(svc.CreateRole("reader"))
	must(svc.CreateRole("editor"))

	must(svc.UpsertUser(store.User{
		ID: "alice", Roles: []string{"reader"},
		Attrs: map[string]string{"team": "platform"},
	}))
	must(svc.UpsertUser(store.User{
		ID: "bob", Roles: []string{"editor"},
		Attrs: map[string]string{"team": "billing"},
	}))

	must(svc.UpsertResource(store.Resource{
		ID: "doc-1", Kind: "document",
		Attrs: map[string]string{"owner_team": "platform"},
	}))
	must(svc.UpsertResource(store.Resource{
		ID: "secret-1", Kind: "secret",
		Attrs: map[string]string{"classification": "restricted"},
	}))

	// reader 且同团队可读 doc-1（RBAC + ABAC 组合）。
	must(svc.PutPolicy(store.Policy{
		ID: "doc-read-same-team", RoleID: "reader", ResourceID: "doc-1",
		Actions: []string{"read"}, Effect: store.EffectAllow,
		Conditions: map[string]string{
			"sub.attr.team":       "platform",
			"res.attr.owner_team": "platform",
		},
	}))
	// editor 可写 doc-1。
	must(svc.PutPolicy(store.Policy{
		ID: "doc-write-editor", RoleID: "editor", ResourceID: "doc-1",
		Actions: []string{"write"}, Effect: store.EffectAllow,
	}))
	// secret-1 对一切角色显式拒绝：优先级高于任何 allow（即使 admin 也是 deny）。
	must(svc.PutPolicy(store.Policy{
		ID: "secret-global-deny", RoleID: "", ResourceID: "secret-1",
		Effect: store.EffectDeny,
	}))
}

func must(err error) {
	if err != nil {
		log.Fatalf("引导数据失败: %v", err)
	}
}
