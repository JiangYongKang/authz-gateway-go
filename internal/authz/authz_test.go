package authz

import (
	"fmt"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

func logTrace(t *testing.T, name string, sub *store.User, action, resource string, tr *Trace) {
	t.Helper()
	roles := ""
	for i, r := range sub.Roles {
		if i > 0 {
			roles += ","
		}
		roles += r
	}
	t.Logf("用例=%s 输入={subject=%s roles=[%s] action=%s resource=%s} 结论=%s 原因=%s 规则数=%d 缓存命中=%v",
		name, sub.ID, roles, action, resource, tr.Decision, tr.Reason, len(tr.Rules), tr.FromCache)
	for _, rt := range tr.Rules {
		t.Logf("    规则 %s effect=%s matched=%v why=%s cond=%v", rt.PolicyID, rt.Effect, rt.Matched, rt.MatchWhy, rt.CondResults)
	}
}

func TestDefaultDeny(t *testing.T) {
	u := &store.User{ID: "u1", Roles: []string{"reader"}}
	ev := NewEvaluator(0)
	tr := ev.Evaluate(u, "read", nil, nil)
	logTrace(t, "无任何规则-默认拒绝", u, "read", "", tr)
	if tr.Decision != DecisionDeny || tr.Reason != ReasonDefaultDeny {
		t.Fatalf("期望默认拒绝, 得到 %s/%s", tr.Decision, tr.Reason)
	}
}

func TestDenyOverrides_OrderIndependent(t *testing.T) {
	u := &store.User{ID: "u1", Roles: []string{"editor"}}
	res := &store.Resource{ID: "doc-1", Kind: "doc"}

	// 同一逻辑规则集合，以两种顺序提供；冲突时结论必须恒定为 deny。
	policiesA := []*store.Policy{
		{ID: "p-allow", RoleID: "editor", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectAllow},
		{ID: "p-deny", RoleID: "editor", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectDeny},
	}
	policiesB := []*store.Policy{
		{ID: "p-deny", RoleID: "editor", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectDeny},
		{ID: "p-allow", RoleID: "editor", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectAllow},
	}
	// 再加两条 allow 制造“多数允许”干扰，验证 deny 仍然优先。
	policiesC := append(copyPolicies(policiesA),
		&store.Policy{ID: "p-allow-2", RoleID: "editor", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectAllow},
		&store.Policy{ID: "p-allow-3", RoleID: "", ResourceID: "doc-1", Actions: []string{"write"}, Effect: store.EffectAllow},
	)

	ev := NewEvaluator(0)
	trA := ev.Evaluate(u, "write", res, policiesA)
	trB := ev.Evaluate(u, "write", res, policiesB)
	trC := ev.Evaluate(u, "write", res, policiesC)
	logTrace(t, "冲突-allow在前", u, "write", "doc-1", trA)
	logTrace(t, "冲突-deny在前", u, "write", "doc-1", trB)
	logTrace(t, "冲突-多条allow一条deny", u, "write", "doc-1", trC)
	for i, tr := range []*Trace{trA, trB, trC} {
		if tr.Decision != DecisionDeny || tr.Reason != ReasonDenyMatched {
			t.Fatalf("场景%d: 冲突时必须显式拒绝, 得到 %s/%s", i, tr.Decision, tr.Reason)
		}
	}
}

func TestAllowWhenOnlyAllowMatches(t *testing.T) {
	u := &store.User{ID: "u1", Roles: []string{"reader"}, Attrs: map[string]string{"team": "platform"}}
	res := &store.Resource{ID: "doc-1", Kind: "doc", Attrs: map[string]string{"owner_team": "platform"}}
	policies := []*store.Policy{
		{ID: "owner-read", RoleID: "reader", ResourceID: "doc-1", Actions: []string{"read"},
			Effect:     store.EffectAllow,
			Conditions: map[string]string{"sub.attr.team": "platform", "res.attr.owner_team": "platform"}},
	}
	ev := NewEvaluator(16)
	tr := ev.Evaluate(u, "read", res, policies)
	logTrace(t, "ABAC 属性匹配-允许", u, "read", "doc-1", tr)
	if tr.Decision != DecisionPermit {
		t.Fatalf("期望允许, 得到 %s/%s", tr.Decision, tr.Reason)
	}
	// 第二次命中缓存
	tr2 := ev.Evaluate(u, "read", res, policies)
	if !tr2.FromCache {
		t.Fatal("相同输入第二次应命中缓存")
	}
	t.Logf("缓存验证: 第二次 FromCache=%v, 结论=%s", tr2.FromCache, tr2.Decision)

	// 属性不匹配 -> 无规则命中 -> 默认拒绝
	u2 := &store.User{ID: "u2", Roles: []string{"reader"}, Attrs: map[string]string{"team": "billing"}}
	tr3 := ev.Evaluate(u2, "read", res, policies)
	logTrace(t, "ABAC 属性不符-默认拒绝", u2, "read", "doc-1", tr3)
	if tr3.Decision != DecisionDeny || tr3.Reason != ReasonDefaultDeny {
		t.Fatalf("属性不符应默认拒绝, 得到 %s/%s", tr3.Decision, tr3.Reason)
	}
}

func TestDenyWinsOverGlobalAllow(t *testing.T) {
	u := &store.User{ID: "u1", Roles: []string{"admin", "reader"}}
	res := &store.Resource{ID: "secret-1"}
	policies := []*store.Policy{
		{ID: "global-allow", RoleID: "admin", ResourceID: "", Actions: nil, Effect: store.EffectAllow},
		{ID: "protect-secret", RoleID: "", ResourceID: "secret-1", Actions: nil, Effect: store.EffectDeny},
	}
	ev := NewEvaluator(0)
	for _, act := range []string{"read", "write", "delete"} {
		tr := ev.Evaluate(u, act, res, policies)
		logTrace(t, fmt.Sprintf("全局allow vs 资源deny: %s", act), u, act, "secret-1", tr)
		if tr.Decision != DecisionDeny {
			t.Fatalf("动作 %s 下显式 deny 必须压过全局 allow", act)
		}
	}
}

func TestCacheInvalidatedAfterPolicyChange(t *testing.T) {
	u := &store.User{ID: "u1", Roles: []string{"reader"}}
	res := &store.Resource{ID: "doc-1"}
	allow := []*store.Policy{{ID: "p1", RoleID: "reader", ResourceID: "doc-1",
		Actions: []string{"read"}, Effect: store.EffectAllow}}
	deny := append(copyPolicies(allow),
		&store.Policy{ID: "p2", RoleID: "reader", ResourceID: "doc-1", Actions: []string{"read"}, Effect: store.EffectDeny})

	ev := NewEvaluator(64)
	tr1 := ev.Evaluate(u, "read", res, allow)
	if tr1.Decision != DecisionPermit {
		t.Fatalf("初始应允许, 得到 %s", tr1.Decision)
	}
	// 策略集合变化（含新 deny），缓存键包含策略摘要：
	tr2 := ev.Evaluate(u, "read", res, deny)
	logTrace(t, "策略变更后(新增deny)", u, "read", "doc-1", tr2)
	if tr2.Decision != DecisionDeny {
		t.Fatalf("新增 deny 后结论必须翻转, 得到 %s", tr2.Decision)
	}
	if tr2.FromCache {
		t.Fatal("策略集合变化后不得命中旧缓存")
	}
	// 显式失效也必须清空
	ev.Invalidate()
	if ev.CacheLen() != 0 {
		t.Fatal("Invalidate 后缓存必须为空")
	}
}

func copyPolicies(in []*store.Policy) []*store.Policy {
	out := make([]*store.Policy, len(in))
	for i, p := range in {
		cp := *p
		out[i] = &cp
	}
	return out
}
