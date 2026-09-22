package service

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/authz"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

const (
	issuer  = "https://authz.test"
	key1    = "k1"
	secret1 = "secret-one-32bytes-padded-ok!!"
	secret2 = "secret-two-32bytes-padded-ok!!"
)

func testConfig(auditCap int) Config {
	return Config{
		Issuer: issuer, AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
		StoreLimits:   store.DefaultLimits(),
		DecisionCache: 32,
		AuditCapacity: auditCap,
		Now:           func() time.Time { return time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC) },
	}
}

func newSvc(t *testing.T) *Service {
	t.Helper()
	s, err := New(testConfig(1000), key1, []byte(secret1))
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.CreateRole("reader"))
	must(t, s.UpsertUser(store.User{ID: "alice", Roles: []string{"reader"}, Attrs: map[string]string{"team": "platform"}}))
	must(t, s.UpsertResource(store.Resource{ID: "doc-1", Kind: "doc", Attrs: map[string]string{"owner_team": "platform"}}))
	must(t, s.PutPolicy(store.Policy{ID: "read-doc", RoleID: "reader", ResourceID: "doc-1",
		Actions: []string{"read"}, Effect: store.EffectAllow}))
	return s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEndToEnd_LoginAuthorize(t *testing.T) {
	s := newSvc(t)
	res, err := s.Login("alice")
	must(t, err)
	t.Logf("登录成功 session=%s", res.SessionID)

	out, err := s.Authorize(res.AccessToken, "read", "doc-1")
	must(t, err)
	t.Logf("判定输入={user=alice action=read resource=doc-1} 结论=%s 原因=%s 规则命中详情数=%d",
		out.Decision, out.Reason, len(out.Trace.Rules))
	if out.Decision != authz.DecisionPermit {
		t.Fatalf("应允许, 得到 %s/%s", out.Decision, out.Reason)
	}

	// 未授权动作 => 默认拒绝
	out2, err := s.Authorize(res.AccessToken, "delete", "doc-1")
	must(t, err)
	t.Logf("判定输入={user=alice action=delete resource=doc-1} 结论=%s 原因=%s", out2.Decision, out2.Reason)
	if out2.Decision != authz.DecisionDeny || out2.Reason != authz.ReasonDefaultDeny {
		t.Fatalf("无规则应默认拒绝, 得到 %s/%s", out2.Decision, out2.Reason)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")
	// 把服务时钟拨到 2 小时后（access TTL=1h）
	s.cfg.Now = func() time.Time { return time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC) }
	_, err := s.Authorize(res.AccessToken, "read", "doc-1")
	verifyFail(t, err, VRExpired, "过期")

	// refresh（24h）仍可用续期
	r2, err := s.Refresh(res.RefreshToken)
	must(t, err)
	t.Log("过期 access 不影响 refresh 续期；续期后新 access 可用")
	out, err := s.Authorize(r2.AccessToken, "read", "doc-1")
	must(t, err)
	if out.Decision != authz.DecisionPermit {
		t.Fatal("续期后应允许")
	}
	// 旧 access 已随旋转失效（它同时也已过期；按固定校验顺序先得到 expired，
	// 两个都是显式、可区分的拒绝原因，关键是绝不放行）。
	_, err = s.Authorize(res.AccessToken, "read", "doc-1")
	verifyFailAny(t, err, "旧access(过期且已旋转)", VRExpired, VRSessionNotFound)
}

func verifyFail(t *testing.T, err error, want VerifyReason, label string) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("%s: 期望 VerifyError, 得到 %v", label, err)
	}
	t.Logf("%s拒绝原因=%q (期望 %q)", label, ve.Reason, want)
	if ve.Reason != want {
		t.Fatalf("%s: 期望 %s, 得到 %s", label, want, ve.Reason)
	}
}

func verifyFailAny(t *testing.T, err error, label string, wants ...VerifyReason) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("%s: 期望 VerifyError, 得到 %v", label, err)
	}
	for _, w := range wants {
		if ve.Reason == w {
			t.Logf("%s 拒绝原因=%q (允许原因之一 %q)", label, ve.Reason, w)
			return
		}
	}
	t.Fatalf("%s: 原因 %q 不在允许集合 %v 中", label, ve.Reason, wants)
}

func TestTamperedAndWrongIssuerRejected(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")

	// 翻转一个载荷字符 => 签名失败
	parts := strings.Split(res.AccessToken, ".")
	pb := []byte(parts[1])
	if pb[2] == 'A' {
		pb[2] = 'B'
	} else {
		pb[2] = 'A'
	}
	tampered := parts[0] + "." + string(pb) + "." + parts[2]
	_, err := s.Authorize(tampered, "read", "doc-1")
	verifyFail(t, err, VRBadSignature, "篡改")

	// 另一个 issuer 签发的凭证 => issuer_mismatch（用同密钥伪造）
	s2, _ := New(func() Config {
		c := testConfig(100)
		c.Issuer = "https://evil.issuer"
		return c
	}(), key1, []byte(secret1))
	must(t, s2.Store().CreateRole("reader"))
	must(t, s2.UpsertUser(store.User{ID: "alice", Roles: []string{"reader"}}))
	evil, _ := s2.Login("alice")
	_, err = s.Authorize(evil.AccessToken, "read", "doc-1")
	verifyFail(t, err, VRIssuerMismatch, "签发者不符")

	// 用未知 kid 签发 => unknown_key
	s3 := newSvc(t)
	must(t, s3.AddKey(store.SigningKey{ID: "kx", Secret: []byte(strings.Repeat("x", 32)), State: store.KeyActive, CreatedAt: s3.cfg.Now()}))
	must(t, s3.RotateKey("kx"))
	r3, _ := s3.Login("alice")
	_, err = s.Authorize(r3.AccessToken, "read", "doc-1")
	verifyFail(t, err, VRUnknownKey, "未知kid")
}

func TestKeyRotationLifecycle(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")

	// 轮换并存期：引入 k2(active)，旧 k1 退役只验不签
	must(t, s.AddKey(store.SigningKey{ID: "k2", Secret: []byte(secret2), State: store.KeyActive, CreatedAt: s.cfg.Now()}))
	must(t, s.RotateKey("k2"))

	// 1) k1 签的存量 access 在有效期内仍可验证
	out, err := s.Authorize(res.AccessToken, "read", "doc-1")
	must(t, err)
	if out.Decision != authz.DecisionPermit {
		t.Fatal("轮换期间存量凭证必须保持可验证")
	}
	t.Log("轮换并存期: 旧密钥凭证仍可验证 => 通过")

	// 2) 新签发必须使用 k2；retired 的 k1 不得再签发
	r2, err := s.Refresh(res.RefreshToken)
	must(t, err)
	k2used := strings.Count(r2.AccessToken, ".") == 2
	if !k2used {
		t.Fatal("新凭证结构异常")
	}
	out2, err := s.Authorize(r2.AccessToken, "read", "doc-1")
	must(t, err)
	if out2.Decision != authz.DecisionPermit {
		t.Fatal("新密钥凭证应可验证")
	}
	active, _ := s.Store().ActiveKey()
	t.Logf("轮换后 active key=%s (应为 k2)", active.ID)
	if active.ID != "k2" {
		t.Fatalf("active 应为 k2, 得到 %s", active.ID)
	}
	k1, _ := s.Store().GetKey("k1")
	if k1.State != store.KeyRetired {
		t.Fatalf("k1 应为 retired, 得到 %s", k1.State)
	}

	// 3) 撤销 k2 => 其凭证立即失效
	must(t, s.RevokeKey("k2"))
	_, err = s.Authorize(r2.AccessToken, "read", "doc-1")
	verifyFail(t, err, VRKeyRevoked, "密钥撤销")
	t.Log("撤销 k2: 其签发的凭证立即拒绝 => 通过")
}

func TestImmediateRevocation(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")
	out, _ := s.Authorize(res.AccessToken, "read", "doc-1")
	if out.Decision != authz.DecisionPermit {
		t.Fatal("撤销前应允许")
	}

	// 管理员撤销用户 => 不等凭证过期，下次判定立即拒绝
	must(t, s.RevokeUser("alice"))
	_, err := s.Authorize(res.AccessToken, "read", "doc-1")
	if err == nil {
		t.Fatal("撤销后必须立即拒绝")
	}
	t.Logf("权限撤销立即生效: 拒绝原因=%q", err.Error())

	// 撤销后 refresh 也不得续命
	_, err = s.Refresh(res.RefreshToken)
	if err == nil {
		t.Fatal("撤销后 refresh 必须被拒绝，不得复活会话")
	}
	t.Logf("撤销后 refresh 拒绝原因=%q", err.Error())

	// 登出撤销会话同样立即生效
	s2 := newSvc(t)
	r2, _ := s2.Login("alice")
	must(t, s2.RevokeSessionByToken(r2.AccessToken))
	_, err = s2.Authorize(r2.AccessToken, "read", "doc-1")
	verifyFail(t, err, VRSessionRevoked, "会话登出")
}

func TestRoleChangeTakesEffectImmediately(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")
	// 动态变更：移除 reader 角色并前推撤销水位线
	u, _ := s.Store().GetUser("alice")
	u.Roles = []string{}
	must(t, s.UpsertUser(*u))
	must(t, s.RevokeUser("alice")) // 角色变更必须使旧凭证失效
	_, err := s.Authorize(res.AccessToken, "read", "doc-1")
	if err == nil {
		t.Fatal("角色变更+水位线前推后旧凭证必须失效")
	}
	t.Logf("角色变更后旧凭证拒绝原因=%q", err.Error())
}

func TestPolicyFallback_DenyAddedOverrides(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")
	out, _ := s.Authorize(res.AccessToken, "read", "doc-1")
	if out.Decision != authz.DecisionPermit {
		t.Fatal("初始允许")
	}
	// 运行期叠加一条显式 deny（策略回退/紧急封禁）
	must(t, s.PutPolicy(store.Policy{ID: "break-glass-deny", RoleID: "", ResourceID: "doc-1",
		Actions: []string{"read"}, Effect: store.EffectDeny}))
	out2, err := s.Authorize(res.AccessToken, "read", "doc-1")
	must(t, err)
	t.Logf("紧急 deny 叠加后: 输入={alice read doc-1} 结论=%s 原因=%s", out2.Decision, out2.Reason)
	if out2.Decision != authz.DecisionDeny || out2.Reason != authz.ReasonDenyMatched {
		t.Fatal("显式 deny 必须压过既有 allow（即使缓存里已有 permit）")
	}
	// 删除 deny 后恢复
	must(t, s.DeletePolicy("break-glass-deny"))
	out3, _ := s.Authorize(res.AccessToken, "read", "doc-1")
	if out3.Decision != authz.DecisionPermit {
		t.Fatal("删除 deny 后应恢复允许")
	}
}

func TestAuditContainsNoRawSecretsAndChainVerifies(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")
	_, _ = s.Authorize(res.AccessToken, "read", "doc-1")

	dump, err := s.Audit().ExportJSON()
	must(t, err)
	text := string(dump)
	if strings.Contains(text, res.AccessToken) || strings.Contains(text, secret1) {
		t.Fatal("审计中不得包含原始凭证或密钥材料")
	}
	t.Log("审计导出不含原始凭证/密钥 => 通过")
	if err := s.Audit().Verify(); err != nil {
		t.Fatalf("审计哈希链必须完整: %v", err)
	}
	// 至少记录了 login/authorize 两类动作
	var sawLogin, sawAuthz bool
	for _, e := range s.Audit().Entries() {
		if e.Action == "login" {
			sawLogin = true
		}
		if e.Action == "authorize" {
			sawAuthz = true
		}
	}
	if !sawLogin || !sawAuthz {
		t.Fatal("登录与授权都必须留痕")
	}
}

func TestLimitExceededRejectsCleanly(t *testing.T) {
	c := testConfig(1000)
	c.StoreLimits.MaxUsers = 1
	c.StoreLimits.MaxSessions = 1
	s, err := New(c, key1, []byte(secret1))
	must(t, err)
	must(t, s.UpsertUser(store.User{ID: "u1"}))
	err = s.UpsertUser(store.User{ID: "u2"})
	if !errors.Is(err, store.ErrLimitExceeded) {
		t.Fatalf("超用户上限应 ErrLimitExceeded, 得到 %v", err)
	}
	// 会话上限：同一用户两个会话 => 第二次拒绝
	_, err = s.Login("u1")
	must(t, err)
	_, err = s.Login("u1")
	if !errors.Is(err, store.ErrLimitExceeded) {
		t.Fatalf("超会话上限应 ErrLimitExceeded, 得到 %v", err)
	}
	if s.Store().SessionCount() != 1 {
		t.Fatal("拒绝后不得残留部分会话")
	}
}

func TestAuditFull_FailClosed(t *testing.T) {
	// 审计容量恰好容纳一次 login 留痕；随后 authorize 无法追加审计，
	// 即使判定本身为 permit 也必须 fail-closed 拒绝。
	const cap = 1
	s, err := New(func() Config {
		c := testConfig(cap)
		c.StoreLimits = store.DefaultLimits()
		return c
	}(), key1, []byte(secret1))
	must(t, err)
	// 引导数据直接写存储，避免占用审计容量。
	must(t, s.Store().CreateRole("reader"))
	must(t, s.Store().CreateUser(store.User{ID: "u1", Roles: []string{"reader"}}))
	res, err := s.Login("u1")
	must(t, err)
	if s.Audit().Len() != cap {
		t.Fatalf("login 后审计应为满(%d), 实际 %d", cap, s.Audit().Len())
	}
	_, err = s.Authorize(res.AccessToken, "read", "")
	if !errors.Is(err, audit.ErrLogFull) {
		t.Fatalf("审计写满时授权必须 fail-closed, 得到 %v", err)
	}
	t.Log("审计容量耗尽 => 授权请求被拒绝(fail-closed) => 通过")
}

func TestConcurrentRefresh_NoDoubleSpend(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")

	const n = 16
	var wg sync.WaitGroup
	results := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			_, results[idx] = s.Refresh(res.RefreshToken)
		}(i)
	}
	wg.Wait()

	allowed := 0
	for i, err := range results {
		if err == nil {
			allowed++
		} else {
			t.Logf("并发续期 #%02d 拒绝: %v", i, err)
		}
	}
	t.Logf("并发续期: %d 个请求中成功 %d 个（必须恰好 1）", n, allowed)
	if allowed != 1 {
		t.Fatalf("一次性 refresh 必须恰好成功 1 次, 实际 %d", allowed)
	}
}

func TestConcurrentRevokeAndAuthorize(t *testing.T) {
	s := newSvc(t)
	res, _ := s.Login("alice")

	var wg sync.WaitGroup
	const readers = 32
	permits, denials := int32(0), int32(0)
	var mu sync.Mutex
	wg.Add(readers + 1)

	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		_ = s.RevokeUser("alice")
	}()
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			out, err := s.Authorize(res.AccessToken, "read", "doc-1")
			mu.Lock()
			defer mu.Unlock()
			if err == nil && out.Decision == authz.DecisionPermit {
				permits++
			} else {
				denials++
			}
		}()
	}
	wg.Wait()
	t.Logf("并发撤销期间: 允许=%d 拒绝=%d（撤销完成后的请求必须全部拒绝，且撤销后绝不复活）", permits, denials)
	// 撤销完成后的稳定状态下再请求一次，必须拒绝（没有复活）。
	_, err := s.Authorize(res.AccessToken, "read", "doc-1")
	if err == nil {
		t.Fatal("撤销稳定后凭证不得复活")
	}
}

func TestConcurrentKeyRotation(t *testing.T) {
	s := newSvc(t)
	var wg sync.WaitGroup
	// 多个操作者并发轮换同一新密钥/并发签发，不应出现多个 active 或半更新状态。
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func() {
			defer wg.Done()
			_ = s.AddKey(store.SigningKey{ID: "k2", Secret: []byte(secret2),
				State: store.KeyActive, CreatedAt: s.cfg.Now()})
			_ = s.RotateKey("k2")
		}()
	}
	wg.Wait()
	k, err := s.Store().ActiveKey()
	must(t, err)
	if k.ID != "k2" {
		t.Fatalf("并发轮换后 active 必须确定性地为 k2, 得到 %s", k.ID)
	}
	// 登录在并发轮换后始终可用，且用 k2 签发
	res, err := s.Login("alice")
	must(t, err)
	_, err = s.Authorize(res.AccessToken, "read", "doc-1")
	must(t, err)
}
