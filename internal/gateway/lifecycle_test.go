package gateway

import (
	"context"
	"sync"
	"testing"
	"time"
)

// 推进假时钟。
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestExpiredTokenRejected(t *testing.T) {
	gw, fc := testGateway(t)
	issued := mustIssue(t, gw, "alice")
	ctx := context.Background()

	fc.advance(gw.cfg.TokenTTL + time.Second)
	t.Logf("input: token after ttl+1s (exp=%v now=%v)", issued.ExpiresAt, fc.t)
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("decision basis: allowed=%v reason=%s", r.Allowed, r.Reason)
	if r.Allowed || r.Reason != ReasonTokenExpired {
		t.Fatalf("expired token must be rejected as token_expired, got %+v", r)
	}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	// 新增一条与允许规则完全冲突的显式拒绝。
	if _, err := gw.UpsertPolicy(ctx, PolicyInput{
		ID: "deny-alice-read", Deny: true, Users: []string{"alice"},
		Resources: []string{"doc-1"}, Actions: []string{"read"},
	}, "tester"); err != nil {
		t.Fatal(err)
	}
	issued := mustIssue(t, gw, "alice")
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("input: conflicting allow(role=reader)+deny(user=alice)")
	t.Logf("decision basis: allowed=%v reason=%s matchedDeny=%v matchedAllow=%v",
		r.Allowed, r.Reason, r.MatchedDeny, r.MatchedAllow)
	if r.Allowed || r.Reason != ReasonExplicitDeny {
		t.Fatalf("explicit deny must win, got %+v", r)
	}
}

func TestRevocationImmediate(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")

	// 第一次判定放行（可能写入正面缓存）。
	if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); !r.Allowed {
		t.Fatalf("pre-revoke should allow, got %s", r.Reason)
	}
	if err := gw.Revoke(ctx, issued.SessionID, "tester"); err != nil {
		t.Fatal(err)
	}
	// 撤销后立即拒绝，旧 JTI 与可能存在的缓存结论都必须失效。
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("input: same token immediately after revoke")
	t.Logf("decision basis: allowed=%v reason=%s", r.Allowed, r.Reason)
	if r.Allowed || r.Reason != ReasonSessionRevoked {
		t.Fatalf("revocation must take effect immediately, got %+v", r)
	}
}

func TestRenewSupersedesOldToken(t *testing.T) {
	gw, fc := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")

	fc.advance(30 * time.Minute)
	renewed, err := gw.Renew(ctx, issued.Token)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	t.Logf("input: renew -> new jti=%s old jti=%s", renewed.JTI, issued.JTI)

	// 旧凭证立即失效（不得复活）。
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("decision basis for OLD token: allowed=%v reason=%s", r.Allowed, r.Reason)
	if r.Allowed || r.Reason != ReasonCredentialStale {
		t.Fatalf("old token must be superseded, got %+v", r)
	}
	// 新凭证有效。
	r2 := gw.Authorize(ctx, AuthorizeRequest{Token: renewed.Token, Resource: "doc-1", Action: "read"})
	t.Logf("decision basis for NEW token: allowed=%v reason=%s", r2.Allowed, r2.Reason)
	if !r2.Allowed {
		t.Fatalf("new token must be allowed, reason=%s", r2.Reason)
	}
}

func TestConcurrentRenewOnlyOneSucceeds(t *testing.T) {
	gw, fc := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	fc.advance(30 * time.Minute)

	const n = 16
	var wg sync.WaitGroup
	results := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := gw.Renew(ctx, issued.Token)
			results[i] = err
		}(i)
	}
	wg.Wait()
	success, stale := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			success++
		case ReasonOf(err) == ReasonCredentialStale:
			stale++
		default:
			t.Fatalf("unexpected renew error: %v", err)
		}
	}
	t.Logf("input: %d concurrent renews of same token; decision basis: success=%d superseded=%d", n, success, stale)
	if success != 1 || stale != n-1 {
		t.Fatalf("want exactly 1 success and %d superseded, got %d/%d", n-1, success, stale)
	}

	// 会话中最终的当前 JTI 必须与唯一成功者一致；旧凭证仍不可用。
	sess, err := gw.Store().GetSession(issued.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.CredVersion != 2 {
		t.Fatalf("credential version must be 2, got %d", sess.CredVersion)
	}
	if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); r.Allowed {
		t.Fatalf("old token must not be usable after concurrent renewals")
	}
}

func TestRoleChangeTakesEffect(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); !r.Allowed {
		t.Fatalf("pre-change should allow: %s", r.Reason)
	}
	if err := gw.AssignRoles(ctx, "alice", []string{"auditor"}, "tester"); err != nil {
		t.Fatal(err)
	}
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("input: authorize after role downgrade reader->auditor")
	t.Logf("decision basis: allowed=%v reason=%s", r.Allowed, r.Reason)
	if r.Allowed {
		t.Fatalf("role revocation must take effect without re-login")
	}
}
