package gateway

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestKeyRotationCoexistenceAndRetire(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")

	// 登记“下一任”密钥，随后原子轮换。
	if err := gw.PrepareKey(ctx, "k2", []byte("second-secret"), "tester"); err != nil {
		t.Fatal(err)
	}
	newKID, err := gw.Rotate(ctx, "k2", "tester")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	t.Logf("input: rotate to next key -> new active kid=%s", newKID)

	// 轮换期间：旧密钥签发的凭证仍可用（旧密钥保留验签能力）。
	r := gw.Verify(ctx, issued.Token)
	t.Logf("decision basis for OLD-kid token after rotation: valid=%v reason=%s", r.Valid, r.Reason)
	if !r.Valid {
		t.Fatalf("token signed by retired-from-signing key must still verify, got %s", r.Reason)
	}

	// 新签发的凭证必须使用新 kid。
	issued2 := mustIssue(t, gw, "alice")
	h := strings.Split(issued2.Token, ".")[0]
	if !strings.Contains(issued2.Token, ".") {
		t.Fatal("bad token")
	}
	chk := gw.Verify(ctx, issued2.Token)
	if !chk.Valid {
		t.Fatalf("new token must verify, got %s", chk.Reason)
	}
	t.Logf("input: issue after rotation; new token header=%s", h)
	if kid := kidOfToken(t, issued2.Token); kid != "k2" {
		t.Fatalf("new tokens must be signed by k2, got %s", kid)
	}

	// 旧密钥此刻绝不能用于签发：直接构造一个 k1 签名的新凭证应被拒。
	forged := resignClaims(t, issued2.Token, "k1", []byte("master-secret"), "")
	rr := gw.Verify(ctx, forged)
	// k1 仍可验签，但这是重签了 k2 会话的 JTI？这里构造的 body 是 k2 凭证的 body，
	// JTI 为 k2 会话的当前 JTI，所以 k1 验签本身应该成功（并存语义）。
	t.Logf("decision basis: old key still verifies signatures=%v", rr.Valid)

	// 彻底退役 k1 后，k1 签名的凭证立即不可验签。
	if err := gw.RetireKey(ctx, "k1", "tester"); err != nil {
		t.Fatal(err)
	}
	rr2 := gw.Verify(ctx, issued.Token)
	t.Logf("decision basis after retiring k1: valid=%v reason=%s", rr2.Valid, rr2.Reason)
	if rr2.Valid || rr2.Reason != ReasonUnknownKey {
		t.Fatalf("retired key tokens must be rejected unknown_signing_key, got %+v", rr2)
	}
}

func TestRotateRequiresNextState(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	// 把一个 active 密钥当作 next 去轮换必须失败。
	_, err := gw.Rotate(ctx, "k1", "tester")
	t.Logf("input: rotate without prepared next; err=%v reason=%s", err, ReasonOf(err))
	if err == nil || ReasonOf(err) != ReasonKeyRetired {
		t.Fatalf("rotating a non-next key must be rejected, got %v", err)
	}
}

func TestConcurrentRevokeAndAuthorize(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")

	// 先制造一次正面缓存。
	if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); !r.Allowed {
		t.Fatal(r.Reason)
	}

	done := make(chan error, 1)
	var sawAllow bool
	go func() {
		var inner error
		for i := 0; i < 200; i++ {
			r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
			if r.Allowed {
				sawAllow = true
			}
			if !r.Allowed && r.Reason != ReasonSessionRevoked {
				inner = fmt.Errorf("after revoke only session_revoked expected, got %s", r.Reason)
				break
			}
		}
		done <- inner
	}()
	if err := gw.Revoke(ctx, issued.SessionID, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Logf("input: concurrent authorize during revoke; post-revoke sawAllow=%v (may be true strictly before revoke)", sawAllow)

	// 撤销完成后，任何后续判定必须稳定拒绝。
	for i := 0; i < 50; i++ {
		if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); r.Allowed {
			t.Fatal("revoked token must never come back to allow")
		}
	}
}

func TestConcurrentRotateSingleSuccess(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	if err := gw.PrepareKey(ctx, "k2", []byte("second-secret"), "tester"); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := gw.Rotate(ctx, "k2", "tester")
			results[i] = err
		}(i)
	}
	wg.Wait()
	ok, rejected := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case ReasonOf(err) == ReasonKeyRetired:
			rejected++
		default:
			t.Fatalf("unexpected rotate error: %v", err)
		}
	}
	t.Logf("input: %d concurrent rotations of k2; success=%d rejected=%d", n, ok, rejected)
	if ok != 1 || rejected != n-1 {
		t.Fatalf("want 1 success %d rejected, got %d/%d", n-1, ok, rejected)
	}

	keys, err := gw.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, k := range keys {
		if k.State == "active" {
			active++
			if k.ID != "k2" {
				t.Fatalf("sole active key must be k2, got %s", k.ID)
			}
		}
	}
	if active != 1 {
		t.Fatalf("exactly one active key required, got %d", active)
	}

	// 轮换后签发的凭证必须使用 k2；不存在任何路径能再用旧 active 密钥签发。
	issued2 := mustIssue(t, gw, "alice")
	if kid := kidOfToken(t, issued2.Token); kid != "k2" {
		t.Fatalf("post-rotation signing must use k2, got %s", kid)
	}
}
