package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/config"
)

func testGateway(t *testing.T) (*Gateway, *fakeClock) {
	t.Helper()
	cfg := config.Defaults()
	cfg.RenewWindow = 0 // 测试中任何时刻都允许续期
	gw := New(cfg)
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	gw.SetClock(fc.now)
	ctx := context.Background()
	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("master-secret"), "bootstrap"); err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}
	if err := gw.PutUser(ctx, UserInput{Name: "alice", Roles: []string{"reader"},
		Attributes: map[string]string{"dept": "eng"}}); err != nil {
		t.Fatalf("put user: %v", err)
	}
	if err := gw.PutResource(ctx, ResourceInput{Name: "doc-1", Kind: "doc", Owner: "alice"}); err != nil {
		t.Fatalf("put resource: %v", err)
	}
	if _, err := gw.UpsertPolicy(ctx, PolicyInput{
		ID: "allow-reader-read", Roles: []string{"reader"},
		Resources: []string{"doc-1"}, Actions: []string{"read"},
	}, "bootstrap"); err != nil {
		t.Fatalf("policy: %v", err)
	}
	return gw, fc
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func mustIssue(t *testing.T, gw *Gateway, user string) IssueResult {
	t.Helper()
	res, err := gw.Issue(context.Background(), IssueRequest{Username: user})
	if err != nil {
		t.Fatalf("issue %s: %v", user, err)
	}
	return res
}

func TestIssueVerifyAndAuthorize(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	t.Logf("input: issue alice -> jti=%s session=%s", issued.JTI, issued.SessionID)

	chk := gw.Verify(ctx, issued.Token)
	t.Logf("input: verify issued token; decision basis: valid=%v reason=%s", chk.Valid, chk.Reason)
	if !chk.Valid {
		t.Fatalf("issued token must verify: %s", chk.Reason)
	}

	auth := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("input: authorize read doc-1; decision basis: allowed=%v reason=%s matchedAllow=%v",
		auth.Allowed, auth.Reason, auth.MatchedAllow)
	if !auth.Allowed {
		t.Fatalf("reader must be allowed to read, got reason=%s", auth.Reason)
	}

	// 默认拒绝：未被规则覆盖的动作。
	auth2 := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "delete"})
	t.Logf("input: authorize delete doc-1; decision basis: allowed=%v reason=%s", auth2.Allowed, auth2.Reason)
	if auth2.Allowed || auth2.Reason != ReasonNoMatchingPolicy {
		t.Fatalf("unmatched action must default-deny, got %+v", auth2)
	}
}

func TestTamperedAndMismatchedTokens(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")

	tampered := issued.Token[:len(issued.Token)-3] + "AAA"
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"tampered_signature", tampered, ReasonBadSignature},
		{"garbage", "not-a-jwt", ReasonTokenMalformed},
		{"wrong_key", resignClaims(t, issued.Token, "k1", []byte("attacker-secret"), ""), ReasonBadSignature},
		{"wrong_issuer", resignClaims(t, issued.Token, "k1", []byte("master-secret"), "evil"), ReasonIssuerMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %s token len=%d", tc.name, len(tc.token))
			r := gw.Authorize(ctx, AuthorizeRequest{Token: tc.token, Resource: "doc-1", Action: "read"})
			t.Logf("decision basis: allowed=%v reason=%s", r.Allowed, r.Reason)
			if r.Allowed || r.Reason != tc.want {
				t.Fatalf("want deny/%s, got allowed=%v reason=%s", tc.want, r.Allowed, r.Reason)
			}
		})
	}
}

func TestUnknownUserCannotIssue(t *testing.T) {
	gw, _ := testGateway(t)
	_, err := gw.Issue(context.Background(), IssueRequest{Username: "ghost"})
	t.Logf("input: issue unknown user; err=%v reason=%s", err, ReasonOf(err))
	if err == nil || ReasonOf(err) != ReasonUserNotFound {
		t.Fatalf("unknown user must fail with user_not_found, got %v", err)
	}
}
