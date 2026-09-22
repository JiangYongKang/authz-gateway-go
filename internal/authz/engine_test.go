package authz

import (
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

func allowPolicy(id string) store.Policy {
	return store.Policy{ID: id, Deny: false, Roles: []string{"reader"},
		Resources: []string{"doc-1"}, Actions: []string{"read"}}
}
func denyPolicy(id string) store.Policy {
	p := allowPolicy(id)
	p.Deny = true
	return p
}

func baseReq() Request {
	return Request{
		Subject:  "alice",
		Roles:    []string{"reader"},
		Resource: "doc-1",
		Action:   "read",
	}
}

func TestDefaultDeny(t *testing.T) {
	eng := NewEngine(0)
	got := eng.Evaluate(baseReq(), nil)
	t.Logf("input: subject=alice role=reader action=read resource=doc-1 policies=[]")
	if got.Decision != Deny || got.Reason != "no_matching_policy" {
		t.Fatalf("expected default deny, got %+v", got)
	}
	t.Logf("decision basis: %s (%s)", got.Decision, got.Reason)
}

func TestExplicitDenyWinsRegardlessOfOrder(t *testing.T) {
	eng := NewEngine(0)
	deny := denyPolicy("p-deny")
	allow1 := allowPolicy("p-allow-1")
	allow2 := allowPolicy("p-allow-2")

	orders := [][]store.Policy{
		{deny, allow1, allow2},
		{allow1, deny, allow2},
		{allow1, allow2, deny},
	}
	for i, policies := range orders {
		req := baseReq()
		t.Logf("input order#%d: %s, %s, %s", i, policies[0].ID, policies[1].ID, policies[2].ID)
		got := eng.Evaluate(req, policies)
		if got.Decision != Deny || got.Reason != "explicit_deny" {
			t.Fatalf("order#%d expected explicit deny, got %+v", i, got)
		}
		if len(got.MatchedAllow) != 2 || len(got.MatchedDeny) != 1 {
			t.Fatalf("order#%d explanation mismatch: %+v", i, got)
		}
		if got.MatchedDeny[0] != "p-deny" {
			t.Fatalf("order#%d matched deny not reported: %+v", i, got)
		}
		t.Logf("decision basis: deny overrides allow; matchedDeny=%v matchedAllow=%v",
			got.MatchedDeny, got.MatchedAllow)
	}
}

func TestAllowOnlyWhenNoDeny(t *testing.T) {
	eng := NewEngine(0)
	got := eng.Evaluate(baseReq(), []store.Policy{allowPolicy("p-allow-1")})
	t.Logf("input: single allow policy")
	if got.Decision != Allow || got.Reason != "allow" {
		t.Fatalf("expected allow, got %+v", got)
	}
	t.Logf("decision basis: %s via %v", got.Decision, got.MatchedAllow)
}

func TestABACConditions(t *testing.T) {
	eng := NewEngine(0)
	p := allowPolicy("p-owner")
	p.Conditions = map[string]string{"resource.owner": "alice"}
	req := baseReq()
	req.ResourceAttrs = map[string]string{"owner": "bob"}
	got := eng.Evaluate(req, []store.Policy{p})
	t.Logf("input: subject attr condition resource.owner=alice, actual owner=bob")
	if got.Decision != Deny {
		t.Fatalf("ABAC condition mismatch must deny, got %+v", got)
	}
	t.Logf("decision basis: %s (%s)", got.Decision, got.Reason)

	req.ResourceAttrs["owner"] = "alice"
	got = eng.Evaluate(req, []store.Policy{p})
	if got.Decision != Allow {
		t.Fatalf("ABAC condition match must allow, got %+v", got)
	}
	t.Logf("decision basis: allow via %v", got.MatchedAllow)
}

func TestRuleSetTooLargeDenies(t *testing.T) {
	eng := NewEngine(1)
	got := eng.Evaluate(baseReq(), []store.Policy{allowPolicy("a"), denyPolicy("b")})
	t.Logf("input: 2 policies with maxRuleCount=1")
	if got.Decision != Deny || got.Reason != "rule_set_too_large" {
		t.Fatalf("oversized rule set must deny, got %+v", got)
	}
	t.Logf("decision basis: %s (%s)", got.Decision, got.Reason)
}
