package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/config"
	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
)

func setup(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.Defaults()
	cfg.RenewWindow = 0
	gw := gateway.New(cfg)
	srv := New(gw)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	post := func(path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		out["__status"] = float64(resp.StatusCode)
		return out
	}

	if err := gw.BootstrapSigningKey(t.Context(), "k1", []byte("sec"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutUser(t.Context(), gateway.UserInput{Name: "alice", Roles: []string{"reader"}}); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutResource(t.Context(), gateway.ResourceInput{Name: "doc-1", Kind: "doc", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}
	post("/v1/admin/policies", map[string]any{
		"actor": "b",
		"policy": map[string]any{
			"id": "p1", "roles": []string{"reader"},
			"resources": []string{"doc-1"}, "actions": []string{"read"},
		},
	})
	return srv, ts
}

func TestHTTPFullFlow(t *testing.T) {
	_, ts := setup(t)

	do := func(method, path string, body any) (int, map[string]any) {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		raw, _ := readAll(resp)
		_ = json.Unmarshal(raw, &out)
		t.Logf("input: %s %s body=%v", method, path, compact(body))
		t.Logf("decision basis: status=%d resp=%s", resp.StatusCode, string(raw))
		return resp.StatusCode, out
	}

	_, issued := do("POST", "/v1/tokens/issue", map[string]string{"username": "alice"})
	tok, _ := issued["token"].(string)
	if tok == "" {
		t.Fatal("issue did not return token")
	}

	st, chk := do("POST", "/v1/tokens/verify", map[string]string{"token": tok})
	if st != 200 || chk["valid"] != true {
		t.Fatalf("verify failed: %+v", chk)
	}

	st, auth := do("POST", "/v1/authorize",
		map[string]string{"token": tok, "resource": "doc-1", "action": "read"})
	if st != 200 || auth["allowed"] != true {
		t.Fatalf("authorize should allow: %+v", auth)
	}

	// 篡改：必须 403 且原因可区分。
	st, bad := do("POST", "/v1/authorize",
		map[string]string{"token": tok[:len(tok)-3] + "AAA", "resource": "doc-1", "action": "read"})
	if st != 403 || bad["reason"] != "bad_signature" {
		t.Fatalf("tampered token: %d %+v", st, bad)
	}

	// 撤销后立刻拒绝。
	sid, _ := issued["session_id"].(string)
	do("POST", "/v1/sessions/revoke", map[string]string{"session_id": sid, "actor": "tester"})
	st, rev := do("POST", "/v1/authorize",
		map[string]string{"token": tok, "resource": "doc-1", "action": "read"})
	if st != 403 || rev["reason"] != "session_revoked" {
		t.Fatalf("post-revoke: %d %+v", st, rev)
	}

	// 审计包含全部敏感操作，且响应中没有凭证/密钥泄漏。
	resp, err := http.Get(ts.URL + "/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var auditPage map[string]any
	raw, _ := readAll(resp)
	_ = json.Unmarshal(raw, &auditPage)
	if strings.Contains(string(raw), tok) || strings.Contains(string(raw), "\"sec\"") {
		t.Fatal("audit response leaked token or secret material")
	}
	events, _ := auditPage["events"].([]any)
	if len(events) < 4 {
		t.Fatalf("expected audit events, got %d", len(events))
	}
	t.Logf("audit events=%d, no sensitive material=true", len(events))
}

func readAll(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	s := string(b)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}
