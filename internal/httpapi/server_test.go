package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/service"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

func newTestServer(t *testing.T) (*Server, *service.Service) {
	t.Helper()
	cfg := service.Config{
		Issuer: "https://authz.test", AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
		StoreLimits: store.DefaultLimits(), DecisionCache: 8, AuditCapacity: 500,
	}
	svc, err := service.New(cfg, "k1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateRole("reader"); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpsertUser(store.User{ID: "alice", Roles: []string{"reader"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpsertResource(store.Resource{ID: "doc-1"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PutPolicy(store.Policy{ID: "p1", RoleID: "reader", ResourceID: "doc-1",
		Actions: []string{"read"}, Effect: store.EffectAllow}); err != nil {
		t.Fatal(err)
	}
	return New(svc), svc
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	t.Logf("%s %s token=%v => HTTP %d body=%s", method, path, token != "", rec.Code,
		strings.TrimSpace(rec.Body.String()))
	return rec.Code, out
}

func TestHTTPFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()

	st, login := do(t, h, "POST", "/v1/login", "", map[string]string{"user_id": "alice"})
	if st != 200 {
		t.Fatalf("login status=%d", st)
	}
	at := login["access_token"].(string)
	rt := login["refresh_token"].(string)

	// permit
	st, body := do(t, h, "POST", "/v1/authorize", at, map[string]string{"action": "read", "resource_id": "doc-1"})
	if st != 200 || body["decision"] != "permit" {
		t.Fatalf("允许场景: %d %v", st, body)
	}
	// 默认拒绝（无策略动作）
	st, body = do(t, h, "POST", "/v1/authorize", at, map[string]string{"action": "delete", "resource_id": "doc-1"})
	if st != 403 || body["reason"] != "default_deny_no_match" {
		t.Fatalf("默认拒绝: %d %v", st, body)
	}
	// 缺凭证
	st, _ = do(t, h, "POST", "/v1/authorize", "", map[string]string{"action": "read", "resource_id": "doc-1"})
	if st != 403 {
		t.Fatalf("缺凭证应 403, 得到 %d", st)
	}
	// 篡改
	tampered := strings.Split(at, ".")
	b := []byte(tampered[1])
	b[0]++
	st, body = do(t, h, "POST", "/v1/authorize", strings.Join(tampered[:1], ".")+"."+string(b)+"."+tampered[2],
		map[string]string{"action": "read", "resource_id": "doc-1"})
	if st != 403 || body["error"] != "bad_signature" {
		t.Fatalf("篡改应 bad_signature: %d %v", st, body)
	}
	// 续期 + 重放
	st, _ = do(t, h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": rt})
	if st != 200 {
		t.Fatalf("续期失败 %d", st)
	}
	st, body = do(t, h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": rt})
	if st != 403 || body["error"] != "session_not_found" {
		t.Fatalf("重放旧 refresh 必须 403 session_not_found: %d %v", st, body)
	}
	// 审计可查且链完整
	st, body = do(t, h, "GET", "/v1/audit/verify", "", nil)
	if st != 200 || body["status"] != "intact" {
		t.Fatalf("审计链应完整: %d %v", st, body)
	}
}
