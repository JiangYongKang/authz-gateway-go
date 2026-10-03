package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/config"
	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
)

func getRaw(t *testing.T, url string) (int, []byte) {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	return r.StatusCode, buf.Bytes()
}

func TestAuditExportEndpoint(t *testing.T) {
	_, ts := setup(t)

	// 制造几条审计记录。
	resp, err := http.Post(ts.URL+"/v1/tokens/issue", "application/json",
		strings.NewReader(`{"username":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 合法范围：返回自包含证据，离线核验通过。
	status, body := getRaw(t, ts.URL+"/v1/audit/export?from=1&to=2")
	v := audit.VerifyEvidence(body)
	t.Logf("input: GET /v1/audit/export?from=1&to=2; conclusion: status=%d verdict=%s", status, v.Verdict)
	if status != http.StatusOK || v.Verdict != audit.VerdictOK {
		t.Fatalf("valid export must be 200 and verify ok, got %d %s", status, v.Verdict)
	}

	// 范围不合法：400 + 可区分原因码。
	status, body = getRaw(t, ts.URL+"/v1/audit/export?from=3&to=1")
	var e1 map[string]any
	_ = json.Unmarshal(body, &e1)
	t.Logf("input: GET export from=3&to=1; conclusion: status=%d reason=%v", status, e1["reason"])
	if status != http.StatusBadRequest || e1["reason"] != "export_range_invalid" {
		t.Fatalf("inverted range must be 400 export_range_invalid, got %d %v", status, e1)
	}

	// 超出已记录序号：400。
	status, _ = getRaw(t, ts.URL+"/v1/audit/export?from=1&to=999")
	if status != http.StatusBadRequest {
		t.Fatalf("out-of-range export must be 400, got %d", status)
	}

	// 缺参数：400。
	status, _ = getRaw(t, ts.URL+"/v1/audit/export?from=1")
	if status != http.StatusBadRequest {
		t.Fatalf("missing param must be 400, got %d", status)
	}
}

func TestAuditExportEndpointLimit(t *testing.T) {
	cfg := config.Defaults()
	cfg.MaxExport = 1
	gw := gateway.New(cfg)
	ts := httptest.NewServer(New(gw).Handler())
	t.Cleanup(ts.Close)
	if err := gw.BootstrapSigningKey(t.Context(), "k1", []byte("sec"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutUser(t.Context(), gateway.UserInput{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/v1/tokens/issue", "application/json",
		strings.NewReader(`{"username":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	status, body := getRaw(t, ts.URL+"/v1/audit/export?from=1&to=2")
	var e map[string]any
	_ = json.Unmarshal(body, &e)
	t.Logf("input: GET export [1,2] with MaxExport=1; conclusion: status=%d reason=%v", status, e["reason"])
	if status != http.StatusRequestEntityTooLarge || e["reason"] != "export_limit_exceeded" {
		t.Fatalf("over-limit export must be 413 export_limit_exceeded, got %d %v", status, e)
	}
	// 拒绝后不留半成品：上限内的导出仍正常。
	status, body = getRaw(t, ts.URL+"/v1/audit/export?from=1&to=1")
	if status != http.StatusOK || audit.VerifyEvidence(body).Verdict != audit.VerdictOK {
		t.Fatalf("within-limit export after rejection must work, got %d", status)
	}
}
