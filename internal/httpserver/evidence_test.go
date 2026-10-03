package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/evidence"
	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
)

// HTTP 端到端：导出接口返回自包含产物，离线核验通过；篡改后被识别；
// 非法/超界/超限范围给出可区分的 HTTP 状态与原因码。
func TestHTTPEvidenceExportAndVerify(t *testing.T) {
	_, ts := setup(t)

	post := func(path string, body any) {
		b, _ := json.Marshal(body)
		resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	// 产生若干审计记录。
	post("/v1/tokens/issue", map[string]string{"username": "alice"})
	post("/v1/tokens/issue", map[string]string{"username": "alice"})

	get := func(path string) (int, []byte) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := readAll(resp)
		return resp.StatusCode, raw
	}

	// 公钥信任锚可查询。
	status, raw := get("/v1/audit/evidence/key")
	if status != http.StatusOK {
		t.Fatalf("evidence key status=%d body=%s", status, raw)
	}
	var keyInfo map[string]string
	if err := json.Unmarshal(raw, &keyInfo); err != nil {
		t.Fatal(err)
	}
	if keyInfo["algorithm"] != evidence.AlgEd25519 || keyInfo["key_id"] == "" {
		t.Fatalf("bad key info: %s", raw)
	}
	t.Logf("input: GET evidence key; conclusion: key_id=%s alg=%s",
		keyInfo["key_id"], keyInfo["algorithm"])

	// 导出 [1,2]。
	status, raw = get("/v1/audit/evidence?from=1&to=2")
	if status != http.StatusOK {
		t.Fatalf("export status=%d body=%s", status, raw)
	}
	res := evidence.Verify(raw)
	if !res.OK() {
		t.Fatalf("fresh export verify: %s (%s)", res.Status, res.Detail)
	}
	t.Logf("input: GET evidence?from=1&to=2; conclusion: %s — %s", res.Status, res.Detail)

	// 缺参数 → 400。
	if status, body := get("/v1/audit/evidence?from=1"); status != http.StatusBadRequest {
		t.Fatalf("missing to: status=%d body=%s", status, body)
	}
	// 非法范围 → 400 export_invalid_range。
	status, raw = get("/v1/audit/evidence?from=5&to=2")
	if status != http.StatusBadRequest || !containsReason(raw, gateway.ReasonExportInvalidRange) {
		t.Fatalf("illegal range: status=%d body=%s", status, raw)
	}
	// 超出已提交 → 403 export_range_unavailable。
	status, raw = get("/v1/audit/evidence?from=1&to=999")
	if status != http.StatusForbidden || !containsReason(raw, gateway.ReasonExportUnavailable) {
		t.Fatalf("beyond committed: status=%d body=%s", status, raw)
	}
	t.Log("conclusion: missing params=>400, illegal range=>400 export_invalid_range, " +
		"beyond committed=>403 export_range_unavailable")

	// 取回一份合法产物，改写嵌套内容后必须核验失败。
	_, good := get("/v1/audit/evidence?from=1&to=2")
	var a evidence.Artifact
	if err := json.Unmarshal(good, &a); err != nil {
		t.Fatal(err)
	}
	a.Records[0].Actor = "mallory"
	bad, _ := json.Marshal(a)
	if evidence.Verify(bad).OK() {
		t.Fatal("tampered artifact must not verify")
	}
	// 原始字节再次核验仍通过（无状态核验）。
	if !evidence.Verify(good).OK() {
		t.Fatal("re-verifying untouched bytes must still pass")
	}
	t.Log("conclusion: tampering nested content of the exported copy is detected offline; " +
		"untouched bytes still verify")
}

func containsReason(raw []byte, reason string) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	return m["reason"] == reason
}
