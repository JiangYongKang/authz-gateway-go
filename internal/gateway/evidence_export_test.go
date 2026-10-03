package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/config"
	"github.com/highcumontoa/authz-gateway-go/internal/evidence"
)

func newEvidenceGateway(t *testing.T, exportRecords, exportBytes int) *Gateway {
	t.Helper()
	cfg := config.Defaults()
	cfg.RenewWindow = 0
	cfg.AuditExportMaxRecords = exportRecords
	cfg.AuditExportMaxBytes = exportBytes
	gw := New(cfg)
	ctx := context.Background()
	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("master-secret"), "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutUser(ctx, UserInput{Name: "alice", Roles: []string{"reader"},
		Attributes: map[string]string{"dept": "eng"}}); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutResource(ctx, ResourceInput{Name: "doc-1", Kind: "doc", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.UpsertPolicy(ctx, PolicyInput{
		ID: "allow-reader-read", Roles: []string{"reader"},
		Resources: []string{"doc-1"}, Actions: []string{"read"},
	}, "bootstrap"); err != nil {
		t.Fatal(err)
	}
	return gw
}

// 端到端：敏感操作产生审计 → 导出 → 仅用字节独立核验通过；
// 且产物里没有凭证原文/签名密钥。
func TestGatewayExportVerifiesOffline(t *testing.T) {
	gw := newEvidenceGateway(t, 0, 0)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	if r := gw.Authorize(ctx, AuthorizeRequest{
		Token: issued.Token, Resource: "doc-1", Action: "read"}); !r.Allowed {
		t.Fatalf("setup authorize: %s", r.Reason)
	}
	n := gw.AuditLog().Len()
	t.Logf("input: performed issue+authorize, audit len=%d, token len=%d", n, len(issued.Token))

	a, err := gw.ExportAuditEvidence(1, int64(n))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	res := evidence.Verify(raw)
	if !res.OK() {
		t.Fatalf("independent verify: %s (%s)", res.Status, res.Detail)
	}
	t.Logf("conclusion: exported [1,%d], independent verifier says %s — %s",
		n, res.Status, res.Detail)

	if strings.Contains(string(raw), issued.Token) {
		t.Fatal("artifact must not contain the raw credential")
	}
	if strings.Contains(string(raw), "master-secret") {
		t.Fatal("artifact must not contain the signing secret")
	}

	info, err := gw.EvidencePublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyID != a.KeyID || info.Algorithm != evidence.AlgEd25519 {
		t.Fatalf("public key info mismatch: %+v vs artifact key %s", info, a.KeyID)
	}
	t.Logf("conclusion: artifact has no token/secret; evidence key_id=%s published for verifiers",
		info.KeyID)
}

// 外部篡改导出副本：服务端再查/再导出不受影响，原样产物仍可核验。
func TestGatewayExternalTamperIsContained(t *testing.T) {
	gw := newEvidenceGateway(t, 0, 0)
	mustIssue(t, gw, "alice")
	n := gw.AuditLog().Len()

	a, err := gw.ExportAuditEvidence(1, int64(n))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := a.Encode()

	var copyArt evidence.Artifact
	if err := json.Unmarshal(raw, &copyArt); err != nil {
		t.Fatal(err)
	}
	copyArt.Records[0].Actor = "external-mallory"
	copyArt.Records[0].Detail = map[string]string{"injected": "1"}
	bad, _ := json.Marshal(copyArt)
	if evidence.Verify(bad).OK() {
		t.Fatal("tampered external copy must not verify")
	}

	// 服务端视角：审计记录未变、再导出字节一致、核验仍通过。
	events, _ := gw.AuditSince(0)
	if events[0].Actor == "external-mallory" || events[0].Detail["injected"] != "" {
		t.Fatal("server-side audit was affected by external tampering")
	}
	a2, err := gw.ExportAuditEvidence(1, int64(n))
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := a2.Encode()
	if string(raw2) != string(raw) {
		t.Fatal("server re-export must be identical after external tampering")
	}
	if !evidence.Verify(raw2).OK() {
		t.Fatal("pristine server re-export must still verify")
	}
	t.Log("input: external party edits its copy incl. nested detail; " +
		"conclusion: copy fails verify, server audit and re-export unaffected")
}

// 并发写入 + 并发导出：导出原因可区分、没有半成品，每次导出都能离线核验。
func TestGatewayConcurrentExportDuringWrites(t *testing.T) {
	gw := newEvidenceGateway(t, 0, 0)
	ctx := context.Background()
	mustIssue(t, gw, "alice")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var firstBad string
	var wmu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			// issue 与 authorize 都会写审计，构成与导出并发的敏感写入。
			tok := mustIssue(t, gw, "alice").Token
			gw.Authorize(ctx, AuthorizeRequest{
				Token: tok, Resource: "doc-1", Action: "read"})
		}
		close(stop)
	}()

	var exports, validExports int
	var emu sync.Mutex
loop:
	for {
		select {
		case <-stop:
			break loop
		default:
		}
		to := int64(gw.AuditLog().Len())
		if to < 1 {
			continue
		}
		a, err := gw.ExportAuditEvidence(1, to)
		if err != nil {
			// 快照保证 to<=快照长度；并发下这里出现任何错误都是缺陷。
			wmu.Lock()
			if firstBad == "" {
				firstBad = err.Error()
			}
			wmu.Unlock()
			continue
		}
		raw, _ := a.Encode()
		res := evidence.Verify(raw)
		emu.Lock()
		exports++
		if res.OK() {
			validExports++
		} else if firstBad == "" {
			firstBad = res.Status + ": " + res.Detail
		}
		emu.Unlock()
	}
	wg.Wait()
	if firstBad != "" {
		t.Fatalf("concurrent export/verify problem: %s", firstBad)
	}
	finalTo := int64(gw.AuditLog().Len())
	a, err := gw.ExportAuditEvidence(1, finalTo)
	if err != nil {
		t.Fatalf("final export: %v", err)
	}
	raw, _ := a.Encode()
	if res := evidence.Verify(raw); !res.OK() {
		t.Fatalf("final export verify: %s (%s)", res.Status, res.Detail)
	}
	t.Logf("input: 1 writer x200 issue+authorize alongside exports; "+
		"conclusion: %d exports, %d verified valid; final [1,%d] contiguous",
		exports, validExports, finalTo)
}

// 超上限明确拒绝、原因可区分，且不产生半成品、不影响后续导出。
func TestGatewayExportLimitsRejected(t *testing.T) {
	gw := newEvidenceGateway(t, 3, 0)
	for i := 0; i < 5; i++ {
		mustIssue(t, gw, "alice")
	}
	_, err := gw.ExportAuditEvidence(1, 4)
	if err == nil || ReasonOf(err) != ReasonExportTooMany {
		t.Fatalf("want %s, got %v", ReasonExportTooMany, err)
	}
	t.Logf("input: MaxRecords=3 Export(1,4); conclusion: %s (%v)", ReasonExportTooMany, err)

	_, err = gw.ExportAuditEvidence(0, 2)
	if err == nil || ReasonOf(err) != ReasonExportInvalidRange {
		t.Fatalf("want %s, got %v", ReasonExportInvalidRange, err)
	}
	t.Logf("conclusion: invalid range => %s", ReasonExportInvalidRange)

	// “超出已提交边界”与“条数超限”必须可区分：用无条数上限的网关单独验证。
	gwUnbounded := newEvidenceGateway(t, 0, 0)
	mustIssue(t, gwUnbounded, "alice")
	committed := gwUnbounded.AuditLog().Len()
	if _, err := gwUnbounded.ExportAuditEvidence(1, int64(committed)+10); err == nil || ReasonOf(err) != ReasonExportUnavailable {
		t.Fatalf("want %s, got %v", ReasonExportUnavailable, err)
	}
	t.Logf("conclusion: beyond committed (%d) => %s", committed, ReasonExportUnavailable)

	// 拒绝后再导出（上限内）仍成功。
	a, err := gw.ExportAuditEvidence(1, 3)
	if err != nil {
		t.Fatalf("export within limit after rejection: %v", err)
	}
	raw, _ := a.Encode()
	if !evidence.Verify(raw).OK() {
		t.Fatal("post-rejection export must be a valid, complete artifact")
	}
}
