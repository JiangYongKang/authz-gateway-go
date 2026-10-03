package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/config"
)

func TestExportAuditAfterRealFlowVerifiesAndHidesSecrets(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()

	issued := mustIssue(t, gw, "alice")
	res := gw.Authorize(ctx, AuthorizeRequest{
		Token: issued.Token, Resource: "doc-1", Action: "read",
	})
	if !res.Allowed {
		t.Fatalf("authorize must allow: %+v", res)
	}
	if err := gw.Revoke(ctx, issued.SessionID, "tester"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	n := gw.AuditLog().Len()
	ev, err := gw.ExportAudit(1, int64(n))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	data, _ := json.Marshal(ev)
	v := audit.VerifyEvidence(data)
	t.Logf("input: issue+authorize+revoke then export [1,%d]; conclusion: verdict=%s records=%d", n, v.Verdict, v.Records)
	if v.Verdict != audit.VerdictOK {
		t.Fatalf("evidence of real flow must verify, got %+v", v)
	}

	// 导出的产物不得携带凭证原文或密钥材料。
	if strings.Contains(string(data), issued.Token) {
		t.Fatal("evidence must not contain the raw credential")
	}
	if strings.Contains(string(data), "master-secret") {
		t.Fatal("evidence must not contain signing key material")
	}
}

func TestExportAuditLimitHasDistinctReason(t *testing.T) {
	cfg := config.Defaults()
	cfg.MaxExport = 2
	gw := New(cfg)
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	gw.SetClock(fc.now)
	ctx := context.Background()
	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("master-secret"), "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutUser(ctx, UserInput{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, gw, "alice") // 产生多条审计记录
	mustIssue(t, gw, "alice")

	n := int64(gw.AuditLog().Len())
	if n < 3 {
		t.Fatalf("need >=3 audit records for this test, got %d", n)
	}
	_, err := gw.ExportAudit(1, n)
	t.Logf("input: export [1,%d] with MaxExport=2; conclusion: err=%v reason=%s", n, err, ExportReasonOf(err))
	if ExportReasonOf(err) != ReasonExportLimit {
		t.Fatalf("over-limit export must report %s, got %s (%v)", ReasonExportLimit, ExportReasonOf(err), err)
	}
	if _, err := gw.ExportAudit(1, n+1); ExportReasonOf(err) != ReasonExportRangeInvalid {
		t.Fatalf("out-of-range export must report %s, got %s", ReasonExportRangeInvalid, ExportReasonOf(err))
	}
	// 上限内的导出不受影响。
	if _, err := gw.ExportAudit(1, 2); err != nil {
		t.Fatalf("within-limit export must succeed: %v", err)
	}
}
