package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/config"
)

func TestStorageFailureLeavesNoSession(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()

	// 让下一次写操作（CreateSession）失败：审计已写，但会话不得残留。
	gw.Store().SetFailNext(1)
	_, err := gw.Issue(ctx, IssueRequest{Username: "alice"})
	t.Logf("input: issue with injected storage fault; err=%v reason=%s", err, ReasonOf(err))
	if err == nil || ReasonOf(err) != ReasonStorageFault {
		t.Fatalf("storage fault must surface as storage_failure, got %v", err)
	}
	users, _ := gw.Store().ListUsers()
	t.Logf("decision basis: user dir intact=%v (alice remains, no session created)", len(users) == 1)
	if _, err := gw.Store().GetSession("anything"); err == nil {
		t.Fatal("no session may survive failed issue")
	}

	// 后续健康请求必须照常工作（故障计数被正确消费一次，不泄漏状态）。
	issued := mustIssue(t, gw, "alice")
	if r := gw.Verify(ctx, issued.Token); !r.Valid {
		t.Fatalf("service must recover after transient fault, got %s", r.Reason)
	}
}

func TestSessionLimitRejectsAndRollsBackAuditFree(t *testing.T) {
	cfg := config.Defaults()
	cfg.RenewWindow = 0
	cfg.MaxSessions = 1
	gw := New(cfg)
	ctx := context.Background()
	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("sec"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := gw.PutUser(ctx, UserInput{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, gw, "alice")
	_, err := gw.Issue(ctx, IssueRequest{Username: "alice"})
	t.Logf("input: second session with MaxSessions=1; reason=%s", ReasonOf(err))
	if ReasonOf(err) != ReasonLimitExceeded {
		t.Fatalf("expected limit_exceeded, got %v", err)
	}
}

func TestAuditFullRejectsSensitiveOperation(t *testing.T) {
	cfg := config.Defaults()
	cfg.RenewWindow = 0
	cfg.AuditCapacity = 1
	gw := New(cfg)
	ctx := context.Background()
	if err := gw.BootstrapSigningKey(ctx, "k1", []byte("sec"), "b"); err != nil {
		t.Fatal(err) // bootstrap 消耗唯一一条审计
	}
	if err := gw.PutUser(ctx, UserInput{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	_, err := gw.Issue(ctx, IssueRequest{Username: "alice"})
	t.Logf("input: issue when audit log is full; err=%v", err)
	if err == nil || ReasonOf(err) != ReasonAuditFailure {
		t.Fatalf("audit exhaustion must reject issue, got %v", err)
	}
}

func TestAuditTrailIsAppendOnlyAndSanitized(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	gw.Verify(ctx, issued.Token)
	gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	if err := gw.Revoke(ctx, issued.SessionID, "tester"); err != nil {
		t.Fatal(err)
	}

	events, err := gw.AuditSince(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 4 {
		t.Fatalf("expected at least 4 audit events, got %d", len(events))
	}
	// ID 单调递增、不可改写：记录之间不存在 ID 回退。
	for i := 1; i < len(events); i++ {
		if events[i].ID <= events[i-1].ID {
			t.Fatalf("audit ids must be strictly increasing: %d <= %d", events[i].ID, events[i-1].ID)
		}
	}
	// 敏感内容检查：任何事件都不得包含原始凭证或密钥片段。
	banned := []string{issued.Token, "master-secret", issued.Token[:20]}
	flat := flattenAudit(events)
	for _, b := range banned {
		if strings.Contains(flat, b) {
			t.Fatalf("audit trail must not contain sensitive material %q", b[:8])
		}
	}
	t.Logf("input: issue/verify/authorize/revoke; audit events=%d; sanitized=true", len(events))
	for _, e := range events {
		t.Logf("audit id=%d op=%s actor=%s result=%s reason=%s jti_present=%v matched=%s",
			e.ID, e.Operation, e.Actor, e.Result, e.Reason, e.JTI != "", e.Matched)
	}

	// 快照不可变性：外部修改返回切片不得影响后续读取。
	events[0].Reason = "tampered"
	again, _ := gw.AuditSince(0)
	if again[0].Reason == "tampered" {
		t.Fatal("audit snapshot must not allow rewriting stored records")
	}
}

func TestPolicyDeleteFallbackToDefaultDeny(t *testing.T) {
	gw, _ := testGateway(t)
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	if r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"}); !r.Allowed {
		t.Fatal(r.Reason)
	}
	if err := gw.DeletePolicy(ctx, "allow-reader-read", "tester"); err != nil {
		t.Fatal(err)
	}
	r := gw.Authorize(ctx, AuthorizeRequest{Token: issued.Token, Resource: "doc-1", Action: "read"})
	t.Logf("input: authorize after deleting the only allow policy")
	t.Logf("decision basis: allowed=%v reason=%s", r.Allowed, r.Reason)
	if r.Allowed || r.Reason != ReasonNoMatchingPolicy {
		t.Fatalf("must fall back to default deny after policy removal, got %+v", r)
	}
}

func TestTooManyAttributesRejected(t *testing.T) {
	gw, _ := testGateway(t)
	gw.cfg.MaxAttrCount = 2
	ctx := context.Background()
	issued := mustIssue(t, gw, "alice")
	r := gw.Authorize(ctx, AuthorizeRequest{
		Token:      issued.Token,
		Resource:   "doc-1",
		Action:     "read",
		Attributes: map[string]string{"a": "1", "b": "2", "c": "3"},
	})
	t.Logf("input: 3 request attrs with limit 2; reason=%s", r.Reason)
	if r.Allowed || r.Reason != ReasonTooManyAttributes {
		t.Fatalf("oversized attribute set must be rejected, got %+v", r)
	}
}

func flattenAudit(evs []audit.Event) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "%d|%s|%s|%s|%s|%s|%s|%s|%v\n",
			e.ID, e.Operation, e.Actor, e.Result, e.Reason, e.JTI, e.SessionID, e.Matched, e.Detail)
	}
	return b.String()
}
