package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// 辅助：写入一条带嵌套 Detail 的记录，返回其序号。
func mustAppendOne(t *testing.T, l *Log, op string, detail map[string]string) Event {
	t.Helper()
	ev, err := l.Append(Event{Operation: op, Result: "success", Detail: detail})
	if err != nil {
		t.Fatalf("append %q: %v", op, err)
	}
	return ev
}

// 辅助：导出 [1,1] 并序列化，用于逐字节对比。
func mustExportBytes(t *testing.T, l *Log, from, to int64) []byte {
	t.Helper()
	ev, err := l.Export(from, to, 0)
	if err != nil {
		t.Fatalf("export [%d,%d]: %v", from, to, err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return data
}

// 场景一：改“读到的记录”的顶层字段，再查、再导出必须仍是原值。
func TestReadCopyTopLevelMutationDoesNotAffectLog(t *testing.T) {
	l := New(10)
	mustAppendOne(t, l, "issue-token", map[string]string{"scope": "read"})
	t.Logf("input: append operation=issue-token detail.scope=read; then mutate top-level fields of the record returned by Since")

	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	got[0].Operation = "forged-op"
	got[0].Result = "denied"
	got[0].ID = 999

	again, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Operation != "issue-token" || again[0].Result != "success" || again[0].ID != 1 {
		t.Fatalf("stored record changed after mutating read copy: %+v", again[0])
	}
	t.Logf("conclusion: re-query still returns operation=issue-token result=success id=1; top-level mutation of read copy is invisible to the log")
}

// 场景二：改“读到的记录”里嵌套的 Detail，再查、再导出必须仍是原值，
// 且与改动前的导出逐字节一致。
func TestReadCopyNestedMutationDoesNotAffectLog(t *testing.T) {
	l := New(10)
	mustAppendOne(t, l, "issue-token", map[string]string{"scope": "read"})
	before := mustExportBytes(t, l, 1, 1)
	t.Logf("input: append detail.scope=read; export baseline; then mutate nested detail of the record returned by Since")

	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	got[0].Detail["scope"] = "admin"
	got[0].Detail["injected"] = "x"

	again, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Detail["scope"] != "read" || len(again[0].Detail) != 1 {
		t.Fatalf("stored nested detail changed after mutating read copy: %+v", again[0].Detail)
	}
	after := mustExportBytes(t, l, 1, 1)
	if !bytes.Equal(before, after) {
		t.Fatalf("export after nested mutation differs from baseline:\nbefore=%s\nafter=%s", before, after)
	}
	if v := VerifyEvidence(after); v.Verdict != VerdictOK {
		t.Fatalf("re-exported evidence must verify ok, got %v (%s)", v.Verdict, v.Detail)
	}
	t.Logf("conclusion: re-query shows detail.scope=read (len=1); re-export is byte-identical to baseline and verifies ok")
}

// 场景三：写入时返回给调用方的那条记录，事后被改（顶层 + 嵌套），
// 服务端再查、再导出必须仍是原值。
func TestAppendReturnedRecordMutationDoesNotAffectLog(t *testing.T) {
	l := New(10)
	returned := mustAppendOne(t, l, "rotate-key", map[string]string{"kid": "k1"})
	before := mustExportBytes(t, l, 1, 1)
	t.Logf("input: append returns record id=%d detail.kid=k1; then mutate the returned record in place (top-level + nested)", returned.ID)

	returned.Operation = "forged-op"
	returned.Detail["kid"] = "k2-forged"
	returned.Detail["extra"] = "y"

	again, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Operation != "rotate-key" || again[0].Detail["kid"] != "k1" || len(again[0].Detail) != 1 {
		t.Fatalf("stored record changed after mutating Append's returned record: %+v", again[0])
	}
	after := mustExportBytes(t, l, 1, 1)
	if !bytes.Equal(before, after) {
		t.Fatalf("export after mutating returned record differs from baseline:\nbefore=%s\nafter=%s", before, after)
	}
	t.Logf("conclusion: re-query shows operation=rotate-key detail.kid=k1 (len=1); re-export byte-identical to baseline")
}

// 场景四：多个读取方并发读取同一段记录、各自就地改动，
// 彼此互不影响，服务端记录也不被改坏（配合 -race 运行）。
func TestConcurrentReadersAreIsolated(t *testing.T) {
	l := New(100)
	const records = 8
	for i := 0; i < records; i++ {
		mustAppendOne(t, l, "op", map[string]string{"idx": fmt.Sprintf("%d", i)})
	}
	before := mustExportBytes(t, l, 1, records)
	t.Logf("input: %d records appended; %d concurrent readers each read the full range and mutate their own copies (top-level + nested)", records, records*2)

	var wg sync.WaitGroup
	errs := make(chan string, records*2)
	for r := 0; r < records*2; r++ {
		wg.Add(1)
		go func(tag int) {
			defer wg.Done()
			for round := 0; round < 20; round++ {
				got, err := l.Since(0)
				if err != nil {
					errs <- err.Error()
					return
				}
				if len(got) != records {
					errs <- fmt.Sprintf("reader %d: expected %d records, got %d", tag, records, len(got))
					return
				}
				for i := range got {
					// 读到手之前，记录必须仍是原值——其他读者的改动不可见。
					want := fmt.Sprintf("%d", got[i].ID-1)
					if got[i].Detail["idx"] != want {
						errs <- fmt.Sprintf("reader %d: record %d detail.idx=%q, want %q", tag, got[i].ID, got[i].Detail["idx"], want)
						return
					}
					got[i].Operation = fmt.Sprintf("forged-by-reader-%d", tag)
					got[i].Detail["idx"] = "forged"
					got[i].Detail["reader"] = fmt.Sprintf("%d", tag)
				}
			}
		}(r)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}

	after := mustExportBytes(t, l, 1, records)
	if !bytes.Equal(before, after) {
		t.Fatalf("export after concurrent readers differs from baseline:\nbefore=%s\nafter=%s", before, after)
	}
	if v := VerifyEvidence(after); v.Verdict != VerdictOK {
		t.Fatalf("evidence after concurrent readers must verify ok, got %v (%s)", v.Verdict, v.Detail)
	}
	t.Logf("conclusion: no reader observed another reader's mutations; final export byte-identical to baseline and verifies ok")
}

// 场景五（回归护栏）：修复不得改变既有语义——只追加、序号严格连续、
// 写满拒绝、敏感材料不落盘、同范围重复导出逐字节一致。
func TestIsolationFixPreservesExistingSemantics(t *testing.T) {
	l := New(2)
	if _, err := l.Append(Event{Operation: "a", JTI: "j-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Event{Operation: "b", Detail: map[string]string{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Event{Operation: "c"}); err != ErrAuditFull {
		t.Fatalf("full log must reject with ErrAuditFull, got %v", err)
	}
	got, _ := l.Since(0)
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("sequence must stay strictly contiguous: %+v", got)
	}
	e1 := mustExportBytes(t, l, 1, 2)
	e2 := mustExportBytes(t, l, 1, 2)
	if !bytes.Equal(e1, e2) {
		t.Fatal("repeated export of the same range must be byte-identical")
	}
	if bytes.Contains(e1, []byte("secret")) || bytes.Contains(e1, []byte("private")) {
		t.Fatal("sensitive material must never appear in exported evidence")
	}
	t.Logf("input: cap=2, two appends then a third; conclusion: ErrAuditFull, ids 1..2 contiguous, repeated export byte-identical, no sensitive material in evidence")
}
