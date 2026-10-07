package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// 辅助：写入一条带嵌套 Detail 的记录，返回其 ID。
func appendSample(t *testing.T, l *Log, op string) Event {
	t.Helper()
	e, err := l.Append(Event{
		Operation: op,
		Result:    "success",
		Detail:    map[string]string{"k": "v", "nested": "original"},
	})
	if err != nil {
		t.Fatalf("append %s: %v", op, err)
	}
	return e
}

// 改顶层字段：读取方就地改 Since 结果的顶层字段，
// 服务端再查同一条必须仍是原值。
func TestSinceSnapshotTopLevelMutationIsolated(t *testing.T) {
	l := New(10)
	appendSample(t, l, "op-a")

	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: Since(0) 取到 id=%d operation=%q，调用方就地改顶层字段 Operation=%q", got[0].ID, got[0].Operation, "tampered")
	got[0].Operation = "tampered"
	got[0].Result = "denied"

	again, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Operation != "op-a" || again[0].Result != "success" {
		t.Fatalf("stored record changed by caller mutation: %+v", again[0])
	}
	t.Logf("conclusion: 再查 id=%d 仍为 operation=%q result=%q，服务端历史未被改写", again[0].ID, again[0].Operation, again[0].Result)
}

// 改嵌套字段：读取方就地改 Since 结果里嵌套的 Detail map，
// 服务端再查、再导出必须仍是原值，且导出与改动前逐字节一致。
func TestSinceSnapshotNestedMutationIsolated(t *testing.T) {
	l := New(10)
	appendSample(t, l, "op-b")

	before, err := l.Export(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}

	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: Since(0) 取到 id=%d detail=%v，调用方就地改嵌套字段 Detail[k]=%q 并新增键", got[0].ID, got[0].Detail, "mutated")
	got[0].Detail["k"] = "mutated"
	got[0].Detail["injected"] = "x"

	// 再查同一条：必须是原值。
	again, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Detail["k"] != "v" || again[0].Detail["nested"] != "original" {
		t.Fatalf("nested detail changed by caller mutation: %v", again[0].Detail)
	}
	if _, leaked := again[0].Detail["injected"]; leaked {
		t.Fatalf("caller-injected key leaked into stored record: %v", again[0].Detail)
	}

	// 再导出同一范围：必须与改动前逐字节一致。
	after, err := l.Export(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("export changed after caller mutation:\nbefore=%s\nafter=%s", beforeJSON, afterJSON)
	}
	if v := VerifyEvidence(afterJSON); v.Verdict != VerdictOK {
		t.Fatalf("re-exported evidence must verify ok, got %v (%s)", v.Verdict, v.Detail)
	}
	t.Logf("conclusion: 再查 detail=%v 为原值；再导出与改动前逐字节一致（head=%s），离线核验 ok", again[0].Detail, after.Head)
}

// 写入返回值隔离：Append 返回的记录事后被调用方改动（顶层+嵌套），
// 服务端再查、再导出必须仍是写入时的原值。
func TestAppendReturnedRecordMutationIsolated(t *testing.T) {
	l := New(10)
	returned, err := l.Append(Event{
		Operation: "op-c",
		Result:    "success",
		Detail:    map[string]string{"k": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: Append 返回 id=%d operation=%q detail=%v，调用方事后就地改返回记录", returned.ID, returned.Operation, returned.Detail)
	returned.Operation = "tampered"
	returned.Detail["k"] = "mutated"
	returned.Detail["injected"] = "x"

	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Operation != "op-c" || got[0].Detail["k"] != "v" {
		t.Fatalf("stored record changed via returned record: %+v", got[0])
	}
	if _, leaked := got[0].Detail["injected"]; leaked {
		t.Fatalf("caller-injected key leaked into stored record: %v", got[0].Detail)
	}

	ev, err := l.Export(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Records[0].Event.Operation != "op-c" || ev.Records[0].Event.Detail["k"] != "v" {
		t.Fatalf("export reflects caller mutation of returned record: %+v", ev.Records[0].Event)
	}
	t.Logf("conclusion: 再查/再导出 id=%d 仍为 operation=%q detail=%v，写入返回值与服务端历史互不影响", got[0].ID, got[0].Operation, got[0].Detail)
}

// 并发读取：多个读取方同时取同一段记录并各自就地改动，
// 彼此互不影响，服务端历史保持原值；须配合 -race 运行。
func TestConcurrentReadersIsolated(t *testing.T) {
	l := New(64)
	for i := 0; i < 8; i++ {
		appendSample(t, l, fmt.Sprintf("op-%d", i))
	}
	baseline, err := l.Export(1, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}

	const readers = 16
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for round := 0; round < 20; round++ {
				got, err := l.Since(0)
				if err != nil {
					errs <- err
					return
				}
				marker := fmt.Sprintf("reader-%d-round-%d", r, round)
				for i := range got {
					// 各自就地改自己拿到的副本：顶层 + 嵌套。
					got[i].Operation = marker
					got[i].Detail["k"] = marker
					got[i].Detail["reader"] = marker
				}
			}
		}(r)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	t.Logf("input: %d 个读取方并发各读 20 轮，每轮就地改自己副本的顶层与嵌套字段", readers)

	// 服务端历史必须仍是原值。
	got, err := l.Since(0)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range got {
		wantOp := fmt.Sprintf("op-%d", i)
		if e.Operation != wantOp || e.Detail["k"] != "v" || e.Detail["nested"] != "original" {
			t.Fatalf("stored record %d corrupted by concurrent readers: %+v", e.ID, e)
		}
		if _, leaked := e.Detail["reader"]; leaked {
			t.Fatalf("reader-injected key leaked into stored record %d: %v", e.ID, e.Detail)
		}
	}
	// 再导出必须与基线逐字节一致。
	after, err := l.Export(1, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baselineJSON, afterJSON) {
		t.Fatal("export differs from baseline after concurrent reader mutations")
	}
	t.Logf("conclusion: 8 条记录全部保持原值，再导出与基线逐字节一致（head=%s），并发读取互不影响", after.Head)
}
