package audit

import "testing"

func TestAppendOnlyCapacityAndSanitizedSnapshot(t *testing.T) {
	l := New(2)
	if _, err := l.Append(Event{Operation: "a", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Event{Operation: "b", Result: "denied", JTI: "j1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Event{Operation: "c"}); err != ErrAuditFull {
		t.Fatalf("full log must reject, got %v", err)
	}
	got, _ := l.Since(0)
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("append-only sequence wrong: %+v", got)
	}
	// 快照篡改不得影响存储。
	got[0].Operation = "tampered"
	again, _ := l.Since(0)
	if again[0].Operation == "tampered" {
		t.Fatal("snapshot must be a defensive copy")
	}
	since1, _ := l.Since(1)
	if len(since1) != 1 || since1[0].ID != 2 {
		t.Fatalf("Since paging wrong: %+v", since1)
	}
	t.Logf("input: audit cap=2; basis: third append denied ErrAuditFull, ids monotonic, copies isolated")
}

func TestDetailMapIsCopied(t *testing.T) {
	l := New(10)
	d := map[string]string{"k": "v"}
	if _, err := l.Append(Event{Operation: "x", Detail: d}); err != nil {
		t.Fatal(err)
	}
	d["k"] = "mutated-after-append"
	got, _ := l.Since(0)
	if got[0].Detail["k"] != "v" {
		t.Fatal("later mutation of caller map must not change the stored record")
	}
}
