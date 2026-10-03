package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// fill 向日志追加 n 条记录并返回日志。
func fill(t *testing.T, n int) *Log {
	t.Helper()
	l := New(0)
	for i := 1; i <= n; i++ {
		if _, err := l.Append(Event{
			Operation: fmt.Sprintf("op-%d", i),
			Result:    "success",
			JTI:       fmt.Sprintf("jti-%d", i),
			Detail:    map[string]string{"k": fmt.Sprintf("v-%d", i)},
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return l
}

func mustExport(t *testing.T, l *Log, from, to int64, max int) Evidence {
	t.Helper()
	ev, err := l.Export(from, to, max)
	if err != nil {
		t.Fatalf("export [%d,%d]: %v", from, to, err)
	}
	return ev
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestExportThenIndependentVerifyOK(t *testing.T) {
	l := fill(t, 5)
	ev := mustExport(t, l, 2, 4, 0)
	data := mustJSON(t, ev)

	// 模拟完全独立的一方：只拿到序列化字节，不接触服务。
	v := VerifyEvidence(data)
	t.Logf("input: export range [2,4] of 5 appended events; conclusion: verdict=%s records=%d", v.Verdict, v.Records)
	if v.Verdict != VerdictOK || v.Records != 3 {
		t.Fatalf("independent verification must pass, got %+v", v)
	}
}

func TestExportIsDeterministic(t *testing.T) {
	l := fill(t, 4)
	a := mustJSON(t, mustExport(t, l, 1, 4, 0))
	b := mustJSON(t, mustExport(t, l, 1, 4, 0))
	if string(a) != string(b) {
		t.Fatal("repeated export of the same range must be byte-identical")
	}
	t.Logf("input: export [1,4] twice; conclusion: identical bytes (%d bytes)", len(a))
}

func TestVerifyDetectsSequenceBreaks(t *testing.T) {
	cases := map[string]func(ev *Evidence){
		"gap": func(ev *Evidence) { ev.Records[1].Event.ID += 10 }, // 跳号
		"duplicate": func(ev *Evidence) { // 重复序号
			ev.Records[2].Event.ID = ev.Records[1].Event.ID
		},
		"reordered": func(ev *Evidence) { // 顺序被重排
			ev.Records[0], ev.Records[1] = ev.Records[1], ev.Records[0]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l := fill(t, 4)
			ev := mustExport(t, l, 1, 4, 0)
			mutate(&ev)
			v := VerifyEvidence(mustJSON(t, &ev))
			t.Logf("input: %s in exported copy; conclusion: verdict=%s detail=%q", name, v.Verdict, v.Detail)
			if v.Verdict != VerdictSequenceBroken {
				t.Fatalf("%s must be detected as sequence_broken, got %+v", name, v)
			}
		})
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]func(ev *Evidence){
		"nested_detail": func(ev *Evidence) { ev.Records[1].Event.Detail["k"] = "forged" },
		"operation":     func(ev *Evidence) { ev.Records[0].Event.Operation = "forged" },
		"record_hash":   func(ev *Evidence) { ev.Records[2].Hash = "00" },
		"head":          func(ev *Evidence) { ev.Head = "ff" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l := fill(t, 4)
			ev := mustExport(t, l, 1, 4, 0)
			mutate(&ev)
			v := VerifyEvidence(mustJSON(t, &ev))
			t.Logf("input: tamper %s in exported copy; conclusion: verdict=%s detail=%q", name, v.Verdict, v.Detail)
			if v.Verdict != VerdictTampered {
				t.Fatalf("tampering %s must be detected, got %+v", name, v)
			}
		})
	}
}

func TestVerifyRejectsInvalidRangeAndMalformed(t *testing.T) {
	l := fill(t, 3)
	good := mustExport(t, l, 1, 3, 0)

	// 范围本身不合法：from > to。
	bad := good
	bad.From, bad.To = 3, 1
	v := VerifyEvidence(mustJSON(t, &bad))
	t.Logf("input: declared range [3,1]; conclusion: verdict=%s", v.Verdict)
	if v.Verdict != VerdictInvalidRange {
		t.Fatalf("inverted range must be invalid_range, got %+v", v)
	}

	// 记录条数与声明区间不符。
	bad2 := good
	bad2.Records = bad2.Records[:2]
	v = VerifyEvidence(mustJSON(t, &bad2))
	t.Logf("input: range [1,3] but only 2 records; conclusion: verdict=%s", v.Verdict)
	if v.Verdict != VerdictInvalidRange {
		t.Fatalf("count mismatch must be invalid_range, got %+v", v)
	}

	// 根本不是证据产物。
	v = VerifyEvidence([]byte("{not json"))
	t.Logf("input: unparseable bytes; conclusion: verdict=%s", v.Verdict)
	if v.Verdict != VerdictMalformed {
		t.Fatalf("garbage must be malformed, got %+v", v)
	}
}

func TestExportRejectsInvalidRangeAndLimit(t *testing.T) {
	l := fill(t, 3)
	for _, r := range [][2]int64{{0, 2}, {3, 2}, {2, 9}} {
		if _, err := l.Export(r[0], r[1], 0); err != ErrExportRange {
			t.Fatalf("range %v must be rejected with ErrExportRange, got %v", r, err)
		}
	}
	if _, err := l.Export(1, 3, 2); err != ErrExportLimit {
		t.Fatalf("over-limit export must be rejected with ErrExportLimit, got %v", err)
	}
	// 拒绝不得产生半成品：日志内容与长度不变，合法导出仍正常。
	if l.Len() != 3 {
		t.Fatalf("rejected export must not mutate the log, len=%d", l.Len())
	}
	ev := mustExport(t, l, 1, 3, 3) // 恰好等于上限应放行
	if got := VerifyEvidence(mustJSON(t, ev)).Verdict; got != VerdictOK {
		t.Fatalf("at-limit export must verify ok, got %s", got)
	}
	t.Logf("input: invalid ranges + over-limit request; conclusion: rejected with distinct errors, no partial artifact")
}

func TestExportedCopyTamperingDoesNotAffectServer(t *testing.T) {
	l := fill(t, 4)
	ev := mustExport(t, l, 1, 4, 0)
	original := mustJSON(t, ev)

	// 外部拿到导出副本后肆意改动（含嵌套的 Detail）。
	ev.Records[0].Event.Operation = "forged"
	ev.Records[1].Event.Detail["k"] = "forged"
	ev.Head = "ff"

	// 服务端记录不变。
	events, _ := l.Since(0)
	if events[0].Operation == "forged" || events[1].Detail["k"] == "forged" {
		t.Fatal("mutating an exported copy must not change stored records")
	}
	// 再次导出仍是原值，且与首次导出逐字节一致。
	again := mustJSON(t, mustExport(t, l, 1, 4, 0))
	if string(again) != string(original) {
		t.Fatal("re-export after external tampering must be identical to the first export")
	}
	// 未被动过的那份产物仍然核验通过。
	if got := VerifyEvidence(original).Verdict; got != VerdictOK {
		t.Fatalf("untouched artifact must still verify, got %s", got)
	}
	t.Logf("input: tamper exported copy incl. nested detail; conclusion: server records & re-export unchanged, original artifact still ok")
}

func TestConcurrentExportAndAppend(t *testing.T) {
	l := New(0)
	const total = 300 // 写入总量有界，避免测试无限增长
	done := make(chan struct{})

	// 写入方：持续追加敏感操作记录，写满 total 条后停。
	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			if _, err := l.Append(Event{Operation: "op", Detail: map[string]string{"i": fmt.Sprint(i)}}); err != nil {
				t.Errorf("append: %v", err)
				return
			}
		}
	}()

	// 导出方：在写入进行中反复导出，每份都必须是一致边界。
	rounds := 0
	for {
		select {
		case <-done:
			goto finished
		default:
		}
		to := l.Len()
		if to == 0 {
			continue
		}
		ev, err := l.Export(1, int64(to), 0)
		if err != nil {
			t.Fatalf("export during writes: %v", err)
		}
		v := VerifyEvidence(mustJSON(t, ev))
		if v.Verdict != VerdictOK {
			t.Fatalf("concurrent export must be a consistent boundary, got %+v", v)
		}
		// 无半条记录、无跳号、无重复：序号严格连续。
		for i, r := range ev.Records {
			if r.Event.ID != int64(i+1) {
				t.Fatalf("ids not contiguous at %d", i)
			}
		}
		rounds++
	}
finished:
	// 写入结束后最终全量导出也必须完整可核验。
	ev, err := l.Export(1, total, 0)
	if err != nil {
		t.Fatalf("final export: %v", err)
	}
	if v := VerifyEvidence(mustJSON(t, ev)); v.Verdict != VerdictOK {
		t.Fatalf("final export must verify, got %+v", v)
	}
	t.Logf("input: %d concurrent exports racing %d appends; conclusion: every export is a consistent, verifiable boundary", rounds, total)
}

// TestStandaloneVerifierProcess 证明核验可以由完全独立的进程完成：
// 把导出产物写成文件，用单独构建的 audit-verify 二进制核验。
func TestStandaloneVerifierProcess(t *testing.T) {
	l := fill(t, 3)
	good := mustJSON(t, mustExport(t, l, 1, 3, 0))

	dir := t.TempDir()
	bin := dir + "/audit-verify"
	build := exec.Command("go", "build", "-o", bin, "./cmd/audit-verify")
	build.Dir = "../.." // 模块根目录
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build verifier: %v\n%s", err, out)
	}

	evidenceFile := dir + "/evidence.json"
	if err := os.WriteFile(evidenceFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, evidenceFile).CombinedOutput()
	t.Logf("input: verify untouched artifact in a separate process; conclusion: exit=0 output=%s", out)
	if err != nil {
		t.Fatalf("separate-process verification of intact artifact must pass: %v\n%s", err, out)
	}

	// 改动产物中的一个字节级内容（嵌套 detail 值），独立进程必须判 tampered。
	var ev Evidence
	if err := json.Unmarshal(good, &ev); err != nil {
		t.Fatal(err)
	}
	ev.Records[1].Event.Detail["k"] = "forged-by-outsider"
	forged := mustJSON(t, &ev)
	if err := os.WriteFile(evidenceFile, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, evidenceFile)
	out, err = cmd.CombinedOutput()
	t.Logf("input: verify outsider-modified artifact in a separate process; conclusion: exit=%v output=%s", err, out)
	if err == nil || !strings.Contains(string(out), string(VerdictTampered)) {
		t.Fatalf("modified artifact must fail with tampered verdict, got err=%v out=%s", err, out)
	}
}
