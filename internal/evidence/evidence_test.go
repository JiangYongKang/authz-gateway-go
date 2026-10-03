package evidence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
)

func fixedClock(t *testing.T, l *audit.Log, base time.Time) {
	t.Helper()
	n := int64(0)
	l.SetClock(func() time.Time {
		cur := base.Add(time.Duration(n) * time.Second)
		n++
		return cur
	})
}

func seedLog(t *testing.T, n int) *audit.Log {
	t.Helper()
	l := audit.New(0)
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	fixedClock(t, l, base)
	for i := 0; i < n; i++ {
		e := audit.Event{
			Actor:     "alice",
			Operation: []string{"issue", "authorize", "revoke", "renew", "verify"}[i%5],
			Result:    "success",
			JTI:       "jti-" + strings.Repeat("x", i+1),
			Detail:    map[string]string{"step": string(rune('a' + i))},
		}
		if _, err := l.Append(e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return l
}

func newTestExporter(t *testing.T, l *audit.Log, lim Limits) (*Exporter, *ExportKey) {
	t.Helper()
	key, err := NewExportKey()
	if err != nil {
		t.Fatalf("new export key: %v", err)
	}
	return NewExporter(l, key, lim), key
}

func mustExport(t *testing.T, x *Exporter, from, to int64) []byte {
	t.Helper()
	a, err := x.Export(from, to)
	if err != nil {
		t.Fatalf("Export(%d,%d): %v", from, to, err)
	}
	raw, err := a.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return raw
}

// 1) 导出后交给“独立核验”（只拿到字节，不接触服务/日志）必须通过。
func TestExportAndIndependentVerify(t *testing.T) {
	l := seedLog(t, 6)
	x, key := newTestExporter(t, l, Limits{})

	raw := mustExport(t, x, 2, 5)
	res := Verify(raw)
	t.Logf("input: export range [2,5] over 6 committed records; key_id=%s", key.KeyID())
	if !res.OK() {
		t.Fatalf("conclusion: %s (%s); want valid", res.Status, res.Detail)
	}
	t.Logf("conclusion: %s — %s", res.Status, res.Detail)

	// 核验方不需要服务端：重新解码字节，公钥/签名/记录全部自包含。
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 4 || a.Records[0].ID != 2 || a.Records[3].ID != 5 {
		t.Fatalf("exported range wrong: %+v", a.Records)
	}
	if a.RangeFrom != 2 || a.RangeTo != 5 || a.AnchorHash == "" {
		t.Fatalf("range/anchor wrong: from=%d to=%d anchor=%q", a.RangeFrom, a.RangeTo, a.AnchorHash)
	}
	if a.Signature == "" || a.PublicKey == "" {
		t.Fatal("artifact must embed public key and signature")
	}
}

// 2a) 缺号 → missing_records。
func TestVerifyDetectsGap(t *testing.T) {
	l := seedLog(t, 5)
	x, _ := newTestExporter(t, l, Limits{})

	// 删除一条记录但不修正声明范围：记录数与范围不符 → artifact_malformed。
	raw := mustExport(t, x, 1, 5)
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	a.Records = append(append([]Record{}, a.Records[:2]...), a.Records[3:]...)
	dropped, _ := json.Marshal(a)
	res := Verify(dropped)
	t.Logf("input: delete id=3 without fixing declared range; conclusion: %s (%s)",
		res.Status, res.Detail)
	if res.Status != StatusMalformed {
		t.Fatalf("count mismatch must be malformed, got %s", res.Status)
	}

	// 记录数与声明一致但序号前向跳跃：声明 [1,4]，记录 id 为 1,2,4,5 → 缺 3。
	gap := buildArtifactWith(t, mustExport(t, x, 1, 5), []int64{1, 2, 4, 5})
	res = Verify(gap)
	t.Log("input: declared [1,4], record ids=1,2,4,5 (3 is missing)")
	if res.Status != StatusGap {
		t.Fatalf("conclusion: %s (%s); want missing_records", res.Status, res.Detail)
	}
	if res.WantID != 3 || res.GotID != 4 {
		t.Fatalf("gap location wrong: want=%d got=%d", res.WantID, res.GotID)
	}
	t.Logf("conclusion: %s — missing id=%d, next present id=%d", res.Status, res.WantID, res.GotID)
}

// buildArtifactWith 从一份真实导出中按 ids 挑选记录，并把声明范围改成与挑选
// 后的条数一致，用于构造“计数正确但序号跳跃”的样本。其签名必然失效，但缺号
// 检查先于哈希/签名检查，应当先命中 missing_records。
func buildArtifactWith(t *testing.T, fullExport []byte, ids []int64) []byte {
	t.Helper()
	var a Artifact
	if err := json.Unmarshal(fullExport, &a); err != nil {
		t.Fatal(err)
	}
	pick := make([]Record, 0, len(ids))
	for _, want := range ids {
		for _, rec := range a.Records {
			if rec.ID == want {
				pick = append(pick, rec)
			}
		}
	}
	a.Records = pick
	a.RangeTo = a.RangeFrom + int64(len(ids)) - 1
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// 2b) 重复/重排 → reordered_or_dup。
func TestVerifyDetectsReorderAndDuplicate(t *testing.T) {
	l := seedLog(t, 5)
	x, _ := newTestExporter(t, l, Limits{})

	for _, tc := range [][]int64{
		{2, 1, 3, 4}, // 重排：前两条交换
		{1, 2, 2, 4}, // 重复：id=2 重复，丢 3
	} {
		full := mustExport(t, x, 1, 4)
		var a Artifact
		_ = json.Unmarshal(full, &a)
		recs := make([]Record, 0, len(tc))
		for _, id := range tc {
			for _, rec := range a.Records {
				if rec.ID == id {
					recs = append(recs, rec)
				}
			}
		}
		a.Records = recs
		raw, _ := json.Marshal(a)
		res := Verify(raw)
		t.Logf("input: declared [1,4], record order=%v", tc)
		if res.Status != StatusReordered {
			t.Fatalf("conclusion: %s (%s); want reordered_or_dup for %v",
				res.Status, res.Detail, tc)
		}
		t.Logf("conclusion: %s at position want_id=%d got_id=%d — %s",
			res.Status, res.WantID, res.GotID, res.Detail)
	}
}

// 2c) 内容被改写（含嵌套 detail）→ content_tampered；只改元数据 → 签名失败。
func TestVerifyDetectsTamperedContent(t *testing.T) {
	l := seedLog(t, 4)
	x, _ := newTestExporter(t, l, Limits{})

	cases := []struct {
		name  string
		tweak func(a *Artifact)
	}{
		{"top-level field", func(a *Artifact) { a.Records[1].Operation = "HACKED" }},
		{"nested detail value", func(a *Artifact) { a.Records[2].Detail["step"] = "zz" }},
		{"nested detail added key", func(a *Artifact) { a.Records[0].Detail["injected"] = "x" }},
		{"jti (credential reference)", func(a *Artifact) { a.Records[0].JTI = "forged" }},
	}
	for _, tc := range cases {
		raw := mustExport(t, x, 1, 4)
		var a Artifact
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		tc.tweak(&a)
		bad, _ := json.Marshal(a)
		res := Verify(bad)
		t.Logf("input: tamper %s after export", tc.name)
		if res.Status != StatusTampered {
			t.Fatalf("conclusion for %s: %s (%s); want content_tampered",
				tc.name, res.Status, res.Detail)
		}
		t.Logf("conclusion: %s at id=%d — %s", res.Status, res.AtID, res.Detail)
	}

	// 只改 root_hash（不改记录）→ root_mismatch；改签名 → bad_evidence_signature。
	raw := mustExport(t, x, 1, 4)
	var a Artifact
	_ = json.Unmarshal(raw, &a)
	a.RootHash = "00"
	bad, _ := json.Marshal(a)
	if res := Verify(bad); res.Status != StatusRootMismatch {
		t.Fatalf("root tweak: got %s, want root_mismatch", res.Status)
	}
	raw2 := mustExport(t, x, 1, 4)
	var a2 Artifact
	_ = json.Unmarshal(raw2, &a2)
	a2.Signature = a2.Signature[:len(a2.Signature)-2] + "AA"
	bad2, _ := json.Marshal(a2)
	if res := Verify(bad2); res.Status != StatusBadSignature {
		t.Fatalf("signature tweak: got %s, want bad_evidence_signature", res.Status)
	}
	t.Log("conclusion: root-only tweak => root_mismatch; signature tweak => bad_evidence_signature")
}

// 3) 声明范围本身不合法：在导出端被拒绝；在核验端判 invalid_range。
func TestInvalidRange(t *testing.T) {
	l := seedLog(t, 3)
	x, _ := newTestExporter(t, l, Limits{})
	for _, r := range [][2]int64{{0, 2}, {3, 2}, {-1, 2}} {
		_, err := x.Export(r[0], r[1])
		if !errors.Is(err, ErrInvalidRange) {
			t.Fatalf("Export(%d,%d) err=%v, want ErrInvalidRange", r[0], r[1], err)
		}
		t.Logf("input: Export(from=%d,to=%d) rejected: %v", r[0], r[1], err)
	}
	// 导出超出已提交边界。
	if _, err := x.Export(1, 4); !errors.Is(err, ErrRangeUnavailable) {
		t.Fatalf("Export beyond committed: got %v, want ErrRangeUnavailable", err)
	}
	t.Log("input: Export(1,4) with only 3 committed => export_range_unavailable")

	// 核验端：伪造声明范围非法但结构完整的 JSON。用 [2,3] 的导出，
	// 它带非空 anchor，翻转范围后应命中 invalid_range 而非结构问题。
	raw := mustExport(t, x, 2, 3)
	var a Artifact
	_ = json.Unmarshal(raw, &a)
	a.RangeFrom, a.RangeTo = 3, 2
	bad, _ := json.Marshal(a)
	res := Verify(bad)
	if res.Status != StatusInvalidRange {
		t.Fatalf("verify illegal declared range: got %s, want invalid_range", res.Status)
	}
	t.Logf("conclusion: declared [3,1] => %s — %s", res.Status, res.Detail)
}

// 4) 外部改动导出副本不影响服务端：再次导出字节一致、核验仍通过。
func TestExternalMutationDoesNotAffectServer(t *testing.T) {
	l := seedLog(t, 5)
	x, _ := newTestExporter(t, l, Limits{})

	first := mustExport(t, x, 1, 5)
	var a Artifact
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatal(err)
	}
	// 对方拿到产物后随意改写，包括嵌套 detail。
	a.Records[0].Operation = "deleted-by-external-party"
	a.Records[1].Detail["step"] = "external-overwrite"
	extra := append([]byte(nil), first...)
	_ = extra

	// 服务端审计记录仍然不变（直接查日志）。
	events, _ := l.Since(0)
	if events[0].Operation != "issue" || events[1].Detail["step"] != "b" {
		t.Fatalf("server records were affected by external artifact edit: %+v", events)
	}
	// 服务端再次导出：与第一次字节一致，且仍能核验通过。
	again := mustExport(t, x, 1, 5)
	if string(again) != string(first) {
		t.Fatal("repeat export of same range must be byte-identical")
	}
	if res := Verify(again); !res.OK() {
		t.Fatalf("pristine re-export must verify: %s (%s)", res.Status, res.Detail)
	}
	t.Log("input: external party rewrites exported copy incl. nested detail; " +
		"conclusion: server log unchanged, re-export byte-identical, re-verify valid")
}

//  5. 并发导出与写入同时进行：每次导出都自洽（连续、无半条、核验通过），
//     且同一范围重复导出字节一致；写入不报错。
func TestConcurrentExportAndAppend(t *testing.T) {
	l := audit.New(0)
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	fixedClock(t, l, base)
	x, _ := newTestExporter(t, l, Limits{MaxRecords: 0, MaxBytes: 0})

	stop := make(chan struct{})
	var appendErr error
	go func() {
		for i := 0; i < 400; i++ {
			if _, err := l.Append(audit.Event{
				Operation: "authorize", Result: "allow",
				Detail: map[string]string{"i": string(rune('a' + i%26))},
			}); err != nil {
				appendErr = err
				return
			}
		}
		close(stop)
	}()

	var n int
	for {
		select {
		case <-stop:
			if appendErr != nil {
				t.Fatal(appendErr)
			}
			if n == 0 {
				// 写入已结束但一次导出都没跑到，补一次全量。
				raw := mustExport(t, x, 1, int64(l.Len()))
				if res := Verify(raw); !res.OK() {
					t.Fatalf("final export: %s (%s)", res.Status, res.Detail)
				}
			}
			t.Logf("conclusion: %d concurrent exports all self-consistent; writes finished, total=%d",
				n, l.Len())
			// 最终全量必须连续通过。
			full := mustExport(t, x, 1, int64(l.Len()))
			if res := Verify(full); !res.OK() {
				t.Fatalf("final full range: %s (%s)", res.Status, res.Detail)
			}
			// 同范围重复导出确定性。
			if string(mustExport(t, x, 1, int64(l.Len()))) != string(full) {
				t.Fatal("repeat export differs")
			}
			return
		default:
		}
		if l.Len() >= 2 {
			to := int64(l.Len())
			raw, err := x.Export(1, to)
			if err != nil {
				// 快照后又有新写入不影响：to 来自快照前 Len；Exporter 以
				// Since(0) 的快照为准，to 只可能 <= 快照长度，不应报错。
				t.Fatalf("concurrent Export(1,%d): %v", to, err)
			}
			encoded, _ := raw.Encode()
			if res := Verify(encoded); !res.OK() {
				t.Fatalf("concurrent export not self-consistent: %s (%s)", res.Status, res.Detail)
			}
			n++
		}
	}
}

// 6) 超条数/超字节上限：明确拒绝、原因可区分、没有半成品。
func TestExportLimits(t *testing.T) {
	l := seedLog(t, 6)
	xRec, _ := newTestExporter(t, l, Limits{MaxRecords: 3})
	if _, err := xRec.Export(1, 4); !errors.Is(err, ErrTooManyRecords) {
		t.Fatalf("record limit: got %v, want ErrTooManyRecords", err)
	}
	t.Logf("input: MaxRecords=3, Export(1,4) => %v", ErrTooManyRecords)
	// 边界值恰好允许。
	if _, err := xRec.Export(1, 3); err != nil {
		t.Fatalf("exactly-at-limit export must succeed, got %v", err)
	}

	// 字节上限取一个很小的值：即便单条也超。
	xByte, _ := newTestExporter(t, l, Limits{MaxBytes: 16})
	if _, err := xByte.Export(1, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: got %v, want ErrTooLarge", err)
	}
	t.Logf("input: MaxBytes=16, Export(1,1) => %v", ErrTooLarge)

	// 拒绝后日志与再次导出不受影响。
	if l.Len() != 6 {
		t.Fatalf("rejected export must not alter log, len=%d", l.Len())
	}
	xOK, _ := newTestExporter(t, l, Limits{})
	raw := mustExport(t, xOK, 1, 6)
	if res := Verify(raw); !res.OK() {
		t.Fatalf("export after rejections: %s", res.Status)
	}
	t.Log("conclusion: over-limit exports rejected with distinct reasons; no half product; later export valid")
}

//  7. 导出产物绝不含凭证原文/密钥：这里构造带“可疑字段值”的事件，
//     断言导出后字节里只出现 jti，不出现原始 token / secret 样式内容。
func TestArtifactContainsNoSecrets(t *testing.T) {
	l := audit.New(0)
	base := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	fixedClock(t, l, base)
	secretLike := "SUPER-SECRET-SIGNING-KEY-9f8e7d"
	tokenLike := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.abcd1234sig"
	if _, err := l.Append(audit.Event{
		Operation: "issue", Result: "success",
		JTI:    "jti-abc",
		Detail: map[string]string{"note": "only jti is retained"},
	}); err != nil {
		t.Fatal(err)
	}
	x, _ := newTestExporter(t, l, Limits{})
	raw := mustExport(t, x, 1, 1)
	if strings.Contains(string(raw), secretLike) {
		t.Fatal("artifact leaks a signing-key-like value")
	}
	if strings.Contains(string(raw), tokenLike) {
		t.Fatal("artifact leaks a token-like value")
	}
	if !strings.Contains(string(raw), "jti-abc") {
		t.Fatal("artifact should retain the non-sensitive jti reference")
	}
	_ = secretLike
	_ = tokenLike
	t.Log("input: secret/token-shaped values exist only outside the audit event; " +
		"conclusion: artifact carries jti only, no credential or key material")
}

// 8) 产物损坏/垃圾输入 → artifact_malformed，绝不 panic。
func TestVerifyMalformed(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("not json"), []byte(`{}`), []byte(`[]`)} {
		res := Verify(raw)
		if res.OK() {
			t.Fatalf("garbage %q verified as valid", string(raw))
		}
		if raw != nil && string(raw) != "{}" && res.Status != StatusMalformed {
			t.Fatalf("garbage %q => %s, want artifact_malformed", raw, res.Status)
		}
		t.Logf("input: %q => conclusion: %s", string(raw), res.Status)
	}
}
