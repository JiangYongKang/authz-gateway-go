package audit

import (
	"errors"
	"strings"
	"testing"
)

func TestAppendAndVerifyChain(t *testing.T) {
	log := New(100)
	for i := 0; i < 5; i++ {
		e, err := log.Append(AppendInput{
			Actor: "u1", Action: "authorize", Resource: "doc",
			Decision: DecisionAllow, Reason: "ok",
			Detail: map[string]string{"i": string(rune('0' + i))},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		t.Logf("写入 seq=%d hash=%s prev=%s", e.Seq, e.Hash[:12], e.PrevHash[:min(12, len(e.PrevHash))])
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("完整链校验失败: %v", err)
	}
	entries := log.Entries()

	// 改写一条历史记录 => Verify 必须发现。
	entries[2].Reason = "tampered"
	if chainVerify(entries) == nil {
		t.Fatal("篡改历史记录后哈希链应校验失败")
	}
	// 直接对内部链外副本篡改不影响真实链（确认 Entries 返回的是拷贝）。
	if err := log.Verify(); err != nil {
		t.Fatalf("外部拷贝改写不应影响内部链: %v", err)
	}
}

func chainVerify(es []*Entry) error {
	var prev string
	for _, e := range es {
		if e.PrevHash != prev {
			return errors.New("prev mismatch")
		}
		h, err := computeHash(e)
		if err != nil || h != e.Hash {
			return errors.New("hash mismatch")
		}
		prev = h
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestSensitiveRedaction(t *testing.T) {
	raw := map[string]string{
		"token":         "eyJhbGciOi.IkpXVCJ9.sig-part",
		"Authorization": "Bearer eyJhbGciOi.IkpbCj9.sig-part",
		"key_secret":    "super-secret-bytes",
		"action":        "read",
		"reason":        "ok",
	}
	out := Sanitize(raw)
	for k, v := range out {
		t.Logf("脱敏: %s = %q", k, v)
	}
	if out["token"] != Redacted || out["Authorization"] != Redacted || out["key_secret"] != Redacted {
		t.Fatal("敏感字段必须脱敏")
	}
	if out["action"] != "read" || out["reason"] != "ok" {
		t.Fatal("普通字段不得被脱敏")
	}
	// 通过 Append 写入时同样脱敏
	log := New(10)
	e, err := log.Append(AppendInput{
		Actor: "u", Action: "login", Decision: DecisionAllow,
		Detail: map[string]string{"refresh_token": "eyJhbGciOi.IkpbCj9.sig", "normal": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Detail["refresh_token"] != Redacted {
		t.Fatalf("审计落盘的 refresh_token 必须脱敏, 得到 %q", e.Detail["refresh_token"])
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{e.Detail["refresh_token"]}, "")), "ey") {
		t.Fatal("凭证片段不得出现在审计中")
	}
}

func TestCapacityRejectsWithoutPartialWrite(t *testing.T) {
	log := New(2)
	if _, err := log.Append(AppendInput{Actor: "a", Action: "x", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(AppendInput{Actor: "a", Action: "x", Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	_, err := log.Append(AppendInput{Actor: "a", Action: "x", Decision: DecisionAllow})
	if !errors.Is(err, ErrLogFull) {
		t.Fatalf("超限应返回 ErrLogFull, 得到 %v", err)
	}
	if log.Len() != 2 {
		t.Fatalf("拒绝写入后不得产生半写入, len=%d", log.Len())
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("容量拒绝后链仍须完整: %v", err)
	}
}

func TestInvalidDecisionRejected(t *testing.T) {
	log := New(10)
	if _, err := log.Append(AppendInput{Actor: "a", Action: "x", Decision: "maybe"}); err == nil {
		t.Fatal("非法 decision 必须被拒绝")
	}
}
