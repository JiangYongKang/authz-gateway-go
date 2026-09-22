package store

import (
	"errors"
	"testing"
	"time"
)

func TestLimitsAndFailWriteAtomicity(t *testing.T) {
	s := NewBounded(1, 1, 1, 1, 2)
	if err := s.PutUser(User{Name: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutUser(User{Name: "u2"}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want ErrLimitExceeded, got %v", err)
	}

	// 故障注入必须在任何修改前生效：注入后写失败，状态不变化，且只失败一次。
	s.SetFailNext(1)
	if err := s.PutResource(Resource{Name: "r1"}); !errors.Is(err, ErrStorageFault) {
		t.Fatalf("want ErrStorageFault, got %v", err)
	}
	if err := s.PutResource(Resource{Name: "r1"}); err != nil {
		t.Fatalf("fault must be consumed once, then writes recover: %v", err)
	}
	if _, err := s.GetResource("r1"); err != nil {
		t.Fatalf("successful write after transient fault must persist, got %v", err)
	}
	t.Logf("input: bounded store + injected fault; decision basis: limits reject, fault has no partial write")
}

func TestSessionCASAndRevoke(t *testing.T) {
	s := New()
	now := time.Unix(100, 0)
	if err := s.CreateSession(Session{ID: "s1", Username: "alice", CurrentJTI: "j1", CredVersion: 1, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// 错误预期版本 => 冲突，状态不变。
	if err := s.RenewSessionCAS("s1", "j1", 99, "j2", now.Add(2*time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version must conflict, got %v", err)
	}
	if err := s.RenewSessionCAS("s1", "j1", 1, "j2", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("valid CAS must succeed: %v", err)
	}
	got, _ := s.GetSession("s1")
	if got.CurrentJTI != "j2" || got.CredVersion != 2 {
		t.Fatalf("CAS update mismatch: %+v", got)
	}
	// 撤销后续期一律冲突。
	if err := s.RevokeSession("s1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewSessionCAS("s1", "j2", 2, "j3", now.Add(3*time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("renew after revoke must conflict, got %v", err)
	}
	v1, v2 := s.AuthzVersion(), s.AuthzVersion()
	if v1 != v2 {
		t.Fatal("authz version must be stable without writes")
	}
	t.Logf("input: CAS renew/revoke; decision basis: stale=conflict, revoke bumps version=%d", v2)
}

func TestRotationStateMachine(t *testing.T) {
	s := New()
	if err := s.PutKeySecret("k1", []byte("a"), KeyActive); err != nil {
		t.Fatal(err)
	}
	if err := s.PutKeySecret("k2", []byte("b"), KeyNext); err != nil {
		t.Fatal(err)
	}
	kid, sec, err := s.ActiveSigningKey()
	if err != nil || kid != "k1" || string(sec) != "a" {
		t.Fatalf("active key before rotation wrong: %s %v %v", kid, sec, err)
	}
	if _, err := s.RotateKeys("k2"); err != nil {
		t.Fatal(err)
	}
	kid, _, err = s.ActiveSigningKey()
	if err != nil || kid != "k2" {
		t.Fatalf("active after rotation must be k2, got %s %v", kid, err)
	}
	// k1 仍可验签（retired 状态但密钥仍可取）。
	if _, state, err := s.GetKeySecret("k1"); err != nil || state != KeyRetired {
		t.Fatalf("old key must remain verifiable as retired, got state=%d err=%v", state, err)
	}
	// 再次轮换 k2（已经是 active）必须冲突。
	if _, err := s.RotateKeys("k2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-rotating active key must conflict, got %v", err)
	}
	t.Logf("input: rotate k1(active)+k2(next); basis: k2 signs, k1 retired but verifiable")
}

func TestSnapshotsAreDefensiveCopies(t *testing.T) {
	s := New()
	_ = s.PutUser(User{Name: "u", Roles: []string{"r"}, Attributes: map[string]string{"k": "v"}})
	u, _ := s.GetUser("u")
	u.Roles[0] = "tampered"
	u.Attributes["k"] = "tampered"
	u2, _ := s.GetUser("u")
	if u2.Roles[0] != "r" || u2.Attributes["k"] != "v" {
		t.Fatal("mutating returned snapshot must not affect store")
	}
}
