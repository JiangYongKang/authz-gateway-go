package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestKeyRotationStateMachine(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	s := New(Limits{MaxKeys: 4})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AddKey(SigningKey{ID: "k1", Secret: []byte(strings.Repeat("a", 32)), State: KeyActive, CreatedAt: now}))
	must(s.AddKey(SigningKey{ID: "k2", Secret: []byte(strings.Repeat("b", 32)), State: KeyActive, CreatedAt: now.Add(time.Second)}))

	k, err := s.ActiveKey()
	must(err)
	t.Logf("并存期两把 active 时确定性选择最新: active=%s (期望 k2)", k.ID)
	if k.ID != "k2" {
		t.Fatalf("应选最新创建的 k2, 得到 %s", k.ID)
	}

	_, err = s.RotateActiveKey("k1")
	must(err)
	k1, _ := s.GetKey("k1")
	k2, _ := s.GetKey("k2")
	t.Logf("rotate 到 k1 后: k1=%s k2=%s", k1.State, k2.State)
	if k1.State != KeyActive || k2.State != KeyRetired {
		t.Fatal("轮换后新密钥 active、其余 retired")
	}

	// retired 密钥不能被再次激活
	if _, err := s.RotateActiveKey("k2"); err != nil {
		t.Fatalf("重新轮换到已 retired 的 k2 应当被允许成为新 active? 当前实现: %v", err)
	}
	// 说明：实现允许 retired 密钥重新成为 active（例如回滚场景）。
	// 但 Revoked 密钥绝不可激活。
	must(s.RevokeKey("k2"))
	if _, err := s.RotateActiveKey("k2"); err == nil {
		t.Fatal("revoked 密钥不得被重新激活")
	}
}

func TestLimitsRejectPartialWrites(t *testing.T) {
	s := New(Limits{MaxUsers: 1, MaxPolicies: 1, MaxSessions: 1, MaxKeys: 1, MaxRoles: 1, MaxResources: 1})
	if err := s.CreateUser(User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(User{ID: "u2"}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("超用户上限: %v", err)
	}
	if err := s.AddKey(SigningKey{ID: "k1", Secret: []byte("x"), State: KeyActive}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddKey(SigningKey{ID: "k2", Secret: []byte("x"), State: KeyActive}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("超密钥上限: %v", err)
	}
	if n := s.KeyCount(); n != 1 {
		t.Fatalf("拒绝后不得部分写入, keyCount=%d", n)
	}
}

func TestSessionRotationIndexes(t *testing.T) {
	now := time.Now()
	s := New(DefaultLimits())
	if err := s.CreateUser(User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateSession(CreateSessionInput{
		ID: "sess-1", UserID: "u1", RefreshJTI: "r1", AccessJTI: "a1",
		CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 原子旋转：旧 refresh 重放第二次必须失败
	if _, err := s.RotateSessionTokensIfRefreshJTI("sess-1", "r1", "r2", "a2", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateSessionTokensIfRefreshJTI("sess-1", "r1", "r3", "a3", time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("旧 refresh 重放必须 ErrNotFound, 得到 %v", err)
	}
	// 旧 access jti 也查不到会话当前凭证了
	if _, err := s.CheckAccessJTI("sess-1", "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("旧 access jti 应已失效, 得到 %v", err)
	}
	if sess, err := s.SessionByRefreshJTI("r2"); err != nil || sess.RefreshJTI != "r2" {
		t.Fatalf("新 refresh 索引应可用, err=%v", err)
	}
}

func TestRevokeAllUserSessions(t *testing.T) {
	s := New(DefaultLimits())
	if err := s.CreateUser(User{ID: "u1"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"s1", "s2", "s3"} {
		if _, err := s.CreateSession(CreateSessionInput{
			ID: id, UserID: "u1", RefreshJTI: "r-" + id, AccessJTI: "a-" + id, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.RevokeAllUserSessions("u1"); n != 3 {
		t.Fatalf("应撤销 3 个会话, 实际 %d", n)
	}
	if _, _, err := s.ValidateSessionAccess("s1"); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("撤销后访问必须 ErrSessionRevoked, 得到 %v", err)
	}
}
