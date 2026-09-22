package token

import (
	"strings"
	"testing"
	"time"
)

// 测试用密钥集：kid-1 为主密钥，kid-old 为历史密钥。
func testKeys(kid string) ([]byte, bool) {
	switch kid {
	case "kid-1":
		return []byte("secret-one-32bytes-padded-ok!!"), true
	case "kid-old":
		return []byte("secret-old-32bytes-padded-ok!!!!"), true
	default:
		return nil, false
	}
}

func sampleClaims(now time.Time) *Claims {
	return &Claims{
		Issuer:    "https://issuer.local",
		Subject:   "user-1",
		SessionID: "sess-1",
		TokenID:   "jti-1",
		TokenType: TypeAccess,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Roles:     []string{"reader"},
	}
}

func logCase(t *testing.T, name string, input string, want Reason, got Reason) {
	t.Helper()
	preview := input
	if len(preview) > 48 {
		preview = preview[:48] + "...(截断)"
	}
	t.Logf("用例=%s 输入=%q 期望原因=%q 实际原因=%q", name, preview, want, got)
}

func TestVerify_HappyPath(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	raw, err := Sign(sampleClaims(now), "kid-1", []byte("secret-one-32bytes-padded-ok!!"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, reason := Verify(raw, "https://issuer.local", now.Add(time.Minute), testKeys)
	logCase(t, "合法凭证", raw, ReasonOK, reason)
	if reason != ReasonOK {
		t.Fatalf("期望 ok, 得到 %s", reason)
	}
	if got.Subject != "user-1" {
		t.Fatalf("subject 解析错误: %s", got.Subject)
	}
}

func TestVerify_Rejections(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	valid, _ := Sign(sampleClaims(now), "kid-1", []byte("secret-one-32bytes-padded-ok!!"))

	cases := []struct {
		name   string
		tamper func(string) string
		issuer string
		at     time.Time
		keyfn  KeyFunc
		want   Reason
	}{
		{
			name: "过期凭证", at: now.Add(2 * time.Hour), issuer: "https://issuer.local",
			keyfn: testKeys, want: ReasonExpired,
		},
		{
			name: "签发者不符", at: now.Add(time.Minute), issuer: "https://other.issuer",
			keyfn: testKeys, want: ReasonIssuerMismatch,
		},
		{
			name: "签名密钥不匹配(另一把密钥验签)", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn: func(kid string) ([]byte, bool) {
				if kid == "kid-1" {
					return []byte("a-totally-different-wrong-secret"), true
				}
				return nil, false
			}, want: ReasonBadSignature,
		},
		{
			name: "凭证被篡改(翻转载荷字符)", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn: testKeys,
			tamper: func(raw string) string {
				parts := strings.Split(raw, ".")
				p := []byte(parts[1])
				if p[0] == 'A' {
					p[0] = 'B'
				} else {
					p[0] = 'A'
				}
				parts[1] = string(p)
				return strings.Join(parts, ".")
			}, want: ReasonBadSignature,
		},
		{
			name: "kid 未知(密钥已彻底删除)", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn: func(kid string) ([]byte, bool) { return nil, false }, want: ReasonUnknownKey,
		},
		{
			name: "结构损坏(两段式)", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn: testKeys,
			tamper: func(raw string) string {
				parts := strings.Split(raw, ".")
				return parts[0] + "." + parts[1]
			}, want: ReasonMalformed,
		},
		{
			name: "算法混淆(none)", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn: testKeys,
			tamper: func(raw string) string {
				parts := strings.Split(raw, ".")
				parts[0] = "eyJhbGciOiJub25lIiwia2lkIjoia2lkLTEiLCJ0eXAiOiJKV1QifQ"
				return strings.Join(parts, ".")
			}, want: ReasonUnsupportedAlg,
		},
		{
			name: "空字符串", at: now.Add(time.Minute), issuer: "https://issuer.local",
			keyfn:  testKeys,
			tamper: func(string) string { return "" }, want: ReasonMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := valid
			if tc.tamper != nil {
				raw = tc.tamper(raw)
			}
			_, reason := Verify(raw, tc.issuer, tc.at, tc.keyfn)
			logCase(t, tc.name, raw, tc.want, reason)
			if reason != tc.want {
				t.Fatalf("%s: 期望 %s, 得到 %s", tc.name, tc.want, reason)
			}
		})
	}
}

func TestVerify_HistoricalKeyStillVerifies(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	// 用旧密钥签发的凭证，轮换后旧密钥仍可验证（在有效期内）。
	raw, _ := Sign(sampleClaims(now), "kid-old", []byte("secret-old-32bytes-padded-ok!!!!"))
	_, reason := Verify(raw, "https://issuer.local", now.Add(time.Minute), testKeys)
	logCase(t, "历史密钥验证存量凭证", raw, ReasonOK, reason)
	if reason != ReasonOK {
		t.Fatalf("历史密钥应仍可验证, 得到 %s", reason)
	}
}

func TestSign_RejectsBadInputs(t *testing.T) {
	now := time.Now()
	if _, err := Sign(nil, "k", []byte("x")); err == nil {
		t.Fatal("nil claims 必须报错")
	}
	c := sampleClaims(now)
	if _, err := Sign(c, "", []byte("x")); err == nil {
		t.Fatal("空 kid 必须报错")
	}
	if _, err := Sign(c, "k", nil); err == nil {
		t.Fatal("空密钥必须报错")
	}
	bad := sampleClaims(now)
	bad.ExpiresAt = bad.IssuedAt
	if _, err := Sign(bad, "k", []byte("x")); err == nil {
		t.Fatal("exp<=iat 必须报错")
	}
}
