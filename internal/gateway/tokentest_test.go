package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/highcumontoa/authz-gateway-go/internal/token"
)

var testB64 = base64.RawURLEncoding

// resignClaims 解析原凭证（不验签），用新的 kid/secret/issuer 重签，
// 用于构造“签名密钥不匹配 / 签发者不符”的攻击样本。
func resignClaims(t *testing.T, raw, newKid string, newSecret []byte, issuerOverride string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token shape")
	}
	var c token.Claims
	payload, err := testB64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if issuerOverride != "" {
		c.Issuer = issuerOverride
	}
	h := token.Header{Alg: "HS256", Kid: newKid, Typ: "JWT"}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(c)
	hEnc := testB64.EncodeToString(hb)
	cEnc := testB64.EncodeToString(cb)
	mac := hmac.New(sha256.New, newSecret)
	mac.Write([]byte(hEnc + "." + cEnc))
	sig := testB64.EncodeToString(mac.Sum(nil))
	return hEnc + "." + cEnc + "." + sig
}

func kidOfToken(t *testing.T, raw string) string {
	t.Helper()
	h, err := token.PeekHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h.Kid
}
