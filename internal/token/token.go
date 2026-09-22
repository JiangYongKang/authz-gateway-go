// Package token 提供基于 HMAC-SHA256 的紧凑身份凭证的签发与校验原语。
//
// 凭证格式为 base64url(header).base64url(payload).base64url(signature)，
// 类似 JWT 的三段式结构，但本包不依赖任何第三方实现。
//
// 安全约定：任何异常路径都返回明确的、可区分的拒绝原因(Reason)，
// 调用方必须在 Reason != ReasonOK 时拒绝，绝不允许降级放行。
package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Alg 是本包支持的唯一签名算法。
const Alg = "HS256"

// Reason 是凭证被接受或拒绝的可区分原因。
type Reason string

const (
	ReasonOK             Reason = "ok"               // 凭证合法
	ReasonMalformed      Reason = "malformed_token"  // 结构/编码/字段不合法或被篡改导致无法解析
	ReasonUnsupportedAlg Reason = "unsupported_alg"  // 头部声明了非 HS256 的算法（拒绝算法混淆）
	ReasonUnknownKey     Reason = "unknown_key"      // kid 在已知密钥集合中不存在（含密钥被彻底删除）
	ReasonBadSignature   Reason = "bad_signature"    // 签名不匹配：被篡改或签名密钥不一致
	ReasonIssuerMismatch Reason = "issuer_mismatch"  // 签发者(iss)与预期不符
	ReasonNotYetValid    Reason = "not_before_valid" // 尚未到达生效时间(nbf)
	ReasonExpired        Reason = "expired"          // 已超过过期时间(exp)
)

// Error 让 Reason 同时满足 error 接口，便于上层包装。
func (r Reason) Error() string { return string(r) }

// Type 表示凭证用途，访问凭证与续期凭证严格区分，不可互换使用。
type Type string

const (
	TypeAccess  Type = "access"
	TypeRefresh Type = "refresh"
)

// Claims 是凭证载荷。Roles 与 Attrs 仅为签发时刻的快照，
// 授权判定必须以存储中的最新角色/属性为准，不得直接信任快照。
type Claims struct {
	Issuer    string            `json:"iss"`
	Subject   string            `json:"sub"`
	SessionID string            `json:"sid"`
	TokenID   string            `json:"jti"`
	KeyID     string            `json:"kid"`
	TokenType Type              `json:"typ"`
	IssuedAt  int64             `json:"iat"` // unix 秒
	NotBefore int64             `json:"nbf,omitempty"`
	ExpiresAt int64             `json:"exp"` // unix 秒
	Roles     []string          `json:"roles,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

var b64 = base64.RawURLEncoding

// NewID 返回 16 字节随机十六进制标识，用于会话/凭证 ID。
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read 在正常环境下不会失败；失败即环境不可信，直接 panic 由上层避免静默降级。
		panic("token: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Sign 使用指定 kid 的 HMAC 密钥对 claims 进行签名并序列化。
// 调用方必须保证 keyID 当前允许签发（轮换退役后的密钥不得传入）。
func Sign(c *Claims, keyID string, secret []byte) (string, error) {
	if c == nil {
		return "", errors.New("token: nil claims")
	}
	if keyID == "" || len(secret) == 0 {
		return "", errors.New("token: missing signing key")
	}
	if c.ExpiresAt <= c.IssuedAt {
		return "", errors.New("token: exp must be after iat")
	}
	c.KeyID = keyID
	h := header{Alg: Alg, Kid: keyID, Typ: "JWT"}
	hb, err := json.Marshal(&h)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// KeyFunc 按 kid 查找密钥；found=false 表示该密钥彻底未知。
// 轮换后的历史密钥仍应由实现返回，以便验证既有凭证。
type KeyFunc func(kid string) (secret []byte, found bool)

// Verify 校验原始凭证字符串。返回的 Reason 标明接受/拒绝的唯一原因，
// 被拒绝时 claims 为 nil。校验顺序固定，保证拒绝原因稳定可解释：
// 结构 -> 算法 -> 密钥存在性 -> 签名 -> 载荷 -> 签发者 -> 生效时间 -> 过期时间。
func Verify(raw string, expectedIssuer string, now time.Time, keyFor KeyFunc) (*Claims, Reason) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ReasonMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ReasonMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ReasonMalformed
	}
	if h.Alg != Alg {
		return nil, ReasonUnsupportedAlg
	}
	if h.Kid == "" {
		return nil, ReasonMalformed
	}
	secret, found := keyFor(h.Kid)
	if !found {
		return nil, ReasonUnknownKey
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ReasonMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, ReasonBadSignature
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ReasonMalformed
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return nil, ReasonMalformed
	}
	// 头部 kid 与载荷 kid 不一致同样视为篡改。
	if c.KeyID != "" && c.KeyID != h.Kid {
		return nil, ReasonBadSignature
	}
	if c.Subject == "" || c.SessionID == "" || c.TokenID == "" {
		return nil, ReasonMalformed
	}
	if c.Issuer != expectedIssuer {
		return nil, ReasonIssuerMismatch
	}
	nowU := now.Unix()
	if c.NotBefore != 0 && nowU < c.NotBefore {
		return nil, ReasonNotYetValid
	}
	if nowU >= c.ExpiresAt {
		return nil, ReasonExpired
	}
	return &c, ReasonOK
}

// DecodePayloadOnly 仅供审计/诊断在不验签的情况下读取元信息，
// 绝不能用于任何安全决策；签名段会被忽略。
func DecodePayloadOnly(raw string) (*Claims, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return nil, false
	}
	return &c, true
}

// EqualString 供外部需要常量时间比较时复用。
func EqualString(a, b []byte) bool { return bytes.Equal(a, b) }
