// Package token 实现基于 HMAC-SHA256 的 JWT 风格凭证的签发、解析与校验。
//
// 凭证形态为 compact-serialized JWT：base64url(header).base64url(claims).signature。
// 任何校验异常都返回明确的哨兵错误，调用方必须据此拒绝请求，不得放行。
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	algHS256 = "HS256"
	typJWT   = "JWT"
)

// Header 描述凭证的签名算法与密钥编号。
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Claims 是凭证中与授权相关的声明集合。
type Claims struct {
	Issuer     string            `json:"iss"`
	Subject    string            `json:"sub"`
	Audience   string            `json:"aud,omitempty"`
	IssuedAt   int64             `json:"iat"`
	Expires    int64             `json:"exp"`
	NotBefore  int64             `json:"nbf,omitempty"`
	JTI        string            `json:"jti"`
	SessionID  string            `json:"sid"`
	Attributes map[string]string `json:"attr,omitempty"`
}

// Signer 使用一个带 kid 的 HMAC 密钥签发凭证。
type Signer struct {
	kid    string
	secret []byte
	issuer string
}

// NewSigner 构造一个绑定密钥编号与签发者的签名器。
func NewSigner(kid string, secret []byte, issuer string) *Signer {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Signer{kid: kid, secret: cp, issuer: issuer}
}

var b64 = base64.RawURLEncoding

func encodeJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(raw), nil
}

func decodeJSON(s string, v any) error {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return ErrMalformed
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return ErrMalformed
	}
	return nil
}

func (s *Signer) sign(hEnc, pEnc string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(hEnc + "." + pEnc))
	return b64.EncodeToString(mac.Sum(nil))
}

// Sign 使用当前密钥签发凭证，返回紧凑序列化字符串。
// 凭证的签发者以签名器绑定的 issuer 为准。
func (s *Signer) Sign(c Claims) (string, error) {
	if s == nil || len(s.secret) == 0 || s.kid == "" {
		return "", errors.New("token: signer not initialized")
	}
	if s.issuer != "" {
		c.Issuer = s.issuer
	}
	h := Header{Alg: algHS256, Kid: s.kid, Typ: typJWT}
	hEnc, err := encodeJSON(h)
	if err != nil {
		return "", err
	}
	pEnc, err := encodeJSON(c)
	if err != nil {
		return "", err
	}
	sig := s.sign(hEnc, pEnc)
	return hEnc + "." + pEnc + "." + sig, nil
}

// splitParts 拆分并在结构非法时返回 ErrMalformed。
func splitParts(raw string) (string, string, string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", ErrMalformed
	}
	return parts[0], parts[1], parts[2], nil
}

// PeekHeader 在不验签的情况下读取 header，用于按 kid 选择验签密钥。
func PeekHeader(raw string) (Header, error) {
	hEnc, _, _, err := splitParts(raw)
	if err != nil {
		return Header{}, err
	}
	var h Header
	if err := decodeJSON(hEnc, &h); err != nil {
		return Header{}, err
	}
	if h.Alg != algHS256 {
		// 只接受本服务签发的 HS256 凭证，alg 混淆（如 alg=none）一律拒绝。
		return Header{}, ErrBadSignature
	}
	return h, nil
}

// verifySignature 使用给定密钥常量时间比对签名，并校验 kid 一致。
func verifySignature(raw, kid string, secret []byte) (Header, Claims, error) {
	hEnc, pEnc, sig, err := splitParts(raw)
	if err != nil {
		return Header{}, Claims{}, err
	}
	var h Header
	if err := decodeJSON(hEnc, &h); err != nil {
		return Header{}, Claims{}, err
	}
	if h.Alg != algHS256 || h.Typ != typJWT {
		return Header{}, Claims{}, ErrBadSignature
	}
	if h.Kid != kid {
		return Header{}, Claims{}, ErrUnknownKey
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(hEnc + "." + pEnc))
	expected := b64.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return Header{}, Claims{}, ErrBadSignature
	}
	var c Claims
	if err := decodeJSON(pEnc, &c); err != nil {
		return Header{}, Claims{}, ErrMalformed
	}
	return h, c, nil
}

// Verify 使用给定密钥验证签名与时间窗（过期/尚未生效）。
// issuer 非空时还会校验签发者一致。now 为判定基准时间。
//
// 返回错误为包内哨兵错误之一，调用方必须映射为拒绝原因，不得放行。
func Verify(raw string, kid string, secret []byte, issuer string, now time.Time) (Claims, error) {
	if len(secret) == 0 {
		return Claims{}, ErrUnknownKey
	}
	_, c, err := verifySignature(raw, kid, secret)
	if err != nil {
		return Claims{}, err
	}
	if issuer != "" && c.Issuer != issuer {
		return Claims{}, ErrIssuerMismatch
	}
	if c.NotBefore > 0 && now.Before(time.Unix(c.NotBefore, 0)) {
		return Claims{}, ErrNotValidYet
	}
	if c.Expires > 0 && !now.Before(time.Unix(c.Expires, 0)) {
		return Claims{}, ErrExpired
	}
	if c.JTI == "" || c.SessionID == "" || c.Subject == "" {
		return Claims{}, ErrMalformed
	}
	return c, nil
}
