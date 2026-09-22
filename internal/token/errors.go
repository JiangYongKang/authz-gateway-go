package token

import "errors"

// 凭证校验失败的可区分原因。任何异常路径都返回这些错误，绝不放行。
var (
	ErrMalformed      = errors.New("token malformed")
	ErrBadSignature   = errors.New("token signature does not match")
	ErrUnknownKey     = errors.New("token key id unknown or retired from signing")
	ErrIssuerMismatch = errors.New("token issuer does not match expected issuer")
	ErrExpired        = errors.New("token expired")
	ErrNotValidYet    = errors.New("token not valid yet")
)
