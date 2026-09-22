package gateway

import (
	"errors"
)

// gateway 对调用方暴露的错误类别。HTTP 层据此区分 4xx/5xx；
// 错误文本中携带统一原因码，保证不同入口下拒绝原因一致。
type gwError struct{ kind, reason string }

func (e *gwError) Error() string { return e.kind + ": " + e.reason }

func newGWError(kind, reason string) error {
	return &gwError{kind: kind, reason: reason}
}

func errBadRequest() error { return newGWError("bad request", ReasonBadRequest) }
func errDenied() error     { return newGWError("denied", "denied") }
func errAudit() error      { return newGWError("audit unavailable", ReasonAuditFailure) }

// withReason 基于同类错误构造一个携带具体原因码的全新错误，
// 避免复用共享的错误单例而在并发下相互污染原因码。
func withReason(err error, reason string) error {
	if e, ok := err.(*gwError); ok {
		return newGWError(e.kind, reason)
	}
	return err
}

// IsDenied 报告错误链中是否包含一次“被拒绝的请求”（而非服务器故障）。
func IsDenied(err error) bool {
	var e *gwError
	if errors.As(err, &e) {
		return e.kind == "denied"
	}
	return false
}

// ReasonOf 返回错误链携带的统一原因码。
func ReasonOf(err error) string {
	var e *gwError
	if errors.As(err, &e) {
		return e.reason
	}
	return ReasonStorageFault
}

func mapWrappedStoreError(err error) error {
	if err == nil {
		return nil
	}
	return &gwError{kind: "storage", reason: mapStoreError(err)}
}
