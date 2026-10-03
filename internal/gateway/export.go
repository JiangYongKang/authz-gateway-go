package gateway

import (
	"errors"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
)

// 审计证据导出的可区分拒绝原因码。
const (
	ReasonExportRangeInvalid = "export_range_invalid"  // 范围本身不合法（from<1、to<from、超出已记录序号）
	ReasonExportLimit        = "export_limit_exceeded" // 范围超过单次导出条数上限
)

// ExportAudit 导出 [from, to] 闭区间的审计证据（自包含、可离线核验）。
// 失败时返回可区分错误：audit.ErrExportRange / audit.ErrExportLimit，
// 不产生任何半成品产物。
func (g *Gateway) ExportAudit(from, to int64) (audit.Evidence, error) {
	return g.aud.Export(from, to, g.cfg.MaxExport)
}

// ExportReasonOf 把导出错误映射为统一原因码。
func ExportReasonOf(err error) string {
	switch {
	case errors.Is(err, audit.ErrExportRange):
		return ReasonExportRangeInvalid
	case errors.Is(err, audit.ErrExportLimit):
		return ReasonExportLimit
	default:
		return ReasonAuditFailure
	}
}
