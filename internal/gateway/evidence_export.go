package gateway

import (
	"encoding/base64"
	"errors"

	"github.com/highcumontoa/authz-gateway-go/internal/evidence"
)

// EvidenceKeyInfo 对外暴露导出证据签名密钥的元数据（绝不包含私钥/种子）。
type EvidenceKeyInfo struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// ExportAuditEvidence 导出 ID 闭区间 [from,to] 的自包含审计证据产物。
//
// 拒绝原因均可区分：范围非法 → export_invalid_range；范围超出已提交记录 →
// export_range_unavailable；条数超限 → export_too_many_records；
// 产物过大 → export_too_large。任何拒绝都不返回半成品。
func (g *Gateway) ExportAuditEvidence(from, to int64) (*evidence.Artifact, error) {
	a, err := g.exporter.Export(from, to)
	if err != nil {
		return nil, mapEvidenceError(err)
	}
	return a, nil
}

// EvidencePublicKey 返回导出签名公钥信息，供外部核验方建立信任锚。
func (g *Gateway) EvidencePublicKey() (EvidenceKeyInfo, error) {
	if g.evKey == nil {
		return EvidenceKeyInfo{}, errAudit()
	}
	return EvidenceKeyInfo{
		KeyID:     g.evKey.KeyID(),
		Algorithm: evidence.AlgEd25519,
		PublicKey: base64.RawURLEncoding.EncodeToString(g.evKey.PublicKey()),
	}, nil
}

func mapEvidenceError(err error) error {
	switch {
	case errors.Is(err, evidence.ErrInvalidRange):
		return newGWError("bad request", ReasonExportInvalidRange)
	case errors.Is(err, evidence.ErrRangeUnavailable):
		return newGWError("denied", ReasonExportUnavailable)
	case errors.Is(err, evidence.ErrTooManyRecords):
		return newGWError("denied", ReasonExportTooMany)
	case errors.Is(err, evidence.ErrTooLarge):
		return newGWError("denied", ReasonExportTooLarge)
	default:
		return errAudit()
	}
}
