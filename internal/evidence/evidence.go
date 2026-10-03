// Package evidence 提供审计证据的导出与离线核验能力。
//
// 导出产物（Artifact）是一份自包含的 JSON 文档：包含指定 ID 范围内的审计
// 记录、逐条 SHA-256 哈希链、范围边界锚点以及导出方的 Ed25519 签名与公钥。
// 持有该文件的独立一方（另一个进程、外部工具）在没有任何服务访问权限的
// 情况下，仅用标准库即可核验记录是否完整连续、是否缺号/重排/重复、是否被
// 事后改写，以及产物声明的范围本身是否合法。
//
// 安全边界：核验只能保证“产物内容与导出方签名一致且链完整”；拿到导出方
// 私钥的人可以伪造任意产物，私钥永不进入产物（产物只携带公钥）。
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
)

const (
	// FormatVersion 是导出产物格式的当前版本。
	FormatVersion = 1
	// AlgEd25519 标识导出方签名算法。
	AlgEd25519 = "Ed25519"
	// ChainSHA256 标识逐条哈希链算法。
	ChainSHA256 = "SHA-256"

	timeLayout = time.RFC3339Nano
)

var b64 = base64.RawURLEncoding

// 核验结论状态（互相可区分，绝不笼统报失败）。
const (
	StatusValid             = "valid"                  // 完整连续且未被改写
	StatusMalformed         = "artifact_malformed"     // 产物无法解析或结构非法
	StatusInvalidRange      = "invalid_range"          // 声明的范围本身不合法
	StatusGap               = "missing_records"        // 中间缺号
	StatusReordered         = "reordered_or_dup"       // 顺序被重排或序号重复
	StatusTampered          = "content_tampered"       // 某条内容被事后改写
	StatusRootMismatch      = "root_mismatch"          // 链根与声明不一致
	StatusBadSignature      = "bad_evidence_signature" // 导出方签名不通过
	StatusUnsupportedKeyAlg = "unsupported_key_alg"    // 不支持的算法/版本
)

// 导出阶段可区分的拒绝原因。
var (
	// ErrInvalidRange 范围不合法（起点<=0 或 起>止）。
	ErrInvalidRange = errors.New("evidence: invalid export range")
	// ErrRangeUnavailable 范围终止点超出当前已提交记录。
	ErrRangeUnavailable = errors.New("evidence: range beyond committed records")
	// ErrTooManyRecords 导出条数超过配置上限。
	ErrTooManyRecords = errors.New("evidence: export record limit exceeded")
	// ErrTooLarge 导出产物字节数超过配置上限。
	ErrTooLarge = errors.New("evidence: export size limit exceeded")
	// ErrExporterNotInitialized 导出器未配置签名密钥。
	ErrExporterNotInitialized = errors.New("evidence: exporter not initialized")
)

// recordCore 是参与哈希计算的记录内容（不含 hash 字段本身）。
// 字段声明顺序即规范化 JSON 的字段顺序，变更顺序会导致旧产物无法核验。
type recordCore struct {
	ID        int64             `json:"id"`
	Time      string            `json:"time"`
	Actor     string            `json:"actor"`
	Operation string            `json:"operation"`
	Result    string            `json:"result"`
	Reason    string            `json:"reason"`
	JTI       string            `json:"jti,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Action    string            `json:"action,omitempty"`
	Matched   string            `json:"matched,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
}

// Record 是产物中一条审计记录：内容 + 链哈希。
type Record struct {
	recordCore
	Hash string `json:"hash"`
}

// signedBody 是导出方签名覆盖的范围与链根摘要。
type signedBody struct {
	FormatVersion int    `json:"format_version"`
	ChainAlg      string `json:"chain_alg"`
	SigAlg        string `json:"sig_alg"`
	KeyID         string `json:"key_id"`
	RangeFrom     int64  `json:"range_from"`
	RangeTo       int64  `json:"range_to"`
	AnchorHash    string `json:"anchor_hash"`
	RootHash      string `json:"root_hash"`
}

// Artifact 是自包含的审计证据产物。
type Artifact struct {
	FormatVersion int      `json:"format_version"`
	ChainAlg      string   `json:"chain_alg"`
	SigAlg        string   `json:"sig_alg"`
	KeyID         string   `json:"key_id"`
	RangeFrom     int64    `json:"range_from"`
	RangeTo       int64    `json:"range_to"`
	AnchorHash    string   `json:"anchor_hash"`
	RootHash      string   `json:"root_hash"`
	Records       []Record `json:"records"`
	PublicKey     string   `json:"public_key"`
	Signature     string   `json:"signature"`
}

// Result 是离线核验的结构化结论。
type Result struct {
	Status string
	Detail string
	// 以下字段在对应异常场景下填充，便于定位问题；不适用时为零值。
	AtID   int64  // 出问题的记录序号
	WantID int64  // 期望序号（缺号时）
	GotID  int64  // 实际序号（缺号/重排时）
	KeyID  string // 产物声明的签名密钥编号
}

// OK 报告核验是否通过（完整连续且未被改写）。
func (r Result) OK() bool { return r.Status == StatusValid }

func (r Result) Error() string {
	if r.Detail != "" {
		return r.Status + ": " + r.Detail
	}
	return r.Status
}

// ExportKey 是导出签名密钥（Ed25519）。私钥/种子只存在于服务端，
// 绝不写入产物；产物只携带公钥。
type ExportKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

// NewExportKey 生成一把随机导出签名密钥。
func NewExportKey() (*ExportKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("evidence: generate export key: %w", err)
	}
	return &ExportKey{priv: priv, pub: pub, id: keyIDOf(pub)}, nil
}

// ExportKeyFromSeed 从 32 字节种子确定性地构造密钥（运维注入用）。
func ExportKeyFromSeed(seed []byte) (*ExportKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("evidence: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(append([]byte(nil), seed...))
	pub := priv.Public().(ed25519.PublicKey)
	return &ExportKey{priv: priv, pub: pub, id: keyIDOf(pub)}, nil
}

func keyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// KeyID 返回密钥编号（公钥的 SHA-256 十六进制）。
func (k *ExportKey) KeyID() string { return k.id }

// PublicKey 返回公钥副本。
func (k *ExportKey) PublicKey() []byte { return append([]byte(nil), k.pub...) }

// Seed 返回私钥种子副本（仅供受控的装配层使用）。
func (k *ExportKey) Seed() []byte { return append([]byte(nil), k.priv.Seed()...) }

// Limits 约束单次导出的规模；零值字段表示不限。
type Limits struct {
	MaxRecords int // 单次导出允许的最大记录条数
	MaxBytes   int // 单次导出产物允许的最大字节数
}

// Exporter 从审计日志导出可离线核验的证据产物。
type Exporter struct {
	log    *audit.Log
	key    *ExportKey
	limits Limits
}

// NewExporter 构造导出器。
func NewExporter(log *audit.Log, key *ExportKey, limits Limits) *Exporter {
	return &Exporter{log: log, key: key, limits: limits}
}

// chainHash 计算单条记录的链哈希：H(prevHex || "." || 规范化JSON(内容))。
// prev 为空串表示这是日志首条记录。
func chainHash(prev string, core recordCore) (string, error) {
	raw, err := json.Marshal(core)
	if err != nil {
		return "", fmt.Errorf("evidence: canonicalize record %d: %w", core.ID, err)
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'.'})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func coreFromEvent(e audit.Event) recordCore {
	c := recordCore{
		ID:        e.ID,
		Time:      e.Time.UTC().Format(timeLayout),
		Actor:     e.Actor,
		Operation: e.Operation,
		Result:    e.Result,
		Reason:    e.Reason,
		JTI:       e.JTI,
		SessionID: e.SessionID,
		Subject:   e.Subject,
		Resource:  e.Resource,
		Action:    e.Action,
		Matched:   e.Matched,
	}
	if len(e.Detail) > 0 {
		// 防御性拷贝：产物数据与调用方、日志快照完全隔离。
		c.Detail = make(map[string]string, len(e.Detail))
		for k, v := range e.Detail {
			c.Detail[k] = v
		}
	}
	return c
}

// Export 导出 ID 闭区间 [from, to] 的审计证据。
//
// 语义：
//   - 范围不合法（from<1 或 from>to）→ ErrInvalidRange；
//   - to 超出当前已提交记录 → ErrRangeUnavailable（拒绝导出一个尚不存在的
//     边界，绝不用“部分记录”冒充完整区间）；
//   - 条数/字节数超上限 → ErrTooManyRecords / ErrTooLarge，不返回半成品；
//   - 产物在单次一致快照上构造，不会出现半条记录、重复序号或跳号；
//   - 同一范围重复导出得到字节一致的产物（产物不含导出时刻等易变字段）。
//
// 只在拷贝快照时短暂持有审计锁，哈希与签名都在锁外完成，不长时间阻塞写入。
func (x *Exporter) Export(from, to int64) (*Artifact, error) {
	if x == nil || x.key == nil {
		return nil, ErrExporterNotInitialized
	}
	if from < 1 || to < from {
		return nil, fmt.Errorf("%w: from=%d to=%d", ErrInvalidRange, from, to)
	}
	count := to - from + 1
	if x.limits.MaxRecords > 0 && count > int64(x.limits.MaxRecords) {
		return nil, fmt.Errorf("%w: requested=%d limit=%d", ErrTooManyRecords, count, x.limits.MaxRecords)
	}

	// Since 返回防御性拷贝快照；锁只在拷贝期间持有。
	snapshot, err := x.log.Since(0)
	if err != nil {
		return nil, fmt.Errorf("evidence: snapshot: %w", err)
	}
	if to > int64(len(snapshot)) {
		return nil, fmt.Errorf("%w: to=%d committed=%d", ErrRangeUnavailable, to, len(snapshot))
	}

	// 在快照上重放哈希链以取得边界锚点（范围前一条记录的链哈希），
	// 随后仅打包 [from,to]。
	var anchor string
	prev := ""
	for i := int64(0); i < from-1; i++ {
		prev, err = chainHash(prev, coreFromEvent(snapshot[i]))
		if err != nil {
			return nil, err
		}
	}
	anchor = prev

	records := make([]Record, 0, count)
	for i := from - 1; i < to; i++ {
		core := coreFromEvent(snapshot[i])
		h, err := chainHash(prev, core)
		if err != nil {
			return nil, err
		}
		records = append(records, Record{recordCore: core, Hash: h})
		prev = h
	}

	a := &Artifact{
		FormatVersion: FormatVersion,
		ChainAlg:      ChainSHA256,
		SigAlg:        AlgEd25519,
		KeyID:         x.key.id,
		RangeFrom:     from,
		RangeTo:       to,
		AnchorHash:    anchor,
		RootHash:      prev,
		Records:       records,
		PublicKey:     b64.EncodeToString(x.key.PublicKey()),
	}
	body, err := json.Marshal(signedBody{
		FormatVersion: a.FormatVersion,
		ChainAlg:      a.ChainAlg,
		SigAlg:        a.SigAlg,
		KeyID:         a.KeyID,
		RangeFrom:     a.RangeFrom,
		RangeTo:       a.RangeTo,
		AnchorHash:    a.AnchorHash,
		RootHash:      a.RootHash,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: canonicalize signed body: %w", err)
	}
	sig := ed25519.Sign(x.key.priv, body)
	a.Signature = b64.EncodeToString(sig)

	if x.limits.MaxBytes > 0 {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("evidence: encode artifact: %w", err)
		}
		if len(raw) > x.limits.MaxBytes {
			return nil, fmt.Errorf("%w: size=%d limit=%d", ErrTooLarge, len(raw), x.limits.MaxBytes)
		}
	}
	return a, nil
}

// Encode 把产物序列化为紧凑 JSON（同一产物字节确定）。
func (a *Artifact) Encode() ([]byte, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("evidence: encode artifact: %w", err)
	}
	return raw, nil
}

// Decode 解析一份导出产物；结构层面的问题留给 Verify 分类。
func Decode(raw []byte) (*Artifact, error) {
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("evidence: decode artifact: %w", err)
	}
	return &a, nil
}

func malformed(format string, args ...any) Result {
	return Result{Status: StatusMalformed, Detail: fmt.Sprintf(format, args...)}
}

// Verify 在完全离线条件下核验导出产物字节：
//
//  1. 结构可解析、算法/版本受支持、密钥与签名编码完整；
//  2. 声明的范围本身合法且记录条数与范围一致；
//  3. 序号连续（缺号 → missing_records；重排/重复 → reordered_or_dup）；
//  4. 逐条重放哈希链（内容被改 → content_tampered；根不符 → root_mismatch）；
//  5. 用产物自带公钥校验导出方 Ed25519 签名（失败 → bad_evidence_signature）。
//
// 任何一步失败即返回对应分类，绝不会把不完整/被改的内容核验为通过。
func Verify(raw []byte) Result {
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return malformed("artifact is not valid JSON: %v", err)
	}
	if a.FormatVersion != FormatVersion {
		return Result{Status: StatusUnsupportedKeyAlg,
			Detail: fmt.Sprintf("unsupported format_version=%d (want %d)", a.FormatVersion, FormatVersion)}
	}
	if a.ChainAlg != ChainSHA256 {
		return Result{Status: StatusUnsupportedKeyAlg, Detail: "unsupported chain_alg: " + a.ChainAlg}
	}
	if a.SigAlg != AlgEd25519 {
		return Result{Status: StatusUnsupportedKeyAlg, Detail: "unsupported sig_alg: " + a.SigAlg}
	}
	pubBytes, err := b64.DecodeString(a.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return malformed("public_key must be base64url of %d bytes", ed25519.PublicKeySize)
	}
	sigBytes, err := b64.DecodeString(a.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return malformed("signature must be base64url of %d bytes", ed25519.SignatureSize)
	}
	// key_id 必填；anchor 允许为空，但仅当范围从首条记录开始。
	if a.KeyID == "" || (a.AnchorHash == "" && a.RangeFrom != 1) {
		return malformed("key_id is required; anchor_hash may be empty only when range_from=1")
	}
	res := Result{KeyID: a.KeyID}

	// 2. 范围合法性。
	if a.RangeFrom < 1 || a.RangeTo < a.RangeFrom {
		res.Status = StatusInvalidRange
		res.Detail = fmt.Sprintf("declared range [%d,%d] is not legal", a.RangeFrom, a.RangeTo)
		return res
	}
	wantCount := int(a.RangeTo - a.RangeFrom + 1)
	if len(a.Records) != wantCount {
		return malformed("records count=%d does not match declared range size=%d", len(a.Records), wantCount)
	}
	for i, rec := range a.Records {
		if rec.Hash == "" {
			return malformed("record at position %d has empty hash", i)
		}
	}
	if a.RootHash == "" {
		return malformed("root_hash is empty")
	}

	// 3. 序号连续性：先全量扫描，“向后出现更小序号”证明重排/重复；
	//    否则任何前向跳跃都是缺号。
	var firstGapIdx, firstBackIdx int = -1, -1
	for i, rec := range a.Records {
		want := a.RangeFrom + int64(i)
		switch {
		case rec.ID < want && firstBackIdx < 0:
			firstBackIdx = i
		case rec.ID > want && firstGapIdx < 0:
			firstGapIdx = i
		}
	}
	if firstBackIdx >= 0 {
		i := firstBackIdx
		got := a.Records[i].ID
		res.Status = StatusReordered
		res.AtID = got
		res.WantID = a.RangeFrom + int64(i)
		res.GotID = got
		res.Detail = fmt.Sprintf("sequence reordered or duplicated at position %d: want id=%d got id=%d", i, res.WantID, got)
		return res
	}
	if firstGapIdx >= 0 {
		i := firstGapIdx
		got := a.Records[i].ID
		res.Status = StatusGap
		res.WantID = a.RangeFrom + int64(i)
		res.GotID = got
		res.AtID = res.WantID
		res.Detail = fmt.Sprintf("missing record id=%d (next present id=%d)", res.WantID, got)
		return res
	}

	// 4. 重放哈希链。
	prev := a.AnchorHash
	for _, rec := range a.Records {
		h, err := chainHash(prev, rec.recordCore)
		if err != nil {
			return malformed("cannot canonicalize record id=%d: %v", rec.ID, err)
		}
		if h != rec.Hash {
			res.Status = StatusTampered
			res.AtID = rec.ID
			res.Detail = fmt.Sprintf("record id=%d content does not match its chained hash", rec.ID)
			return res
		}
		prev = h
	}
	if prev != a.RootHash {
		res.Status = StatusRootMismatch
		res.Detail = fmt.Sprintf("recomputed root %s != declared root %s", prev, a.RootHash)
		return res
	}

	// 5. 签名（含 key_id 与公钥的绑定关系）。
	if want := keyIDOf(ed25519.PublicKey(pubBytes)); want != a.KeyID {
		res.Status = StatusBadSignature
		res.Detail = "key_id does not match the embedded public key"
		return res
	}
	body, err := json.Marshal(signedBody{
		FormatVersion: a.FormatVersion,
		ChainAlg:      a.ChainAlg,
		SigAlg:        a.SigAlg,
		KeyID:         a.KeyID,
		RangeFrom:     a.RangeFrom,
		RangeTo:       a.RangeTo,
		AnchorHash:    a.AnchorHash,
		RootHash:      a.RootHash,
	})
	if err != nil {
		return malformed("cannot rebuild signed body: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), body, sigBytes) {
		res.Status = StatusBadSignature
		res.Detail = "Ed25519 signature verification failed"
		return res
	}

	res.Status = StatusValid
	res.Detail = fmt.Sprintf("range [%d,%d] is complete, contiguous and unaltered", a.RangeFrom, a.RangeTo)
	return res
}
