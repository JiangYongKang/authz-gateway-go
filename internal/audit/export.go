package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

// 导出阶段的拒绝原因（可区分）。
var (
	// ErrExportRange 表示请求的导出范围本身不合法（from<1、to<from、超出已记录序号）。
	ErrExportRange = errors.New("audit: export range invalid")
	// ErrExportLimit 表示请求范围超过单次导出允许的条数上限。
	ErrExportLimit = errors.New("audit: export exceeds max records")
)

// EvidenceFormat 是导出产物的格式标识，独立核验方据此确认兼容版本。
const EvidenceFormat = "audit-evidence/v1"

// Record 是导出产物中的一条记录：事件本体 + 其在哈希链上的摘要。
type Record struct {
	Event Event  `json:"event"`
	Hash  string `json:"hash"`
}

// Evidence 是自包含的审计证据产物：交给完全独立的一方，
// 无需任何服务访问权限即可核验该段记录的完整性与真实性。
type Evidence struct {
	Format  string   `json:"format"`
	From    int64    `json:"from"`
	To      int64    `json:"to"`
	Records []Record `json:"records"`
	Head    string   `json:"head"`
}

// chainSeed 由格式标识与声明范围派生哈希链起点，
// 使核验方仅凭产物自身即可重放整条链。
func chainSeed(from, to int64) []byte {
	h := sha256.New()
	h.Write([]byte(EvidenceFormat))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(from))
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(to))
	h.Write(b[:])
	return h.Sum(nil)
}

// chainNext 以前一摘要与事件本体的规范 JSON 推进哈希链。
// encoding/json 对结构体字段序与 map 键序的输出是确定的，
// 因此同一事件在任何进程中都得到同一摘要。
func chainNext(prev []byte, e Event) ([]byte, error) {
	canon, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(canon)
	return h.Sum(nil), nil
}

// Export 导出 [from, to] 闭区间内的记录为自包含证据。
//
// 一致性：序号由同一把互斥锁单调分配且只追加，导出在锁内拷贝
// [from,to] 切片，因此产物必然是某一一致边界——无半条记录、
// 无跳号、无重复；对同一范围重复导出结果逐字节一致。
// 锁仅在拷贝期间持有，哈希计算在锁外进行，不会长时间阻塞写入。
//
// 拒绝原因可区分：范围不合法返回 ErrExportRange，超过 maxRecords
// （>0 时）返回 ErrExportLimit；失败时不产生任何半成品产物。
func (l *Log) Export(from, to int64, maxRecords int) (Evidence, error) {
	if from < 1 || to < from {
		return Evidence{}, ErrExportRange
	}

	l.mu.Lock()
	if to > l.seq {
		l.mu.Unlock()
		return Evidence{}, ErrExportRange
	}
	if maxRecords > 0 && to-from+1 > int64(maxRecords) {
		l.mu.Unlock()
		return Evidence{}, ErrExportLimit
	}
	// 深拷贝：事件值拷贝 + Detail map 逐条复制（与 Since/Append 共用
	// 同一 cloneEvent 实现），调用方事后如何改动产物都不可能影响日志本体。
	src := l.events[from-1 : to]
	events := make([]Event, len(src))
	for i, e := range src {
		events[i] = cloneEvent(e)
	}
	l.mu.Unlock()

	ev := Evidence{
		Format:  EvidenceFormat,
		From:    from,
		To:      to,
		Records: make([]Record, len(events)),
	}
	prev := chainSeed(from, to)
	for i, e := range events {
		next, err := chainNext(prev, e)
		if err != nil {
			return Evidence{}, err
		}
		ev.Records[i] = Record{Event: e, Hash: hex.EncodeToString(next)}
		prev = next
	}
	ev.Head = hex.EncodeToString(prev)
	return ev, nil
}

// Verdict 是独立核验的结论分类。
type Verdict string

const (
	VerdictOK             Verdict = "ok"              // 完整连续、未被改写
	VerdictMalformed      Verdict = "malformed"       // 产物无法解析或格式不符
	VerdictInvalidRange   Verdict = "invalid_range"   // 声明的范围本身不合法
	VerdictSequenceBroken Verdict = "sequence_broken" // 缺号、重复或顺序被重排
	VerdictTampered       Verdict = "tampered"        // 记录内容被事后改写
)

// Verification 是一次独立核验的结果。
type Verification struct {
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail,omitempty"`
	Records int     `json:"records"`
}

// VerifyEvidence 在不访问任何服务的前提下核验一份导出产物。
//
// 判定顺序固定，结论可区分：
//  1. 无法解析 / 格式标识不符            → VerdictMalformed
//  2. 声明范围不合法（from<1、to<from、
//     记录条数与区间长度不符）           → VerdictInvalidRange
//  3. 序号未严格连续覆盖 [from,to]
//     （缺号、重复、重排）               → VerdictSequenceBroken
//  4. 哈希链重放与摘要不符（内容被改写） → VerdictTampered
//  5. 全部通过                          → VerdictOK
//
// 核验是纯函数：不触碰任何服务端状态，同一输入必然得到同一结论。
func VerifyEvidence(data []byte) Verification {
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return Verification{Verdict: VerdictMalformed, Detail: "artifact is not valid JSON evidence: " + err.Error()}
	}
	if ev.Format != EvidenceFormat {
		return Verification{Verdict: VerdictMalformed, Detail: "unsupported format: " + ev.Format}
	}
	if ev.From < 1 || ev.To < ev.From {
		return Verification{Verdict: VerdictInvalidRange, Detail: "declared range is not a valid closed interval"}
	}
	if int64(len(ev.Records)) != ev.To-ev.From+1 {
		return Verification{Verdict: VerdictInvalidRange, Detail: "record count does not match declared range"}
	}
	for i, r := range ev.Records {
		want := ev.From + int64(i)
		if r.Event.ID != want {
			return Verification{
				Verdict: VerdictSequenceBroken,
				Detail:  "sequence broken at position " + itoa(i) + ": expected id " + itoa64(want) + ", got " + itoa64(r.Event.ID),
				Records: len(ev.Records),
			}
		}
	}
	prev := chainSeed(ev.From, ev.To)
	for _, r := range ev.Records {
		next, err := chainNext(prev, r.Event)
		if err != nil {
			return Verification{Verdict: VerdictMalformed, Detail: err.Error()}
		}
		if got := hex.EncodeToString(next); got != r.Hash {
			return Verification{
				Verdict: VerdictTampered,
				Detail:  "hash chain mismatch at record id " + itoa64(r.Event.ID),
				Records: len(ev.Records),
			}
		}
		prev = next
	}
	if head := hex.EncodeToString(prev); head != ev.Head {
		return Verification{Verdict: VerdictTampered, Detail: "head digest mismatch", Records: len(ev.Records)}
	}
	return Verification{Verdict: VerdictOK, Records: len(ev.Records)}
}

func itoa(i int) string     { return strconv.Itoa(i) }
func itoa64(i int64) string { return strconv.FormatInt(i, 10) }
