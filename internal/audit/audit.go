// Package audit 提供仅追加(append-only)的审计日志。
//
// 每条记录通过 "前一条记录哈希 -> 当前记录哈希" 的哈希链接入链，
// 任何对历史记录的事后改写都会导致 Verify() 失败。
//
// 安全约束：
//   - 原始凭证、密钥、口令等敏感内容一律不得入链；写入前经 Sanitize 脱敏。
//   - 容量达到上限后追加返回 ErrLogFull，由上层按拒绝策略处理，
//     失败不会产生半写入（记录要么完整入链，要么不存在）。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// 决策与动作使用字符串常量，保证日志中语义稳定。
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionError Decision = "error" // 系统错误：与 deny 一样不可放行
)

// ErrLogFull 表示审计存储达到容量上限，本次追加被整体拒绝。
var ErrLogFull = errors.New("audit: log capacity reached")

// Redacted 是敏感字段被替换后的占位文本。
const Redacted = "[REDACTED]"

// sensitiveKeys 列出必须脱敏的字段名（小写匹配）。
// 该清单是防御性的：即使上层误传 token/密钥，也不会落盘。
var sensitiveKeys = map[string]bool{
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"raw_token":     true,
	"secret":        true,
	"key_secret":    true,
	"keymaterial":   true,
	"key_material":  true,
	"password":      true,
	"passwd":        true,
	"authorization": true,
}

// Entry 是一条不可变审计记录。
type Entry struct {
	Seq       int64             `json:"seq"`
	Time      time.Time         `json:"time"`
	Actor     string            `json:"actor"`
	SessionID string            `json:"session_id,omitempty"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource,omitempty"`
	Decision  Decision          `json:"decision"`
	Reason    string            `json:"reason,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// Log 是并发安全的哈希链审计日志。零值不可用，必须用 New 构造。
type Log struct {
	mu      sync.Mutex
	maxSize int
	entries []*Entry
}

// New 创建容量上限为 maxSize 的审计日志；maxSize <= 0 表示不允许写入任何记录。
func New(maxSize int) *Log {
	return &Log{maxSize: maxSize, entries: make([]*Entry, 0)}
}

// Sanitize 返回 detail 的脱敏副本：键名命中敏感清单的值被替换，
// 同时剔除原始凭证样式的值（以 "ey" 开头且形如三段式的 JWT）。
func Sanitize(detail map[string]string) map[string]string {
	if detail == nil {
		return nil
	}
	out := make(map[string]string, len(detail))
	for k, v := range detail {
		switch {
		case sensitiveKeys[strings.ToLower(k)]:
			out[k] = Redacted
		case looksLikeToken(v):
			out[k] = Redacted
		default:
			out[k] = v
		}
	}
	return out
}

func looksLikeToken(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return strings.HasPrefix(v, "ey")
}

// AppendInput 是写入审计日志的输入（敏感字段会被脱敏）。
type AppendInput struct {
	Actor     string
	SessionID string
	Action    string
	Resource  string
	Decision  Decision
	Reason    string
	Detail    map[string]string
	Time      time.Time // 零值表示由日志填充当前时间
}

// Append 原子地追加一条记录并返回其完整副本。
// 达到容量上限时返回 ErrLogFull，且不会修改日志。
func (l *Log) Append(in AppendInput) (*Entry, error) {
	if in.Action == "" {
		return nil, errors.New("audit: empty action")
	}
	if in.Decision != DecisionAllow && in.Decision != DecisionDeny && in.Decision != DecisionError {
		return nil, fmt.Errorf("audit: invalid decision %q", in.Decision)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= l.maxSize {
		return nil, ErrLogFull
	}
	ts := in.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	e := &Entry{
		Seq:       int64(len(l.entries)) + 1,
		Time:      ts,
		Actor:     in.Actor,
		SessionID: in.SessionID,
		Action:    in.Action,
		Resource:  in.Resource,
		Decision:  in.Decision,
		Reason:    in.Reason,
		Detail:    Sanitize(in.Detail),
	}
	if len(l.entries) > 0 {
		e.PrevHash = l.entries[len(l.entries)-1].Hash
	}
	h, err := computeHash(e)
	if err != nil {
		// 序列化失败属于内部错误：不写入，避免半截记录。
		return nil, fmt.Errorf("audit: hash entry: %w", err)
	}
	e.Hash = h
	l.entries = append(l.entries, e)
	// 返回副本，避免调用方持有链内指针后改写。
	cp := *e
	return &cp, nil
}

// computeHash 对记录的规范表示做 SHA-256。字段顺序固定（JSON 结构固定 + Detail 键排序），
// 保证同一逻辑记录在任何机器上得到相同哈希。
func computeHash(e *Entry) (string, error) {
	detail := e.Detail
	keys := make([]string, 0, len(detail))
	for k := range detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(strconvFormatInt(e.Seq))
	sb.WriteString("|")
	sb.WriteString(e.Time.UTC().Format(time.RFC3339Nano))
	sb.WriteString("|")
	sb.WriteString(e.Actor)
	sb.WriteString("|")
	sb.WriteString(e.SessionID)
	sb.WriteString("|")
	sb.WriteString(e.Action)
	sb.WriteString("|")
	sb.WriteString(e.Resource)
	sb.WriteString("|")
	sb.WriteString(string(e.Decision))
	sb.WriteString("|")
	sb.WriteString(e.Reason)
	sb.WriteString("|")
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(detail[k])
		sb.WriteString(";")
	}
	sb.WriteString("|")
	sb.WriteString(e.PrevHash)
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:]), nil
}

func strconvFormatInt(i int64) string {
	// 避免额外 import strconv 的轻量格式化（seq 恒正）。
	if i == 0 {
		return "0"
	}
	var b [24]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// Len 返回当前记录数。
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Entries 返回全部记录的深拷贝快照（按序列号升序）。
func (l *Log) Entries() []*Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Entry, len(l.entries))
	for i, e := range l.entries {
		cp := *e
		if e.Detail != nil {
			cp.Detail = make(map[string]string, len(e.Detail))
			for k, v := range e.Detail {
				cp.Detail[k] = v
			}
		}
		out[i] = &cp
	}
	return out
}

// ExportJSON 导出日志的规范 JSON（用于离线核验）。
func (l *Log) ExportJSON() ([]byte, error) {
	return json.Marshal(l.Entries())
}

// Verify 重放整条哈希链：任一记录被增删改写都会返回错误。
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var prev string
	for i, e := range l.entries {
		if e.PrevHash != prev {
			return fmt.Errorf("audit: chain broken at seq %d: prev hash mismatch", e.Seq)
		}
		want, err := computeHash(e)
		if err != nil {
			return fmt.Errorf("audit: seq %d hash error: %w", e.Seq, err)
		}
		if want != e.Hash {
			return fmt.Errorf("audit: chain broken at seq %d: hash mismatch", e.Seq)
		}
		if e.Seq != int64(i+1) {
			return fmt.Errorf("audit: chain broken at index %d: seq gap", i)
		}
		prev = e.Hash
	}
	return nil
}
