// Package audit 维护只追加的审计日志。记录一旦写入即不可修改或删除；
// 容量超限时按“拒绝写入并向上游报错”的策略处理，绝不静默丢弃。
package audit

import (
	"errors"
	"sync"
	"time"
)

// ErrAuditFull 在审计容量达到上限、无法再追加时返回。
var ErrAuditFull = errors.New("audit: capacity exhausted")

// Event 是一条不可变审计记录。
// 严禁写入原始凭证、签名密钥等敏感内容：凭证只记录其 jti。
type Event struct {
	ID        int64             `json:"id"`
	Time      time.Time         `json:"time"`
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

// Log 是有界只追加审计日志。
type Log struct {
	mu       sync.Mutex
	capacity int
	seq      int64
	events   []Event
	now      func() time.Time
}

// New 创建容量为 capacity 的审计日志；capacity<=0 表示不限。
func New(capacity int) *Log {
	return &Log{capacity: capacity, now: time.Now}
}

// SetClock 注入时间源（测试用）。
func (l *Log) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = f
}

// Append 追加一条不可变记录，返回分配后的记录（含 ID 与时间）。
// 容量耗尽时返回 ErrAuditFull，调用方必须据此拒绝对应敏感操作。
//
// 注意：Event 以值拷贝保存，Detail map 逐条复制；调用方事后修改入参
// 不影响已写入记录。返回值同样是独立深拷贝：调用方事后改动返回记录
// 的任意一层（含嵌套 Detail），都不会影响服务端已存下的历史。
func (l *Log) Append(e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.capacity > 0 && len(l.events) >= l.capacity {
		return Event{}, ErrAuditFull
	}
	l.seq++
	e.ID = l.seq
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	// 入栈与返回值各自持有独立的 Detail 副本，互不共享。
	stored := cloneEvent(e)
	// 追加到独立后备数组的切片，避免与外部缓冲区共享底层数组。
	l.events = append(l.events, stored)
	return cloneEvent(stored), nil
}

// cloneEvent 返回事件的深拷贝：结构体按值复制，Detail map 逐条复制，
// 使拷贝与原事件不共享任何可就地修改的引用。
func cloneEvent(e Event) Event {
	if e.Detail != nil {
		cp := make(map[string]string, len(e.Detail))
		for k, v := range e.Detail {
			cp[k] = v
		}
		e.Detail = cp
	}
	return e
}

// Since 返回 ID 大于 afterID 的记录（按 ID 升序），深拷贝快照；
// 调用方对返回值的任何修改（含嵌套的 Detail）都不可能改写日志内容。
func (l *Log) Since(afterID int64) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, len(l.events))
	for _, e := range l.events {
		if e.ID > afterID {
			out = append(out, cloneEvent(e))
		}
	}
	return out, nil
}

// Len 返回当前记录数。
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}
