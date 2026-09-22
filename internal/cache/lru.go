// Package cache 提供有容量上限的 LRU 缓存，用于正面授权结论的短缓存。
// 容量由配置约束；被淘汰的条目立即释放，不泄漏资源。
package cache

import (
	"container/list"
	"sync"
)

type item[K comparable, V any] struct {
	key      K
	value    V
	expireAt int64
}

// LRU 是并发安全的有界最近最少使用缓存。
type LRU[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List // 前端为最近使用
	idx      map[K]*list.Element
}

// NewLRU 创建容量为 capacity 的缓存；capacity<=0 表示不缓存（所有 Get 未命中）。
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	return &LRU[K, V]{
		capacity: capacity,
		ll:       list.New(),
		idx:      make(map[K]*list.Element),
	}
}

// Get 返回未过期的条目；不存在或已过期返回 false。
// 命中会刷新为最近使用。
func (c *LRU[K, V]) Get(key K, now int64) (V, bool) {
	var zero V
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[key]
	if !ok {
		return zero, false
	}
	it := el.Value.(*item[K, V])
	if it.expireAt > 0 && now >= it.expireAt {
		c.removeEl(el)
		return zero, false
	}
	c.ll.MoveToFront(el)
	return it.value, true
}

// Add 写入条目（带 unix 过期时间），超容量时淘汰最久未用条目。
func (c *LRU[K, V]) Add(key K, value V, expireAt int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capacity <= 0 {
		return // 缓存关闭：不保留任何引用，避免资源泄漏
	}
	if el, ok := c.idx[key]; ok {
		c.ll.MoveToFront(el)
		it := el.Value.(*item[K, V])
		it.value = value
		it.expireAt = expireAt
		return
	}
	el := c.ll.PushFront(&item[K, V]{key: key, value: value, expireAt: expireAt})
	c.idx[key] = el
	for c.ll.Len() > c.capacity {
		c.removeEl(c.ll.Back())
	}
}

func (c *LRU[K, V]) removeEl(el *list.Element) {
	if el == nil {
		return
	}
	it := el.Value.(*item[K, V])
	delete(c.idx, it.key)
	c.ll.Remove(el)
}

// InvalidateIf 按谓词使条目失效；用于授权版本变化时清空全部结论。
func (c *LRU[K, V]) InvalidateIf(match func(K) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, el := range c.idx {
		if match(k) {
			c.removeEl(el)
		}
	}
}

// Len 返回当前条目数。
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
