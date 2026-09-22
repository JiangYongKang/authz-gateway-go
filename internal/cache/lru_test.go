package cache

import "testing"

func TestLRUBoundsExpiryAndInvalidation(t *testing.T) {
	c := NewLRU[string, int](2)
	c.Add("a", 1, 10)
	c.Add("b", 2, 10)
	if v, ok := c.Get("a", 5); !ok || v != 1 {
		t.Fatal("expected hit a")
	}
	// 插入第三个，b 是最久未用，应被淘汰。
	c.Add("c", 3, 10)
	if _, ok := c.Get("b", 5); ok {
		t.Fatal("b should have been evicted")
	}
	if c.Len() != 2 {
		t.Fatalf("capacity bound violated: %d", c.Len())
	}
	// 过期。
	if _, ok := c.Get("a", 11); ok {
		t.Fatal("expired entry must miss")
	}
	c.Add("d", 4, 0)
	c.InvalidateIf(func(k string) bool { return true })
	if c.Len() != 0 {
		t.Fatal("full invalidation must empty cache")
	}
	disabled := NewLRU[string, int](0)
	disabled.Add("x", 1, 0)
	if _, ok := disabled.Get("x", 0); ok {
		t.Fatal("capacity<=0 must keep nothing")
	}
	t.Logf("input: LRU cap=2 eviction+expiry+invalidation; basis: size stays bounded")
}
