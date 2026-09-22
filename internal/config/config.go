// Package config 定义服务的可配置上限与判定规模约束。
package config

import "time"

// Config 描述容量上限与时限。零值用 Defaults 填充。
type Config struct {
	MaxUsers      int
	MaxResources  int
	MaxPolicies   int
	MaxSessions   int
	MaxKeys       int
	DecisionCache int           // 正面判定缓存条目上限，0 表示关闭
	AuditCapacity int           // 审计记录上限，<=0 表示不限
	TokenTTL      time.Duration // 凭证默认有效期
	RenewWindow   time.Duration // 过期前可续期的时间窗（0 表示任何未过期时刻都可续期）
	DecisionTTL   time.Duration // 正面判定缓存有效期
	MaxRuleCount  int           // 单次判定最多求值的规则数，0 表示不限
	MaxAttrCount  int           // 单次请求允许携带的属性数量上限，0 表示不限
	Issuer        string        // 期望的凭证签发者
}

// Defaults 返回带默认上限的配置。
func Defaults() Config {
	return Config{
		MaxUsers:      1000,
		MaxResources:  1000,
		MaxPolicies:   500,
		MaxSessions:   10_000,
		MaxKeys:       16,
		DecisionCache: 256,
		AuditCapacity: 100_000,
		TokenTTL:      time.Hour,
		RenewWindow:   30 * time.Minute,
		DecisionTTL:   10 * time.Second,
		MaxRuleCount:  500,
		MaxAttrCount:  64,
		Issuer:        "authz-gateway-local",
	}
}

// MergeDefaults 将零值字段填充为默认值，返回新配置。
func (c Config) MergeDefaults() Config {
	d := Defaults()
	if c.MaxUsers == 0 {
		c.MaxUsers = d.MaxUsers
	}
	if c.MaxResources == 0 {
		c.MaxResources = d.MaxResources
	}
	if c.MaxPolicies == 0 {
		c.MaxPolicies = d.MaxPolicies
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = d.MaxSessions
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = d.MaxKeys
	}
	if c.DecisionCache == 0 {
		c.DecisionCache = d.DecisionCache
	}
	if c.AuditCapacity == 0 {
		c.AuditCapacity = d.AuditCapacity
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = d.TokenTTL
	}
	if c.DecisionTTL == 0 {
		c.DecisionTTL = d.DecisionTTL
	}
	if c.MaxRuleCount == 0 {
		c.MaxRuleCount = d.MaxRuleCount
	}
	if c.MaxAttrCount == 0 {
		c.MaxAttrCount = d.MaxAttrCount
	}
	if c.Issuer == "" {
		c.Issuer = d.Issuer
	}
	return c
}
