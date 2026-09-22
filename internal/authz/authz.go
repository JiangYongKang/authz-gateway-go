// Package authz 实现基于角色(RBAC)与属性(ABAC)的授权判定。
//
// 判定语义（顺序无关，可解释）：
//  1. 默认拒绝：没有任何规则匹配 => deny(default_deny)。
//  2. 显式拒绝优先：收集所有匹配规则，只要存在一条 effect=deny，结论即 deny；
//     无论 allow 规则有多少、规则按什么顺序求值，结论恒定。
//  3. 仅当存在至少一条匹配的 allow 且不存在任何匹配的 deny 时才 allow。
//
// 每次判定返回 Trace：参与匹配的规则、各自条件判定结果与最终原因，
// 供审计与问题排查使用。判定输入来自调用方提供的存储最新快照，
// 不使用凭证内嵌的角色快照，因此权限变更下一次判定立即生效。
package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

// DecisionReason 是授权结论的细分原因。
type DecisionReason string

const (
	ReasonAllowMatched  DecisionReason = "allow_rule_matched"
	ReasonDenyMatched   DecisionReason = "explicit_deny_overrides" // 命中显式 deny（优先级高于一切 allow）
	ReasonDefaultDeny   DecisionReason = "default_deny_no_match"   // 无规则匹配
	ReasonMissingUser   DecisionReason = "missing_subject"
	ReasonMissingAction DecisionReason = "missing_action"
)

// Decision 是授权结论。
type Decision string

const (
	DecisionPermit Decision = "permit"
	DecisionDeny   Decision = "deny"
)

// Input 是一次授权判定的输入（主体/资源取存储最新状态）。
type Input struct {
	SubjectID string
	Action    string
}

// RuleTrace 记录单条规则在本次判定中的求值情况。
type RuleTrace struct {
	PolicyID    string            `json:"policy_id"`
	RoleID      string            `json:"role_id"`
	ResourceID  string            `json:"resource_id"`
	Effect      store.Effect      `json:"effect"`
	Matched     bool              `json:"matched"`
	MatchWhy    string            `json:"match_why,omitempty"`
	Conditions  map[string]string `json:"conditions,omitempty"`
	CondResults map[string]bool   `json:"condition_results,omitempty"`
}

// Trace 是一次判定的完整依据。
type Trace struct {
	SubjectID    string         `json:"subject_id"`
	SubjectRoles []string       `json:"subject_roles"`
	Action       string         `json:"action"`
	ResourceID   string         `json:"resource_id"`
	Decision     Decision       `json:"decision"`
	Reason       DecisionReason `json:"reason"`
	Rules        []RuleTrace    `json:"rules"`
	FromCache    bool           `json:"from_cache"`
}

// Evaluator 对给定主体/动作/资源做授权判定。
type Evaluator struct {
	mu       sync.Mutex
	cache    map[string]*Trace
	maxCache int
}

// NewEvaluator 创建判定器；maxCacheEntries<=0 表示禁用缓存。
// 缓存条目只缓存“纯函数判定结果”，键包含全部判定输入（含资源属性快照），
// 策略/角色一旦变更必须由上层调用 Invalidate 清空。
func NewEvaluator(maxCacheEntries int) *Evaluator {
	var c map[string]*Trace
	if maxCacheEntries > 0 {
		c = make(map[string]*Trace, maxCacheEntries)
	}
	return &Evaluator{cache: c, maxCache: maxCacheEntries}
}

// CacheLen 返回当前缓存条目数。
func (e *Evaluator) CacheLen() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cache)
}

// Invalidate 清空判定缓存。任何权限/角色/资源/策略变更后必须调用，
// 以保证“变更后新判定”不使用陈旧结论。
func (e *Evaluator) Invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cache != nil {
		e.cache = make(map[string]*Trace, e.maxCache)
	}
}

// cacheKey 由全部影响判定结论的输入构成。
func cacheKey(subject *store.User, action string, resource *store.Resource, policies []*store.Policy) string {
	h := sha256.New()
	writeField := func(name, v string) {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	writeField("sub", subject.ID)
	roles := append([]string(nil), subject.Roles...)
	sort.Strings(roles)
	writeField("roles", strings.Join(roles, ","))
	attrKeys := make([]string, 0, len(subject.Attrs))
	for k := range subject.Attrs {
		attrKeys = append(attrKeys, k)
	}
	sort.Strings(attrKeys)
	for _, k := range attrKeys {
		writeField("sa."+k, subject.Attrs[k])
	}
	writeField("act", action)
	if resource != nil {
		writeField("res", resource.ID)
		writeField("res.kind", resource.Kind)
		rk := make([]string, 0, len(resource.Attrs))
		for k := range resource.Attrs {
			rk = append(rk, k)
		}
		sort.Strings(rk)
		for _, k := range rk {
			writeField("ra."+k, resource.Attrs[k])
		}
	}
	// 策略集合进入键：策略增删改会改变其规范化摘要。
	pids := make([]string, 0, len(policies))
	for _, p := range policies {
		pids = append(pids, p.ID)
	}
	sort.Strings(pids)
	writeField("policy_ids", strings.Join(pids, ","))
	policyByID := make(map[string]*store.Policy, len(policies))
	for _, p := range policies {
		policyByID[p.ID] = p
	}
	for _, id := range pids {
		p := policyByID[id]
		writeField("p.eff."+p.ID, string(p.Effect))
		writeField("p.role."+p.ID, p.RoleID)
		writeField("p.res."+p.ID, p.ResourceID)
		acts := append([]string(nil), p.Actions...)
		sort.Strings(acts)
		writeField("p.acts."+p.ID, strings.Join(acts, ","))
		ck := make([]string, 0, len(p.Conditions))
		for k := range p.Conditions {
			ck = append(ck, k)
		}
		sort.Strings(ck)
		for _, k := range ck {
			writeField("p.cond."+p.ID+"."+k, p.Conditions[k])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Evaluate 执行判定。subject 必须为存储中的最新用户状态；
// resource 为 nil 时仅资源通配规则可匹配；policies 为当前全部策略快照。
func (e *Evaluator) Evaluate(subject *store.User, action string, resource *store.Resource, policies []*store.Policy) *Trace {
	if subject == nil {
		return &Trace{Action: action, Decision: DecisionDeny, Reason: ReasonMissingUser, Rules: []RuleTrace{}}
	}
	if action == "" {
		return &Trace{SubjectID: subject.ID, SubjectRoles: append([]string(nil), subject.Roles...),
			Decision: DecisionDeny, Reason: ReasonMissingAction, Rules: []RuleTrace{}}
	}

	key := ""
	if e.maxCache > 0 {
		key = cacheKey(subject, action, resource, policies)
		e.mu.Lock()
		if hit, ok := e.cache[key]; ok {
			cp := *hit
			cp.FromCache = true
			e.mu.Unlock()
			return &cp
		}
		e.mu.Unlock()
	}

	t := evaluateFresh(subject, action, resource, policies)

	if key != "" {
		e.mu.Lock()
		// 二次确认 + 容量上限：缓存满时不驱逐（拒绝写入缓存），不影响判定正确性，
		// 仅放弃本次缓存机会；绝不因为缓存容量问题改变授权结论。
		if _, ok := e.cache[key]; !ok && len(e.cache) < e.maxCache {
			cp := *t
			cp.FromCache = false
			e.cache[key] = &cp
		}
		e.mu.Unlock()
	}
	return t
}

func evaluateFresh(subject *store.User, action string, resource *store.Resource, policies []*store.Policy) *Trace {
	roleSet := make(map[string]bool, len(subject.Roles))
	for _, r := range subject.Roles {
		roleSet[r] = true
	}
	t := &Trace{
		SubjectID:    subject.ID,
		SubjectRoles: append([]string(nil), subject.Roles...),
		Action:       action,
		Rules:        []RuleTrace{},
	}
	if resource != nil {
		t.ResourceID = resource.ID
	}

	var matchedAllow, matchedDeny int
	for _, p := range policies {
		rt := RuleTrace{
			PolicyID: p.ID, RoleID: p.RoleID, ResourceID: p.ResourceID, Effect: p.Effect,
			Conditions: cloneMap(p.Conditions), CondResults: map[string]bool{},
		}
		// 角色匹配：全局规则(RoleID 空)恒过；否则主体须拥有该角色。
		roleOK := p.RoleID == "" || roleSet[p.RoleID]
		// 动作匹配：Actions 为空表示该资源上任意动作。
		actionOK := len(p.Actions) == 0 || containsString(p.Actions, action)
		// 资源匹配：ResourceID 为空表示任意资源；否则精确相等。
		resourceOK := p.ResourceID == "" || (resource != nil && resource.ID == p.ResourceID)
		// 条件全部满足。
		condsOK := true
		for ck, cv := range p.Conditions {
			ok := evalCondition(ck, cv, action, subject, resource, roleSet)
			rt.CondResults[ck] = ok
			if !ok {
				condsOK = false
			}
		}
		rt.Matched = roleOK && actionOK && resourceOK && condsOK
		switch {
		case !roleOK:
			rt.MatchWhy = "role_not_held"
		case !actionOK:
			rt.MatchWhy = "action_not_matched"
		case !resourceOK:
			rt.MatchWhy = "resource_not_matched"
		case !condsOK:
			rt.MatchWhy = "condition_failed"
		default:
			rt.MatchWhy = "fully_matched"
		}
		if rt.Matched {
			if p.Effect == store.EffectDeny {
				matchedDeny++
			} else {
				matchedAllow++
			}
		}
		t.Rules = append(t.Rules, rt)
	}

	// 结论合成：deny 优先；无任何匹配 => 默认拒绝。
	switch {
	case matchedDeny > 0:
		t.Decision = DecisionDeny
		t.Reason = ReasonDenyMatched
	case matchedAllow > 0:
		t.Decision = DecisionPermit
		t.Reason = ReasonAllowMatched
	default:
		t.Decision = DecisionDeny
		t.Reason = ReasonDefaultDeny
	}
	return t
}

// evalCondition 对单条属性约束求值。支持的键：
//
//	sub.attr.<name>  主体自定义属性相等
//	res.attr.<name>  资源自定义属性相等
//	sub.role         主体是否拥有指定角色（值为角色 ID）
//	action           动作相等（通常已由 Actions 处理，提供给 ABAC 直配）
func evalCondition(key, want, action string, subject *store.User, resource *store.Resource, roleSet map[string]bool) bool {
	switch {
	case strings.HasPrefix(key, "sub.attr."):
		name := strings.TrimPrefix(key, "sub.attr.")
		return subject.Attrs[name] == want
	case strings.HasPrefix(key, "res.attr."):
		if resource == nil {
			return false
		}
		name := strings.TrimPrefix(key, "res.attr.")
		return resource.Attrs[name] == want
	case key == "sub.role":
		return roleSet[want]
	case key == "action":
		return action == want
	default:
		// 未知条件键不满足：无法证明的约束一律不放行。
		return false
	}
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
