// Package authz 实现基于角色与属性的授权判定。
//
// 语义（顺序无关、结论确定）：
//   - 默认拒绝：没有任何规则匹配 => Deny，理由 "no_matching_policy"。
//   - 显式拒绝优先：只要存在一条匹配的 deny 规则，结论恒为 Deny，
//     无论有多少匹配的 allow 规则，也无论规则求值顺序如何。
//   - 仅当至少一条 allow 规则匹配且没有任何 deny 规则匹配时才 Allow。
//
// 判定结果同时返回命中的全部规则，使结论可解释、可追溯。
package authz

import (
	"sort"

	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

// Decision 是判定结论。
type Decision string

const (
	Deny  Decision = "deny"
	Allow Decision = "allow"
)

// Request 是一次授权判定请求。
type Request struct {
	Subject       string
	Roles         []string
	SubjectAttrs  map[string]string
	Resource      string
	ResourceKind  string
	ResourceOwner string
	ResourceAttrs map[string]string
	Action        string
}

// Explanation 解释结论：命中的允许/拒绝规则与最终理由。
type Explanation struct {
	Decision     Decision
	Reason       string
	MatchedDeny  []string
	MatchedAllow []string
}

// Engine 对给定策略集合执行判定。引擎本身无状态、对求值顺序免疫。
type Engine struct {
	maxRuleCount int
}

// NewEngine 创建引擎；maxRuleCount<=0 表示不限规则数量。
func NewEngine(maxRuleCount int) *Engine { return &Engine{maxRuleCount: maxRuleCount} }

// Evaluate 在策略快照上执行判定。为保证顺序无关，方法始终先求完全部规则，
// 再以“任意 deny 命中 => 拒绝”做汇总，绝不短路，也不依赖切片顺序。
//
// 为防止结论受 map 迭代或存储返回顺序影响，返回的命中规则按 id 排序。
func (e *Engine) Evaluate(req Request, policies []store.Policy) Explanation {
	// 判定规模上限：策略数量超过可求值上限时直接拒绝，绝不基于部分规则放行。
	if e.maxRuleCount > 0 && len(policies) > e.maxRuleCount {
		return Explanation{Decision: Deny, Reason: "rule_set_too_large"}
	}
	var matchedDeny, matchedAllow []string
	for _, p := range policies {
		if ruleMatches(req, p) {
			if p.Deny {
				matchedDeny = append(matchedDeny, p.ID)
			} else {
				matchedAllow = append(matchedAllow, p.ID)
			}
		}
	}
	sort.Strings(matchedDeny)
	sort.Strings(matchedAllow)

	switch {
	case len(matchedDeny) > 0:
		// 显式拒绝恒优先于任何允许。
		return Explanation{Decision: Deny, Reason: "explicit_deny",
			MatchedDeny: matchedDeny, MatchedAllow: matchedAllow}
	case len(matchedAllow) > 0:
		return Explanation{Decision: Allow, Reason: "allow",
			MatchedDeny: matchedDeny, MatchedAllow: matchedAllow}
	default:
		return Explanation{Decision: Deny, Reason: "no_matching_policy"}
	}
}

// containsAny 判断目标值是否命中候选集合；空集合视为“该维度不约束”。
// 支持 "*" 通配符（匹配任意值）。
func containsAny(candidates []string, target string) bool {
	if len(candidates) == 0 {
		return true
	}
	for _, c := range candidates {
		if c == "*" || c == target {
			return true
		}
	}
	return false
}

// ruleMatches 判定单条规则是否适用于请求。
//
// 各维度取交集（AND）：任一维度非空就必须命中。
//   - Users/Subject 与 Roles 描述主体；
//   - Resources 支持具体资源名或 "*"；
//   - Actions 支持具体动作或 "*"；
//   - Conditions 为属性等值条件，键以 "resource." 前缀表示资源属性，
//     "subject." 前缀（或无前缀）表示主体属性。
func ruleMatches(req Request, p store.Policy) bool {
	if !containsAny(p.Users, req.Subject) {
		return false
	}
	if len(p.Roles) > 0 {
		hit := false
		for _, want := range p.Roles {
			if want == "*" {
				hit = true
				break
			}
			for _, have := range req.Roles {
				if have == want {
					hit = true
					break
				}
			}
		}
		if !hit {
			return false
		}
	}
	if !containsAny(p.Resources, req.Resource) {
		return false
	}
	if !containsAny(p.Actions, req.Action) {
		return false
	}
	for k, want := range p.Conditions {
		have, ok := lookupAttr(req, k)
		if !ok || have != want {
			return false
		}
	}
	return true
}

// lookupAttr 解析条件键并取值。
func lookupAttr(req Request, key string) (string, bool) {
	const resPrefix = "resource."
	const subPrefix = "subject."
	switch {
	case len(key) > len(resPrefix) && key[:len(resPrefix)] == resPrefix:
		v, ok := req.ResourceAttrs[key[len(resPrefix):]]
		return v, ok
	case len(key) > len(subPrefix) && key[:len(subPrefix)] == subPrefix:
		v, ok := req.SubjectAttrs[key[len(subPrefix):]]
		return v, ok
	default:
		v, ok := req.SubjectAttrs[key]
		return v, ok
	}
}
