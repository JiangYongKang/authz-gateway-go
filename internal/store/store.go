// Package store 是授权网关的本地内存存储（生产环境可用持久化实现替换同一接口）。
//
// 一致性模型：
//   - 单一互斥锁保护全部映射，任何多对象变更在持锁期间完成，
//     不会出现半更新状态；读路径使用读锁并永远读取已提交的最新状态，
//     因此权限/角色撤销在“下一次判定”立即生效，无需等待凭证过期。
//   - 所有集合均有可配置数量上限，超限时返回 ErrLimitExceeded，
//     且变更在写入前完成校验，失败不留任何部分写入。
//   - 不返回内部 map/slice，所有读出值均为深拷贝，调用方无法绕过锁改写状态。
package store

import (
	"errors"
	"sync"
	"time"
)

// 预定义错误。调用方按错误值区分拒绝原因。
var (
	ErrNotFound         = errors.New("store: not found")
	ErrAlreadyExists    = errors.New("store: already exists")
	ErrLimitExceeded    = errors.New("store: configured limit exceeded")
	ErrNoActiveKey      = errors.New("store: no active signing key")
	ErrSessionRevoked   = errors.New("store: session revoked")
	ErrStaleVersion     = errors.New("store: credential version stale (user/role revoked or changed)")
	ErrUnknownTokenType = errors.New("store: unknown token type")
)

// Effect 是策略效果。Deny 永远优先于 Allow。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// User 是主体。Roles 为角色 ID 列表；Attrs 为主体属性（供 ABAC 条件使用）。
// RevokeBefore 为“撤销水位线”：签发时间早于该时刻的凭证一律失效，
// 这使得管理员对用户的权限/角色变更可立即作用于其所有存量凭证。
type User struct {
	ID           string
	Roles        []string
	Attrs        map[string]string
	RevokeBefore time.Time
}

// Resource 是受保护对象。Attrs 供 ABAC 条件使用（如 owner、env、tier）。
type Resource struct {
	ID    string
	Kind  string
	Attrs map[string]string
}

// Policy 是单条授权规则。
//   - Roles 非空时表示规则仅适用于这些角色；为空表示适用于任意角色。
//   - Actions 非空时按动作匹配；为空表示匹配该资源上的任意动作。
//   - Conditions 为属性相等约束，键形如 "sub.team" / "res.owner" / "sub.role"；
//     特殊键 "sub.role" 对用户任一角色成立即可。所有条件须同时满足(AND)。
//   - 条件求值结果只用于挑选 allow/deny 规则，最终结论统一由求值器决定，
//     规则在策略列表中的先后顺序不影响结论（见 authz 包）。
type Policy struct {
	ID         string
	RoleID     string // 规则挂载的角色（空串表示全局规则）
	ResourceID string // 空串表示适用于任意资源
	Actions    []string
	Effect     Effect
	Conditions map[string]string
	Priority   int // 仅用于审计展示；结论不依赖求值顺序
}

// KeyState 表示签名密钥生命周期状态。
type KeyState string

const (
	KeyActive  KeyState = "active"  // 可签发、可验证
	KeyRetired KeyState = "retired" // 轮换退役：仅可验证历史凭证，不得再签发
	KeyRevoked KeyState = "revoked" // 密钥疑似泄露：连带凭证立即失效
)

// SigningKey 是 HMAC 密钥材料及其状态。Secret 绝不可进入审计日志。
type SigningKey struct {
	ID        string
	Secret    []byte
	State     KeyState
	CreatedAt time.Time
}

// Session 记录一次登录会话及其两张凭证的元信息。
// ID 是会话的稳定标识（凭证 sid），续期旋转 jti 时会话 ID 不变；
// RefreshJTI / AccessJTI 是当前有效凭证的一次性标识，续期后旧 jti 立即失效。
type Session struct {
	ID          string
	UserID      string
	RefreshJTI  string
	AccessJTI   string
	CreatedAt   time.Time
	UserVersion time.Time // 最近一次签发时用户的 RevokeBefore 快照
	Revoked     bool
}

// Limits 配置各类对象的数量上限；零值字段表示沿用 DefaultLimits。
type Limits struct {
	MaxUsers     int
	MaxRoles     int // 角色数量（角色以名字为 ID，存储仅做集合管理）
	MaxResources int
	MaxPolicies  int
	MaxSessions  int
	MaxKeys      int
}

// DefaultLimits 给出保守默认上限。
func DefaultLimits() Limits {
	return Limits{
		MaxUsers: 1000, MaxRoles: 100, MaxResources: 1000,
		MaxPolicies: 1000, MaxSessions: 10000, MaxKeys: 32,
	}
}

func (l Limits) orDefault() Limits {
	d := DefaultLimits()
	if l.MaxUsers <= 0 {
		l.MaxUsers = d.MaxUsers
	}
	if l.MaxRoles <= 0 {
		l.MaxRoles = d.MaxRoles
	}
	if l.MaxResources <= 0 {
		l.MaxResources = d.MaxResources
	}
	if l.MaxPolicies <= 0 {
		l.MaxPolicies = d.MaxPolicies
	}
	if l.MaxSessions <= 0 {
		l.MaxSessions = d.MaxSessions
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = d.MaxKeys
	}
	return l
}

// Store 是内存存储。
type Store struct {
	mu           sync.RWMutex
	users        map[string]*User
	roles        map[string]struct{}
	resources    map[string]*Resource
	policies     map[string]*Policy
	sessions     map[string]*Session
	refreshIndex map[string]string // refresh jti -> 稳定会话 ID（续期时原子替换）
	accessIndex  map[string]string // access jti -> 稳定会话 ID
	keys         map[string]*SigningKey
	limits       Limits
}

// New 以给定上限创建空存储。
func New(limits Limits) *Store {
	return &Store{
		users:        map[string]*User{},
		roles:        map[string]struct{}{},
		resources:    map[string]*Resource{},
		policies:     map[string]*Policy{},
		sessions:     map[string]*Session{},
		refreshIndex: map[string]string{},
		accessIndex:  map[string]string{},
		keys:         map[string]*SigningKey{},
		limits:       limits.orDefault(),
	}
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneAttrs(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func cloneUser(u *User) *User {
	return &User{ID: u.ID, Roles: cloneStringSlice(u.Roles), Attrs: cloneAttrs(u.Attrs), RevokeBefore: u.RevokeBefore}
}

func cloneResource(r *Resource) *Resource {
	return &Resource{ID: r.ID, Kind: r.Kind, Attrs: cloneAttrs(r.Attrs)}
}

func clonePolicy(p *Policy) *Policy {
	return &Policy{
		ID: p.ID, RoleID: p.RoleID, ResourceID: p.ResourceID,
		Actions: cloneStringSlice(p.Actions), Effect: p.Effect,
		Conditions: cloneAttrs(p.Conditions), Priority: p.Priority,
	}
}

func cloneKey(k *SigningKey) *SigningKey {
	return &SigningKey{ID: k.ID, Secret: cloneBytes(k.Secret), State: k.State, CreatedAt: k.CreatedAt}
}

func cloneSession(s *Session) *Session {
	cp := *s
	return &cp
}

// ---- 用户 ----

// CreateUser 在容量允许时新增用户；ID 重复返回 ErrAlreadyExists。
func (s *Store) CreateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if u.ID == "" {
		return errors.New("store: empty user id")
	}
	if len(s.users) >= s.limits.MaxUsers {
		return ErrLimitExceeded
	}
	if _, ok := s.users[u.ID]; ok {
		return ErrAlreadyExists
	}
	s.users[u.ID] = cloneUser(&u)
	return nil
}

// GetUser 返回用户深拷贝；不存在返回 ErrNotFound。
func (s *Store) GetUser(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneUser(u), nil
}

// UpdateUser 全量替换用户字段（用于角色/属性动态变更）。
func (s *Store) UpdateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[u.ID]; !ok {
		return ErrNotFound
	}
	s.users[u.ID] = cloneUser(&u)
	return nil
}

// RevokeUserCredentials 将用户的撤销水位线前推到 now，
// 使所有 iat < now 的存量凭证在下一次校验时立即失效。
func (s *Store) RevokeUserCredentials(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return ErrNotFound
	}
	if now.After(u.RevokeBefore) {
		u.RevokeBefore = now
	}
	return nil
}

// ---- 角色 ----

// CreateRole 登记一个角色 ID（空角色集合即“无任何权限”）。
func (s *Store) CreateRole(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "" {
		return errors.New("store: empty role id")
	}
	if _, ok := s.roles[id]; ok {
		return ErrAlreadyExists
	}
	if len(s.roles) >= s.limits.MaxRoles {
		return ErrLimitExceeded
	}
	s.roles[id] = struct{}{}
	return nil
}

// HasRole 判断角色是否存在。
func (s *Store) HasRole(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.roles[id]
	return ok
}

// RoleCount 返回角色数量。
func (s *Store) RoleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.roles)
}

// ---- 资源 ----

// CreateResource 新增资源定义。
func (s *Store) CreateResource(r Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.ID == "" {
		return errors.New("store: empty resource id")
	}
	if _, ok := s.resources[r.ID]; ok {
		return ErrAlreadyExists
	}
	if len(s.resources) >= s.limits.MaxResources {
		return ErrLimitExceeded
	}
	s.resources[r.ID] = cloneResource(&r)
	return nil
}

// GetResource 返回资源深拷贝。
func (s *Store) GetResource(id string) (*Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.resources[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneResource(r), nil
}

// ---- 策略 ----

// PutPolicy 新增或替换策略（按 ID 幂等）。新增超限时返回 ErrLimitExceeded。
func (s *Store) PutPolicy(p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.ID == "" {
		return errors.New("store: empty policy id")
	}
	if p.Effect != EffectAllow && p.Effect != EffectDeny {
		return errors.New("store: invalid policy effect")
	}
	if _, ok := s.policies[p.ID]; !ok {
		if len(s.policies) >= s.limits.MaxPolicies {
			return ErrLimitExceeded
		}
	}
	s.policies[p.ID] = clonePolicy(&p)
	return nil
}

// DeletePolicy 删除策略；不存在返回 ErrNotFound。
func (s *Store) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[id]; !ok {
		return ErrNotFound
	}
	delete(s.policies, id)
	return nil
}

// ListPolicies 返回全部策略的深拷贝，顺序按 ID 排序，
// 保证不同调用/不同 map 迭代顺序下求值输入一致。
func (s *Store) ListPolicies() []*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Policy, 0, len(s.policies))
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		out = append(out, clonePolicy(s.policies[id]))
	}
	return out
}

// ---- 签名密钥（轮换）----

// AddKey 登记一把密钥。轮换流程：
//  1. AddKey(active) 引入新密钥（此时旧密钥可先保持 active，二者并存）；
//  2. RotateActiveKey 将旧 active 置为 retired（只验不签），新密钥成为唯一 active；
//  3. retired 密钥永远无法再回到 active，历史凭证在其有效期内仍可验证；
//  4. 疑似泄露时 RevokeKey 立即拒绝该 kid 的一切凭证。
func (s *Store) AddKey(k SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if k.ID == "" {
		return errors.New("store: empty key id")
	}
	if len(k.Secret) == 0 {
		return errors.New("store: empty key secret")
	}
	if k.State != KeyActive && k.State != KeyRetired && k.State != KeyRevoked {
		return errors.New("store: invalid key state")
	}
	if _, ok := s.keys[k.ID]; ok {
		return ErrAlreadyExists
	}
	if len(s.keys) >= s.limits.MaxKeys {
		return ErrLimitExceeded
	}
	s.keys[k.ID] = cloneKey(&k)
	return nil
}

// GetKey 返回密钥深拷贝。
func (s *Store) GetKey(id string) (*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.keys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneKey(k), nil
}

// ActiveKey 返回当前唯一可用于签发的密钥；不存在或全部退役返回 ErrNoActiveKey。
func (s *Store) ActiveKey() (*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*SigningKey
	for _, k := range s.keys {
		if k.State == KeyActive {
			active = append(active, k)
		}
	}
	if len(active) == 0 {
		return nil, ErrNoActiveKey
	}
	// active 多于一把时，以创建时间最新者为准（轮换并存期的确定性选择）。
	pick := active[0]
	for _, k := range active[1:] {
		if k.CreatedAt.After(pick.CreatedAt) {
			pick = k
		}
	}
	return cloneKey(pick), nil
}

// RotateActiveKey 原子地把 newKeyID 置为 active，其余 active 置为 retired。
// 新密钥必须事先 AddKey。整个过程持同一把锁，不存在“旧密钥已退役但新密钥未生效”的窗口。
func (s *Store) RotateActiveKey(newKeyID string) (*SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nk, ok := s.keys[newKeyID]
	if !ok {
		return nil, ErrNotFound
	}
	if nk.State == KeyRevoked {
		return nil, errors.New("store: cannot activate revoked key")
	}
	for _, k := range s.keys {
		if k.ID == newKeyID {
			k.State = KeyActive
		} else if k.State == KeyActive {
			k.State = KeyRetired // 单向：retired 永不再签
		}
	}
	return cloneKey(nk), nil
}

// RetireKey 将指定密钥置为 retired（只验不签）。
func (s *Store) RetireKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.keys[id]
	if !ok {
		return ErrNotFound
	}
	if k.State == KeyRevoked {
		return errors.New("store: cannot retire revoked key")
	}
	k.State = KeyRetired
	return nil
}

// RevokeKey 将密钥置为 revoked，其全部凭证立即失效。
func (s *Store) RevokeKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.keys[id]
	if !ok {
		return ErrNotFound
	}
	k.State = KeyRevoked
	return nil
}

// VerifyKeySecret 供凭证验签阶段使用：返回密钥副本与状态。
// 找不到返回 ErrNotFound；revoked 密钥的凭证必须被拒绝。
func (s *Store) VerifyKeySecret(id string) (*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.keys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneKey(k), nil
}

// KeyCount 返回密钥数量。
func (s *Store) KeyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// ---- 会话与凭证生命周期 ----

// CreateSessionInput 是建会话输入。ID 为稳定会话 ID（为空则由调用方生成）。
type CreateSessionInput struct {
	ID          string
	UserID      string
	RefreshJTI  string
	AccessJTI   string
	CreatedAt   time.Time
	UserVersion time.Time
}

// CreateSession 原子登记新会话及其双 jti 索引。
// 超限时返回 ErrLimitExceeded，索引与会话在同一临界区内建立，不留部分状态。
func (s *Store) CreateSession(in CreateSessionInput) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if in.ID == "" || in.UserID == "" || in.RefreshJTI == "" || in.AccessJTI == "" {
		return nil, errors.New("store: incomplete session input")
	}
	if _, ok := s.users[in.UserID]; !ok {
		return nil, ErrNotFound
	}
	if _, dup := s.sessions[in.ID]; dup {
		return nil, ErrAlreadyExists
	}
	if _, dup := s.refreshIndex[in.RefreshJTI]; dup {
		return nil, ErrAlreadyExists
	}
	if _, dup := s.accessIndex[in.AccessJTI]; dup {
		return nil, ErrAlreadyExists
	}
	if len(s.sessions) >= s.limits.MaxSessions {
		return nil, ErrLimitExceeded
	}
	sess := &Session{
		ID:          in.ID,
		UserID:      in.UserID,
		RefreshJTI:  in.RefreshJTI,
		AccessJTI:   in.AccessJTI,
		CreatedAt:   in.CreatedAt,
		UserVersion: in.UserVersion,
	}
	s.sessions[in.ID] = sess
	s.refreshIndex[in.RefreshJTI] = in.ID
	s.accessIndex[in.AccessJTI] = in.ID
	return cloneSession(sess), nil
}

// GetSession 返回会话副本。
func (s *Store) GetSession(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSession(sess), nil
}

// RevokeSession 按稳定会话 ID 撤销单个会话（登出/管理员强制下线）。
// 撤销是终态：重复撤销同一 ID 幂等成功，不会让调用方误以为会话复活。
func (s *Store) RevokeSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[id]; ok {
		sess.Revoked = true
		return nil
	}
	return ErrNotFound
}

// RevokeSessionByJTI 按 refresh 或 access jti 撤销会话（凭证级登出）。
func (s *Store) RevokeSessionByJTI(jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sid, ok := s.refreshIndex[jti]
	if !ok {
		sid, ok = s.accessIndex[jti]
	}
	if !ok {
		return ErrNotFound
	}
	s.sessions[sid].Revoked = true
	return nil
}

// RevokeAllUserSessions 撤销某用户的全部会话（管理员强制全部下线）。
// 返回受影响会话数。
func (s *Store) RevokeAllUserSessions(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			sess.Revoked = true
			n++
		}
	}
	return n
}

// SessionByRefreshJTI 按 refresh 凭证 jti 定位会话（续期入口使用）。
func (s *Store) SessionByRefreshJTI(jti string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sid, ok := s.refreshIndex[jti]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSession(s.sessions[sid]), nil
}

// SessionByAccessJTI 按 access 凭证 jti 定位会话。
func (s *Store) SessionByAccessJTI(jti string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sid, ok := s.accessIndex[jti]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSession(s.sessions[sid]), nil
}

// ValidateSessionAccess 在签发/校验访问凭证的共享路径上检查会话与用户版本：
//   - 会话必须存在且未撤销；
//   - 凭证携带的用户版本(userVersion=签发时用户 RevokeBefore)必须等于当前水位线，
//     否则说明签发后发生过角色/权限变更或撤销 → 立即拒绝。
//
// 返回当前用户深拷贝供判定使用。
func (s *Store) ValidateSessionAccess(sessionID string) (*User, *Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if sess.Revoked {
		return nil, nil, ErrSessionRevoked
	}
	u := s.users[sess.UserID]
	if u == nil {
		return nil, nil, ErrNotFound
	}
	if !sess.UserVersion.Equal(u.RevokeBefore) {
		return nil, nil, ErrStaleVersion
	}
	return cloneUser(u), cloneSession(sess), nil
}

// BumpSessionUserVersion 在续期时把会话版本对齐到用户当前水位线，
// 前提是用户当前未被撤销（由调用方先检查 RevokeBefore 与凭证 iat 的关系）。
func (s *Store) BumpSessionUserVersion(sessionID string, userVersion time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	sess.UserVersion = userVersion
	return nil
}

// SessionCount 返回会话数量。
func (s *Store) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// CheckAccessJTI 校验 access 凭证 jti 是否仍是该会话的当前有效 access。
// 会话已撤销返回 ErrSessionRevoked；jti 已被续期旋转掉返回 ErrNotFound。
func (s *Store) CheckAccessJTI(sessionID, accessJTI string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if sess.AccessJTI != accessJTI {
		return nil, ErrNotFound
	}
	return cloneSession(sess), nil
}

// CheckRefreshJTI 校验 refresh 凭证 jti 是否仍是该会话的当前有效 refresh。
func (s *Store) CheckRefreshJTI(sessionID, refreshJTI string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if sess.RefreshJTI != refreshJTI {
		return nil, ErrNotFound
	}
	return cloneSession(sess), nil
}

// ReplaceResource 全量替换已存在的资源定义（保留同一 ID）。
func (s *Store) ReplaceResource(r Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.resources[r.ID]; !ok {
		return ErrNotFound
	}
	s.resources[r.ID] = cloneResource(&r)
	return nil
}

// RotateSessionTokensIfRefreshJTI 在同一临界区内完成“校验当前 refresh jti + 原子旋转”，
// 消除先查后改的 TOCTOU 竞态：并发重放同一 refresh 凭证时，只有一个调用能成功。
//   - 会话不存在        => ErrNotFound
//   - 会话已撤销        => ErrSessionRevoked
//   - oldRefreshJTI 与当前不符（已被旋转掉）=> ErrNotFound
func (s *Store) RotateSessionTokensIfRefreshJTI(sessionID, oldRefreshJTI, newRefreshJTI, newAccessJTI string, userVersion time.Time) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if sess.RefreshJTI != oldRefreshJTI {
		return nil, ErrNotFound
	}
	if _, dup := s.refreshIndex[newRefreshJTI]; dup {
		return nil, ErrAlreadyExists
	}
	if _, dup := s.accessIndex[newAccessJTI]; dup {
		return nil, ErrAlreadyExists
	}
	delete(s.refreshIndex, sess.RefreshJTI)
	delete(s.accessIndex, sess.AccessJTI)
	sess.RefreshJTI = newRefreshJTI
	sess.AccessJTI = newAccessJTI
	sess.UserVersion = userVersion
	s.refreshIndex[newRefreshJTI] = sessionID
	s.accessIndex[newAccessJTI] = sessionID
	return cloneSession(sess), nil
}
