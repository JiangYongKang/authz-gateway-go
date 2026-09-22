// Package store 提供本地内存存储，模拟用户、角色、资源、策略、签名密钥与
// 会话/凭证状态的完整流转。所有变更都通过单一互斥串行化，以保证并发下的
// 原子性与一致可见性：不存在半更新状态，也不存在跨操作的中间读。
package store

import (
	"sort"
	"sync"
	"time"
)

// 存储层错误。
var (
	ErrNotFound      = errStore("store: not found")
	ErrAlreadyExists = errStore("store: already exists")
	ErrLimitExceeded = errStore("store: configured capacity limit exceeded")
	ErrConflict      = errStore("store: optimistic concurrency conflict")
	ErrStorageFault  = errStore("store: simulated storage failure")
	ErrKeyRetired    = errStore("store: key retired and cannot sign")
)

type errStore string

func (e errStore) Error() string { return string(e) }

// User 是本地身份目录中的一个主体。
type User struct {
	Name       string
	Roles      []string
	Attributes map[string]string
}

// Resource 是受保护资源。
type Resource struct {
	Name       string
	Kind       string
	Owner      string
	Attributes map[string]string
}

// KeyState 表示签名密钥在轮换生命周期中的状态。
type KeyState int

const (
	// KeyActive 可用于签发与验签。
	KeyActive KeyState = iota
	// KeyNext 为已登记的“下一任”密钥，可验签但不用于签发。
	KeyNext
	// KeyRetired 已退役，只保留验签能力，不得再签发。
	KeyRetired
)

// String 返回密钥状态的可读名称。
func (k KeyState) String() string {
	switch k {
	case KeyActive:
		return "active"
	case KeyNext:
		return "next"
	case KeyRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// KeyInfo 描述一个签名密钥的元数据（不含密钥明文）。
type KeyInfo struct {
	ID        string
	State     KeyState
	CreatedAt time.Time
	RetiredAt time.Time
}

// Session 保存一次登录签发出来的凭证生命周期状态。
//
// 撤销：Revoked=true 且 CurrentJTI 置空，任何凭证立刻无法通过校验。
// 续期：以 CAS 方式用新 JTI/新版本替换旧值，并发下只有一个续期成功，
// 旧 JTI 立即失效，杜绝已撤销凭证复活或重复计数。
type Session struct {
	ID          string
	Username    string
	CurrentJTI  string
	CredVersion int64
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Revoked     bool
	RevokedAt   time.Time
	Attributes  map[string]string
}

// Policy 是一条授权规则。Deny=true 为显式拒绝，其优先级恒高于允许。
type Policy struct {
	ID         string
	Version    int64
	Deny       bool
	Roles      []string
	Users      []string
	Resources  []string
	Actions    []string
	Conditions map[string]string
	CreatedAt  time.Time
}

type keyEntry struct {
	info   KeyInfo
	secret []byte
}

// Store 是内存存储。
type Store struct {
	mu           sync.Mutex
	users        map[string]User
	resources    map[string]Resource
	policies     map[string]Policy
	keys         map[string]*keyEntry
	sessions     map[string]*Session
	authzVersion int64
	failNext     int
	now          func() time.Time

	maxUsers     int
	maxResources int
	maxPolicies  int
	maxSessions  int
	maxKeys      int
}

// New 创建空存储（不设容量上限）；需要上限时用 NewBounded。
func New() *Store {
	return NewBounded(0, 0, 0, 0, 0)
}

// NewBounded 创建带各类上限的存储，上限<=0 表示该类不限。
func NewBounded(maxUsers, maxResources, maxPolicies, maxSessions, maxKeys int) *Store {
	return &Store{
		users:        make(map[string]User),
		resources:    make(map[string]Resource),
		policies:     make(map[string]Policy),
		keys:         make(map[string]*keyEntry),
		sessions:     make(map[string]*Session),
		now:          time.Now,
		maxUsers:     maxUsers,
		maxResources: maxResources,
		maxPolicies:  maxPolicies,
		maxSessions:  maxSessions,
		maxKeys:      maxKeys,
	}
}

// SetClock 注入时间源（测试用）。
func (s *Store) SetClock(f func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = f
}

// failWrite 在故障注入开启时消费一次失败配额并返回 true。
// 必须在任何状态修改之前调用，从而保证失败时无部分写入。
func (s *Store) failWrite() bool {
	if s.failNext > 0 {
		s.failNext--
		return true
	}
	return false
}

// SetFailNext 让下 n 次写操作返回 ErrStorageFault。
func (s *Store) SetFailNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = n
}

func cloneStrings(in []string) []string {
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

// bumpAuthzVersion 在影响授权结论的变更发生时推进版本号。
func (s *Store) bumpAuthzVersion() { s.authzVersion++ }

// ---- 用户 ----

// PutUser 创建或更新用户；任何成功变更都提升授权版本。
func (s *Store) PutUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.users[u.Name]; !ok && s.maxUsers > 0 && len(s.users) >= s.maxUsers {
		return ErrLimitExceeded
	}
	s.users[u.Name] = User{
		Name:       u.Name,
		Roles:      cloneStrings(u.Roles),
		Attributes: cloneAttrs(u.Attributes),
	}
	s.bumpAuthzVersion()
	return nil
}

func (s *Store) GetUser(name string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Roles = cloneStrings(u.Roles)
	u.Attributes = cloneAttrs(u.Attributes)
	return u, nil
}

func (s *Store) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.users[name]; !ok {
		return ErrNotFound
	}
	delete(s.users, name)
	s.bumpAuthzVersion()
	return nil
}

func (s *Store) ListUsers() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.users))
	for n := range s.users {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]User, 0, len(names))
	for _, n := range names {
		u := s.users[n]
		u.Roles = cloneStrings(u.Roles)
		u.Attributes = cloneAttrs(u.Attributes)
		out = append(out, u)
	}
	return out, nil
}

// ---- 资源 ----

func (s *Store) PutResource(r Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.resources[r.Name]; !ok && s.maxResources > 0 && len(s.resources) >= s.maxResources {
		return ErrLimitExceeded
	}
	s.resources[r.Name] = Resource{
		Name:       r.Name,
		Kind:       r.Kind,
		Owner:      r.Owner,
		Attributes: cloneAttrs(r.Attributes),
	}
	s.bumpAuthzVersion()
	return nil
}

func (s *Store) GetResource(name string) (Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resources[name]
	if !ok {
		return Resource{}, ErrNotFound
	}
	r.Attributes = cloneAttrs(r.Attributes)
	return r, nil
}

func (s *Store) DeleteResource(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.resources[name]; !ok {
		return ErrNotFound
	}
	delete(s.resources, name)
	s.bumpAuthzVersion()
	return nil
}

// ---- 策略 ----

// PutPolicy 创建或更新策略并返回存储后的副本。版本号由调用方在更新时推进，
// 存储层同时提升整体授权版本。
func (s *Store) PutPolicy(p Policy) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return Policy{}, ErrStorageFault
	}
	if _, ok := s.policies[p.ID]; !ok && s.maxPolicies > 0 && len(s.policies) >= s.maxPolicies {
		return Policy{}, ErrLimitExceeded
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = s.now()
	}
	p.Roles = cloneStrings(p.Roles)
	p.Users = cloneStrings(p.Users)
	p.Resources = cloneStrings(p.Resources)
	p.Actions = cloneStrings(p.Actions)
	p.Conditions = cloneAttrs(p.Conditions)
	s.policies[p.ID] = p
	s.bumpAuthzVersion()
	return p, nil
}

func (s *Store) GetPolicy(id string) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok {
		return Policy{}, ErrNotFound
	}
	return clonePolicy(p), nil
}

func clonePolicy(p Policy) Policy {
	p.Roles = cloneStrings(p.Roles)
	p.Users = cloneStrings(p.Users)
	p.Resources = cloneStrings(p.Resources)
	p.Actions = cloneStrings(p.Actions)
	p.Conditions = cloneAttrs(p.Conditions)
	return p
}

func (s *Store) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.policies[id]; !ok {
		return ErrNotFound
	}
	delete(s.policies, id)
	s.bumpAuthzVersion()
	return nil
}

func (s *Store) ListPolicies() ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Policy, 0, len(ids))
	for _, id := range ids {
		out = append(out, clonePolicy(s.policies[id]))
	}
	return out, nil
}

// AuthzVersion 在任何影响授权结论的变更后单调递增，用于缓存一致性。
func (s *Store) AuthzVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authzVersion
}

// ---- 签名密钥 ----

// PutKeySecret 登记密钥及其初始状态。
func (s *Store) PutKeySecret(id string, secret []byte, state KeyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.keys[id]; !ok && s.maxKeys > 0 && len(s.keys) >= s.maxKeys {
		return ErrLimitExceeded
	}
	sec := make([]byte, len(secret))
	copy(sec, secret)
	s.keys[id] = &keyEntry{
		info:   KeyInfo{ID: id, State: state, CreatedAt: s.now()},
		secret: sec,
	}
	return nil
}

func (s *Store) GetKeySecret(id string) ([]byte, KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, 0, ErrNotFound
	}
	out := make([]byte, len(k.secret))
	copy(out, k.secret)
	return out, k.info.State, nil
}

func (s *Store) ListKeys() ([]KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return s.keys[ids[i]].info.CreatedAt.Before(s.keys[ids[j]].info.CreatedAt) ||
			(s.keys[ids[i]].info.CreatedAt.Equal(s.keys[ids[j]].info.CreatedAt) && ids[i] < ids[j])
	})
	out := make([]KeyInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.keys[id].info)
	}
	return out, nil
}

// ActiveSigningKey 返回当前唯一可用于签发的密钥（id 与 secret 副本）。
func (s *Store) ActiveSigningKey() (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.keys {
		if k.info.State == KeyActive {
			sec := make([]byte, len(k.secret))
			copy(sec, k.secret)
			return id, sec, nil
		}
	}
	return "", nil, ErrNotFound
}

// RotateKeys 原子完成轮换：next -> active（用于签发），旧 active -> retired
// （仅验签，不得再签发）。nextID 必须处于 next 状态。返回新签发密钥 id。
func (s *Store) RotateKeys(nextID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return "", ErrStorageFault
	}
	nxt, ok := s.keys[nextID]
	if !ok {
		return "", ErrNotFound
	}
	if nxt.info.State != KeyNext {
		return "", ErrConflict
	}
	for _, k := range s.keys {
		if k.info.State == KeyActive {
			k.info.State = KeyRetired
			k.info.RetiredAt = s.now()
		}
	}
	nxt.info.State = KeyActive
	// 轮换属于安全边界变更：推进授权版本，使任何旧判定缓存立即失效。
	s.bumpAuthzVersion()
	return nextID, nil
}

// RetireKey 将密钥彻底退役：从存储移除，之后连验签也不再支持。
func (s *Store) RetireKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	k, ok := s.keys[id]
	if !ok {
		return ErrNotFound
	}
	k.info.State = KeyRetired
	k.info.RetiredAt = s.now()
	delete(s.keys, id)
	return nil
}

// ---- 会话 / 凭证状态 ----

// CreateSession 登记新会话。
func (s *Store) CreateSession(sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	if _, ok := s.sessions[sess.ID]; ok {
		return ErrAlreadyExists
	}
	if s.maxSessions > 0 && len(s.sessions) >= s.maxSessions {
		return ErrLimitExceeded
	}
	sess.Attributes = cloneAttrs(sess.Attributes)
	s.sessions[sess.ID] = &sess
	return nil
}

func (s *Store) GetSession(id string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	out := *sess
	out.Attributes = cloneAttrs(sess.Attributes)
	return out, nil
}

// RenewSessionCAS 以 CAS 方式把会话的 (oldJTI,oldVersion) 更新为新值。
// 若会话不存在、已撤销、或现存版本与预期不符，返回 ErrConflict/ErrNotFound，
// 状态保持不变。
func (s *Store) RenewSessionCAS(id, oldJTI string, oldVersion int64, newJTI string, newExpiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	sess, ok := s.sessions[id]
	if !ok {
		return ErrNotFound
	}
	if sess.Revoked {
		return ErrConflict
	}
	if sess.CurrentJTI != oldJTI || sess.CredVersion != oldVersion {
		return ErrConflict
	}
	sess.CurrentJTI = newJTI
	sess.CredVersion++
	sess.ExpiresAt = newExpiry
	return nil
}

// RevokeSession 原子撤销会话：撤销标记与 JTI 清空在同一临界区内完成，
// 并提升授权版本，使任何缓存的正面结论立即失效。
func (s *Store) RevokeSession(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWrite() {
		return ErrStorageFault
	}
	sess, ok := s.sessions[id]
	if !ok {
		return ErrNotFound
	}
	if !sess.Revoked {
		sess.Revoked = true
		sess.RevokedAt = at
		sess.CurrentJTI = ""
		sess.CredVersion++
		s.bumpAuthzVersion()
	}
	return nil
}

// DeleteSession 删除会话（仅用于签发失败时的内部补偿）。
func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return ErrNotFound
	}
	delete(s.sessions, id)
	return nil
}
