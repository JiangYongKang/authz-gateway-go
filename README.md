# authz-gateway-go

一套**本地运行**的授权判定与凭证生命周期管理服务。用内存存储模拟用户、角色、资源、
策略与凭证的完整流转，目标是让「授权结论、凭证续期、权限变更」在所有入口
（HTTP / 程序化调用 / 未来的 CLI 等）下**结论一致、原因可解释、默认安全**。

仅依赖 Go 标准库，无第三方依赖。

---

## 1. 目录结构

| 包 | 职责 |
|---|---|
| `internal/token` | HMAC-SHA256 三段式凭证（类 JWT）的签发与校验，输出**可区分的拒绝原因** |
| `internal/store` | 内存存储：用户/角色/资源/策略/密钥/会话；单把 `RWMutex`、容量上限、深拷贝 |
| `internal/authz` | RBAC + ABAC 判定器；默认拒绝、显式 deny 优先、与求值顺序无关；带 trace 与有界缓存 |
| `internal/audit` | 仅追加哈希链审计日志；敏感字段脱敏；容量上限 |
| `internal/service` | 编排层，统一入口：登录/校验/授权/续期/撤销/轮换，fail-closed |
| `internal/httpapi` | 本地 HTTP 接口，所有动作都走同一个 service |
| `cmd/authz-gateway` | 可运行的演示进程，启动时引导示例模型 |

---

## 2. 凭证模型

凭证为 `base64url(header).base64(payload).base64(signature)`，HMAC-SHA256 签名。

- 两类凭证严格区分：`access` 与 `refresh`，**不可互换**（载荷 `typ` 字段）。
- 载荷含：`iss/sub/sid/jti/kid/typ/iat/nbf/exp/roles/attrs`。
- 载荷里的 `roles/attrs` 只是**签发时刻快照**；授权判定永远读取存储中的最新角色/属性，
  不直接信任快照，因此权限变更无需等凭证过期即可生效。

### 2.1 固定的校验顺序（拒绝原因稳定、可区分）

凭证校验按以下顺序进行，第一个失败点即返回原因；**任何异常都返回拒绝，绝不降级放行**：

1. `malformed_token` —— 非三段式、base64/JSON 无法解析、关键字段缺失
2. `unsupported_alg` —— 头部算法不是 `HS256`（拒绝 `none` 等算法混淆）
3. `unknown_key` —— `kid` 在已知密钥集合中不存在
4. `bad_signature` —— 签名不匹配（凭证被篡改或签名密钥不一致）
5. 载荷 `kid` 与头部不一致也按篡改 → `bad_signature`
6. `issuer_mismatch` —— 签发者 `iss` 与本服务期望签发者不符
7. `not_before_valid` —— 未到 `nbf`
8. `expired` —— 当前时间 `>= exp`
9. `wrong_token_type` —— access/refresh 用错入口
10. `signing_key_revoked` —— 签名密钥已被撤销（即使签名本身正确）
11. `session_not_found` / `session_revoked` —— 会话不存在或已撤销/已旋转
12. `credential_version_stale` —— 凭证签发后用户权限/角色发生过变更或被撤销

> 一张凭证可能同时满足多个拒绝条件（例如既过期又被旋转）。系统按**固定顺序**
> 返回最靠前的原因，保证结论确定、可复现、可解释；调用方只需判断「非 ok 即拒绝」。

---

## 3. 授权模型（RBAC + ABAC）

- **主体(User)**：拥有若干角色与自定义属性（如 `team`）。
- **资源(Resource)**：有类型与属性（如 `owner_team`）。
- **策略(Policy)**：`角色 + 资源 + 动作集合 + 属性条件(AND) + effect(allow/deny)`。
  - 角色为空表示全局规则；资源为空表示任意资源；动作为空表示任意动作。
  - 条件键：`sub.attr.<k>`、`res.attr.<k>`、`sub.role`、`action`。
  - 无法证明的条件/未知条件键一律视为不满足。

### 3.1 判定合成规则（核心）

对策略集合求值后：

1. **默认拒绝**：没有任何规则匹配 → `deny(default_deny_no_match)`。
2. **显式拒绝优先（deny-overrides）**：只要存在一条匹配的 `deny`，无论有多少条
   `allow`、无论规则按什么顺序求值，结论恒为 `deny(explicit_deny_overrides)`。
3. 至少一条匹配 `allow` 且无任何匹配 `deny` → `permit(allow_rule_matched)`。

实现先**收集全部匹配结果再统一合成**（而非短路/首条命中），因此结论与规则在
map 中的迭代顺序、在列表中的先后位置完全无关。冲突场景在
`internal/authz/authz_test.go` 中以「allow 在前 / deny 在前 / 多条 allow 对一条 deny」
三种排列验证结论一致。

每次判定返回完整 **trace**：每条规则是否命中、未命中原因
（`role_not_held/action_not_matched/resource_not_matched/condition_failed`）、
每个条件的布尔结果，作为审计与排查依据。

### 3.2 判定缓存与可见性语义

- 判定器有可配置的有界缓存（`DecisionCache`），缓存键由**全部判定输入**
  （主体角色/属性、动作、资源属性、策略集合的规范化摘要）构成。
- 任何用户/资源/策略管理变更后，service 会调用 `Invalidate()` 清空缓存，
  保证「变更后新判定」不读旧结论；缓存满时**不驱逐、仅放弃写入**，绝不影响正确性。

---

## 4. 动态变更与即时撤销

- **用户撤销水位线 `RevokeBefore`**：管理员变更用户角色/属性或强制下线时前推水位线。
  凭证 `iat` 早于水位线、或会话记录的版本与当前水位线不一致 →
  `credential_version_stale`，**下一次判定立即失效**，不等 `exp`。
- **会话撤销**：登出/管理员撤销会话立即标记 `Revoked`；也可一次性撤销某用户全部会话。
- **策略紧急封禁（回退）**：运行期叠加一条 `deny` 立即压过既有 `allow`；删除后恢复。
- 管理面更新用户时会**保留服务端维护的撤销水位线**，避免外部写入把它清零导致凭证复活。

---

## 5. 密钥轮换语义

密钥有三态：`active`（可签发、可验证）、`retired`（只验不签）、`revoked`（立即失效）。

典型轮换流程（见 `TestKeyRotationLifecycle`）：

1. `AddKey(k2, active)`：引入新密钥。轮换**并存期**内 `k1`、`k2` 均可验证。
2. `RotateKey(k2)`：在**单个临界区**内把 `k2` 置为唯一 `active`，其余 `active`
   一律置为 `retired`。不存在「旧的已退役、新的未生效」的半更新窗口。
3. 轮换完成后：
   - `k1` 签发的**存量凭证在其有效期内仍可验证**（历史密钥保留用于验签）；
   - `retired` 密钥**不得再用于签发**（签发只取 `active`）。
4. 怀疑密钥泄露时 `RevokeKey(k2)`：该 `kid` 的所有凭证**立即**被拒绝
   （`signing_key_revoked`）。`revoked` 是终态，不能再被激活。

签发时若存在多把 `active`（并存窗口），确定性地选择创建时间最新者。

---

## 6. 续期（refresh）与并发安全

- refresh 凭证**一次性使用**。续期在**同一个存储临界区**内完成
  「校验当前 refresh jti + 摘除旧 access/refresh jti + 登记新 jti」
  （`RotateSessionTokensIfRefreshJTI`），消除先查后改的 TOCTOU 竞态。
- 并发重放同一 refresh：**恰好一次成功**，其余得到 `session_not_found`
  （`TestConcurrentRefresh_NoDoubleSpend`，`-race -count=5` 验证）。
- 续期后旧 access 与旧 refresh **同时立即失效**，已撤销凭证不会因续期复活。
- 会话使用稳定 `sid`，access/refresh 通过独立 jti 反向索引定位，旋转不改 sid。
- 全存储由单把 `RWMutex` 保护，多请求并发访问同一用户/会话/密钥时读取的是
  已提交的一致快照；并发轮换、撤销、授权不会出现半更新、重复计数或复活。

---

## 7. 审计

- 仅追加哈希链：每条记录包含 `prev_hash` 与自身内容的 SHA-256，
  事后增删改写任意一条都会被 `Audit.Verify()` / `GET /v1/audit/verify` 发现。
- **绝不写入敏感内容**：`token/access_token/refresh_token/secret/key_secret/password/
  authorization` 等键名，以及任何形如三段式凭证的值，落盘前统一替换为 `[REDACTED]`。
  记录中只保留主体、会话 ID、动作、资源、结论、原因与判定元信息（规则数、是否命中缓存等）。
- 审计容量可配；写满返回 `audit.ErrLogFull`。**授权路径上审计写失败按 fail-closed
  拒绝请求**（即使判定本身是 permit），见 `TestAuditFull_FailClosed`。

---

## 8. 容量上限与失败策略（fail-closed）

`store.Limits` 可限制用户/角色/资源/策略/会话/密钥数量：

- 超限返回 `ErrLimitExceeded`，且「先校验、后写入」，失败不留部分状态。
- 存储错误、审计错误、缺失密钥等一切「无法确定是否允许」的情况一律拒绝。
- 存储读路径返回深拷贝，调用方无法绕过锁改写内部状态。

---

## 9. HTTP 接口（本地）

| 方法 & 路径 | 说明 |
|---|---|
| `POST /v1/login` `{user_id}` | 签发 access/refresh 对 |
| `POST /v1/refresh` `{refresh_token}` | 一次性续期，旋转出新凭证对 |
| `POST /v1/logout` `{refresh_token}` | 撤销会话 |
| `POST /v1/authorize`（`Authorization: Bearer <access>`）`{action, resource_id}` | 校验 + 授权，返回结论与 trace |
| `GET  /v1/audit` | 导出审计条目（已脱敏） |
| `GET  /v1/audit/verify` | 校验哈希链完整性 |
| `GET  /healthz` | 健康检查 |

状态码：凭证/授权类拒绝 `403`（body 中 `error` 或 `reason` 可区分原因）；
请求格式 `400`；资源不存在 `404`；冲突 `409`；容量/审计不可用 `503`。

---

## 10. 验证方法

### 运行全部测试（建议带竞态检测）

```bash
go test ./...
go test -race -count=5 ./...
go vet ./...
```

测试以**安全场景**为主：过期/篡改/错误密钥/错误签发者凭证、冲突规则的顺序无关性、
密钥轮换并存与撤销、用户/会话即时撤销、refresh 重放、并发轮换与并发撤销、
策略紧急回退、容量上限与审计 fail-closed、哈希链篡改检出与敏感脱敏。
单测日志使用 `t.Logf` 打印**输入**与**判定依据**（每条规则与条件结果），用 `-v` 查看：

```bash
go test ./internal/authz/ -v      # 查看冲突规则的逐条 trace
go test ./internal/token/ -v      # 查看各类拒绝原因
go test ./internal/service/ -v    # 查看轮换/撤销/续期的输入与结论
```

### 本地启动演示进程

```bash
go run ./cmd/authz-gateway
```

另开终端：

```bash
BASE=http://127.0.0.1:8080
# 1) 登录（引导数据中有 alice: reader/team=platform）
LOGIN=$(curl -s -XPOST $BASE/v1/login -d '{"user_id":"alice"}')
AT=$(echo "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2) 授权：alice 同团队读 doc-1 => permit
curl -s -XPOST $BASE/v1/authorize -H "Authorization: Bearer $AT" \
  -d '{"action":"read","resource_id":"doc-1"}'

# 3) 访问 secret-1：全局显式 deny 压过一切 => 403 explicit_deny_overrides
curl -s -XPOST $BASE/v1/authorize -H "Authorization: Bearer $AT" \
  -d '{"action":"read","resource_id":"secret-1"}'

# 4) 查看审计（已脱敏）并校验哈希链
curl -s $BASE/v1/audit
curl -s $BASE/v1/audit/verify
```
