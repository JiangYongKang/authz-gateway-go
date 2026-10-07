# authz-gateway-go

本地运行的**授权判定与凭证生命周期管理服务**。用本地内存存储模拟用户、角色、
资源、策略、签名密钥与会话/凭证的完整流转，目标是让授权结论、凭证续期与
权限变更在所有入口（Go API、HTTP）下保持**一致、可解释、可审计**。

仅依赖 Go 标准库。

---

## 1. 组件与目录

| 包 | 职责 |
| --- | --- |
| `internal/token` | HS256（JWT 紧凑序列化）凭证的签发、解析与验签，返回**可区分**的哨兵错误 |
| `internal/store` | 内存存储：用户/资源/策略/密钥/会话；单锁串行化、容量上限、故障注入、CAS 续期、原子轮换 |
| `internal/authz` | 无状态 RBAC+ABAC 判定引擎；默认拒绝、显式拒绝优先、顺序无关 |
| `internal/audit` | 有界、只追加、不可改写的审计日志（防御性拷贝）；自包含证据导出与离线核验 |
| `internal/cache` | 有容量上限、带 TTL 的 LRU 正面判定缓存 |
| `internal/config` | 判定规模与容量上限配置 |
| `internal/gateway` | 编排层：签发/校验/续期/撤销/轮换/判定/审计，所有入口共享同一套逻辑 |
| `internal/httpserver` | 本地 HTTP JSON 入口 |
| `cmd/authz-gateway` | 可直接运行的演示服务（含种子数据） |

---

## 2. 凭证模型

凭证形态为 `base64url(header).base64url(claims).HMAC-SHA256`，声明包含：

`iss / sub / iat / nbf / exp / jti / sid / attr`。

凭证**不是**持票即信：除常规 JWT 校验外，服务端会话还保存凭证的
**当前版本标识** `(CurrentJTI, CredVersion)`。判定时强制要求凭证中的 `jti`
等于会话当前 JTI，因此：

- 续期后旧 JTI 立即失效（`credential_superseded`），旧凭证不会复活；
- 撤销把会话标记为 revoked 并清空当前 JTI，一切凭证立即失效
  （`session_revoked`），无须等待自然过期。

### 2.1 校验链（顺序固定，任一失败即拒绝，绝不放行）

1. 结构非法 / 不是三段 / 字段不可解码 → `token_malformed`
2. `alg` 非 `HS256`、`typ` 非 `JWT`（含 `alg=none` 混淆）→ `bad_signature`
3. header 中的 `kid` 在密钥库中不存在（已彻底退役）→ `unknown_signing_key`
4. HMAC 常量时间比对失败（篡改、密钥不匹配）→ `bad_signature`
5. `iss` 与期望签发者不一致 → `issuer_mismatch`
6. `nbf` 未到 → `token_not_valid_yet`；`exp` 已过 → `token_expired`
7. 会话不存在 → `session_missing`
8. 会话已撤销 → `session_revoked`
9. 凭证 JTI 不是会话当前 JTI（被续期取代）→ `credential_superseded`
10. 服务端会话过期时间已到 → `token_expired`

这些原因码在 Go API（错误链 `gateway.ReasonOf(err)`）与 HTTP 响应体
`reason` 字段中完全一致。

### 2.2 续期语义

- 只能用“当前有效”的凭证续期；新凭证在锁外用当前 active 密钥预签，
  随后以 **CAS**（`sid + oldJTI + oldVersion`）原子切换会话状态。
- 并发续期：**恰好一个成功**，其余得到 `credential_superseded`，
  不会重复计数（版本号只 +1），旧凭证也不会复活。
- 可配置续期窗口 `RenewWindow`（仅在临近过期时允许续期；测试中置 0 表示不限）。

---

## 3. 授权模型（RBAC + ABAC，默认拒绝）

一次判定输入：主体（用户、角色、主体属性）、资源（含属主、类型、属性）、
动作。规则字段：

```jsonc
{
  "id": "p-1", "deny": false,
  "roles": ["reader"],          // 空 = 该维度不约束；支持 "*"
  "users": ["alice"],
  "resources": ["doc-1"],
  "actions": ["read"],
  "conditions": {               // 属性等值条件
    "dept": "engineering",          // 无前缀 / subject. = 主体属性
    "resource.classification": "internal"
  }
}
```

### 3.1 结论汇总（与求值顺序无关）

引擎对策略快照中**全部**规则求值后再汇总，绝不短路：

1. 只要存在**任意一条匹配的 deny 规则** → `deny / explicit_deny`，
   **无论有多少 allow 命中，也无论规则排列顺序**；
2. 否则，只要存在至少一条匹配的 allow → `allow`；
3. 都不匹配 → `deny / no_matching_policy`（默认拒绝）。

返回结果同时包含 `matched_deny` 与 `matched_allow`（按 id 排序），
使每一个结论都能解释“依据哪些规则、为何拒绝”。

其余默认拒绝场景：用户不存在、资源未登记、规则数量超过
`MaxRuleCount`（`rule_set_too_large`，绝不用部分规则放行）、
请求属性数超过 `MaxAttrCount`（`too_many_attributes`）。

### 3.2 变更可见性：撤销/改权立即生效

- 存储维护单调递增的 `AuthzVersion`；策略增删改、用户角色变更、
  撤销、密钥轮换都会推进它。
- 正面判定缓存条目**绑定版本号与短 TTL**：任何上述变更后，版本失配即失效；
  撤销还会按会话显式清缓存。
- 每次判定都重新校验会话当前 JTI，因此撤销的生效不依赖缓存过期，
  也不等待凭证到期。

---

## 4. 签名密钥轮换语义

密钥有三态：

| 状态 | 可签发 | 可验签 |
| --- | :---: | :---: |
| `active` | 是（全库唯一） | 是 |
| `next` | 否 | 是（轮换并存期预先分发） |
| `retired` | 否 | 是（轮换后旧 active 自动转入，仅验签） |
| 已彻底删除（RetireKey） | 否 | **否** |

流程：

1. `PrepareKey(k2)`：登记 `next` 密钥，立即具备验签能力，但不能签发；
2. `Rotate(k2)`：**原子**地把 k2 置为唯一 active、旧 active 置为 retired。
   - 轮换期间：旧密钥签发的存量凭证仍可验签通过（新旧并存）；
   - 轮换之后：新签发的凭证一律使用 k2，旧密钥**永远不能再用于签发**；
   - 并发轮换同一个 next：恰好一次成功，其余被拒，最终仍只有一把 active；
3. `RetireKey(k1)`：把历史密钥彻底移除，此后 k1 签名的凭证得到
   `unknown_signing_key`。

密钥元数据查询只返回 kid/状态/时间，绝不返回密钥明文。

---

## 5. 审计

- 所有敏感操作都留痕：`issue / verify / renew / revoke / authorize /
  admin_policy_* / admin_assign_roles / admin_key_*`。
- 记录**只追加**：ID 严格单调递增，返回的是防御性拷贝，外部无法改写。
- **读取与服务端历史互相独立**：`Append` 的返回值、`Since` 的查询结果、
  `Export` 的导出产物，都是与服务端历史**不共享任何引用**的深拷贝
  （含嵌套的 `Detail`）。调用方无论怎么读、怎么转发、是否就地改动
  取到或返回的记录（顶层字段或嵌套内容），都**不可能**改写服务端
  已记录的历史；之后按同一序号再查、按同一范围再导出，拿到的仍是
  最初写入的原值。多个读取方并发读取同一段记录并各自改动时，
  彼此互不影响，服务端记录保持原值。
- **绝不写入敏感内容**：凭证只记录 `jti`（不记 token 本体），不记任何
  签名密钥；`GET /v1/audit` 亦不回传敏感材料。
- 审计容量（`AuditCapacity`）写满后 `Append` 返回 `ErrAuditFull`，
  敏感操作（签发/撤销/轮换/改策略/改角色）随之**拒绝执行**，绝不静默跳过。

### 5.1 审计证据导出与独立核验

面向外部合规审计：把一段记录导出为**自包含证据产物**（JSON），
交给完全独立的一方——另起进程或外部工具，**无需任何服务访问权限**
即可自行核验。

- **导出**：`Gateway.ExportAudit(from, to)`（Go API）或
  `GET /v1/audit/export?from=&to=`（HTTP），导出 `[from,to]` 闭区间。
  产物格式 `audit-evidence/v1`：声明范围 + 每条记录（事件本体 + 链上摘要）
  + 头摘要。哈希链以「格式标识 + 范围」为起点逐条推进，
  核验方仅凭产物自身即可完整重放。
- **独立核验**：`audit.VerifyEvidence(data)`（纯函数，不碰任何服务端状态）
  或独立工具 `cmd/audit-verify`（`audit-verify evidence.json`，
  结论为 ok 时退出码 0）。结论**可区分**，绝不笼统报失败：
  - `ok` —— 该段记录完整连续、未被改写；
  - `sequence_broken` —— 中间缺号、序号重复或顺序被重排；
  - `tampered` —— 某条内容（含嵌套的 detail）被事后改写，或摘要被换；
  - `invalid_range` —— 产物声明的范围本身不合法（区间倒置、条数与区间不符）；
  - `malformed` —— 产物无法解析或格式标识不符。
- **一致性边界**：序号由同一把锁单调分配且只追加，导出在锁内拷贝切片、
  锁外算哈希，因此每份产物都是某个一致边界——无半条记录、无跳号、
  无重复；与并发写入同时进行也自洽，且不长时间阻塞签发/判定/变更。
  对同一范围重复导出，结果**逐字节一致**。
- **离不可改**：产物是深拷贝。对方怎么读、怎么转发、就地改动（包括嵌套
  内容）都不影响服务端记录；之后再查、再导出仍是原值，
  未被动过的那份产物再核验仍通过。
- **不含敏感材料**：记录本身只含 `jti` 等业务字段，导出的产物同样
  不含凭证原文与签名密钥。
- **规模上限**：单次导出条数由 `config.MaxExport` 限制（默认 10000）。
  拒绝原因可区分：范围不合法 → `export_range_invalid`（HTTP 400），
  超上限 → `export_limit_exceeded`（HTTP 413）；
  失败时不产生任何半成品产物，也不留下占着不放的资源。
- **边界与兼容**：核验保证的是「该导出段内部完整连续且未被改写」；
  它不证明该段与服务端更早历史的衔接（段前历史不在产物内）。
  产物格式标识为 `audit-evidence/v1`，未来格式变更会换新标识，
  核验方按标识决定兼容性。

---

## 6. 容量上限与故障策略

`config.Config`（见 `internal/config`）可限制：用户/资源/策略/会话/密钥
数量、判定缓存条数、审计容量、单次审计证据导出条数（`MaxExport`）、
规则数、请求属性数等。

- 超限：返回 `limit_exceeded`（HTTP 429）/ 相应拒绝原因，不降级放行。
- 存储写失败（可用 `Store.SetFailNext(n)` 注入）：故障在**任何状态修改
  之前**被消费，因此不会产生半写入；签发路径失败时不会残留会话，
  服务在下一次请求自动恢复。
- HTTP 层：拒绝类 → 403；非法请求 → 400；限流 → 429；
  审计/存储故障 → 503。任何异常都不会被回答为 200 放行。

---

## 7. 运行与验证方法

### 7.1 启动

```bash
go run ./cmd/authz-gateway -addr 127.0.0.1:8088
```

启动后自带种子：密钥 `k1`、用户 `alice(reader,editor)` / `bob(reader)`、
资源 `doc-1`、两条 allow 策略。

### 7.2 手工验证（curl）

先用短凭证有效期启动，便于直接观察“过期”和“续期窗口”语义：

```bash
go run ./cmd/authz-gateway -addr 127.0.0.1:8088 -token-ttl 90s -renew-window 60s
BASE=http://127.0.0.1:8088

# 1) 签发
TOK=$(curl -s -X POST $BASE/v1/tokens/issue \
  -d '{"username":"alice"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 2) 校验
curl -s -X POST $BASE/v1/tokens/verify -d "{\"token\":\"$TOK\"}"

# 3) 允许：reader read *
curl -s -X POST $BASE/v1/authorize \
  -d "{\"token\":\"$TOK\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":true,...,"matched_allow":["p-readers-read"]}

# 4) 默认拒绝：无匹配规则
curl -s -X POST $BASE/v1/authorize \
  -d "{\"token\":\"$TOK\",\"resource\":\"doc-1\",\"action\":\"delete\"}"
# => {"allowed":false,"reason":"no_matching_policy"}

# 5) 篡改：改签名末尾
curl -s -X POST $BASE/v1/authorize \
  -d "{\"token\":\"${TOK%???}AAA\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":false,"reason":"bad_signature"}

# 6) 显式拒绝优先：插入一条与 allow 冲突的 deny
curl -s -X POST $BASE/v1/admin/policies -d '{
  "actor":"demo","policy":{"id":"p-deny","deny":true,
  "users":["alice"],"resources":["doc-1"],"actions":["read"]}}'
curl -s -X POST $BASE/v1/authorize \
  -d "{\"token\":\"$TOK\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":false,"reason":"explicit_deny",
#     "matched_deny":["p-deny"],"matched_allow":["p-readers-read"]}

# 7) 撤销立即生效（先删除 deny 以便对照）
curl -s -X DELETE "$BASE/v1/admin/policies/p-deny?actor=demo"
SID=$(curl -s -X POST $BASE/v1/tokens/verify -d "{\"token\":\"$TOK\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
curl -s -X POST $BASE/v1/sessions/revoke -d "{\"session_id\":\"$SID\",\"actor\":\"demo\"}"
curl -s -X POST $BASE/v1/authorize \
  -d "{\"token\":\"$TOK\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":false,"reason":"session_revoked"}

# 8) 续期后旧凭证作废
#    默认有续期窗口（凭证临近过期才允许续期）。若想“任意时刻可续期”，
#    启动时传 -renew-window 0；下面的示例假定 renew-window=0。
TOK2=$(curl -s -X POST $BASE/v1/tokens/issue -d '{"username":"bob"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
NEW=$(curl -s -X POST $BASE/v1/tokens/renew -d "{\"token\":\"$TOK2\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST $BASE/v1/authorize -d "{\"token\":\"$TOK2\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":false,"reason":"credential_superseded"}
curl -s -X POST $BASE/v1/authorize -d "{\"token\":\"$NEW\",\"resource\":\"doc-1\",\"action\":\"read\"}"
# => {"allowed":true}

# 9) 密钥轮换：登记 next -> 原子轮换；旧凭证仍可验签，新凭证用新 kid
curl -s -X POST $BASE/v1/admin/keys/prepare \
  -d '{"kid":"k2","secret":"second-key","actor":"demo"}'
curl -s -X POST $BASE/v1/admin/keys/rotate -d '{"kid":"k2","actor":"demo"}'
curl -s $BASE/v1/keys

# 10) 审计（只含 jti，无 token/密钥）
curl -s "$BASE/v1/audit?after_id=0" | python3 -m json.tool | head -40

# 11) 导出审计证据并用独立进程离线核验
curl -s "$BASE/v1/audit/export?from=1&to=5" > evidence.json
go run ./cmd/audit-verify evidence.json
# => {"verdict":"ok","records":5}   （退出码 0）
# 改动产物任意内容（含嵌套 detail）再核验 => {"verdict":"tampered",...}，退出码 1
# 范围不合法 => HTTP 400 export_range_invalid；超 MaxExport => HTTP 413 export_limit_exceeded
```

### 7.3 自动化测试

```bash
go test ./...                      # 全量
go test -race ./...                # 含数据竞争检测
go test -v ./internal/authz        # 冲突规则/默认拒绝/ABAC/规模上限
go test -v ./internal/gateway      # 过期/篡改/并发续期/并发轮换/撤销/故障回退/审计
go test -v -race ./internal/audit  # 审计只追加/容量拒绝/证据导出核验/读取隔离
```

本地复现与验证「读取不影响服务端历史」：

```bash
go test -v -race -run 'Isolated' ./internal/audit
```

覆盖：改 `Since` 结果的顶层字段、改嵌套 `Detail`、改动后再查再导出仍是原值
（导出与改动前逐字节一致）、`Append` 返回值事后被改、16 路并发读取各自改动
互不影响。每个用例的日志都打印输入（取到/返回的记录与改动方式）与结论
（再查/再导出仍为原值）。

测试以 `-v` 运行时会打印每个场景的**输入**与**判定依据**（`input:` /
`decision basis:` / 命中规则 / 拒绝原因）。重点场景：

- 过期凭证、篡改签名、错误密钥、错误签发者、`alg=none` —— 拒绝且原因可区分；
- allow 与 deny 冲突在三种规则排列下结论一致（deny 恒胜）；
- 16 路并发续期同一张凭证：恰好 1 成功，其余 `credential_superseded`，
  版本号只增加一次，旧凭证不复活；
- 8 路并发轮换：恰好 1 次成功，最终唯一 active；
- 撤销与判定并发：撤销完成后结论稳定为 `session_revoked`；
- 存储故障注入：失败不留会话、不残留部分写入、后续请求自愈；
- 策略删除后回退为默认拒绝；审计容量打满后敏感操作被拒；
- 审计证据导出：独立进程核验通过；缺号/重复/重排判 `sequence_broken`，
  改写（含嵌套 detail）判 `tampered`，范围不合法判 `invalid_range`；
  外部改动导出副本不影响服务端记录与再次导出；并发导出与写入自洽；
  超 `MaxExport` 明确拒绝（`export_limit_exceeded`）且不留半成品。
- 审计读取隔离：改 `Since` 结果的顶层/嵌套字段、改 `Append` 返回值、
  多读取方并发各自改动，均不影响服务端历史；再查、再导出仍是原值，
  同一范围重复导出逐字节一致。
