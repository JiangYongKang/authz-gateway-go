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
| `internal/audit` | 有界、只追加、不可改写的审计日志（防御性拷贝） |
| `internal/evidence` | 审计证据导出（哈希链 + Ed25519 签名）与**完全离线**核验 |
| `internal/cache` | 有容量上限、带 TTL 的 LRU 正面判定缓存 |
| `internal/config` | 判定规模与容量上限配置 |
| `internal/gateway` | 编排层：签发/校验/续期/撤销/轮换/判定/审计/证据导出，所有入口共享同一套逻辑 |
| `internal/httpserver` | 本地 HTTP JSON 入口 |
| `cmd/authz-gateway` | 可直接运行的演示服务（含种子数据） |
| `cmd/audit-evidence-verify` | 审计证据产物的**独立离线核验工具**（不访问服务） |

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
- **绝不写入敏感内容**：凭证只记录 `jti`（不记 token 本体），不记任何
  签名密钥；`GET /v1/audit` 亦不回传敏感材料。
- 审计容量（`AuditCapacity`）写满后 `Append` 返回 `ErrAuditFull`，
  敏感操作（签发/撤销/轮换/改策略/改角色）随之**拒绝执行**，绝不静默跳过。

### 5.1 审计证据导出与离线核验（合规对接）

除了服务自己按序号回查，还可以把**一段记录导出成一份自包含产物**，交给
完全独立的一方（另一个进程、外部合规工具）在**没有任何服务访问权限**的
情况下自行核验。入口：

- `GET /v1/audit/evidence?from=N&to=M`：导出 ID 闭区间 `[N,M]` 的证据；
- `GET /v1/audit/evidence/key`：查询导出签名公钥与 `key_id`（**不含私钥**）；
- Go API：`gateway.Gateway.ExportAuditEvidence(from,to)`、`EvidencePublicKey()`；
- 核验逻辑：`internal/evidence.Verify(bytes)`，只依赖 Go 标准库；
- 命令行：`cmd/audit-evidence-verify`（可拷贝到任意机器单独编译运行）。

**产物结构**（紧凑 JSON，字段顺序固定，下同）：

```jsonc
{
  "format_version": 1,
  "chain_alg": "SHA-256",
  "sig_alg": "Ed25519",
  "key_id": "<导出公钥的 SHA-256，hex>",
  "range_from": 1, "range_to": 100,
  "anchor_hash": "<范围前一条记录的链哈希；from=1 时为空串>",
  "root_hash":   "<重放完该区间最后一条记录后的链哈希>",
  "records": [
    { "id": 1, "time": "...RFC3339Nano(UTC)...", "operation": "...",
      "jti": "...", "detail": { ... },
      "hash": "hex( H( prev_hash || '.' || 规范化JSON(本条内容) ) )" }
    // ...
  ],
  "public_key": "base64url(32字节 Ed25519 公钥)",
  "signature":  "base64url( Ed25519私钥签名(规范化JSON(范围+锚点+根)) )"
}
```

**核验保证到哪一步**。核验方只需要产物字节，按固定顺序得到**互相可区分**
的结论，绝不会把不完整内容当通过：

| 结论 `status` | 含义 |
| --- | --- |
| `valid` | 范围合法、序号连续、哈希链完整、内容未改、导出方签名有效 |
| `invalid_range` | 产物声明的范围本身不合法（`from<1` 或 `to<from`） |
| `missing_records` | 中间**缺号**（前向跳号），并指出 `want_id/got_id` |
| `reordered_or_dup` | 记录被**重排或序号重复**（后向出现更小序号） |
| `content_tampered` | 某条记录内容（含**嵌套的 `detail`**）被事后改写，指出 `at_id` |
| `root_mismatch` | 记录链重算出的根与声明的 `root_hash` 不一致 |
| `bad_evidence_signature` | Ed25519 签名不通过，或 `key_id` 与内嵌公钥不绑定 |
| `artifact_malformed` | 不是合法 JSON、字段缺失、编码错误、记录条数与声明范围不符等 |
| `unsupported_key_alg` | 不支持的 `format_version / chain_alg / sig_alg` |

**单向隔离（导出副本不可反噬服务端）**：

- 产物在审计锁内取**深拷贝快照**后在锁外计算哈希与签名；对方对产物字节的
  任何读取、转发、就地改动（包括嵌套 `detail`）都不可能触及服务端记录；
  之后服务端再查、再导出，拿到的仍是原值；
- 同一范围重复导出的产物**字节一致**（产物不含“导出时刻”等易变字段）；
  未被改动的同一份产物重复核验结论一致。

**敏感内容**：产物字段与审计记录一致——凭证只记 `jti`，不含 token 本体，
不含任何签名密钥；导出签名私钥/种子永不进入产物，产物只携带公钥。

**一致性与不阻塞写入**：导出基于单次快照，不会出现半条记录、重复序号或
莫名跳号；只在内存拷贝期间短暂持锁，逐条哈希与签名均在锁外完成，不长时间
卡住签发、判定与变更。

**边界（请务必知悉）**：

1. 核验只证明“这份产物与**导出方私钥**对应的签名一致、内部链完整”。
   私钥泄露后，持有者可伪造一份自洽产物；请用带外渠道保管种子并只分发公钥。
   核验工具支持 `-expect-key KEYID` 把产物绑定到你信任的那把公钥，
   还可用 `-expect-from/-expect-to` 绑定期望范围，拒绝“另一把合法密钥/另一段
   合法范围”的产物冒充本次证据。
2. 核验**不联网**、不判断“区间之外是否还缺记录”。若要证明某段之后没有隐藏
   记录，应导出到当时的末尾 ID（`GET /v1/audit` 可查当前长度），或要求相邻
   区间产物的 `anchor_hash` 首尾相接。
3. 未配置固定种子时，服务每次启动使用随机证据密钥（重启后旧产物仍可用其
   内嵌公钥正常离线核验，但无法再与“当前服务的 key_id”关联）。生产部署应
   通过 `-evidence-seed` 注入 32 字节固定种子（hex 或 base64）。
4. 证据导出不是全量转储通道：受 `AuditExportMaxRecords`（默认 10,000 条）与
   `AuditExportMaxBytes`（默认 8 MiB）双重约束。

**导出被拒时原因可区分，且不产生半成品**：

| 场景 | 哨兵错误（`internal/evidence`） | 网关原因码 | HTTP |
| --- | --- | --- | --- |
| `from<1` 或 `from>to` | `ErrInvalidRange` | `export_invalid_range` | 400 |
| `to` 超过当前已提交记录 | `ErrRangeUnavailable` | `export_range_unavailable` | 403 |
| 条数超上限 | `ErrTooManyRecords` | `export_too_many_records` | 429 |
| 产物字节超上限 | `ErrTooLarge` | `export_too_large` | 429 |

**兼容性**：产物格式以 `format_version` 标识，当前为 `1`。规范化哈希对字段
顺序敏感（Go `encoding/json` 按结构体声明序输出，map 的 key 按字典序），
核验端只要求能解析该 JSON 结构、实现 SHA-256 与 Ed25519 即可，不依赖本仓库
代码；时间统一为 UTC 的 RFC3339Nano 字符串。后续不兼容变更会提升版本号，
旧版本核验器对未知版本返回 `unsupported_key_alg` 而不是误判通过。

---

## 6. 容量上限与故障策略

`config.Config`（见 `internal/config`）可限制：用户/资源/策略/会话/密钥
数量、判定缓存条数、审计容量、规则数、请求属性数等。

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

# 11) 导出审计证据并交给独立工具离线核验
go build -o /tmp/aev ./cmd/audit-evidence-verify
KID=$(curl -s $BASE/v1/audit/evidence/key | python3 -c 'import sys,json;print(json.load(sys.stdin)["key_id"])')
curl -s "$BASE/v1/audit/evidence?from=1&to=5" > evidence.json
/tmp/aev -expect-key "$KID" -expect-from 1 -expect-to 5 evidence.json
# => status: valid ; exit=0

# 12) 外部篡改（哪怕改的是嵌套 detail）必然被识别
python3 - <<'PY'
import json
a=json.load(open('evidence.json'))
a['records'][0]['actor']='mallory'
a['records'][1]['detail']={'injected':'x'}
json.dump(a,open('evidence-tampered.json','w'))
PY
/tmp/aev evidence-tampered.json
# => status: content_tampered, at_id=1 ; exit=5

# 13) 拒绝原因可区分
curl -s -i "$BASE/v1/audit/evidence?from=5&to=2"   # 400 export_invalid_range
curl -s -i "$BASE/v1/audit/evidence?from=1&to=999999" # 403 export_range_unavailable
```

### 7.3 自动化测试

```bash
go test ./...                      # 全量
go test -race ./...                # 含数据竞争检测
go test -v ./internal/authz        # 冲突规则/默认拒绝/ABAC/规模上限
go test -v ./internal/gateway      # 过期/篡改/并发续期/并发轮换/撤销/故障回退/审计
go test -v ./internal/evidence     # 证据导出/离线核验/缺号/重排重复/改写/上限/并发
```

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
- 审计证据导出后交给独立核验通过；缺号、重复/重排、内容改写（含嵌套
  `detail`）、链根不符、签名失效分别得到可区分结论；
- 外部改动导出副本（含嵌套内容）后：服务端记录不变、服务端再次导出字节
  一致且仍核验通过；同一份未改动产物可重复核验；
- 并发导出与敏感写入同时进行：每次导出都是连续无半条记录的一致边界、可离线
  核验；同一范围重复导出字节一致；
- 超条数/超字节上限：明确拒绝、原因可区分、不产生半成品，拒绝后再导出正常；
- 产物不含凭证原文与签名密钥，只保留非敏感的 `jti` 引用。

### 7.4 独立核验工具退出码

`cmd/audit-evidence-verify` 以退出码区分核验结论，便于外部流水线消费：
`0=valid`、`2=invalid_range`、`3=missing_records`、`4=reordered_or_dup`、
`5=content_tampered`、`6=root_mismatch`、`7=bad_evidence_signature`、
`8=artifact_malformed`、`9=unsupported_key_alg`、`10=期望(key/范围)不符`、
`1=用法/读取错误`。文件参数传 `-` 时从标准输入读取。
