# 重症紧急代理协作（icu-proxy）

把 ICU 家属联络中「谁有权、通知了谁、基于哪版文书、谁在何时确认」沉淀为一套
**可审计服务**。仅依赖 Python 标准库，写操作全部进入一条哈希链追加日志。

## 边界：系统做什么、不做什么

- 系统**只做协作留痕**：维护代理资格与顺位、最小披露、联系尝试与升级、版本化确认、
  冲突复核流转、抢救例外记录、终止事件和复盘视图。
- 系统**不替医生作任何医疗决定**。抢救例外仅记录有资质医护填写的紧迫性说明与处置，
  并要求事后补齐依据；`clinical_decision_engine: false`。

## 领域规则

### 代理资格与顺位

资格由三类依据共同决定：

| 依据 | 值 | 含义 |
| --- | --- | --- |
| 患者预先指定 | `designated` | 患者本人授权 |
| 法定关系 | `legal` | 监护/近亲属等法定身份 |
| 院方核验 | `verified` | 身份、关系、授权书经院方核验，是**生效闸门** |

- 必须同时具备 `verified` 与 `designated`/`legal` 之一，且在 `valid_from`–`expires_at`
  有效期内，才进入顺位。
- 顺位：法定关系优先于预先指定；同源按登记的非负 rank，再按 agent_id 稳定排序。
- 终止事件：转院 `transfer`、恢复意识 `regained`、撤销代理 `revoked`（可针对单人）、
  离院 `discharged`。终止后权限立即失效，在途相关事项关闭；已终止的联系人**不能被
  重新登记静默复活**。
- `authority_snapshot` 可对任意时刻重算顺位，并给出每个联系人未入选的原因。

### 最小披露

每个事项范围有白名单字段，超出或缺失都被拒绝：

- `critical_notice`：`condition_summary`、`urgency`
- `exam_consent`：`exam_name`、`purpose`、`key_risks`
- `transfer`：`transfer_reason`、`target_facility`、`transport_risk`

通知只携带该白名单摘要，并对摘要做哈希入档。

### 通知、失联与逐级升级

- 联系结果三态：`delivered` / `rejected` / `unreachable`，逐渠道记录尝试。
- 仅当前位**拒收或失联**才通知下一位；上一通知无结果时禁止并行发出；
  前位已送达但尚未表态时不得越级。
- 顺位耗尽 → 事项 `unresolved`，可走抢救例外。
- 联系回调支持 `request_id` 幂等，内容相同的重复回调被抑制。

### 远程确认与不可变文书

- `add_document_version` 只追加版本，内容由服务端重算 SHA-256 摘要，客户端摘要不符
  则拒绝入档。
- 确认必须满足：通知已送达、确认人就是收通知的人、签署时资格仍有效、通知绑定的
  文书摘要仍是最新版本；并记录身份校验方式、凭据与签署时间。
- 文书更新后：旧确认在复盘时标记为 `superseded`；旧通知再确认被服务端拒绝；
  系统以**新版本向同一顺位重新通知**，重新送达后方可签署。
- `exam_consent`、`transfer` 取得有效确认即关闭；`critical_notice` 以知悉为目的，
  确认后仍可继续通知其余联系人。

### 意见冲突与复核

- 同一事项中确认与拒收并存 → 自动进入 `conflict`。
- `escalate_review` 转 `ethics`（伦理）或 `medical_affairs`（医务），复核期间暂停
  受理决定；`decide_review` 必须由具备 `review.decide` 权限者给出不少于 10 字的
  书面理由，事项以复核结论关闭。

### 抢救例外

- 仅具备 `emergency.exception` 权限的有资质医护可开立，需填写紧迫性说明与已采取的
  处置；例外为 `open`，事后由具备 `emergency.substantiate` 权限者补齐病程记录、
  影像等依据后转为 `substantiated`。

### 终止、跨午夜与幂等

- 事项开立使用 `idempotency_key`（同键返回同一事项）与
  `(患者, 事项范围, 业务日)` 双键抑制：业务日按 UTC+8 切分，**跨 UTC 午夜交班或
  重复回调只要仍属同一业务日就不会重复发起同一事项**；下一业务日才可新建。

### 复盘与隐私

- 审查视图 `review_dossier`（需 `audit.read`）：还原开立时与当前的资格顺位、
  披露摘要、文书版本链、全部通知与尝试、立场、带实时有效性状态的确认、复核结论、
  例外理由与终止事件；打开时先校验整条哈希链。
- 家属视图 `family_view`：只能看到与本人相关的通知、披露与确认，不返回其他联系人、
  他人电话、临床紧迫性叙述或复核内部理由；无关人查询统一返回 404，不泄露事项存在。

## 审计日志

每条记录含 `seq / at / actor_id / action / payload / prev_hash / hash`，
`hash = sha256(canonical({seq, prev_hash, body}))`。`verify_audit_chain()` 重算整条
链，任何篡改、删条或断序都会被发现。敏感长文本（紧迫性说明、复核理由）只存摘要入
审计链，正文留在领域记录中，按视图权限披露。

## HTTP 接口

- `GET /health`：服务身份。
- `POST /rpc`：信封 `{"method", "actor": {"actor_id", "permissions"}, "params"}`。
  方法见 `CollaborationService.METHODS`。错误码：400 校验 / 403 权限 / 404 不存在 /
  409 状态冲突。
- `GET /matters/{id}`：审查视图（需带 `actor_id`，默认授予审计权限仅为演示；
  生产部署应接入鉴权中间件）。
- `GET /matters/{id}?view=family&agent_id=...`：家属视图。

## 运行与测试

```bash
python3 service.py --check          # 身份与空审计链自检
python3 service.py --port 8000      # 启动服务
python3 -m unittest discover -s tests -v   # 37 个端到端契约测试
```

`fixtures/sample.json` 只保存可公开的领域样例（依据、工作流、审计事件名），
不含真实个人资料或业务凭据。

## 生产化待办（当前为内存实现）

审计哈希链已具备离线校验形态，但持久化、密钥/登录鉴权、签名原文（而非仅证据号）
上链、备份与留存策略需在接入真实 HIS 时补充；领域规则与状态机可直接复用。
