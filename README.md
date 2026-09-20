# 重症紧急代理协作（icu-proxy）

面向 ICU 家属联络的**可审计协作服务**：维护"谁当前有权代表患者"，按顺位通知、
最少披露病情摘要、绑定不可变文书版本收集远程确认，记录失联升级、意见冲突复核与
抢救例外。复盘时可逐项还原当时的代理资格、披露内容、联系尝试、决定版本与例外理由。

> **边界声明**：系统只做记录与路由，不输出医疗建议、不替医生作任何医疗决定。
> 抢救紧迫性由具权限医护书面说明并负责，冲突结论由伦理委员会/医务处人工填写。

## 领域规则

### 代理资格与顺位
- 三重依据：**患者预先指定**、**法定关系**、**院方核验**。
- 院方核验是生效闸门（仅医务处可执行），不能单独产生资格；未核验/核验驳回不生效。
- 顺位：预先指定整体优先于法定关系；法定关系按 监护人 > 配偶 > 成年子女 > 父母 > 其他近亲属。
- 资格有 `valid_from / valid_to` 时间窗与事项覆盖范围；支持按任意时点 `as_of` 重算。
- 终止：患者**转院、恢复意识、撤销代理、离院**终止全部权限；也可定向撤销单个联系人。

### 事项与通知
- 事项类型：病危通知（仅需知悉）、检查/治疗同意、转院决定。
- 发起必须带幂等键；跨午夜交班、重复回调使用同键返回同一事项，绝不重复发起。
- 按当前有效顺位逐级联系：失联/拒收自动落到下一位；全部失败自动升级医务处并开复核单。
- **最少披露**：送达时冻结披露包，字段必须在该事项的白名单内，绑定当时文书版本 hash。
- 已送达待确认者不会被重复送达；久无回复可补记失联以推进升级。

### 远程确认
- 确认绑定：文书摘要、不可变版本（`document_sha256`）、身份校验方式与证据、服务端签署时间，
  并生成 `binding_hash`。
- 身份校验：回拨已核验电话 / 安全链接令牌（家属自助仅限此方式）/ 现场核验证件。
- 文书内容更新即发布新版本，旧确认自动标记 `superseded`，事项重新征求当前版本意见。
- 同一联系人同一版本重复确认幂等；同一版本内立场反转留痕并进入冲突流程。

### 冲突与抢救例外
- 有效联系人立场相反：事项挂起 `conflict`，自动开伦理复核单；未结论前不能形成决定。
- 复核必须书面记录理由与采纳立场，由伦理委员会或医务处在其归口单上结论。
- 抢救例外：仅主治及以上/医务处可开立，紧迫性说明必填，限期（默认 24h）补齐依据；
  逾期可追踪，依据由医务处事后审核。

### 复盘与隐私
- `replay`（医务处/伦理/审查人员/主治可查）还原：资格、各时点有效顺位快照、文书版本、
  披露包、尝试、确认、复核单、例外及相关审计条目，并强制校验哈希链。
- 审计日志为哈希链（前条摘要入链），任何篡改、删除、重排都会在校验时暴露。
- 家属视图只含本人资料；其他联系人仅显示脱敏计数，不含姓名、电话、立场或证据。
  无关家属查询返回"不存在"，不泄漏事项存在性。

## 运行

```bash
pip install -r requirements.txt
python3 service.py --check           # 基础自检
python3 service.py --port 8000       # 启动服务；GET /health 返回项目标识
python3 -m pytest -q                 # 全部测试
python3 -m unittest discover -s tests -v
```

## HTTP API（均为 JSON，业务请求需 `X-Actor: <actor_id>`）

首次引导（首位医务处建立后锁定；需环境变量 `BOOTSTRAP_TOKEN` 与同名请求头）：
`POST /v1/bootstrap`

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /v1/actors` · `POST /v1/patients` | 登记人员/患者 |
| `POST /v1/patients/:pid/grants` | 建立资格（basis / relation / 顺位 / 有效期 / 事项范围） |
| `GET  /v1/patients/:pid/grants?matter_type=…&at=…` | 查询某时点有效顺位 |
| `POST /v1/grants/:gid/verification` | 医务处核验（仅医务处） |
| `POST /v1/patients/:pid/terminations` | 权限终止（患者级或定向） |
| `POST /v1/matters`（`Idempotency-Key`） | 发起事项，重复键返回原事项 |
| `GET  /v1/matters/:mid/next-contact` | 当前应联系的顺位联系人 |
| `POST /v1/matters/:mid/documents` | 发布不可变文书版本 |
| `POST /v1/matters/:mid/attempts` | 记录送达/拒收/失联（送达冻结最小披露） |
| `POST /v1/matters/:mid/confirmations` | 远程确认（版本+身份+签署时间绑定） |
| `POST /v1/matters/:mid/resolve` | 医护基于单一有效立场形成处置依据 |
| `POST /v1/referrals/:rid/conclude` | 伦理/医务复核结论（理由必填） |
| `POST /v1/matters/:mid/emergency-exceptions` | 开立抢救例外（主治/医务处） |
| `POST /v1/exceptions/:eid/basis` · `…/review` | 补齐依据 / 医务处审核 |
| `GET  /v1/exceptions/overdue` | 逾期未补依据的例外 |
| `GET  /v1/matters/:mid/replay` | 审查人员完整复盘（校验哈希链） |
| `GET  /v1/matters/:mid/family-view` | 家属本人受限视图 |
| `GET  /v1/audit` | 导出审计哈希链 |

## 代码结构

```
icuproxy/
  enums.py      角色、事项、依据、顺位、送达结果、立场、终止原因等枚举
  models.py     患者/资格/文书版本/事项/尝试/披露包/确认/复核单/例外
  clock.py      可注入时钟（跨午夜场景测试）
  crypto.py     规范化 JSON 与 SHA-256
  audit.py      哈希链审计日志与篡改校验
  service.py    核心领域规则（资格、升级、版本绑定、冲突、例外、复盘）
  httpapi.py    JSON HTTP 路由与角色映射
service.py      启动入口（保留 /health 与 --check）
tests/          72 项契约测试（unittest/pytest 均可运行）
fixtures/       公开领域样例，不含真实个人资料
```

当前实现状态保存在进程内存中；生产部署需在其外补充持久化、TLS 与真实身份联合校验。
`fixtures/sample.json` 只描述数据边界，不包含真实个人资料或业务凭据。
