"""重症紧急代理协作服务（icu-proxy）。

职责边界（见 README「不做什么」）：
  * 维护代理资格、顺位与有效期；
  * 按事项做最小病情披露并记录送达 / 拒收 / 失联 / 逐级升级；
  * 远程确认绑定文书不可变版本、身份校验与签署时间；
  * 意见冲突转交伦理或医务复核；抢救例外只记录医护的紧迫性说明与事后补证；
  * 终止事件、跨午夜幂等、复盘还原与家属隐私视图。

软件不替医生作任何医疗决定：所有医学判断只以「有资质医护的说明」入档。

仅依赖标准库；所有写操作进入一条哈希链追加日志，可离线校验完整性。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

SERVICE_ID = "icu-proxy"
SERVICE_NAME = "重症紧急代理协作"
SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# 领域枚举
# ---------------------------------------------------------------------------


class BasisType(str, Enum):
    """代理资格的三类依据：患者预先指定、法定关系、院方核验。"""

    DESIGNATED = "designated"          # 患者预先指定
    LEGAL = "legal"                    # 法定关系（监护人/近亲属等）
    HOSPITAL_VERIFIED = "verified"     # 院方核验（身份/关系/授权书）


class RoleScope(str, Enum):
    CRITICAL_NOTICE = "critical_notice"  # 病危通知
    EXAM_CONSENT = "exam_consent"        # 检查同意
    TRANSFER = "transfer"                # 转院


class Channel(str, Enum):
    PHONE = "phone"
    SMS = "sms"
    SECURE_LINK = "secure-link"


class ContactResult(str, Enum):
    DELIVERED = "delivered"
    REJECTED = "rejected"       # 明确拒收 / 拒绝对话
    UNREACHABLE = "unreachable"  # 失联（无人接听、关机、超时等）


class Stance(str, Enum):
    CONFIRM = "confirm"
    REFUSE = "refuse"


class MatterStatus(str, Enum):
    OPEN = "open"                     # 仍在联系 / 等待决定
    CONFIRMED = "confirmed"           # 已取得与当前文书版本绑定的确认
    CONFLICT = "conflict"             # 多名有权联系人意见相反
    UNDER_REVIEW = "under_review"     # 已转伦理/医务复核
    RESOLVED = "resolved"             # 复核结论关闭事项
    UNRESOLVED = "unresolved"         # 顺位耗尽仍无确认（可触发抢救例外）
    TERMINATED = "terminated"         # 终止事件导致事项失效


class AgentStatus(str, Enum):
    ACTIVE = "active"
    TERMINATED = "terminated"


class TerminationReason(str, Enum):
    TRANSFER = "transfer"                      # 患者转院
    REGAINED_CONSCIOUSNESS = "regained"       # 恢复意识
    REVOKED = "revoked"                        # 撤销代理（可针对单人）
    DISCHARGED = "discharged"                  # 离院


class ConfirmationStatus(str, Enum):
    VALID = "valid"
    SUPERSEDED = "superseded"   # 文书已有更新版本
    INVALID = "invalid"         # 签署时代理资格/事项/版本不成立


class ReviewRoute(str, Enum):
    ETHICS = "ethics"
    MEDICAL_AFFAIRS = "medical_affairs"


class ReviewState(str, Enum):
    PENDING = "pending"
    DECIDED = "decided"


class ExceptionStatus(str, Enum):
    OPEN = "open"                  # 紧急处置已执行，依据待补齐
    SUBSTANTIATED = "substantiated"  # 事后依据已补齐

# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class DomainError(Exception):
    code = "domain_error"


class NotFoundError(DomainError):
    code = "not_found"


class StateConflictError(DomainError):
    code = "state_conflict"


class AuthorizationError(DomainError):
    code = "forbidden"


class ValidationError(DomainError):
    code = "validation_error"

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical(obj: Any) -> str:
    """稳定序列化：哈希前的唯一编码。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_digest(content: Any) -> str:
    return sha256_hex(canonical(content))


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_:.-]{0,63}$")


def require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise ValidationError(f"{field_name} 必须是 1-64 位字母数字 _:.- 标识")
    return value


def enum_value(enum_cls: type[Enum], value: Any, field_name: str) -> Enum:
    try:
        return enum_cls(value)
    except (ValueError, TypeError) as exc:
        allowed = ", ".join(m.value for m in enum_cls)  # type: ignore[attr-defined]
        raise ValidationError(f"{field_name} 仅允许: {allowed}") from exc

# ---------------------------------------------------------------------------
# 哈希链追加审计日志（不可变、可独立校验）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: datetime
    actor_id: str
    action: str
    payload: dict
    prev_hash: str
    hash: str

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "at": iso(self.at),
            "actor_id": self.actor_id,
            "action": self.action,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def append(self, actor_id: str, action: str, payload: dict, at: datetime) -> AuditEntry:
        body = {
            "schema": SCHEMA_VERSION,
            "at": iso(at),
            "actor_id": actor_id,
            "action": action,
            "payload": payload,
        }
        with self._lock:
            seq = len(self._entries) + 1
            prev_hash = self._entries[-1].hash if self._entries else self.GENESIS
            digest = sha256_hex(canonical({"seq": seq, "prev_hash": prev_hash, "body": body}))
            entry = AuditEntry(seq, at, actor_id, action, payload, prev_hash, digest)
            self._entries.append(entry)
            return entry

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def verify(self) -> None:
        """重算整条链；任何篡改或断序都抛异常。"""
        prev = self.GENESIS
        for entry in self._entries:
            if entry.prev_hash != prev:
                raise StateConflictError(f"审计链在 seq={entry.seq} 断链")
            body = {
                "schema": SCHEMA_VERSION,
                "at": iso(entry.at),
                "actor_id": entry.actor_id,
                "action": entry.action,
                "payload": entry.payload,
            }
            digest = sha256_hex(
                canonical({"seq": entry.seq, "prev_hash": prev, "body": body})
            )
            if digest != entry.hash:
                raise StateConflictError(f"审计链在 seq={entry.seq} 哈希不一致")
            prev = entry.hash

# ---------------------------------------------------------------------------
# 代理资格
# ---------------------------------------------------------------------------


@dataclass
class Agent:
    agent_id: str
    patient_id: str
    display_name: str
    channels: dict[str, str]            # channel -> 地址（电话/令牌标识），视图层脱敏
    bases: set[BasisType]
    scope_ranks: dict[RoleScope, int]   # 授予的事项范围及同权重下顺位（小者优先）
    valid_from: datetime
    expires_at: Optional[datetime]
    status: AgentStatus = AgentStatus.ACTIVE
    terminated_at: Optional[datetime] = None
    termination_reason: Optional[TerminationReason] = None

    def as_dict(self, *, mask_contact: bool) -> dict:
        if mask_contact:
            channels = {ch: mask_address(addr) for ch, addr in self.channels.items()}
        else:
            channels = dict(self.channels)
        return {
            "agent_id": self.agent_id,
            "patient_id": self.patient_id,
            "display_name": self.display_name,
            "channels": channels,
            "bases": sorted(b.value for b in self.bases),
            "scopes": sorted(s.value for s in self.scope_ranks),
            "valid_from": iso(self.valid_from),
            "expires_at": iso(self.expires_at) if self.expires_at else None,
            "status": self.status.value,
            "terminated_at": iso(self.terminated_at) if self.terminated_at else None,
            "termination_reason": (
                self.termination_reason.value if self.termination_reason else None
            ),
        }


def mask_address(addr: str) -> str:
    """家属视图：只暴露渠道类型与末位，不暴露完整号码/令牌。"""
    if len(addr) <= 3:
        return "***"
    return "***" + addr[-2:]


# 各事项范围允许向联系人披露的最少病情字段（白名单）。
SCOPE_DISCLOSURE_FIELDS: dict[RoleScope, tuple[str, ...]] = {
    RoleScope.CRITICAL_NOTICE: ("condition_summary", "urgency"),
    RoleScope.EXAM_CONSENT: ("exam_name", "purpose", "key_risks"),
    RoleScope.TRANSFER: ("transfer_reason", "target_facility", "transport_risk"),
}

# 院方核验是生效闸门；授权来源权重：法定关系优先于预先指定，
# 同源内按 scope_ranks，再按 agent_id 稳定排序。
_SOURCE_WEIGHT = {BasisType.LEGAL: 0, BasisType.DESIGNATED: 1}

# ---------------------------------------------------------------------------
# 文书版本（不可变）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DocumentVersion:
    doc_id: str
    version: int
    title: str
    digest: str
    created_at: datetime

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "version": self.version,
            "title": self.title,
            "digest": self.digest,
            "created_at": iso(self.created_at),
        }

    def ref(self) -> dict:
        return {"doc_id": self.doc_id, "version": self.version, "digest": self.digest}

# ---------------------------------------------------------------------------
# 联系尝试 / 通知 / 确认 / 复核 / 例外
# ---------------------------------------------------------------------------


@dataclass
class ContactAttempt:
    attempt_id: str
    notification_id: str
    agent_id: str
    channel: Channel
    result: ContactResult
    at: datetime
    actor_id: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "attempt_id": self.attempt_id,
            "notification_id": self.notification_id,
            "agent_id": self.agent_id,
            "channel": self.channel.value,
            "result": self.result.value,
            "at": iso(self.at),
            "actor_id": self.actor_id,
            "detail": self.detail,
        }


@dataclass
class Notification:
    notification_id: str
    agent_id: str
    level: int                     # 升级层级：0 = 第一顺位
    channels: list[Channel]
    disclosure: dict              # 实际发出的最少摘要快照
    doc_ref: dict
    created_at: datetime
    attempts: list[ContactAttempt] = field(default_factory=list)
    delivered_at: Optional[datetime] = None

    @property
    def state(self) -> str:
        if self.delivered_at:
            return "delivered"
        results = {a.result for a in self.attempts}
        if results and results <= {ContactResult.UNREACHABLE}:
            return "unreachable"
        if ContactResult.REJECTED in results:
            return "rejected"
        return "pending"

    def as_dict(self) -> dict:
        return {
            "notification_id": self.notification_id,
            "agent_id": self.agent_id,
            "level": self.level,
            "channels": [c.value for c in self.channels],
            "state": self.state,
            "disclosure": self.disclosure,
            "doc_ref": self.doc_ref,
            "created_at": iso(self.created_at),
            "delivered_at": iso(self.delivered_at) if self.delivered_at else None,
            "attempts": [a.as_dict() for a in self.attempts],
        }


@dataclass
class Confirmation:
    confirmation_id: str
    notification_id: str
    agent_id: str
    doc_ref: dict
    identity_verification: dict
    signed_at: datetime
    actor_id: str
    request_id: str
    note: str = ""

    def as_dict(self, *, current_status: ConfirmationStatus) -> dict:
        data = {
            "confirmation_id": self.confirmation_id,
            "notification_id": self.notification_id,
            "agent_id": self.agent_id,
            "doc_ref": self.doc_ref,
            "identity_verification": dict(self.identity_verification),
            "signed_at": iso(self.signed_at),
            "actor_id": self.actor_id,
            "note": self.note,
            "status": current_status.value,
        }
        return data


@dataclass
class Review:
    route: ReviewRoute
    opened_at: datetime
    opened_by: str
    state: ReviewState = ReviewState.PENDING
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    outcome: Optional[Stance] = None
    rationale: str = ""

    def as_dict(self) -> dict:
        return {
            "route": self.route.value,
            "state": self.state.value,
            "opened_at": iso(self.opened_at),
            "opened_by": self.opened_by,
            "decided_at": iso(self.decided_at) if self.decided_at else None,
            "decided_by": self.decided_by,
            "outcome": self.outcome.value if self.outcome else None,
            "rationale": self.rationale,
        }


@dataclass
class EmergencyException:
    exception_id: str
    clinician_id: str
    permissions: list[str]
    urgency_statement: str
    action_taken: str
    opened_at: datetime
    status: ExceptionStatus = ExceptionStatus.OPEN
    substantiated_at: Optional[datetime] = None
    substantiated_by: Optional[str] = None
    basis_refs: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "clinician_id": self.clinician_id,
            "permissions": list(self.permissions),
            "urgency_statement": self.urgency_statement,
            "action_taken": self.action_taken,
            "opened_at": iso(self.opened_at),
            "status": self.status.value,
            "substantiated_at": (
                iso(self.substantiated_at) if self.substantiated_at else None
            ),
            "substantiated_by": self.substantiated_by,
            "basis_refs": list(self.basis_refs),
        }


@dataclass
class Matter:
    matter_id: str
    idempotency_key: str
    patient_id: str
    scope: RoleScope
    doc_id: str
    disclosure: dict
    opened_at: datetime
    opened_by: str
    business_date: str
    status: MatterStatus = MatterStatus.OPEN
    notifications: list[Notification] = field(default_factory=list)
    stances: dict[str, Stance] = field(default_factory=dict)  # agent_id -> 立场
    confirmations: list[Confirmation] = field(default_factory=list)
    review: Optional[Review] = None
    exception: Optional[EmergencyException] = None
    termination: Optional[dict] = None
    closed_at: Optional[datetime] = None

    def as_dict(self) -> dict:
        return {
            "matter_id": self.matter_id,
            "idempotency_key": self.idempotency_key,
            "patient_id": self.patient_id,
            "scope": self.scope.value,
            "doc_id": self.doc_id,
            "disclosure": self.disclosure,
            "status": self.status.value,
            "opened_at": iso(self.opened_at),
            "opened_by": self.opened_by,
            "business_date": self.business_date,
            "closed_at": iso(self.closed_at) if self.closed_at else None,
        }

# ---------------------------------------------------------------------------
# 仓储
# ---------------------------------------------------------------------------


@dataclass
class Actor:
    actor_id: str
    permissions: frozenset[str] = frozenset()

    @staticmethod
    def from_dict(data: dict) -> "Actor":
        actor_id = require_id(str(data.get("actor_id", "")), "actor_id")
        perms = data.get("permissions") or []
        if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
            raise ValidationError("permissions 必须是字符串数组")
        return Actor(actor_id, frozenset(perms))


class Repository:
    def __init__(self) -> None:
        self.agents: dict[str, Agent] = {}
        self.documents: dict[str, list[DocumentVersion]] = {}
        self.matters: dict[str, Matter] = {}
        self.key_index: dict[str, str] = {}                 # 幂等键 -> matter_id
        self.day_index: dict[tuple[str, str, str], str] = {}  # 跨午夜抑制
        self.request_index: dict[str, dict] = {}            # request_id -> 响应
        self.notification_index: dict[str, Notification] = {}
        self.attempt_keys: set[str] = set()

# ---------------------------------------------------------------------------
# 应用服务
# ---------------------------------------------------------------------------


class CollaborationService:
    PERM_REGISTER = "agent.register"
    PERM_STAFF = "matter.open"
    PERM_CONTACT = "contact.record"
    PERM_REVIEW = "review.decide"
    PERM_EMERGENCY = "emergency.exception"
    PERM_SUBSTANTIATE = "emergency.substantiate"
    PERM_TERMINATE = "patient.terminate"
    PERM_AUDIT = "audit.read"

    def __init__(
        self,
        clock: Callable[[], datetime] = utcnow,
        business_day_offset: timedelta = timedelta(hours=8),
    ) -> None:
        self.clock = clock
        self.business_day_offset = business_day_offset
        self.repo = Repository()
        self.audit = AuditLog()
        self._lock = threading.RLock()

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None:
            raise ValidationError("时钟必须返回带时区信息的时间")
        return now.astimezone(timezone.utc)

    def _business_date(self, at: datetime) -> str:
        return (at + self.business_day_offset).date().isoformat()

    def _record(self, actor_id: str, action: str, payload: dict) -> AuditEntry:
        return self.audit.append(actor_id, action, payload, self._now())

    def _require_perm(self, actor: Actor, perm: str) -> None:
        if perm not in actor.permissions:
            raise AuthorizationError(f"缺少权限: {perm}")

    # -- 代理登记 / 核验 ----------------------------------------------------

    def register_agent(self, actor: Actor, params: dict) -> dict:
        """登记或补充一名联系人；资格由三依据与有效期共同决定。"""
        self._require_perm(actor, self.PERM_REGISTER)
        agent_id = require_id(params.get("agent_id", ""), "agent_id")
        patient_id = require_id(params.get("patient_id", ""), "patient_id")
        display_name = str(params.get("display_name", "")).strip()
        if not display_name:
            raise ValidationError("display_name 不能为空")
        channels = params.get("channels") or {}
        if not isinstance(channels, dict) or not channels:
            raise ValidationError("channels 至少包含一种联系方式")
        norm_channels: dict[str, str] = {}
        for raw_ch, addr in channels.items():
            ch = enum_value(Channel, raw_ch, "channels 的键")
            if not isinstance(addr, str) or not addr.strip():
                raise ValidationError(f"渠道 {ch.value} 缺少地址")
            norm_channels[ch.value] = addr.strip()

        bases = {
            enum_value(BasisType, b, "bases")
            for b in params.get("bases", [])
        }
        scopes = params.get("scopes")
        if not isinstance(scopes, dict) or not scopes:
            raise ValidationError("scopes 必须是 {事项范围: 顺位} 的非空映射")
        scope_ranks: dict[RoleScope, int] = {}
        for raw_scope, rank in scopes.items():
            scope = enum_value(RoleScope, raw_scope, "scopes 的键")
            if not isinstance(rank, int) or rank < 0:
                raise ValidationError(f"{scope.value} 的顺位必须是非负整数")
            scope_ranks[scope] = rank  # type: ignore[index]

        valid_from = self._parse_ts(params.get("valid_from"), "valid_from", default=self._now())
        expires_at = None
        if params.get("expires_at"):
            expires_at = self._parse_ts(params.get("expires_at"), "expires_at")
            if expires_at <= valid_from:
                raise ValidationError("expires_at 必须晚于 valid_from")

        with self._lock:
            existing = self.repo.agents.get(agent_id)
            if existing and existing.patient_id != patient_id:
                raise ValidationError("联系人不能跨患者复用同一标识")
            if existing and existing.status is AgentStatus.TERMINATED:
                raise StateConflictError(
                    "该联系人权限已终止，不能用登记覆盖；终止不可静默复活"
                )
            agent = Agent(
                agent_id=agent_id,
                patient_id=patient_id,
                display_name=display_name,
                channels=norm_channels,
                bases=bases,  # type: ignore[arg-type]
                scope_ranks=scope_ranks,
                valid_from=valid_from,
                expires_at=expires_at,
            )
            self.repo.agents[agent_id] = agent
            self._record(
                actor.actor_id,
                "agent.registered",
                {
                    "agent_id": agent_id,
                    "patient_id": patient_id,
                    "bases": sorted(b.value for b in bases),
                    "scopes": {s.value: r for s, r in scope_ranks.items()},
                    "channels": sorted(norm_channels),
                    "valid_from": iso(valid_from),
                    "expires_at": iso(expires_at) if expires_at else None,
                },
            )
            return {"agent": agent.as_dict(mask_contact=False)}

    # -- 文书版本 -----------------------------------------------------------

    def add_document_version(self, actor: Actor, params: dict) -> dict:
        """追加一个不可变文书版本；新版本一旦存在，旧确认自动失效。"""
        self._require_perm(actor, self.PERM_STAFF)
        doc_id = require_id(params.get("doc_id", ""), "doc_id")
        title = str(params.get("title", "")).strip()
        if not title:
            raise ValidationError("title 不能为空")
        content = params.get("content")
        if content is None:
            raise ValidationError("content 不能为空")
        digest = content_digest(content)
        client_digest = params.get("digest")
        if client_digest and client_digest != digest:
            raise ValidationError("客户端摘要与服务端重算不一致，拒绝入档")
        with self._lock:
            versions = self.repo.documents.setdefault(doc_id, [])
            version = len(versions) + 1
            dv = DocumentVersion(doc_id, version, title, digest, self._now())
            versions.append(dv)
            self._record(
                actor.actor_id,
                "document.versioned",
                {"doc_id": doc_id, "version": version, "title": title, "digest": digest},
            )
            return {"document": dv.as_dict()}

    def _latest_doc(self, doc_id: str) -> DocumentVersion:
        versions = self.repo.documents.get(doc_id)
        if not versions:
            raise NotFoundError(f"文书不存在: {doc_id}")
        return versions[-1]

    # -- 事项开立（含跨午夜重复抑制与最小披露白名单） -----------------------

    def open_matter(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_STAFF)
        key = require_id(params.get("idempotency_key", ""), "idempotency_key")
        patient_id = require_id(params.get("patient_id", ""), "patient_id")
        scope = enum_value(RoleScope, params.get("scope", ""), "scope")
        doc_id = require_id(params.get("doc_id", ""), "doc_id")
        disclosure = params.get("disclosure")
        if not isinstance(disclosure, dict) or not disclosure:
            raise ValidationError("disclosure 必须是非空对象")
        allowed = set(SCOPE_DISCLOSURE_FIELDS[scope])  # type: ignore[index]
        extra = set(disclosure) - allowed
        if extra:
            raise ValidationError(f"超出 {scope.value} 最少披露字段: {sorted(extra)}")
        missing = [f for f in SCOPE_DISCLOSURE_FIELDS[scope] if not disclosure.get(f)]  # type: ignore[index]
        if missing:
            raise ValidationError(f"缺少必要披露字段: {missing}")

        with self._lock:
            if key in self.repo.key_index:
                matter = self.repo.matters[self.repo.key_index[key]]
                self._record(
                    actor.actor_id,
                    "matter.open.deduped",
                    {"matter_id": matter.matter_id, "idempotency_key": key},
                )
                return {"matter": matter.as_dict(), "deduped": True}

            doc = self._latest_doc(doc_id)
            now = self._now()
            bdate = self._business_date(now)
            day_key = (patient_id, scope.value, bdate)
            if day_key in self.repo.day_index:
                prior = self.repo.matters[self.repo.day_index[day_key]]
                raise StateConflictError(
                    f"同一业务日（{bdate}）该患者的 {scope.value} 事项已存在: "
                    f"{prior.matter_id}；跨午夜交班/重复回调不得重复发起"
                )

            eligible = self._eligible_agents(patient_id, scope, now)

            matter_id = "M-" + uuid.uuid4().hex[:12]
            matter = Matter(
                matter_id=matter_id,
                idempotency_key=key,
                patient_id=patient_id,
                scope=scope,  # type: ignore[arg-type]
                doc_id=doc_id,
                disclosure=dict(disclosure),
                opened_at=now,
                opened_by=actor.actor_id,
                business_date=bdate,
            )
            # 没有生效联系人也允许建档（顺位即空），以便走抢救例外并留痕。
            if not eligible:
                matter.status = MatterStatus.UNRESOLVED
            self.repo.matters[matter_id] = matter
            self.repo.key_index[key] = matter_id
            self.repo.day_index[day_key] = matter_id
            self._record(
                actor.actor_id,
                "matter.opened",
                {
                    "matter_id": matter_id,
                    "idempotency_key": key,
                    "patient_id": patient_id,
                    "scope": scope.value,
                    "business_date": bdate,
                    "doc_ref": doc.ref(),
                    "disclosure_digest": content_digest(disclosure),
                    "disclosure_fields": sorted(disclosure),
                    "eligible_order": [a.agent_id for a in eligible],
                    "no_eligible_contact": not eligible,
                },
            )
            return {"matter": matter.as_dict(), "deduped": False}

    # -- 资格/顺位计算（纯函数式，复盘时可对任意时刻重算） ------------------

    def _eligible_agents(
        self, patient_id: str, scope: RoleScope, at: datetime
    ) -> list[Agent]:
        candidates: list[tuple[tuple[int, int, str], Agent]] = []
        for agent in self.repo.agents.values():
            if agent.patient_id != patient_id:
                continue
            if scope not in agent.scope_ranks:
                continue
            if agent.status is not AgentStatus.ACTIVE:
                continue
            if agent.terminated_at and agent.terminated_at <= at:
                continue
            if not (agent.valid_from <= at):
                continue
            if agent.expires_at and not (at < agent.expires_at):
                continue
            # 院方核验是生效闸门；授权来源必须是预先指定或法定关系之一。
            if BasisType.HOSPITAL_VERIFIED not in agent.bases:
                continue
            source = None
            if BasisType.LEGAL in agent.bases:
                source = BasisType.LEGAL
            elif BasisType.DESIGNATED in agent.bases:
                source = BasisType.DESIGNATED
            else:
                continue
            sort_key = (
                _SOURCE_WEIGHT[source],
                agent.scope_ranks[scope],
                agent.agent_id,
            )
            candidates.append((sort_key, agent))
        candidates.sort(key=lambda item: item[0])
        return [a for _, a in candidates]

    def authority_snapshot(
        self, patient_id: str, scope: RoleScope, at: datetime
    ) -> dict:
        """供复盘：还原某时刻的联系人顺位、有效期与未入选原因。"""
        ordered = self._eligible_agents(patient_id, scope, at)
        considered = []
        for agent in self.repo.agents.values():
            if agent.patient_id != patient_id or scope not in agent.scope_ranks:
                continue
            reasons = []
            if agent.status is not AgentStatus.ACTIVE:
                reasons.append(f"已终止({agent.termination_reason.value if agent.termination_reason else '?'})")
            if agent.terminated_at and agent.terminated_at <= at:
                reasons.append("终止时间已到")
            if not (agent.valid_from <= at):
                reasons.append("尚未生效")
            if agent.expires_at and not (at < agent.expires_at):
                reasons.append("已过期")
            if BasisType.HOSPITAL_VERIFIED not in agent.bases:
                reasons.append("未经院方核验")
            if BasisType.HOSPITAL_VERIFIED in agent.bases and not (
                BasisType.LEGAL in agent.bases or BasisType.DESIGNATED in agent.bases
            ):
                reasons.append("缺授权来源")
            considered.append(
                {
                    "agent_id": agent.agent_id,
                    "eligible": not reasons,
                    "reasons": reasons,
                    "bases": sorted(b.value for b in agent.bases),
                    "rank": agent.scope_ranks.get(scope),
                    "valid_from": iso(agent.valid_from),
                    "expires_at": iso(agent.expires_at) if agent.expires_at else None,
                }
            )
        return {
            "patient_id": patient_id,
            "scope": scope.value,
            "at": iso(at),
            "order": [a.agent_id for a in ordered],
            "considered": considered,
        }

    # -- 通知 / 联系尝试 / 升级 ---------------------------------------------

    def _get_matter(self, matter_id: str) -> Matter:
        matter = self.repo.matters.get(matter_id)
        if not matter:
            raise NotFoundError(f"事项不存在: {matter_id}")
        return matter

    def issue_next_notification(self, actor: Actor, params: dict) -> dict:
        """按顺位向当前应联系的人发出通知；仅在前位拒收或失联后才逐级升级。"""
        self._require_perm(actor, self.PERM_CONTACT)
        matter_id = require_id(params.get("matter_id", ""), "matter_id")
        with self._lock:
            matter = self._get_matter(matter_id)
            if matter.status not in (MatterStatus.OPEN, MatterStatus.UNRESOLVED):
                raise StateConflictError(f"事项状态 {matter.status.value}，不再发出通知")
            now = self._now()
            order = self._eligible_agents(matter.patient_id, matter.scope, now)
            if not order:
                raise StateConflictError("已无生效联系人")

            latest_doc = self._latest_doc(matter.doc_id)
            latest_by_agent: dict[str, Notification] = {}
            for prior in matter.notifications:
                latest_by_agent[prior.agent_id] = prior
            target = None
            for candidate in order:
                prior = latest_by_agent.get(candidate.agent_id)
                if prior is None:
                    target = candidate
                    break
                state = prior.state
                if state == "pending":
                    raise StateConflictError("上一通知尚无联系结果，禁止并行发出")
                # 通知送达后文书更新：旧通知绑定旧版本，以新版本向同一人重发。
                if prior.doc_ref["digest"] != latest_doc.digest:
                    target = candidate
                    break
                # 已送达且本人尚未形成立场：仍在等待其决定，不能越级。
                if state == "delivered" and candidate.agent_id not in matter.stances:
                    raise StateConflictError("前位已送达且尚未形成决定，不得越级通知")
                # rejected / unreachable，或已送达且已表态 → 继续下一顺位
            if target is None:
                matter.status = MatterStatus.UNRESOLVED
                self._record(
                    actor.actor_id,
                    "matter.exhausted",
                    {"matter_id": matter_id, "at": iso(now)},
                )
                return {"matter": matter.as_dict(), "exhausted": True}

            level = len(matter.notifications)
            doc = latest_doc
            channels = [Channel(c) for c in target.channels if c in {c2.value for c2 in Channel}]
            channels.sort(key=lambda c: [ch.value for ch in Channel].index(c.value))
            notification = Notification(
                notification_id="N-" + uuid.uuid4().hex[:12],
                agent_id=target.agent_id,
                level=level,
                channels=channels,
                disclosure=dict(matter.disclosure),
                doc_ref=doc.ref(),
                created_at=now,
            )
            matter.notifications.append(notification)
            self.repo.notification_index[notification.notification_id] = notification
            self._record(
                actor.actor_id,
                "notification.issued",
                {
                    "matter_id": matter_id,
                    "notification_id": notification.notification_id,
                    "agent_id": target.agent_id,
                    "level": level,
                    "channels": [c.value for c in channels],
                    "doc_ref": doc.ref(),
                    "disclosure_digest": content_digest(matter.disclosure),
                },
            )
            return {"notification": notification.as_dict()}

    def record_contact_attempt(self, actor: Actor, params: dict) -> dict:
        """记录一次渠道尝试（送达/拒收/失联）；重复回调幂等。"""
        self._require_perm(actor, self.PERM_CONTACT)
        notification_id = require_id(
            params.get("notification_id", ""), "notification_id"
        )
        channel = enum_value(Channel, params.get("channel", ""), "channel")
        result = enum_value(ContactResult, params.get("result", ""), "result")
        client_req = params.get("request_id")
        request_id = require_id(
            client_req, "request_id"
        ) if client_req else f"auto:{notification_id}:{channel.value}:{result.value}"
        detail = str(params.get("detail", ""))[:200]

        with self._lock:
            if request_id in self.repo.request_index:
                return dict(self.repo.request_index[request_id])
            dedupe_key = f"{notification_id}|{channel.value}|{result.value}|{detail}"
            if dedupe_key in self.repo.attempt_keys:
                raise StateConflictError("内容相同的联系回调已处理，忽略重复回调")
            notification = self.repo.notification_index.get(notification_id)
            if not notification:
                raise NotFoundError(f"通知不存在: {notification_id}")
            if channel not in notification.channels:  # type: ignore[arg-type]
                raise ValidationError("该渠道不在本通知允许的联系方式内")
            matter = self._get_matter_by_notification(notification_id)
            now = self._now()
            attempt = ContactAttempt(
                attempt_id="C-" + uuid.uuid4().hex[:12],
                notification_id=notification_id,
                agent_id=notification.agent_id,
                channel=channel,  # type: ignore[arg-type]
                result=result,  # type: ignore[arg-type]
                at=now,
                actor_id=actor.actor_id,
                detail=detail,
            )
            notification.attempts.append(attempt)
            if result is ContactResult.DELIVERED and notification.delivered_at is None:
                notification.delivered_at = now
            self.repo.attempt_keys.add(dedupe_key)
            self._record(
                actor.actor_id,
                "contact.attempted",
                {
                    "matter_id": matter.matter_id,
                    "notification_id": notification_id,
                    "attempt_id": attempt.attempt_id,
                    "agent_id": notification.agent_id,
                    "channel": channel.value,
                    "result": result.value,
                    "detail_present": bool(detail),
                },
            )
            response = {"attempt": attempt.as_dict(), "notification_state": notification.state}
            self.repo.request_index[request_id] = response
            return response

    def _get_matter_by_notification(self, notification_id: str) -> Matter:
        for matter in self.repo.matters.values():
            if any(n.notification_id == notification_id for n in matter.notifications):
                return matter
        raise NotFoundError(f"通知不属于任何事项: {notification_id}")

    # -- 远程确认（绑定版本/身份/签署时间）与拒收立场 -----------------------

    def submit_confirmation(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_CONTACT)
        notification_id = require_id(
            params.get("notification_id", ""), "notification_id"
        )
        agent_id = require_id(params.get("agent_id", ""), "agent_id")
        request_id = require_id(params.get("request_id", ""), "request_id")
        identity = params.get("identity_verification")
        if not isinstance(identity, dict) or not identity.get("method"):
            raise ValidationError("identity_verification.method 不能为空")
        if identity["method"] not in {c.value for c in Channel} | {"in-person"}:
            raise ValidationError("不支持的身份校验方式")
        note = str(params.get("note", ""))[:200]

        with self._lock:
            if request_id in self.repo.request_index:
                return dict(self.repo.request_index[request_id])
            notification = self.repo.notification_index.get(notification_id)
            if not notification:
                raise NotFoundError(f"通知不存在: {notification_id}")
            if notification.agent_id != agent_id:
                raise AuthorizationError("该通知未发送给此联系人，不能代为确认")
            if notification.state != "delivered":
                raise StateConflictError("通知未送达，不能形成远程确认")
            matter = self._get_matter_by_notification(notification_id)
            if matter.status in (MatterStatus.CONFIRMED, MatterStatus.TERMINATED,
                                 MatterStatus.RESOLVED, MatterStatus.UNDER_REVIEW):
                raise StateConflictError(f"事项已处于 {matter.status.value}")
            now = self._now()
            eligible = self._eligible_agents(matter.patient_id, matter.scope, now)
            if not any(a.agent_id == agent_id for a in eligible):
                raise AuthorizationError("签署时联系人资格/有效期已不成立")
            latest = self._latest_doc(matter.doc_id)
            if notification.doc_ref["digest"] != latest.digest:
                raise StateConflictError(
                    "文书已更新，本通知绑定的是旧版本；请以新版本重新通知后再确认"
                )

            confirmation = Confirmation(
                confirmation_id="F-" + uuid.uuid4().hex[:12],
                notification_id=notification_id,
                agent_id=agent_id,
                doc_ref=latest.ref(),
                identity_verification={
                    "method": identity["method"],
                    "evidence_id": str(identity.get("evidence_id", "")),
                },
                signed_at=now,
                actor_id=actor.actor_id,
                request_id=request_id,
                note=note,
            )
            matter.confirmations.append(confirmation)
            matter.stances[agent_id] = Stance.CONFIRM
            opposing = [a for a, s in matter.stances.items() if s is Stance.REFUSE]
            if opposing:
                matter.status = MatterStatus.CONFLICT
                self._record(
                    actor.actor_id,
                    "matter.conflict",
                    {
                        "matter_id": matter.matter_id,
                        "confirming_agent": agent_id,
                        "refusing_agents": opposing,
                    },
                )
            elif matter.review is None:
                # 病危通知以知悉为目的；同意类事项取得确认即关闭。
                if matter.scope in (RoleScope.EXAM_CONSENT, RoleScope.TRANSFER):
                    matter.status = MatterStatus.CONFIRMED
                    matter.closed_at = now
            self._record(
                actor.actor_id,
                "confirmation.submitted",
                {
                    "matter_id": matter.matter_id,
                    "confirmation_id": confirmation.confirmation_id,
                    "notification_id": notification_id,
                    "agent_id": agent_id,
                    "doc_ref": latest.ref(),
                    "identity_method": identity["method"],
                    "signed_at": iso(now),
                    "matter_status": matter.status.value,
                },
            )
            response = {
                "confirmation": confirmation.as_dict(
                    current_status=self._confirmation_status(matter, confirmation)
                ),
                "matter_status": matter.status.value,
            }
            self.repo.request_index[request_id] = response
            return response

    def record_refusal(self, actor: Actor, params: dict) -> dict:
        """联系人明确拒绝（拒收文书/不同意）；与确认相立即触发冲突。"""
        self._require_perm(actor, self.PERM_CONTACT)
        notification_id = require_id(
            params.get("notification_id", ""), "notification_id"
        )
        agent_id = require_id(params.get("agent_id", ""), "agent_id")
        reason = str(params.get("reason", ""))[:200]
        with self._lock:
            notification = self.repo.notification_index.get(notification_id)
            if not notification or notification.agent_id != agent_id:
                raise NotFoundError("通知与联系人不匹配")
            matter = self._get_matter_by_notification(notification_id)
            if matter.status in (MatterStatus.CONFIRMED, MatterStatus.TERMINATED,
                                 MatterStatus.RESOLVED, MatterStatus.UNDER_REVIEW):
                raise StateConflictError(f"事项已处于 {matter.status.value}，不再受理立场")
            if notification.state not in ("delivered", "rejected"):
                raise StateConflictError("通知尚未送达/拒收，不能登记决定立场")
            now = self._now()
            matter.stances[agent_id] = Stance.REFUSE
            confirming = [a for a, s in matter.stances.items() if s is Stance.CONFIRM]
            if confirming:
                matter.status = MatterStatus.CONFLICT
            self._record(
                actor.actor_id,
                "stance.refused",
                {
                    "matter_id": matter.matter_id,
                    "notification_id": notification_id,
                    "agent_id": agent_id,
                    "reason_present": bool(reason),
                    "opposed_confirmations": confirming,
                    "matter_status": matter.status.value,
                },
            )
            return {"matter_status": matter.status.value}

    def _confirmation_status(
        self, matter: Matter, confirmation: Confirmation
    ) -> ConfirmationStatus:
        """以签署时刻重算：版本是否仍最新、签署时资格是否成立、是否落在终止之后。"""
        latest = self._latest_doc(matter.doc_id)
        if latest.digest != confirmation.doc_ref["digest"]:
            return ConfirmationStatus.SUPERSEDED
        eligible = self._eligible_agents(
            matter.patient_id, matter.scope, confirmation.signed_at
        )
        if not any(a.agent_id == confirmation.agent_id for a in eligible):
            return ConfirmationStatus.INVALID
        if matter.termination and matter.termination["at"] <= iso(confirmation.signed_at):
            return ConfirmationStatus.INVALID
        return ConfirmationStatus.VALID

    # -- 冲突复核 -----------------------------------------------------------

    def escalate_review(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_CONTACT)
        matter_id = require_id(params.get("matter_id", ""), "matter_id")
        route = enum_value(ReviewRoute, params.get("route", ""), "route")
        with self._lock:
            matter = self._get_matter(matter_id)
            if matter.status not in (MatterStatus.CONFLICT, MatterStatus.OPEN,
                                     MatterStatus.UNRESOLVED):
                raise StateConflictError(f"事项状态 {matter.status.value}，无需复核")
            now = self._now()
            matter.review = Review(
                route=route,  # type: ignore[arg-type]
                opened_at=now,
                opened_by=actor.actor_id,
            )
            matter.status = MatterStatus.UNDER_REVIEW
            self._record(
                actor.actor_id,
                "review.opened",
                {
                    "matter_id": matter_id,
                    "route": route.value,
                    "stances": {a: s.value for a, s in matter.stances.items()},
                },
            )
            return {"review": matter.review.as_dict(), "matter_status": matter.status.value}

    def decide_review(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_REVIEW)
        matter_id = require_id(params.get("matter_id", ""), "matter_id")
        outcome = enum_value(Stance, params.get("outcome", ""), "outcome")
        rationale = str(params.get("rationale", "")).strip()
        if len(rationale) < 10:
            raise ValidationError("复核结论必须包含不少于 10 字的理由")
        with self._lock:
            matter = self._get_matter(matter_id)
            if not matter.review or matter.review.state is not ReviewState.PENDING:
                raise StateConflictError("没有待裁决的复核")
            now = self._now()
            matter.review.state = ReviewState.DECIDED
            matter.review.decided_at = now
            matter.review.decided_by = actor.actor_id
            matter.review.outcome = outcome  # type: ignore[assignment]
            matter.review.rationale = rationale
            matter.status = MatterStatus.RESOLVED
            matter.closed_at = now
            self._record(
                actor.actor_id,
                "review.decided",
                {
                    "matter_id": matter_id,
                    "outcome": outcome.value,
                    "route": matter.review.route.value,
                    "rationale_digest": content_digest(rationale),
                },
            )
            return {"review": matter.review.as_dict(), "matter_status": matter.status.value}

    # -- 抢救例外（只记录医护说明，绝不代作医疗决定） -----------------------

    def open_emergency_exception(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_EMERGENCY)
        matter_id = require_id(params.get("matter_id", ""), "matter_id")
        urgency = str(params.get("urgency_statement", "")).strip()
        action = str(params.get("action_taken", "")).strip()
        if len(urgency) < 10:
            raise ValidationError("紧迫性说明不少于 10 字，且必须由有资质医护填写")
        if len(action) < 5:
            raise ValidationError("需记录已采取的紧急处置")
        with self._lock:
            matter = self._get_matter(matter_id)
            if matter.exception and matter.exception.status is ExceptionStatus.OPEN:
                raise StateConflictError("该事项已有待补证的抢救例外")
            if matter.status is MatterStatus.CONFIRMED:
                raise StateConflictError("已取得有效确认，不适用抢救例外")
            now = self._now()
            exc = EmergencyException(
                exception_id="E-" + uuid.uuid4().hex[:12],
                clinician_id=actor.actor_id,
                permissions=sorted(actor.permissions),
                urgency_statement=urgency,
                action_taken=action,
                opened_at=now,
            )
            matter.exception = exc
            self._record(
                actor.actor_id,
                "exception.opened",
                {
                    "matter_id": matter_id,
                    "exception_id": exc.exception_id,
                    "clinician_id": actor.actor_id,
                    "urgency_digest": content_digest(urgency),
                    "action_digest": content_digest(action),
                    "matter_status_before": matter.status.value,
                    "note": "系统仅记录医护说明，不产生任何医疗结论",
                },
            )
            return {"exception": exc.as_dict()}

    def substantiate_exception(self, actor: Actor, params: dict) -> dict:
        self._require_perm(actor, self.PERM_SUBSTANTIATE)
        matter_id = require_id(params.get("matter_id", ""), "matter_id")
        basis_refs = params.get("basis_refs")
        if not isinstance(basis_refs, list) or not basis_refs:
            raise ValidationError("basis_refs 至少包含一份事后依据（记录/文书标识）")
        for ref in basis_refs:
            if not isinstance(ref, dict) or not ref.get("ref") or not ref.get("kind"):
                raise ValidationError("每条依据需含 kind 与 ref")
        with self._lock:
            matter = self._get_matter(matter_id)
            if not matter.exception:
                raise NotFoundError("该事项没有抢救例外记录")
            if matter.exception.status is ExceptionStatus.SUBSTANTIATED:
                raise StateConflictError("例外已补证，不可重复提交")
            now = self._now()
            matter.exception.status = ExceptionStatus.SUBSTANTIATED
            matter.exception.substantiated_at = now
            matter.exception.substantiated_by = actor.actor_id
            matter.exception.basis_refs = basis_refs
            self._record(
                actor.actor_id,
                "exception.substantiated",
                {
                    "matter_id": matter_id,
                    "exception_id": matter.exception.exception_id,
                    "basis_count": len(basis_refs),
                    "basis_kinds": [b["kind"] for b in basis_refs],
                },
            )
            return {"exception": matter.exception.as_dict()}

    # -- 终止事件 -----------------------------------------------------------

    def record_termination(self, actor: Actor, params: dict) -> dict:
        """转院/恢复意识/撤销代理/离院：终止权限并关闭在途事项。"""
        self._require_perm(actor, self.PERM_TERMINATE)
        patient_id = require_id(params.get("patient_id", ""), "patient_id")
        reason = enum_value(TerminationReason, params.get("reason", ""), "reason")
        agent_id = params.get("agent_id")
        if reason is TerminationReason.REVOKED:
            if not agent_id:
                raise ValidationError("撤销代理必须指定 agent_id")
            require_id(agent_id, "agent_id")
        elif agent_id:
            raise ValidationError("仅撤销代理可指定单个 agent_id")
        now = self._now()
        with self._lock:
            affected_agents: list[str] = []
            for agent in self.repo.agents.values():
                if agent.patient_id != patient_id:
                    continue
                if reason is TerminationReason.REVOKED and agent.agent_id != agent_id:
                    continue
                if agent.status is AgentStatus.ACTIVE:
                    agent.status = AgentStatus.TERMINATED
                    agent.terminated_at = now
                    agent.termination_reason = reason  # type: ignore[assignment]
                    affected_agents.append(agent.agent_id)

            closed_matters: list[str] = []
            for matter in self.repo.matters.values():
                if matter.patient_id != patient_id:
                    continue
                if matter.status in (
                    MatterStatus.RESOLVED,
                    MatterStatus.TERMINATED,
                ):
                    continue
                if reason is TerminationReason.REVOKED:
                    involved = (
                        any(n.agent_id == agent_id for n in matter.notifications)
                        or any(c.agent_id == agent_id for c in matter.confirmations)
                        or agent_id in matter.stances
                    )
                    # 撤销与该在途事项无关的联系人，不影响事项本身。
                    if not involved:
                        continue
                matter.status = MatterStatus.TERMINATED
                matter.closed_at = now
                matter.termination = {
                    "reason": reason.value,
                    "at": iso(now),
                    "by": actor.actor_id,
                    "agent_id": agent_id,
                }
                closed_matters.append(matter.matter_id)

            self._record(
                actor.actor_id,
                "authority.terminated",
                {
                    "patient_id": patient_id,
                    "reason": reason.value,
                    "agent_id": agent_id,
                    "affected_agents": affected_agents,
                    "closed_matters": closed_matters,
                },
            )
            return {"affected_agents": affected_agents, "closed_matters": closed_matters}

    # -- 复盘视图 / 隐私 ----------------------------------------------------

    def _confirmation_status_public(
        self, matter: Matter, confirmation: Confirmation
    ) -> ConfirmationStatus:
        """与内部版一致，但不依赖终止事件的私有键。"""
        latest = self._latest_doc(matter.doc_id)
        if latest.digest != confirmation.doc_ref["digest"]:
            return ConfirmationStatus.SUPERSEDED
        eligible = self._eligible_agents(
            matter.patient_id, matter.scope, confirmation.signed_at
        )
        if not any(a.agent_id == confirmation.agent_id for a in eligible):
            return ConfirmationStatus.INVALID
        if matter.termination and matter.termination["at"] <= iso(confirmation.signed_at):
            return ConfirmationStatus.INVALID
        return ConfirmationStatus.VALID

    def review_dossier(self, actor: Actor, matter_id: str) -> dict:
        """审查人员视图：完整还原资格、披露、尝试、决定版本与例外理由。"""
        self._require_perm(actor, self.PERM_AUDIT)
        with self._lock:
            matter = self._get_matter(matter_id)
            self.audit.verify()
            authority_at_open = self.authority_snapshot(
                matter.patient_id, matter.scope, matter.opened_at
            )
            confirmations = [
                c.as_dict(
                    current_status=self._confirmation_status_public(matter, c)
                )
                for c in matter.confirmations
            ]
            doc_versions = [
                d.as_dict()
                for d in self.repo.documents.get(matter.doc_id, [])
            ]
            agents = {
                a.agent_id: a.as_dict(mask_contact=False)
                for n in matter.notifications
                for a in [self.repo.agents[n.agent_id]]
            }
            self._record(
                actor.actor_id,
                "dossier.viewed",
                {"matter_id": matter_id, "viewer": actor.actor_id, "view": "audit"},
            )
            return {
                "view": "audit",
                "matter": matter.as_dict(),
                "authority_at_open": authority_at_open,
                "authority_now": self.authority_snapshot(
                    matter.patient_id, matter.scope, self._now()
                ),
                "disclosure": matter.disclosure,
                "document_versions": doc_versions,
                "notifications": [n.as_dict() for n in matter.notifications],
                "stances": {a: s.value for a, s in matter.stances.items()},
                "confirmations": confirmations,
                "review": matter.review.as_dict() if matter.review else None,
                "exception": matter.exception.as_dict() if matter.exception else None,
                "termination": matter.termination,
                "agents": agents,
            }

    def family_view(self, agent_id: str, matter_id: str) -> dict:
        """普通家属视图：只见与本人相关的通知/披露/确认，看不到他人隐私。"""
        require_id(agent_id, "agent_id")
        with self._lock:
            matter = self._get_matter(matter_id)
            if not any(n.agent_id == agent_id for n in matter.notifications):
                # 不泄露事项是否存在：统一 404。
                raise NotFoundError(f"事项不存在: {matter_id}")
            own_notifications = [
                n.as_dict() for n in matter.notifications if n.agent_id == agent_id
            ]
            own_confirmations = [
                {
                    "confirmation_id": c.confirmation_id,
                    "doc_ref": c.doc_ref,
                    "signed_at": iso(c.signed_at),
                    "identity_verification": {
                        "method": c.identity_verification["method"]
                    },
                    "status": self._confirmation_status_public(matter, c).value,
                }
                for c in matter.confirmations
                if c.agent_id == agent_id
            ]
            return {
                "view": "family",
                "matter": {
                    "matter_id": matter.matter_id,
                    "scope": matter.scope.value,
                    "status": matter.status.value,
                    "business_date": matter.business_date,
                },
                "notifications": own_notifications,
                "confirmations": own_confirmations,
                # 明确不返回：其他联系人、联系尝试、披露给他人的内容、
                # 紧迫性临床叙述、复核内部理由。
            }

    def verify_audit_chain(self) -> dict:
        with self._lock:
            self.audit.verify()
            return {"entries": len(self.audit.entries()), "integrity": "ok"}

    # -- RPC 分发 -----------------------------------------------------------

    METHODS = {
        "register_agent",
        "add_document_version",
        "open_matter",
        "issue_next_notification",
        "record_contact_attempt",
        "submit_confirmation",
        "record_refusal",
        "escalate_review",
        "decide_review",
        "open_emergency_exception",
        "substantiate_exception",
        "record_termination",
    }

    def dispatch(self, envelope: dict) -> dict:
        if not isinstance(envelope, dict):
            raise ValidationError("请求体必须是对象")
        method = envelope.get("method")
        if method not in self.METHODS:
            raise NotFoundError(f"未知方法: {method}")
        params = envelope.get("params") or {}
        if not isinstance(params, dict):
            raise ValidationError("params 必须是对象")
        actor = Actor.from_dict(envelope.get("actor") or {})
        handler = getattr(self, method)
        return handler(actor, params)

    # -- 私有辅助 -----------------------------------------------------------

    def _parse_ts(
        self, value: Any, field_name: str, default: Optional[datetime] = None
    ) -> datetime:
        if value is None and default is not None:
            return default
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} 必须是 ISO8601 字符串")
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field_name} 时间格式非法") from exc
        if dt.tzinfo is None:
            raise ValidationError(f"{field_name} 必须带时区")
        return dt.astimezone(timezone.utc)


def health_payload() -> dict:
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}

# ---------------------------------------------------------------------------
# HTTP 适配层
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    service: CollaborationService = None  # type: ignore[assignment]

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send_json(200, health_payload())
            return
        if self.path.startswith("/matters/"):
            rest = self.path[len("/matters/") :].split("?", 1)
            matter_id = rest[0]
            query = rest[1] if len(rest) > 1 else ""
            params = dict(
                item.split("=", 1) for item in query.split("&") if "=" in item
            )
            try:
                if params.get("view") == "family":
                    agent_id = params.get("agent_id", "")
                    self._send_json(
                        200, self.service.family_view(agent_id, matter_id)
                    )
                    return
                actor = Actor(
                    actor_id=params.get("actor_id", "anonymous"),
                    permissions=frozenset({CollaborationService.PERM_AUDIT}),
                )
                self._send_json(200, self.service.review_dossier(actor, matter_id))
            except DomainError as exc:
                self._send_domain_error(exc)
            return
        self.send_error(404)

    def do_POST(self):  # noqa: N802
        if self.path != "/rpc":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            envelope = json.loads(raw.decode("utf-8"))
            result = self.service.dispatch(envelope)
            self._send_json(200, {"ok": True, "result": result})
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": {"code": "bad_json"}})
        except DomainError as exc:
            self._send_domain_error(exc)

    def _send_domain_error(self, exc: DomainError) -> None:
        status = {
            ValidationError.code: 400,
            NotFoundError.code: 404,
            StateConflictError.code: 409,
            AuthorizationError.code: 403,
        }.get(exc.code, 422)
        self._send_json(
            status, {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
        )

    def log_message(self, *_args):  # noqa: D401
        return


def build_server(port: int) -> ThreadingHTTPServer:
    service = CollaborationService()
    Handler.service = service
    return ThreadingHTTPServer(("0.0.0.0", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        CollaborationService().verify_audit_chain()
        print("基础检查通过")
        return
    build_server(args.port).serve_forever()


if __name__ == "__main__":
    main()
