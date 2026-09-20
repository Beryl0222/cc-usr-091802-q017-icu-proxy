"""领域模型：全部为可序列化的数据记录，业务规则在 service 层。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .enums import (
    ConfirmationStance,
    DeliveryOutcome,
    DocumentKind,
    MatterStatus,
    MatterType,
    ReferralStatus,
    Relation,
    ReviewBody,
    TerminationReason,
    VerificationStatus,
)


@dataclass
class Actor:
    """系统操作者。联系人同时也是家属侧 Actor。"""

    id: str
    name: str
    role: str  # ActorRole 值
    # 联系人专有字段（系统操作者为 None）
    relation: Optional[str] = None   # Relation 值
    phone: Optional[str] = None
    secure_link_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "relation": self.relation,
            "phone": self.phone,
            "secure_link_id": self.secure_link_id,
        }


@dataclass
class Patient:
    id: str
    name: str
    mrn: str  # 住院号

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "mrn": self.mrn}


@dataclass
class ContactGrant:
    """一名联系人对一名患者的代理资格。

    顺位由 basis 决定：patient_designated 整体优先于 legal；
    院方核验（verification_status=verified）是生效闸门，
    并须落在 [valid_from, valid_to) 时间窗内、未被终止。
    """

    id: str
    patient_id: str
    actor_id: str
    basis: str                       # Basis 值
    relation: Optional[str]         # basis=legal 时的 Relation 值
    rank: int                        # 同类内部顺位（预先指定的指定顺序/法定顺位）
    matters: list[str]               # 授权覆盖的 MatterType 值；空表示全部
    valid_from: str
    valid_to: Optional[str]
    verification_status: str = VerificationStatus.PENDING.value
    verified_by: Optional[str] = None
    verified_at: Optional[str] = None
    verification_note: Optional[str] = None
    # 终止
    terminated_at: Optional[str] = None
    termination_reason: Optional[str] = None
    created_at: Optional[str] = None

    def covers(self, matter_type: str) -> bool:
        return not self.matters or matter_type in self.matters

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "actor_id": self.actor_id,
            "basis": self.basis,
            "relation": self.relation,
            "rank": self.rank,
            "matters": list(self.matters),
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "verification_status": self.verification_status,
            "verified_by": self.verified_by,
            "verified_at": self.verified_at,
            "verification_note": self.verification_note,
            "terminated_at": self.terminated_at,
            "termination_reason": self.termination_reason,
            "created_at": self.created_at,
        }


@dataclass
class TerminationEvent:
    """患者转院/恢复意识/撤销代理/离院等权限终止事件。"""

    id: str
    patient_id: str
    reason: str                       # TerminationReason 值
    at: str
    actor_id: str                     # 记录人
    grant_id: Optional[str] = None    # 定向终止单个联系人时填写
    note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "reason": self.reason,
            "at": self.at,
            "actor_id": self.actor_id,
            "grant_id": self.grant_id,
            "note": self.note,
        }


@dataclass
class DocumentVersion:
    """不可变文书版本。内容一旦写入只能发布新版本。"""

    id: str
    patient_id: str
    matter_id: str
    kind: str                 # DocumentKind 值
    version: int
    title: str
    content: str
    sha256: str               # 对规范化内容的摘要
    created_by: str
    created_at: str
    supersedes: Optional[str] = None  # 上一版本 id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "matter_id": self.matter_id,
            "kind": self.kind,
            "version": self.version,
            "title": self.title,
            "content": self.content,
            "sha256": self.sha256,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "supersedes": self.supersedes,
        }


@dataclass
class DisclosurePacket:
    """一次送达时向联系人披露的**最少**病情摘要，送达即冻结。"""

    id: str
    matter_id: str
    grant_id: str
    actor_id: str
    document_id: str
    document_sha256: str
    minimal_summary: str     # 经裁剪的最小摘要文本
    fields: list[str]        # 摘要包含的字段类别（白名单）
    frozen_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "grant_id": self.grant_id,
            "actor_id": self.actor_id,
            "document_id": self.document_id,
            "document_sha256": self.document_sha256,
            "minimal_summary": self.minimal_summary,
            "fields": list(self.fields),
            "frozen_at": self.frozen_at,
        }


@dataclass
class DeliveryAttempt:
    """一次联系尝试。"""

    id: str
    matter_id: str
    grant_id: str
    actor_id: str
    channel: str
    outcome: str             # DeliveryOutcome 值
    at: str
    recorded_by: str
    detail: Optional[str] = None
    disclosure_id: Optional[str] = None  # 送达成功时关联的披露包
    document_id: Optional[str] = None    # 尝试时事项的当前文书版本
    order_index: int = 0      # 该事项内尝试序号（用于审计）

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "grant_id": self.grant_id,
            "actor_id": self.actor_id,
            "channel": self.channel,
            "outcome": self.outcome,
            "at": self.at,
            "recorded_by": self.recorded_by,
            "detail": self.detail,
            "disclosure_id": self.disclosure_id,
            "document_id": self.document_id,
            "order_index": self.order_index,
        }


@dataclass
class Confirmation:
    """远程确认：绑定文书摘要、不可变版本、身份校验与签署时间。"""

    id: str
    matter_id: str
    grant_id: str
    actor_id: str
    document_id: str
    document_sha256: str
    document_version: int
    stance: str                  # ConfirmationStance 值
    identity_method: str         # 使用的身份校验方式
    identity_evidence: str       # 校验证据（如回拨号码/令牌摘要）
    signed_at: str               # 服务端记录的签署时间
    binding_hash: str            # 对确认关键要素的绑定摘要
    status: str = "valid"        # valid | superseded
    superseded_at: Optional[str] = None
    recorded_by: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "grant_id": self.grant_id,
            "actor_id": self.actor_id,
            "document_id": self.document_id,
            "document_sha256": self.document_sha256,
            "document_version": self.document_version,
            "stance": self.stance,
            "identity_method": self.identity_method,
            "identity_evidence": self.identity_evidence,
            "signed_at": self.signed_at,
            "binding_hash": self.binding_hash,
            "status": self.status,
            "superseded_at": self.superseded_at,
            "recorded_by": self.recorded_by,
        }


@dataclass
class Referral:
    """意见冲突 → 伦理/医务复核；或全失联 → 医务处升级。"""

    id: str
    matter_id: str
    patient_id: str
    body: str                    # ReviewBody 值
    reason: str                  # conflict | all_unreachable
    opened_at: str
    opened_by: str
    status: str = ReferralStatus.OPEN.value
    conflicting: list[str] = field(default_factory=list)  # 冲突的 confirmation id
    concluded_at: Optional[str] = None
    concluded_by: Optional[str] = None
    decision_stance: Optional[str] = None   # 复核采纳的立场（人工决定）
    rationale: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "patient_id": self.patient_id,
            "body": self.body,
            "reason": self.reason,
            "opened_at": self.opened_at,
            "opened_by": self.opened_by,
            "status": self.status,
            "conflicting": list(self.conflicting),
            "concluded_at": self.concluded_at,
            "concluded_by": self.concluded_by,
            "decision_stance": self.decision_stance,
            "rationale": self.rationale,
        }


@dataclass
class EmergencyException:
    """抢救例外：有权限医护说明紧迫性后先行处置，事后补齐依据。

    系统只记录该例外，不生成、不推断任何医疗措施。
    """

    id: str
    matter_id: str
    patient_id: str
    authorized_by: str           # 开立人（须具权限）
    urgency_statement: str       # 紧迫性说明（必填）
    opened_at: str
    basis_due_at: str            # 补齐依据限期
    basis_provided_at: Optional[str] = None
    basis_documents: list[str] = field(default_factory=list)
    basis_reviewed_by: Optional[str] = None
    basis_review_note: Optional[str] = None
    overdue: bool = False        # 由服务在查询时按时间标记

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "patient_id": self.patient_id,
            "authorized_by": self.authorized_by,
            "urgency_statement": self.urgency_statement,
            "opened_at": self.opened_at,
            "basis_due_at": self.basis_due_at,
            "basis_provided_at": self.basis_provided_at,
            "basis_documents": list(self.basis_documents),
            "basis_reviewed_by": self.basis_reviewed_by,
            "basis_review_note": self.basis_review_note,
            "overdue": self.overdue,
        }


@dataclass
class Matter:
    """一个需要家属代理的事项（病危通知/检查同意/转院）。"""

    id: str
    patient_id: str
    type: str                    # MatterType 值
    title: str
    created_at: str
    created_by: str
    idempotency_key: str
    status: str = MatterStatus.OPEN.value
    current_document_id: Optional[str] = None
    # 通知推进
    next_rank_index: int = 0     # 下一应联系的顺位下标
    unreachable_count: int = 0
    last_outcome: Optional[str] = None
    closed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "type": self.type,
            "title": self.title,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "current_document_id": self.current_document_id,
            "next_rank_index": self.next_rank_index,
            "unreachable_count": self.unreachable_count,
            "last_outcome": self.last_outcome,
            "closed_at": self.closed_at,
        }
