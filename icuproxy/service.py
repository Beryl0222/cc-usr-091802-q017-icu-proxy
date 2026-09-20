"""核心领域服务：代理资格、通知升级、版本绑定确认、冲突复核、抢救例外、复盘。

设计边界：本服务只做**记录与路由**，不输出任何医疗建议或处置选择。
抢救例外的紧迫性由具权限医护说明并负责，复核结论由伦理/医务处人工填写。
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional

from .audit import AuditLog
from .clock import Clock, SystemClock
from .crypto import sha256_obj
from .enums import (
    DESIGNATED_BAND,
    EXCEPTION_AUTHORITIES,
    LEGAL_PRIORITY,
    PATIENT_WIDE_REASONS,
    REVIEW_ROLES,
    STANCES_BY_MATTER,
    VERIFICATION_ROLES,
    ActorRole,
    Basis,
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
from .errors import (
    ConflictStateError,
    NotFoundError,
    PermissionDenied,
    StaleVersionError,
    ValidationError,
)
from .models import (
    Actor,
    Confirmation,
    ContactGrant,
    DeliveryAttempt,
    DisclosurePacket,
    DocumentVersion,
    EmergencyException,
    Matter,
    Patient,
    Referral,
    TerminationEvent,
)

# 每种事项允许向联系人披露的最少字段白名单
DISCLOSURE_FIELDS: dict[str, set[str]] = {
    MatterType.CRITICAL_NOTICE.value: {
        "diagnosis_category",
        "current_severity",
        "immediate_risk",
        "treating_team",
    },
    MatterType.EXAM_CONSENT.value: {
        "procedure",
        "purpose",
        "key_risks",
        "alternatives",
        "timing",
    },
    MatterType.TRANSFER_DECISION.value: {
        "transfer_reason",
        "destination_level",
        "transport_risk",
        "timing",
    },
}

# 认可的远程身份校验方式
IDENTITY_METHODS = frozenset(
    {"callback_verified_phone", "secure_link_token", "in_person_id_check"}
)

STAFF_ROLES = frozenset(
    {ActorRole.STAFF, ActorRole.ATTENDING, ActorRole.MEDICAL_AFFAIRS}
)

TERMINAL_NON_DELIVERY = frozenset(
    {DeliveryOutcome.UNREACHABLE.value, DeliveryOutcome.REFUSED.value}
)


def _parse(ts: str):
    from datetime import datetime

    return datetime.fromisoformat(ts)


class ICUProxyService:
    def __init__(self, clock: Optional[Clock] = None):
        self.clock = clock or SystemClock()
        self.audit = AuditLog()

        self.actors: dict[str, Actor] = {}
        self.patients: dict[str, Patient] = {}
        self.grants: dict[str, ContactGrant] = {}
        self.terminations: list[TerminationEvent] = []
        self.documents: dict[str, DocumentVersion] = {}
        self.matters: dict[str, Matter] = {}
        self.attempts: list[DeliveryAttempt] = []
        self.disclosures: dict[str, DisclosurePacket] = {}
        self.confirmations: dict[str, Confirmation] = {}
        self.referrals: dict[str, Referral] = {}
        self.exceptions: dict[str, EmergencyException] = {}

        self._idempotency: dict[str, str] = {}  # 幂等键 -> matter_id
        self._counters: dict[str, int] = {}

    # ==================================================================
    # 基础工具
    # ==================================================================

    def _new_id(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n:04d}"

    def _now(self) -> str:
        return self.clock.now().isoformat()

    def _log(self, event_type: str, actor_id: str, subject: str,
             payload: Optional[dict[str, Any]] = None, at: Optional[str] = None):
        return self.audit.append(event_type, actor_id, subject, payload, at=at)

    def _actor(self, actor_id: str) -> Actor:
        actor = self.actors.get(actor_id)
        if actor is None:
            raise NotFoundError(f"操作者不存在：{actor_id}")
        return actor

    def _patient(self, patient_id: str) -> Patient:
        patient = self.patients.get(patient_id)
        if patient is None:
            raise NotFoundError(f"患者不存在：{patient_id}")
        return patient

    def _require_roles(self, actor_id: str, roles) -> Actor:
        actor = self._actor(actor_id)
        if ActorRole(actor.role) not in set(roles):
            raise PermissionDenied(f"角色 {actor.role} 无权执行该操作")
        return actor

    def _matter(self, matter_id: str) -> Matter:
        matter = self.matters.get(matter_id)
        if matter is None:
            raise NotFoundError(f"事项不存在：{matter_id}")
        return matter

    def _grant(self, grant_id: str) -> ContactGrant:
        grant = self.grants.get(grant_id)
        if grant is None:
            raise NotFoundError(f"代理资格不存在：{grant_id}")
        return grant

    def _current_document(self, matter: Matter) -> DocumentVersion:
        if not matter.current_document_id:
            raise ConflictStateError("该事项尚未发布任何文书版本，无可披露内容")
        return self.documents[matter.current_document_id]

    # ==================================================================
    # 人员与患者登记
    # ==================================================================

    def register_actor(self, requester_id: str, actor_id: str, name: str,
                       role: str, relation: Optional[str] = None,
                       phone: Optional[str] = None,
                       secure_link_id: Optional[str] = None) -> Actor:
        self._require_roles(requester_id, STAFF_ROLES)
        return self._provision_actor(actor_id, name, role, relation, phone,
                                     secure_link_id, requester_id=requester_id,
                                     event="actor.registered")

    def bootstrap_actor(self, actor_id: str, name: str, role: str,
                        relation: Optional[str] = None,
                        phone: Optional[str] = None,
                        secure_link_id: Optional[str] = None) -> Actor:
        """系统首次引导：首个医务处账号建立前可用，其后锁定。"""
        has_admin = any(
            a.role == ActorRole.MEDICAL_AFFAIRS.value for a in self.actors.values()
        )
        if has_admin:
            raise ConflictStateError("系统已完成引导，bootstrap 已锁定")
        return self._provision_actor(actor_id, name, role, relation, phone,
                                     secure_link_id, requester_id="bootstrap",
                                     event="actor.bootstrapped")

    def _provision_actor(self, actor_id: str, name: str, role: str,
                         relation: Optional[str], phone: Optional[str],
                         secure_link_id: Optional[str],
                         requester_id: str, event: str) -> Actor:
        if actor_id in self.actors:
            raise ConflictStateError(f"操作者已存在：{actor_id}")
        try:
            actor_role = ActorRole(role)
        except ValueError as exc:
            raise ValidationError(f"未知角色：{role}") from exc
        if actor_role == ActorRole.FAMILY and relation is not None:
            try:
                Relation(relation)
            except ValueError as exc:
                raise ValidationError(f"未知法定关系：{relation}") from exc
        actor = Actor(
            id=actor_id, name=name, role=actor_role.value,
            relation=relation, phone=phone, secure_link_id=secure_link_id,
        )
        self.actors[actor_id] = actor
        self._log(event, requester_id, f"actor:{actor_id}",
                  {"name": name, "role": actor_role.value,
                   "relation": relation})
        return actor

    def register_patient(self, requester_id: str, patient_id: str,
                         name: str, mrn: str) -> Patient:
        self._require_roles(requester_id, STAFF_ROLES)
        if patient_id in self.patients:
            raise ConflictStateError(f"患者已存在：{patient_id}")
        patient = Patient(id=patient_id, name=name, mrn=mrn)
        self.patients[patient_id] = patient
        self._log("patient.registered", requester_id, f"patient:{patient_id}",
                  {"name": name, "mrn": mrn})
        return patient

    # ==================================================================
    # 代理资格：预先指定 / 法定关系 + 院方核验闸门 + 有效期
    # ==================================================================

    def create_grant(self, requester_id: str, patient_id: str, actor_id: str,
                     basis: str, relation: Optional[str] = None,
                     rank: Optional[int] = None,
                     matters: Optional[list[str]] = None,
                     valid_from: Optional[str] = None,
                     valid_to: Optional[str] = None) -> ContactGrant:
        self._require_roles(requester_id, STAFF_ROLES)
        self._patient(patient_id)
        actor = self._actor(actor_id)
        try:
            grant_basis = Basis(basis)
        except ValueError as exc:
            raise ValidationError(f"未知顺位依据：{basis}") from exc
        if grant_basis == Basis.HOSPITAL_VERIFIED:
            raise ValidationError(
                "院方核验是资格生效闸门，不能单独作为资格依据；"
                "请以预先指定或法定关系建立资格后再提交核验"
            )

        if matters:
            for m in matters:
                try:
                    MatterType(m)
                except ValueError as exc:
                    raise ValidationError(f"未知事项类型：{m}") from exc
        if valid_from is None:
            valid_from = self._now()
        if valid_to is not None and _parse(valid_to) <= _parse(valid_from):
            raise ValidationError("有效期截止时间必须晚于起始时间")

        if grant_basis == Basis.LEGAL:
            if not relation:
                raise ValidationError("法定关系资格必须注明 relation")
            try:
                legal_relation = Relation(relation)
            except ValueError as exc:
                raise ValidationError(f"未知法定关系：{relation}") from exc
            if actor.relation and actor.relation != legal_relation.value:
                raise ValidationError("联系人登记的法定关系与资格记录不一致")
            effective_rank = rank if rank is not None else LEGAL_PRIORITY[legal_relation]
        else:
            legal_relation = None
            if rank is None:
                # 预先指定：按该患者既有指定顺序追加
                existing = [
                    g for g in self.grants.values()
                    if g.patient_id == patient_id
                    and g.basis == Basis.PATIENT_DESIGNATED.value
                ]
                effective_rank = len(existing) + 1
            else:
                effective_rank = rank

        grant = ContactGrant(
            id=self._new_id("grant"),
            patient_id=patient_id,
            actor_id=actor_id,
            basis=grant_basis.value,
            relation=legal_relation.value if legal_relation else None,
            rank=effective_rank,
            matters=list(matters or []),
            valid_from=valid_from,
            valid_to=valid_to,
            created_at=self._now(),
        )
        self.grants[grant.id] = grant
        self._log("grant.created", requester_id, f"grant:{grant.id}",
                  {"patient_id": patient_id, "actor_id": actor_id,
                   "basis": grant.basis, "relation": grant.relation,
                   "rank": grant.rank, "matters": grant.matters,
                   "valid_from": valid_from, "valid_to": valid_to})
        return grant

    def verify_grant(self, requester_id: str, grant_id: str,
                     approved: bool, note: Optional[str] = None
                     ) -> ContactGrant:
        self._require_roles(requester_id, VERIFICATION_ROLES)
        grant = self._grant(grant_id)
        if grant.verification_status != VerificationStatus.PENDING.value:
            raise ConflictStateError("该资格已完成院方核验，不能重复核验")
        grant.verification_status = (
            VerificationStatus.VERIFIED.value if approved
            else VerificationStatus.REJECTED.value
        )
        grant.verified_by = requester_id
        grant.verified_at = self._now()
        grant.verification_note = note
        self._log("grant.verified", requester_id, f"grant:{grant.id}",
                  {"approved": approved, "note": note})
        return grant

    def terminate_proxy(self, requester_id: str, patient_id: str, reason: str,
                        grant_id: Optional[str] = None,
                        note: Optional[str] = None) -> TerminationEvent:
        """患者转院/恢复意识/撤销代理/离院，或定向撤销单个联系人。"""
        self._require_roles(requester_id, STAFF_ROLES)
        self._patient(patient_id)
        try:
            term_reason = TerminationReason(reason)
        except ValueError as exc:
            raise ValidationError(f"未知终止原因：{reason}") from exc

        targeted = term_reason == TerminationReason.CONTACT_REVOKED
        if targeted and not grant_id:
            raise ValidationError("定向撤销联系人必须提供 grant_id")
        if not targeted and grant_id:
            raise ValidationError("患者级终止原因不应指定单个 grant")

        at = self._now()
        if grant_id:
            grant = self._grant(grant_id)
            if grant.patient_id != patient_id:
                raise ValidationError("资格与患者不匹配")

        event = TerminationEvent(
            id=self._new_id("term"),
            patient_id=patient_id,
            reason=term_reason.value,
            at=at,
            actor_id=requester_id,
            grant_id=grant_id,
            note=note,
        )
        self.terminations.append(event)

        affected: list[str] = []
        for g in self.grants.values():
            if g.patient_id != patient_id or g.terminated_at is not None:
                continue
            if grant_id and g.id != grant_id:
                continue
            g.terminated_at = at
            g.termination_reason = term_reason.value
            affected.append(g.id)

        self._log("proxy.terminated", requester_id, f"patient:{patient_id}",
                  {"reason": term_reason.value, "grant_id": grant_id,
                   "affected_grants": affected, "note": note})

        # 没有任何可依赖的在途记录时，进行中的事项随权限一并关闭
        for matter in self.matters.values():
            if matter.patient_id != patient_id:
                continue
            if matter.status not in (MatterStatus.OPEN.value,
                                     MatterStatus.CONFLICT.value):
                continue
            chain = self.effective_grants(patient_id, matter.type, at=_parse(at))
            has_record = self._has_live_confirmation(matter) or bool(
                self._delivered_pending(matter, at=_parse(at))
            )
            if not chain and not has_record:
                matter.status = MatterStatus.CLOSED.value
                matter.closed_at = at
                matter.last_outcome = f"closed:{term_reason.value}"
                self._log("matter.closed_by_termination", requester_id,
                          f"matter:{matter.id}",
                          {"reason": term_reason.value})
        return event

    def _grant_effective_at(self, grant: ContactGrant, matter_type: str, at) -> bool:
        if grant.verification_status != VerificationStatus.VERIFIED.value:
            return False
        if not grant.covers(matter_type):
            return False
        if _parse(grant.valid_from) > at:
            return False
        if grant.valid_to is not None and _parse(grant.valid_to) <= at:
            return False
        if grant.terminated_at is not None and _parse(grant.terminated_at) <= at:
            return False
        return True

    def effective_grants(self, patient_id: str, matter_type: str,
                         at=None) -> list[ContactGrant]:
        """返回某时点有效联系人，按生效顺位排序：预先指定优先于法定关系。"""
        if at is None:
            at = self.clock.now()
        grants = [
            g for g in self.grants.values()
            if g.patient_id == patient_id
            and self._grant_effective_at(g, matter_type, at)
        ]

        def sort_key(g: ContactGrant):
            band = (DESIGNATED_BAND if g.basis == Basis.PATIENT_DESIGNATED.value
                    else 100)
            return (band, g.rank, g.created_at or "", g.id)

        return sorted(grants, key=sort_key)

    # ==================================================================
    # 事项与不可变文书版本
    # ==================================================================

    def open_matter(self, requester_id: str, patient_id: str, matter_type: str,
                    title: str, idempotency_key: str) -> Matter:
        """发起事项。相同幂等键（含跨午夜交班、重复回调）直接返回原事项。"""
        self._require_roles(requester_id, STAFF_ROLES)
        self._patient(patient_id)
        try:
            MatterType(matter_type)
        except ValueError as exc:
            raise ValidationError(f"未知事项类型：{matter_type}") from exc
        if not idempotency_key or not idempotency_key.strip():
            raise ValidationError("idempotency_key 必填，用于防止重复发起")

        existing_id = self._idempotency.get(idempotency_key)
        if existing_id is not None:
            return self.matters[existing_id]

        matter = Matter(
            id=self._new_id("matter"),
            patient_id=patient_id,
            type=matter_type,
            title=title,
            created_at=self._now(),
            created_by=requester_id,
            idempotency_key=idempotency_key,
        )
        self.matters[matter.id] = matter
        self._idempotency[idempotency_key] = matter.id
        self._log("matter.opened", requester_id, f"matter:{matter.id}",
                  {"patient_id": patient_id, "type": matter_type,
                   "title": title, "idempotency_key": idempotency_key})
        return matter

    def publish_document(self, requester_id: str, matter_id: str, kind: str,
                         title: str, content: str) -> DocumentVersion:
        """发布不可变文书版本；内容更新后旧版本上的确认自动失效。"""
        self._require_roles(requester_id, STAFF_ROLES)
        matter = self._matter(matter_id)
        if matter.status in (MatterStatus.CLOSED.value,
                             MatterStatus.EXCEPTION_USED.value):
            raise ConflictStateError(
                f"事项处于 {matter.status}，不能再发布新版本"
            )
        try:
            DocumentKind(kind)
        except ValueError as exc:
            raise ValidationError(f"未知文书类型：{kind}") from exc
        if not content or not content.strip():
            raise ValidationError("文书内容不能为空")

        previous = (self.documents[matter.current_document_id]
                    if matter.current_document_id else None)
        version = (previous.version + 1) if previous else 1
        digest = sha256_obj({"kind": kind, "title": title, "content": content})
        doc = DocumentVersion(
            id=self._new_id("doc"),
            patient_id=matter.patient_id,
            matter_id=matter_id,
            kind=kind,
            version=version,
            title=title,
            content=content,
            sha256=digest,
            created_by=requester_id,
            created_at=self._now(),
            supersedes=previous.id if previous else None,
        )
        self.documents[doc.id] = doc
        matter.current_document_id = doc.id
        self._log("document.published", requester_id, f"matter:{matter.id}",
                  {"document_id": doc.id, "version": version,
                   "sha256": digest, "supersedes": doc.supersedes})

        # 旧确认自动失效；事项回到开放态重新征求当前版本意见
        if previous is not None:
            stale = [
                c for c in self.confirmations.values()
                if c.matter_id == matter_id and c.status == "valid"
            ]
            for c in stale:
                c.status = "superseded"
                c.superseded_at = doc.created_at
                self._log("confirmation.superseded", requester_id,
                          f"confirmation:{c.id}",
                          {"new_document_id": doc.id,
                           "old_document_id": c.document_id})
            if stale and matter.status in (
                MatterStatus.RESOLVED.value,
                MatterStatus.ESCALATED.value,
                MatterStatus.CONFLICT.value,
            ):
                previous_status = matter.status
                matter.status = MatterStatus.OPEN.value
                matter.closed_at = None
                self._log("matter.reopened", requester_id,
                          f"matter:{matter.id}",
                          {"reason": "document_updated",
                           "previous_status": previous_status})
        return doc

    # ==================================================================
    # 通知：最小披露、送达/拒收/失联、逐级升级
    # ==================================================================

    def _attempts_for_current_version(self, matter: Matter) -> list[DeliveryAttempt]:
        return [
            a for a in self.attempts
            if a.matter_id == matter.id
            and a.document_id == matter.current_document_id
        ]

    def _latest_outcome_by_grant(self, matter: Matter) -> dict[str, str]:
        """当前文书版本内，每个联系人最后一次尝试的结果（以后果为准）。"""
        latest: dict[str, DeliveryAttempt] = {}
        for a in self._attempts_for_current_version(matter):
            prev = latest.get(a.grant_id)
            if prev is None or _parse(a.at) >= _parse(prev.at):
                latest[a.grant_id] = a
        return {gid: a.outcome for gid, a in latest.items()}

    def _delivered_pending(self, matter: Matter, at=None) -> set[str]:
        """已送达当前版本、尚未确认、且其后没有失联/拒收补记的联系人。"""
        confirmed_grants = {
            c.grant_id for c in self.confirmations.values()
            if c.matter_id == matter.id and c.status == "valid"
            and c.document_id == matter.current_document_id
        }
        latest = self._latest_outcome_by_grant(matter)
        return {
            gid for gid, outcome in latest.items()
            if outcome == DeliveryOutcome.DELIVERED.value and gid not in confirmed_grants
        }

    def _spent_grants(self, matter: Matter) -> set[str]:
        """当前版本中最后结果为终局未送达（拒收/失联）的联系人。"""
        latest = self._latest_outcome_by_grant(matter)
        return {
            gid for gid, outcome in latest.items()
            if outcome in TERMINAL_NON_DELIVERY
        }

    def notification_chain(self, matter_id: str, at=None) -> list[ContactGrant]:
        matter = self._matter(matter_id)
        chain = self.effective_grants(matter.patient_id, matter.type, at=at)
        spent = self._spent_grants(matter)
        pending = self._delivered_pending(matter, at=at)
        confirmed = {
            c.grant_id for c in self._valid_confirmations(matter)
        }
        return [
            g for g in chain
            if g.id not in spent and g.id not in pending and g.id not in confirmed
        ]

    def next_contact(self, matter_id: str, at=None) -> Optional[ContactGrant]:
        chain = self.notification_chain(matter_id, at=at)
        return chain[0] if chain else None

    def _escalate(self, matter: Matter, reason: str, requester_id: str, at: str):
        matter.status = MatterStatus.ESCALATED.value
        matter.last_outcome = f"escalated:{reason}"
        referral = Referral(
            id=self._new_id("ref"),
            matter_id=matter.id,
            patient_id=matter.patient_id,
            body=ReviewBody.MEDICAL_AFFAIRS.value,
            reason=reason,
            opened_at=at,
            opened_by=requester_id,
        )
        self.referrals[referral.id] = referral
        self._log("referral.opened", requester_id, f"matter:{matter.id}",
                  {"referral_id": referral.id, "body": referral.body,
                   "reason": reason})
        self._log("matter.escalated", requester_id, f"matter:{matter.id}",
                  {"reason": reason, "referral_id": referral.id})
        return referral

    def record_attempt(self, requester_id: str, matter_id: str, grant_id: str,
                       channel: str, outcome: str,
                       detail: Optional[str] = None,
                       minimal_summary: Optional[str] = None,
                       fields: Optional[list[str]] = None
                       ) -> dict[str, Any]:
        """记录一次联系尝试；送达时冻结最小披露包。

        返回 {"attempt": ..., "escalated": bool, "referral": ...}。
        """
        self._require_roles(requester_id, STAFF_ROLES)
        matter = self._matter(matter_id)
        if matter.status != MatterStatus.OPEN.value:
            raise ConflictStateError(
                f"事项处于 {matter.status}，不再接受联系尝试"
            )
        grant = self._grant(grant_id)
        if grant.patient_id != matter.patient_id:
            raise ValidationError("资格与事项不属于同一患者")
        try:
            attempt_outcome = DeliveryOutcome(outcome)
        except ValueError as exc:
            raise ValidationError(f"未知送达结果：{outcome}") from exc

        at = self._now()
        doc = self._current_document(matter)
        chain = self.effective_grants(matter.patient_id, matter.type, at=_parse(at))
        if not chain:
            referral = self._escalate(matter, "all_unreachable", requester_id, at)
            return {"attempt": None, "escalated": True, "referral": referral}
        if not any(g.id == grant_id for g in chain):
            raise ValidationError("该联系人当前不具有效代理资格或不覆盖此事项")

        head = self.next_contact(matter_id, at=_parse(at))
        pending = self._delivered_pending(matter, at=_parse(at))
        if grant_id in pending:
            if attempt_outcome == DeliveryOutcome.DELIVERED:
                # 重复回调/重复交班不得对同一版本重复发起送达
                raise ConflictStateError(
                    "当前版本已向该联系人送达，正在等待其确认，请勿重复发起"
                )
            # 已送达后久未回复，可补记失联/拒收以推进逐级升级
        elif head is None or head.id != grant_id:
            raise ConflictStateError(
                "存在顺位更靠前且尚未尝试的联系人，须按顺位逐级通知"
            )

        disclosure_id: Optional[str] = None
        if attempt_outcome == DeliveryOutcome.DELIVERED:
            allowed = DISCLOSURE_FIELDS[matter.type]
            fields = fields or []
            bad = [f for f in fields if f not in allowed]
            if bad:
                raise ValidationError(
                    f"字段超出该事项允许的最小披露范围：{bad}；"
                    f"允许：{sorted(allowed)}"
                )
            if not minimal_summary or not minimal_summary.strip():
                raise ValidationError("送达必须记录最少病情摘要")
            disclosure = DisclosurePacket(
                id=self._new_id("disc"),
                matter_id=matter_id,
                grant_id=grant_id,
                actor_id=grant.actor_id,
                document_id=doc.id,
                document_sha256=doc.sha256,
                minimal_summary=minimal_summary,
                fields=list(fields),
                frozen_at=at,
            )
            self.disclosures[disclosure.id] = disclosure
            disclosure_id = disclosure.id

        attempt = DeliveryAttempt(
            id=self._new_id("att"),
            matter_id=matter_id,
            grant_id=grant_id,
            actor_id=grant.actor_id,
            channel=channel,
            outcome=attempt_outcome.value,
            at=at,
            recorded_by=requester_id,
            detail=detail,
            disclosure_id=disclosure_id,
            document_id=doc.id,
            order_index=len([a for a in self.attempts if a.matter_id == matter_id]),
        )
        self.attempts.append(attempt)
        matter.last_outcome = attempt_outcome.value
        self._log("attempt.recorded", requester_id, f"matter:{matter.id}",
                  {"attempt_id": attempt.id, "grant_id": grant_id,
                   "actor_id": grant.actor_id, "channel": channel,
                   "outcome": attempt_outcome.value, "detail": detail,
                   "document_id": doc.id,
                   "disclosure_id": disclosure_id})

        escalated = False
        referral = None
        if attempt_outcome in (DeliveryOutcome.UNREACHABLE, DeliveryOutcome.REFUSED):
            new_head = self.next_contact(matter_id, at=_parse(at))
            if new_head is None and not self._delivered_pending(matter, at=_parse(at)):
                referral = self._escalate(
                    matter, "all_unreachable", requester_id, at
                )
                escalated = True
        return {"attempt": attempt, "escalated": escalated, "referral": referral}

    # ==================================================================
    # 远程确认：绑定摘要 / 版本 / 身份校验 / 签署时间
    # ==================================================================

    def _valid_confirmations(self, matter: Matter) -> list[Confirmation]:
        return [
            c for c in self.confirmations.values()
            if c.matter_id == matter.id and c.status == "valid"
            and c.document_id == matter.current_document_id
        ]

    def _has_live_confirmation(self, matter: Matter) -> bool:
        return bool(self._valid_confirmations(matter))

    def record_confirmation(self, requester_id: str, matter_id: str,
                            grant_id: str, stance: str,
                            identity_method: str, identity_evidence: str
                            ) -> dict[str, Any]:
        matter = self._matter(matter_id)
        if matter.status not in (MatterStatus.OPEN.value, MatterStatus.CONFLICT.value):
            raise ConflictStateError(
                f"事项处于 {matter.status}，不能再记录确认"
            )
        grant = self._grant(grant_id)
        requester = self._actor(requester_id)
        if requester.role == ActorRole.FAMILY.value:
            # 家属仅能经本人安全链接为自己确认
            if grant.actor_id != requester_id:
                raise PermissionDenied("只能使用本人的代理资格进行确认")
            if identity_method != "secure_link_token":
                raise PermissionDenied("家属自助确认须通过安全链接身份令牌")
        else:
            self._require_roles(requester_id,
                                {ActorRole.STAFF, ActorRole.ATTENDING})

        if grant.patient_id != matter.patient_id:
            raise ValidationError("资格与事项不属于同一患者")
        at = self._now()
        if not self._grant_effective_at(grant, matter.type, _parse(at)):
            raise ConflictStateError("该联系人代理资格当前已失效，确认无效")

        try:
            confirm_stance = ConfirmationStance(stance)
        except ValueError as exc:
            raise ValidationError(f"未知立场：{stance}") from exc
        allowed = STANCES_BY_MATTER[MatterType(matter.type)]
        if confirm_stance not in allowed:
            raise ValidationError(
                f"事项类型 {matter.type} 不接受立场 {stance}；允许：{sorted(s.value for s in allowed)}"
            )
        if identity_method not in IDENTITY_METHODS:
            raise ValidationError(f"未知身份校验方式：{identity_method}")
        if not identity_evidence or not identity_evidence.strip():
            raise ValidationError("身份校验证据必填")

        doc = self._current_document(matter)

        # 必须先就当前版本完成送达与最小披露
        delivered = [
            a for a in self._attempts_for_current_version(matter)
            if a.grant_id == grant_id
            and a.outcome == DeliveryOutcome.DELIVERED.value
        ]
        if not delivered:
            raise ConflictStateError("尚未向该联系人送达当前文书版本，不能远程确认")

        # 同一联系人同一版本幂等；改主意需走冲突/复核流程留痕
        existing = next(
            (c for c in self._valid_confirmations(matter)
             if c.grant_id == grant_id),
            None,
        )
        if existing is not None:
            if existing.stance == confirm_stance.value:
                return {"confirmation": existing, "conflict": None,
                        "resolved": False, "idempotent": True}
            raise ConflictStateError(
                "该联系人已就当前版本表达相反立场；意见分歧须留痕并转复核"
            )

        signed_at = at
        binding = sha256_obj({
            "matter_id": matter.id,
            "grant_id": grant.id,
            "actor_id": grant.actor_id,
            "document_id": doc.id,
            "document_sha256": doc.sha256,
            "stance": confirm_stance.value,
            "identity_method": identity_method,
            "identity_evidence": identity_evidence,
            "signed_at": signed_at,
        })
        confirmation = Confirmation(
            id=self._new_id("conf"),
            matter_id=matter_id,
            grant_id=grant_id,
            actor_id=grant.actor_id,
            document_id=doc.id,
            document_sha256=doc.sha256,
            document_version=doc.version,
            stance=confirm_stance.value,
            identity_method=identity_method,
            identity_evidence=identity_evidence,
            signed_at=signed_at,
            binding_hash=binding,
            recorded_by=requester_id if requester.role != ActorRole.FAMILY.value else None,
        )
        self.confirmations[confirmation.id] = confirmation
        self._log("confirmation.recorded", requester_id,
                  f"matter:{matter.id}",
                  {"confirmation_id": confirmation.id,
                   "grant_id": grant_id, "actor_id": grant.actor_id,
                   "document_id": doc.id, "document_version": doc.version,
                   "document_sha256": doc.sha256,
                   "stance": confirm_stance.value,
                   "identity_method": identity_method,
                   "binding_hash": binding, "signed_at": signed_at})

        # 意见相反 → 自动挂起并转伦理（或医务）复核
        stances = {c.stance for c in self._valid_confirmations(matter)}
        conflict = None
        if ConfirmationStance.CONSENT.value in stances and \
                ConfirmationStance.REFUSE.value in stances and \
                matter.status != MatterStatus.CONFLICT.value:
            matter.status = MatterStatus.CONFLICT.value
            matter.closed_at = None
            conflicting = [
                c.id for c in self._valid_confirmations(matter)
            ]
            conflict = Referral(
                id=self._new_id("ref"),
                matter_id=matter.id,
                patient_id=matter.patient_id,
                body=ReviewBody.ETHICS.value,
                reason="conflict",
                opened_at=at,
                opened_by=requester_id,
                conflicting=conflicting,
            )
            self.referrals[conflict.id] = conflict
            self._log("conflict.opened", requester_id, f"matter:{matter.id}",
                      {"referral_id": conflict.id, "body": conflict.body,
                       "confirmations": conflicting})
        return {"confirmation": confirmation, "conflict": conflict,
                "resolved": False, "idempotent": False}

    def resolve_matter(self, requester_id: str, matter_id: str,
                       note: Optional[str] = None) -> Matter:
        """医护基于已收集的单一立场确认形成处置依据（软件不替医生作决定）。"""
        self._require_roles(requester_id,
                            {ActorRole.STAFF, ActorRole.ATTENDING,
                             ActorRole.MEDICAL_AFFAIRS})
        matter = self._matter(matter_id)
        if matter.status != MatterStatus.OPEN.value:
            raise ConflictStateError(f"事项处于 {matter.status}，不能直接形成决定")
        valid = self._valid_confirmations(matter)
        if not valid:
            raise ConflictStateError("尚无有效确认，不能形成决定")
        stances = {c.stance for c in valid}
        if len(stances) > 1:
            raise ConflictStateError("存在相反立场，须先经伦理/医务复核")
        matter.status = MatterStatus.RESOLVED.value
        matter.closed_at = self._now()
        self._log("matter.resolved", requester_id, f"matter:{matter.id}",
                  {"confirmation_ids": [c.id for c in valid],
                   "stance": next(iter(stances)), "note": note})
        return matter

    # ==================================================================
    # 伦理 / 医务复核
    # ==================================================================

    def conclude_referral(self, requester_id: str, referral_id: str,
                          decision_stance: Optional[str] = None,
                          rationale: str = "") -> Referral:
        requester = self._require_roles(
            requester_id,
            {ActorRole.ETHICS, ActorRole.MEDICAL_AFFAIRS, ActorRole.ATTENDING},
        )
        referral = self.referrals.get(referral_id)
        if referral is None:
            raise NotFoundError(f"复核单不存在：{referral_id}")
        if referral.status != ReferralStatus.OPEN.value:
            raise ConflictStateError("该复核单已结论")
        if requester.role == ActorRole.ETHICS.value and \
                referral.body != ReviewBody.ETHICS.value:
            raise PermissionDenied("该复核单不属于伦理委员会")
        if requester.role == ActorRole.MEDICAL_AFFAIRS.value and \
                referral.body != ReviewBody.MEDICAL_AFFAIRS.value:
            raise PermissionDenied("该复核单不属于医务处")
        if not rationale or not rationale.strip():
            raise ValidationError("复核必须记录书面理由")

        matter = self._matter(referral.matter_id)
        allowed = STANCES_BY_MATTER[MatterType(matter.type)]
        if referral.reason == "conflict":
            if decision_stance is None:
                raise ValidationError("意见冲突复核必须给出采纳立场")
        if decision_stance is not None:
            try:
                chosen = ConfirmationStance(decision_stance)
            except ValueError as exc:
                raise ValidationError(f"未知立场：{decision_stance}") from exc
            if chosen not in allowed:
                raise ValidationError("采纳立场不属于该事项可接受范围")
            referral.decision_stance = chosen.value

        referral.status = ReferralStatus.CONCLUDED.value
        referral.concluded_at = self._now()
        referral.concluded_by = requester_id
        referral.rationale = rationale
        self._log("referral.concluded", requester_id,
                  f"matter:{matter.id}",
                  {"referral_id": referral.id,
                   "decision_stance": referral.decision_stance,
                   "rationale": rationale})

        if referral.decision_stance is not None:
            matter.status = MatterStatus.RESOLVED.value
            matter.closed_at = referral.concluded_at
            self._log("matter.resolved", requester_id, f"matter:{matter.id}",
                      {"via": "review", "referral_id": referral.id,
                       "stance": referral.decision_stance})
        return referral

    # ==================================================================
    # 抢救例外：具权限医护说明紧迫性，事后补齐依据
    # ==================================================================

    def open_emergency_exception(self, requester_id: str, matter_id: str,
                                 urgency_statement: str,
                                 basis_due_hours: int = 24) -> EmergencyException:
        requester = self._require_roles(requester_id, EXCEPTION_AUTHORITIES)
        matter = self._matter(matter_id)
        if matter.status in (MatterStatus.RESOLVED.value,
                             MatterStatus.CLOSED.value,
                             MatterStatus.EXCEPTION_USED.value):
            raise ConflictStateError(
                f"事项处于 {matter.status}，不适用抢救例外"
            )
        if not urgency_statement or not urgency_statement.strip():
            raise ValidationError("抢救例外必须书面说明紧迫性")
        if basis_due_hours <= 0:
            raise ValidationError("补齐依据限期必须为正数小时")

        at_dt = self.clock.now()
        exception = EmergencyException(
            id=self._new_id("exc"),
            matter_id=matter_id,
            patient_id=matter.patient_id,
            authorized_by=requester_id,
            urgency_statement=urgency_statement,
            opened_at=at_dt.isoformat(),
            basis_due_at=(at_dt + timedelta(hours=basis_due_hours)).isoformat(),
        )
        self.exceptions[exception.id] = exception
        matter.status = MatterStatus.EXCEPTION_USED.value
        matter.closed_at = exception.opened_at
        self._log("exception.opened", requester_id, f"matter:{matter.id}",
                  {"exception_id": exception.id,
                   "urgency_statement": urgency_statement,
                   "basis_due_at": exception.basis_due_at,
                   "authorized_by": requester_id})
        return exception

    def provide_exception_basis(self, requester_id: str, exception_id: str,
                                basis_documents: list[str],
                                note: Optional[str] = None) -> EmergencyException:
        self._require_roles(requester_id,
                            {ActorRole.STAFF, ActorRole.ATTENDING})
        exception = self.exceptions.get(exception_id)
        if exception is None:
            raise NotFoundError(f"抢救例外不存在：{exception_id}")
        if exception.basis_provided_at is not None:
            raise ConflictStateError("该例外已补齐依据，不能重复提交")
        if not basis_documents:
            raise ValidationError("至少提交一份事后依据材料标识")
        exception.basis_documents = list(basis_documents)
        exception.basis_provided_at = self._now()
        self._log("exception.basis_provided", requester_id,
                  f"matter:{exception.matter_id}",
                  {"exception_id": exception.id,
                   "documents": basis_documents, "note": note})
        return exception

    def review_exception_basis(self, requester_id: str, exception_id: str,
                               note: str) -> EmergencyException:
        self._require_roles(requester_id, {ActorRole.MEDICAL_AFFAIRS})
        exception = self.exceptions.get(exception_id)
        if exception is None:
            raise NotFoundError(f"抢救例外不存在：{exception_id}")
        if exception.basis_provided_at is None:
            raise ConflictStateError("依据尚未补齐，不能审核")
        if exception.basis_reviewed_by is not None:
            raise ConflictStateError("该例外依据已审核")
        if not note or not note.strip():
            raise ValidationError("审核意见不能为空")
        exception.basis_reviewed_by = requester_id
        exception.basis_review_note = note
        self._log("exception.basis_reviewed", requester_id,
                  f"matter:{exception.matter_id}",
                  {"exception_id": exception.id, "note": note})
        return exception

    def overdue_exceptions(self, at=None) -> list[EmergencyException]:
        if at is None:
            at = self.clock.now()
        result = []
        for exc in self.exceptions.values():
            if exc.basis_provided_at is None and _parse(exc.basis_due_at) < at:
                exc.overdue = True
                result.append(exc)
        return result

    # ==================================================================
    # 复盘回放与家属隐私视图
    # ==================================================================

    def replay(self, requester_id: str, matter_id: str) -> dict[str, Any]:
        """审查人员还原一个事项的完整处置经过。"""
        self._require_roles(requester_id, REVIEW_ROLES)
        matter = self._matter(matter_id)
        patient = self._patient(matter.patient_id)

        grants = sorted(
            (g for g in self.grants.values() if g.patient_id == matter.patient_id),
            key=lambda g: g.created_at or "",
        )
        # 在每个关键时点重算有效顺位，证明当时"能联系谁"
        checkpoints: list[dict[str, Any]] = []
        for a in sorted(
            [a for a in self.attempts if a.matter_id == matter_id],
            key=lambda a: a.at,
        ):
            chain = self.effective_grants(
                matter.patient_id, matter.type, at=_parse(a.at)
            )
            checkpoints.append({
                "at": a.at,
                "context": "attempt",
                "attempt_id": a.id,
                "chain": [
                    {"grant_id": g.id, "actor_id": g.actor_id,
                     "basis": g.basis, "rank": g.rank}
                    for g in chain
                ],
            })
        for c in sorted(
            [c for c in self.confirmations.values() if c.matter_id == matter_id],
            key=lambda c: c.signed_at,
        ):
            chain = self.effective_grants(
                matter.patient_id, matter.type, at=_parse(c.signed_at)
            )
            checkpoints.append({
                "at": c.signed_at,
                "context": "confirmation",
                "confirmation_id": c.id,
                "chain": [
                    {"grant_id": g.id, "actor_id": g.actor_id,
                     "basis": g.basis, "rank": g.rank}
                    for g in chain
                ],
            })
        checkpoints.sort(key=lambda x: x["at"])

        grant_ids = {g.id for g in grants}
        relevant = [
            e for e in self.audit.entries
            if e.subject == f"matter:{matter_id}"
            or e.payload.get("matter_id") == matter_id
            or e.payload.get("grant_id") in grant_ids
            or e.payload.get("patient_id") == matter.patient_id
        ]
        self.audit.verify()
        return {
            "matter": matter.to_dict(),
            "patient": patient.to_dict(),
            "grants": [g.to_dict() for g in grants],
            "documents": [
                d.to_dict() for d in sorted(
                    (d for d in self.documents.values() if d.matter_id == matter_id),
                    key=lambda d: d.version,
                )
            ],
            "disclosures": [
                d.to_dict() for d in sorted(
                    (d for d in self.disclosures.values() if d.matter_id == matter_id),
                    key=lambda d: d.frozen_at,
                )
            ],
            "attempts": [
                a.to_dict() for a in sorted(
                    (a for a in self.attempts if a.matter_id == matter_id),
                    key=lambda a: a.at,
                )
            ],
            "confirmations": [
                c.to_dict() for c in sorted(
                    (c for c in self.confirmations.values() if c.matter_id == matter_id),
                    key=lambda c: c.signed_at,
                )
            ],
            "referrals": [
                r.to_dict() for r in self.referrals.values()
                if r.matter_id == matter_id
            ],
            "exceptions": [
                e.to_dict() for e in self.exceptions.values()
                if e.matter_id == matter_id
            ],
            "eligibility_snapshots": checkpoints,
            "audit_tail_subject": f"matter:{matter_id}",
            "audit_entries": [e.to_dict() for e in relevant],
            "audit_verified": True,
        }

    def family_view(self, requester_id: str, matter_id: str) -> dict[str, Any]:
        """家属只能看到自己的记录；其他联系人的隐私一律掩码。"""
        actor = self._actor(requester_id)
        if actor.role != ActorRole.FAMILY.value:
            raise PermissionDenied("该视图仅供家属联系人使用")
        matter = self._matter(matter_id)

        my_grants = [
            g for g in self.grants.values()
            if g.patient_id == matter.patient_id and g.actor_id == requester_id
        ]
        if not my_grants:
            # 不向无关人员泄露事项是否存在
            raise NotFoundError(f"事项不存在：{matter_id}")
        my_grant_ids = {g.id for g in my_grants}

        my_attempts = [
            a for a in self.attempts
            if a.matter_id == matter_id and a.grant_id in my_grant_ids
        ]
        my_disclosures = [
            d for d in self.disclosures.values()
            if d.matter_id == matter_id and d.grant_id in my_grant_ids
        ]
        my_confirmations = [
            c for c in self.confirmations.values()
            if c.matter_id == matter_id and c.grant_id in my_grant_ids
        ]

        other_attempts = [
            a for a in self.attempts
            if a.matter_id == matter_id and a.grant_id not in my_grant_ids
        ]
        other_delivered = sum(
            1 for a in other_attempts
            if a.outcome == DeliveryOutcome.DELIVERED.value
        )

        return {
            "matter": {
                "id": matter.id,
                "type": matter.type,
                "title": matter.title,
                "status": matter.status,
                "created_at": matter.created_at,
            },
            "your_grants": [
                {
                    "id": g.id,
                    "basis": g.basis,
                    "rank": g.rank,
                    "matters": g.matters,
                    "valid_from": g.valid_from,
                    "valid_to": g.valid_to,
                    "verification_status": g.verification_status,
                    "terminated_at": g.terminated_at,
                    "termination_reason": g.termination_reason,
                }
                for g in my_grants
            ],
            "your_documents": [
                {
                    "document_id": d.document_id,
                    "document_sha256": d.document_sha256,
                    "minimal_summary": d.minimal_summary,
                    "fields": d.fields,
                    "frozen_at": d.frozen_at,
                }
                for d in sorted(my_disclosures, key=lambda d: d.frozen_at)
            ],
            "your_attempts": [a.to_dict() for a in
                              sorted(my_attempts, key=lambda a: a.at)],
            "your_confirmations": [
                c.to_dict() for c in sorted(my_confirmations, key=lambda c: c.signed_at)
            ],
            # 其他联系人只暴露数量，不含任何身份或联系方式
            "other_contacts": {
                "total_attempts_masked": len(other_attempts),
                "delivered_count_masked": other_delivered,
            },
            "review_in_progress": matter.status == MatterStatus.CONFLICT.value,
        }

    # ==================================================================
    # 只读查询
    # ==================================================================

    def get_matter(self, matter_id: str) -> Matter:
        return self._matter(matter_id)

    def list_matters(self, patient_id: Optional[str] = None) -> list[Matter]:
        if patient_id is None:
            return list(self.matters.values())
        return [m for m in self.matters.values() if m.patient_id == patient_id]

    def export_audit(self) -> list[dict[str, Any]]:
        self.audit.verify()
        return self.audit.export()
