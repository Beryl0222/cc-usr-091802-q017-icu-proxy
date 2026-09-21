"""重症紧急代理协作的端到端领域契约测试。

仅使用标准库，可被 `python3 -m unittest discover` 直接发现。
覆盖：三依据资格与顺位、最小披露、失联升级、版本绑定确认、
冲突复核、抢救例外、终止事件、跨午夜幂等、隐私视图与审计链完整性。
"""

from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path

from service import (
    SERVICE_ID,
    Actor,
    AuditLog,
    AuthorizationError,
    BasisType,
    Channel,
    CollaborationService,
    ConfirmationStatus,
    ContactResult,
    DomainError,
    MatterStatus,
    NotFoundError,
    RoleScope,
    StateConflictError,
    TerminationReason,
    ValidationError,
    build_server,
    canonical,
    content_digest,
    health_payload,
    sha256_hex,
)

REGISTRAR = Actor("reg", frozenset({CollaborationService.PERM_REGISTER}))
STAFF = Actor(
    "nurse.li",
    frozenset(
        {
            CollaborationService.PERM_STAFF,
            CollaborationService.PERM_CONTACT,
        }
    ),
)
CONTACT = Actor("nurse.li", frozenset({CollaborationService.PERM_CONTACT}))
REVIEWER = Actor("ethics.zhao", frozenset({CollaborationService.PERM_REVIEW}))
CLINICIAN = Actor(
    "dr.wang",
    frozenset(
        {
            CollaborationService.PERM_EMERGENCY,
            CollaborationService.PERM_SUBSTANTIATE,
        }
    ),
)
ADMIN = Actor("admin.chen", frozenset({CollaborationService.PERM_TERMINATE}))
AUDITOR = Actor("auditor.sun", frozenset({CollaborationService.PERM_AUDIT}))

# 固定时钟，保证业务日 / 有效期 / 签署时间可断言。
T0 = datetime(2026, 9, 20, 23, 30, tzinfo=timezone.utc)  # 北京时间 9/21 07:30


class MutableClock:
    def __init__(self, start: datetime):
        self.now = start
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.now

    def advance(self, minutes: int = 0, **kw) -> datetime:
        with self.lock:
            self.now += timedelta(minutes=minutes, **kw)
            return self.now


def make_service(start: datetime = T0) -> tuple[CollaborationService, MutableClock]:
    clock = MutableClock(start)
    return CollaborationService(clock=clock), clock


def register(
    svc: CollaborationService,
    agent_id: str,
    *,
    patient: str = "P-1",
    name: str = "家属",
    bases=(BasisType.DESIGNATED, BasisType.HOSPITAL_VERIFIED),
    scopes=None,
    phone="13800000000",
    expires_at=None,
    actor=REGISTRAR,
):
    scopes = scopes or {RoleScope.EXAM_CONSENT: 0, RoleScope.CRITICAL_NOTICE: 0,
                        RoleScope.TRANSFER: 0}
    return svc.register_agent(
        actor,
        {
            "agent_id": agent_id,
            "patient_id": patient,
            "display_name": name,
            "channels": {"phone": phone, "sms": phone},
            "bases": [b.value for b in bases],
            "scopes": {s.value: r for s, r in scopes.items()},
            **({"expires_at": expires_at.isoformat()} if expires_at else {}),
        },
    )


def add_doc(svc, doc_id="D-consent", content=None, title="检查同意书"):
    content = content or {"exam": "CT", "body": "v1"}
    return svc.add_document_version(
        STAFF, {"doc_id": doc_id, "title": title, "content": content}
    )


EXAM_DISCLOSURE = {
    "exam_name": "增强CT",
    "purpose": "明确颅内出血范围",
    "key_risks": "造影剂过敏、肾功能负担",
}


def open_matter(svc, key="K-1", scope=RoleScope.EXAM_CONSENT, doc="D-consent",
                disclosure=None, patient="P-1", actor=STAFF):
    return svc.open_matter(
        actor,
        {
            "idempotency_key": key,
            "patient_id": patient,
            "scope": scope.value,
            "doc_id": doc,
            "disclosure": disclosure or EXAM_DISCLOSURE,
        },
    )


def notify(svc, matter_id, actor=CONTACT):
    return svc.issue_next_notification(actor, {"matter_id": matter_id})


def attempt(svc, notification_id, result, *, channel=Channel.PHONE, actor=CONTACT,
            request_id=None, detail=""):
    params = {
        "notification_id": notification_id,
        "channel": channel.value,
        "result": result.value,
        "detail": detail,
    }
    if request_id:
        params["request_id"] = request_id
    return svc.record_contact_attempt(actor, params)


def deliver(svc, notification_id, req="req-deliver"):
    return attempt(svc, notification_id, ContactResult.DELIVERED, request_id=req)


def confirm(svc, notification_id, agent_id, request_id, actor=CONTACT,
            method="phone", evidence="OTP-123456"):
    return svc.submit_confirmation(
        actor,
        {
            "notification_id": notification_id,
            "agent_id": agent_id,
            "request_id": request_id,
            "identity_verification": {"method": method, "evidence_id": evidence},
        },
    )


# ---------------------------------------------------------------------------


class AuthorityAndOrderingTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()

    def test_three_bases_required_and_legal_outranks_designated(self):
        # 仅有预先指定、未院方核验 → 不生效
        register(self.svc, "a-unverified", bases=(BasisType.DESIGNATED,))
        # 法定关系 + 院方核验
        register(self.svc, "a-spouse", name="配偶",
                 bases=(BasisType.LEGAL, BasisType.HOSPITAL_VERIFIED),
                 scopes={RoleScope.EXAM_CONSENT: 5})
        # 预先指定 + 院方核验，但同事项顺位数字更小
        register(self.svc, "a-friend", name="友人",
                 bases=(BasisType.DESIGNATED, BasisType.HOSPITAL_VERIFIED),
                 scopes={RoleScope.EXAM_CONSENT: 0})
        add_doc(self.svc)
        res = open_matter(self.svc)
        matter_id = res["matter"]["matter_id"]
        n = notify(self.svc, matter_id)
        # 法定关系即使顺位数字更大也排在预先指定之前
        self.assertEqual(n["notification"]["agent_id"], "a-spouse")
        self.assertEqual(n["notification"]["level"], 0)

    def test_expired_agent_skipped_and_reasons_reconstructed(self):
        register(self.svc, "a-expired",
                 expires_at=self.clock.now + timedelta(minutes=5))
        register(self.svc, "a-ok")
        add_doc(self.svc)
        self.clock.advance(minutes=10)
        res = open_matter(self.svc)
        matter_id = res["matter"]["matter_id"]
        n = notify(self.svc, matter_id)
        self.assertEqual(n["notification"]["agent_id"], "a-ok")
        snap = self.svc.authority_snapshot(
            "P-1", RoleScope.EXAM_CONSENT, self.clock.now
        )
        expired = next(c for c in snap["considered"] if c["agent_id"] == "a-expired")
        self.assertFalse(expired["eligible"])
        self.assertIn("已过期", expired["reasons"])

    def test_not_yet_valid_agent_excluded(self):
        register(self.svc, "a-future",
                 expires_at=self.clock.now + timedelta(days=2))
        # 通过显式 valid_from 造一个尚未生效的人
        self.svc.register_agent(
            REGISTRAR,
            {
                "agent_id": "a-later",
                "patient_id": "P-1",
                "display_name": "后补",
                "channels": {"phone": "13900000000"},
                "bases": [BasisType.LEGAL.value, BasisType.HOSPITAL_VERIFIED.value],
                "scopes": {RoleScope.EXAM_CONSENT.value: 0},
                "valid_from": (self.clock.now + timedelta(hours=2)).isoformat(),
            },
        )
        add_doc(self.svc)
        matter_id = open_matter(self.svc)["matter"]["matter_id"]
        n = notify(self.svc, matter_id)
        self.assertEqual(n["notification"]["agent_id"], "a-future")


class DisclosureTest(unittest.TestCase):
    def setUp(self):
        self.svc, _ = make_service()
        register(self.svc, "a1")

    def test_excess_field_rejected(self):
        add_doc(self.svc)
        with self.assertRaises(ValidationError) as cm:
            open_matter(
                self.svc,
                disclosure={**EXAM_DISCLOSURE, "full_diagnosis": "全部病历"},
            )
        self.assertIn("最少披露字段", str(cm.exception))

    def test_missing_field_rejected(self):
        add_doc(self.svc)
        with self.assertRaises(ValidationError):
            open_matter(self.svc, disclosure={"exam_name": "CT"})

    def test_whitelist_per_scope(self):
        add_doc(self.svc, doc_id="D-crit", title="病危通知",
                content={"text": "危重"})
        res = open_matter(
            self.svc, key="K-crit", scope=RoleScope.CRITICAL_NOTICE, doc="D-crit",
            disclosure={"condition_summary": "多器官功能衰竭", "urgency": "即刻"},
        )
        self.assertEqual(res["matter"]["scope"], "critical_notice")


class EscalationTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        register(self.svc, "a1", scopes={RoleScope.EXAM_CONSENT: 0})
        register(self.svc, "a2", scopes={RoleScope.EXAM_CONSENT: 1})
        register(self.svc, "a3", scopes={RoleScope.EXAM_CONSENT: 2})
        add_doc(self.svc)
        self.matter_id = open_matter(self.svc)["matter"]["matter_id"]

    def test_unreachable_escalates_level_by_level(self):
        n1 = notify(self.svc, self.matter_id)["notification"]
        self.assertEqual(n1["agent_id"], "a1")
        # 未记录结果前不能并行通知下一位
        with self.assertRaises(StateConflictError):
            notify(self.svc, self.matter_id)
        attempt(self.svc, n1["notification_id"], ContactResult.UNREACHABLE,
                channel=Channel.PHONE, request_id="r1")
        attempt(self.svc, n1["notification_id"], ContactResult.UNREACHABLE,
                channel=Channel.SMS, request_id="r2")
        self.assertEqual(n1 := self.svc.repo.notification_index[n1["notification_id"]].state,
                         "unreachable")
        n2 = notify(self.svc, self.matter_id)["notification"]
        self.assertEqual(n2["agent_id"], "a2")
        self.assertEqual(n2["level"], 1)

    def test_delivered_blocks_skip_until_decision(self):
        n1 = notify(self.svc, self.matter_id)["notification"]
        deliver(self.svc, n1["notification_id"])
        with self.assertRaises(StateConflictError):
            notify(self.svc, self.matter_id)

    def test_rejection_then_escalation(self):
        n1 = notify(self.svc, self.matter_id)["notification"]
        attempt(self.svc, n1["notification_id"], ContactResult.REJECTED,
                request_id="rj1")
        n2 = notify(self.svc, self.matter_id)["notification"]
        self.assertEqual(n2["agent_id"], "a2")

    def test_exhausted_marks_unresolved(self):
        for idx, agent_id in enumerate(("a1", "a2", "a3")):
            n = notify(self.svc, self.matter_id)["notification"]
            self.assertEqual(n["agent_id"], agent_id)
            attempt(self.svc, n["notification_id"], ContactResult.UNREACHABLE,
                    request_id=f"u{idx}")
        out = notify(self.svc, self.matter_id)
        self.assertTrue(out["exhausted"])
        self.assertEqual(out["matter"]["status"], MatterStatus.UNRESOLVED.value)


class ConfirmationVersioningTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        register(self.svc, "a1")
        add_doc(self.svc)
        self.matter_id = open_matter(self.svc)["matter"]["matter_id"]
        self.n1 = notify(self.svc, self.matter_id)["notification"]
        deliver(self.svc, self.n1["notification_id"])

    def test_confirmation_binds_version_identity_time(self):
        res = confirm(self.svc, self.n1["notification_id"], "a1", "sig-1")
        c = res["confirmation"]
        self.assertEqual(c["doc_ref"]["version"], 1)
        self.assertEqual(c["status"], ConfirmationStatus.VALID.value)
        self.assertTrue(c["signed_at"])
        self.assertEqual(c["identity_verification"]["method"], "phone")
        self.assertEqual(res["matter_status"], MatterStatus.CONFIRMED.value)

    def test_duplicate_callback_is_idempotent(self):
        first = confirm(self.svc, self.n1["notification_id"], "a1", "sig-same")
        second = confirm(self.svc, self.n1["notification_id"], "a1", "sig-same")
        self.assertEqual(
            first["confirmation"]["confirmation_id"],
            second["confirmation"]["confirmation_id"],
        )
        matter = self.svc.repo.matters[self.matter_id]
        self.assertEqual(len(matter.confirmations), 1)

    def test_only_delivered_notification_can_be_confirmed(self):
        # 不同范围避开「同患者同事项同业务日」抑制
        add_doc(self.svc, doc_id="D-crit", title="病危通知", content={"t": 1})
        matter2 = open_matter(
            self.svc, key="K-2", scope=RoleScope.CRITICAL_NOTICE, doc="D-crit",
            disclosure={"condition_summary": "休克", "urgency": "即刻"},
        )["matter"]["matter_id"]
        n2 = notify(self.svc, matter2)["notification"]
        with self.assertRaises(StateConflictError):
            confirm(self.svc, n2["notification_id"], "a1", "sig-early")

    def test_wrong_agent_cannot_confirm(self):
        register(self.svc, "a2", phone="13700000000",
                 scopes={RoleScope.EXAM_CONSENT: 9})
        with self.assertRaises(AuthorizationError):
            confirm(self.svc, self.n1["notification_id"], "a2", "sig-forgery")

    def test_document_update_invalidates_old_confirmation_and_requires_renotify(self):
        res = confirm(self.svc, self.n1["notification_id"], "a1", "sig-v1")
        self.assertEqual(res["matter_status"], MatterStatus.CONFIRMED.value)
        # 追加新版本 → 旧确认状态变为 superseded（复盘时可见）
        self.svc.add_document_version(
            STAFF, {"doc_id": "D-consent", "title": "检查同意书",
                    "content": {"exam": "CT", "body": "v2 含新增条款"}}
        )
        matter = self.svc.repo.matters[self.matter_id]
        conf = matter.confirmations[0]
        self.assertEqual(
            self.svc._confirmation_status_public(matter, conf).value,
            ConfirmationStatus.SUPERSEDED.value,
        )

        # 「旧通知确认被拒 + 新版本重发」在不自动关闭的病危通知事项上验证
        add_doc(self.svc, doc_id="D-crit", title="病危通知", content={"t": 1})
        mc = open_matter(
            self.svc, key="K-c", scope=RoleScope.CRITICAL_NOTICE, doc="D-crit",
            disclosure={"condition_summary": "感染性休克", "urgency": "即刻"},
        )["matter"]["matter_id"]
        nc = notify(self.svc, mc)["notification"]
        deliver(self.svc, nc["notification_id"], req="dc")
        self.svc.add_document_version(
            STAFF, {"doc_id": "D-crit", "title": "病危通知", "content": {"t": 2}}
        )
        # 通知仍送达，但绑定旧摘要 → 服务端以版本原因拒绝
        with self.assertRaises(StateConflictError) as cm:
            confirm(self.svc, nc["notification_id"], "a1", "sig-stale")
        self.assertIn("旧版本", str(cm.exception))
        # 以新版本向同一顺位重新通知
        ncb = notify(self.svc, mc)["notification"]
        self.assertEqual(ncb["agent_id"], "a1")
        self.assertEqual(ncb["level"], 1)
        self.assertNotEqual(ncb["doc_ref"]["digest"], nc["doc_ref"]["digest"])
        deliver(self.svc, ncb["notification_id"], req="dcb")
        ok = confirm(self.svc, ncb["notification_id"], "a1", "sig-v2new")
        self.assertEqual(ok["confirmation"]["doc_ref"]["version"], 2)


class ConflictAndReviewTest(unittest.TestCase):
    def setUp(self):
        self.svc, _ = make_service()
        register(self.svc, "a1", scopes={RoleScope.CRITICAL_NOTICE: 0})
        register(self.svc, "a2", scopes={RoleScope.CRITICAL_NOTICE: 1})
        add_doc(self.svc, doc_id="D-crit", title="病危通知", content={"t": 1})
        self.disclosure = {"condition_summary": "感染性休克", "urgency": "即刻"}
        self.matter_id = open_matter(
            self.svc, key="K-c1", scope=RoleScope.CRITICAL_NOTICE, doc="D-crit",
            disclosure=self.disclosure,
        )["matter"]["matter_id"]

    def _deliver(self, agent_id, req):
        n = notify(self.svc, self.matter_id)["notification"]
        self.assertEqual(n["agent_id"], agent_id)
        deliver(self.svc, n["notification_id"], req=req)
        return n

    def test_conflicting_stances_trigger_conflict_and_review(self):
        n1 = self._deliver("a1", "d1")
        confirm(self.svc, n1["notification_id"], "a1", "s1")
        # 通知类事项确认后不关闭，继续通知下一位
        n2 = notify(self.svc, self.matter_id)["notification"]
        self.assertEqual(n2["agent_id"], "a2")
        deliver(self.svc, n2["notification_id"], req="d2")
        self.svc.record_refusal(
            CONTACT,
            {"notification_id": n2["notification_id"], "agent_id": "a2",
             "reason": "家属意见相反"},
        )
        matter = self.svc.repo.matters[self.matter_id]
        self.assertEqual(matter.status.value, MatterStatus.CONFLICT.value)

        esc = self.svc.escalate_review(
            CONTACT, {"matter_id": self.matter_id, "route": "ethics"}
        )
        self.assertEqual(esc["matter_status"], MatterStatus.UNDER_REVIEW.value)

        # 复核期间不再受理确认
        with self.assertRaises(StateConflictError):
            confirm(self.svc, n2["notification_id"], "a2", "s2")

        decision = self.svc.decide_review(
            REVIEWER,
            {"matter_id": self.matter_id, "outcome": "confirm",
             "rationale": "经伦理委员会讨论，按患者最佳利益执行检查并继续沟通"},
        )
        self.assertEqual(decision["matter_status"], MatterStatus.RESOLVED.value)
        self.assertEqual(decision["review"]["decided_by"], "ethics.zhao")

    def test_reviewer_without_permission_rejected(self):
        with self.assertRaises(AuthorizationError):
            self.svc.decide_review(
                CONTACT,
                {"matter_id": self.matter_id, "outcome": "confirm",
                 "rationale": "试图由联络护士直接裁决并不足字数"},
            )


class EmergencyExceptionTest(unittest.TestCase):
    def setUp(self):
        self.svc, _ = make_service()
        register(self.svc, "a1")
        add_doc(self.svc)
        self.matter_id = open_matter(self.svc)["matter"]["matter_id"]
        n = notify(self.svc, self.matter_id)["notification"]
        attempt(self.svc, n["notification_id"], ContactResult.UNREACHABLE,
                request_id="lost")
        notify(self.svc, self.matter_id)  # exhausted
        self.assertEqual(
            self.svc.repo.matters[self.matter_id].status.value,
            MatterStatus.UNRESOLVED.value,
        )

    def test_clinician_opens_exception_and_substantiates_later(self):
        opened = self.svc.open_emergency_exception(
            CLINICIAN,
            {
                "matter_id": self.matter_id,
                "urgency_statement": "患者脑疝形成，数分钟内可致不可逆损伤，无法等待家属",
                "action_taken": "已行急诊去骨瓣减压",
            },
        )
        exc_id = opened["exception"]["exception_id"]
        self.assertEqual(opened["exception"]["status"], "open")
        self.assertIn(CLINICIAN.actor_id, opened["exception"]["clinician_id"])

        # 无权限的联络护士不能开立抢救例外
        with self.assertRaises(AuthorizationError):
            self.svc.open_emergency_exception(
                CONTACT,
                {"matter_id": self.matter_id,
                 "urgency_statement": "情况确实非常非常紧急来不及等待",
                 "action_taken": "处置"},
            )

        # 事后补齐依据
        done = self.svc.substantiate_exception(
            CLINICIAN,
            {"matter_id": self.matter_id,
             "basis_refs": [
                 {"kind": "record", "ref": "病程记录-20260921-001"},
                 {"kind": "image", "ref": "CT-20260921-0745"},
             ]},
        )
        self.assertEqual(done["exception"]["status"], "substantiated")
        self.assertEqual(len(done["exception"]["basis_refs"]), 2)
        with self.assertRaises(StateConflictError):
            self.svc.substantiate_exception(
                CLINICIAN,
                {"matter_id": self.matter_id,
                 "basis_refs": [{"kind": "record", "ref": "x"}]},
            )

    def test_exception_requires_real_statement(self):
        with self.assertRaises(ValidationError):
            self.svc.open_emergency_exception(
                CLINICIAN,
                {"matter_id": self.matter_id, "urgency_statement": "急",
                 "action_taken": "处置"},
            )


class TerminationTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        register(self.svc, "a1")
        add_doc(self.svc)
        self.matter_id = open_matter(self.svc)["matter"]["matter_id"]

    def test_transfer_terminates_authority_and_closes_matter(self):
        res = self.svc.record_termination(
            ADMIN, {"patient_id": "P-1", "reason": TerminationReason.TRANSFER.value}
        )
        self.assertIn("a1", res["affected_agents"])
        self.assertIn(self.matter_id, res["closed_matters"])
        self.assertEqual(
            self.svc.repo.agents["a1"].status.value, "terminated"
        )
        # 终止后不能再通知
        with self.assertRaises(StateConflictError):
            notify(self.svc, self.matter_id)

    def test_revoking_unrelated_agent_keeps_matter_open(self):
        register(self.svc, "a2", phone="13700000000",
                 scopes={RoleScope.TRANSFER: 0})
        res = self.svc.record_termination(
            ADMIN,
            {"patient_id": "P-1", "reason": TerminationReason.REVOKED.value,
             "agent_id": "a2"},
        )
        self.assertEqual(res["affected_agents"], ["a2"])
        self.assertEqual(res["closed_matters"], [])
        self.assertEqual(
            self.svc.repo.matters[self.matter_id].status.value,
            MatterStatus.OPEN.value,
        )

    def test_revoked_agent_cannot_be_silently_reregistered(self):
        self.svc.record_termination(
            ADMIN,
            {"patient_id": "P-1", "reason": TerminationReason.REVOKED.value,
             "agent_id": "a1"},
        )
        with self.assertRaises(StateConflictError):
            register(self.svc, "a1")

    def test_regained_consciousness_terminates(self):
        res = self.svc.record_termination(
            ADMIN,
            {"patient_id": "P-1",
             "reason": TerminationReason.REGAINED_CONSCIOUSNESS.value},
        )
        self.assertIn("a1", res["affected_agents"])


class IdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        register(self.svc, "a1")
        add_doc(self.svc)

    def test_same_key_returns_same_matter(self):
        first = open_matter(self.svc, key="DUP")
        second = open_matter(self.svc, key="DUP")
        self.assertTrue(second["deduped"])
        self.assertEqual(
            first["matter"]["matter_id"], second["matter"]["matter_id"]
        )

    def test_cross_midnight_same_business_day_rejected(self):
        # T0 = UTC 23:30 → 北京 07:30；推进 30 分钟跨过 UTC 午夜，
        # 但仍属同一北京业务日（9/21）。
        open_matter(self.svc, key="before-midnight")
        self.clock.advance(minutes=40)  # UTC 9/21 00:10，北京 08:10
        with self.assertRaises(StateConflictError) as cm:
            open_matter(self.svc, key="after-midnight")
        self.assertIn("同一业务日", str(cm.exception))

    def test_next_business_day_allowed(self):
        open_matter(self.svc, key="day1")
        self.clock.advance(hours=24)
        res = open_matter(self.svc, key="day2")
        self.assertFalse(res["deduped"])
        self.assertNotEqual(
            res["matter"]["matter_id"],
            open_matter(self.svc, key="day1")["matter"]["matter_id"],
        )

    def test_repeated_contact_callback_deduped(self):
        m = open_matter(self.svc, key="cb")["matter"]["matter_id"]
        n = notify(self.svc, m)["notification"]
        a1 = attempt(self.svc, n["notification_id"], ContactResult.UNREACHABLE,
                     request_id="cb-1", detail="无人接听")
        a2 = attempt(self.svc, n["notification_id"], ContactResult.UNREACHABLE,
                     request_id="cb-1", detail="无人接听")
        self.assertEqual(a1["attempt"]["attempt_id"], a2["attempt"]["attempt_id"])


class AuditChainTest(unittest.TestCase):
    def test_hash_chain_detects_tampering(self):
        svc, _ = make_service()
        register(svc, "a1")
        add_doc(svc)
        open_matter(svc)
        result = svc.verify_audit_chain()
        self.assertEqual(result["integrity"], "ok")
        self.assertGreater(result["entries"], 2)
        # 篡改历史载荷
        svc.audit._entries[1].payload["bases"] = ["hacked"]
        with self.assertRaises(StateConflictError):
            svc.verify_audit_chain()

    def test_chain_linkage_is_manual_recomputable(self):
        svc, _ = make_service()
        register(svc, "a1")
        entries = svc.audit.entries()
        prev = AuditLog.GENESIS
        for e in entries:
            self.assertEqual(e.prev_hash, prev)
            body = {
                "schema": 1,
                "at": e.at.astimezone(timezone.utc).isoformat(),
                "actor_id": e.actor_id,
                "action": e.action,
                "payload": e.payload,
            }
            expect = sha256_hex(
                canonical({"seq": e.seq, "prev_hash": prev, "body": body})
            )
            self.assertEqual(expect, e.hash)
            prev = e.hash


class DossierAndPrivacyTest(unittest.TestCase):
    def setUp(self):
        self.svc, _ = make_service()
        register(self.svc, "a1", name="配偶", phone="13811112222")
        register(self.svc, "a2", name="兄长", phone="13933334444",
                 scopes={RoleScope.EXAM_CONSENT: 1})
        add_doc(self.svc)
        self.matter_id = open_matter(self.svc)["matter"]["matter_id"]
        n1 = notify(self.svc, self.matter_id)["notification"]
        attempt(self.svc, n1["notification_id"], ContactResult.REJECTED,
                request_id="rj", detail="现在不能决定")
        n2 = notify(self.svc, self.matter_id)["notification"]
        deliver(self.svc, n2["notification_id"], req="d2")
        confirm(self.svc, n2["notification_id"], "a2", "final-sig")

    def test_auditor_dossier_reconstructs_everything(self):
        d = self.svc.review_dossier(AUDITOR, self.matter_id)
        self.assertEqual(d["view"], "audit")
        self.assertEqual([n["agent_id"] for n in d["notifications"]], ["a1", "a2"])
        self.assertEqual(d["disclosure"]["exam_name"], "增强CT")
        self.assertEqual(d["confirmations"][0]["status"], "valid")
        self.assertIn("a1", d["agents"])
        self.assertIn("a2", d["agents"])
        # 完整电话号码只在审计视图出现
        self.assertEqual(d["agents"]["a1"]["channels"]["phone"], "13811112222")
        # 开立时顺位可还原
        self.assertEqual(d["authority_at_open"]["order"], ["a1", "a2"])

    def test_family_view_hides_other_contacts(self):
        view = self.svc.family_view("a1", self.matter_id)
        self.assertEqual(view["view"], "family")
        self.assertEqual(len(view["notifications"]), 1)
        self.assertEqual(view["notifications"][0]["agent_id"], "a1")
        rendered = json.dumps(view, ensure_ascii=False)
        self.assertNotIn("a2", rendered)
        self.assertNotIn("13933334444", rendered)
        self.assertNotIn("兄长", rendered)
        # 家属视图也不暴露自己完整联系方式之外的他人临床细节
        self.assertNotIn("final-sig", rendered)

    def test_family_view_404_for_unrelated_agent(self):
        register(self.svc, "a3", phone="13600000000",
                 scopes={RoleScope.TRANSFER: 0})
        with self.assertRaises(NotFoundError):
            self.svc.family_view("a3", self.matter_id)

    def test_auditor_requires_permission(self):
        with self.assertRaises(AuthorizationError):
            self.svc.review_dossier(CONTACT, self.matter_id)


class PermissionTest(unittest.TestCase):
    def test_register_requires_permission(self):
        svc, _ = make_service()
        with self.assertRaises(AuthorizationError):
            register(svc, "a1", actor=STAFF)


class RpcAndHttpTest(unittest.TestCase):
    def test_dispatch_unknown_method(self):
        svc, _ = make_service()
        with self.assertRaises(NotFoundError):
            svc.dispatch({"method": "nope", "actor": {"actor_id": "x"}})

    def test_http_rpc_and_health(self):
        svc, _ = make_service()
        import service as service_mod

        class _Handler(service_mod.Handler):
            pass

        _Handler.service = svc
        server = service_mod.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            payload = json.loads(resp.read())
            self.assertEqual(payload["service"], SERVICE_ID)
            self.assertEqual(health_payload()["status"], "ok")

            body = json.dumps(
                {
                    "method": "register_agent",
                    "actor": {"actor_id": "reg",
                              "permissions": [CollaborationService.PERM_REGISTER]},
                    "params": {
                        "agent_id": "a1", "patient_id": "P-9",
                        "display_name": "家属",
                        "channels": {"phone": "13800000000"},
                        "bases": [BasisType.LEGAL.value,
                                  BasisType.HOSPITAL_VERIFIED.value],
                        "scopes": {RoleScope.EXAM_CONSENT.value: 0},
                    },
                }
            )
            conn.request("POST", "/rpc", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = json.loads(resp.read())
            self.assertTrue(data["ok"])
            self.assertEqual(data["result"]["agent"]["agent_id"], "a1")

            # 403 路径
            conn.request(
                "POST", "/rpc",
                body=json.dumps({"method": "open_matter",
                                 "actor": {"actor_id": "reg", "permissions": []},
                                 "params": {}}),
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 403)
            resp.read()

            # 坏 JSON
            conn.request("POST", "/rpc", body="{not json",
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            resp.read()
        finally:
            server.shutdown()
            server.server_close()


class FixtureTest(unittest.TestCase):
    def test_fixture_matches_contract(self):
        data = json.loads(
            Path("fixtures/sample.json").read_text(encoding="utf-8")
        )
        self.assertEqual(data["service"], SERVICE_ID)
        self.assertFalse(data["context"]["clinical_decision_engine"])
        for item in data["workflow"]:
            self.assertIn("id", item)
            self.assertIn("audit_events", item)


if __name__ == "__main__":
    unittest.main()
