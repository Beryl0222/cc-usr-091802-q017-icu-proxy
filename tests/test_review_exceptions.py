"""意见冲突转复核、抢救例外及依据补齐。"""

import unittest

from icuproxy import (
    Basis,
    DeliveryOutcome,
    MatterStatus,
    MatterType,
    ReferralStatus,
    Relation,
)
from icuproxy.errors import (
    ConflictStateError,
    PermissionDenied,
    ValidationError,
)
from tests.support import build_world, add_family, grant_verified, open_with_document


def deliver_and_confirm(svc, matter, grant, stance):
    svc.record_attempt(
        "staff1", matter.id, grant.id, "phone",
        DeliveryOutcome.DELIVERED.value, minimal_summary="摘要",
        fields=["procedure"],
    )
    return svc.record_confirmation(
        "staff1", matter.id, grant.id, stance,
        "callback_verified_phone", f"ev-{grant.id}-{stance}",
    )


class ConflictReviewTest(unittest.TestCase):
    def setUp(self):
        self.svc, _, self.ids = build_world()
        add_family(self.svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        add_family(self.svc, "child", "子女",
                   relation=Relation.ADULT_CHILD.value)
        self.gs = grant_verified(
            self.svc, "p1", "spouse", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        self.gc = grant_verified(
            self.svc, "p1", "child", Basis.LEGAL.value,
            relation=Relation.ADULT_CHILD.value,
        )
        self.matter, _ = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )

    def test_opposing_stances_open_ethics_referral(self):
        deliver_and_confirm(self.svc, self.matter, self.gs, "consent")
        result = deliver_and_confirm(self.svc, self.matter, self.gc, "refuse")
        self.assertIsNotNone(result["conflict"])
        referral = result["conflict"]
        self.assertEqual(referral.body, "ethics")
        self.assertEqual(referral.reason, "conflict")
        self.assertEqual(set(referral.conflicting),
                         {c.id for c in self.svc.confirmations.values()})
        self.assertEqual(self.svc.get_matter(self.matter.id).status,
                         MatterStatus.CONFLICT.value)

    def test_resolve_blocked_while_conflict_open(self):
        deliver_and_confirm(self.svc, self.matter, self.gs, "consent")
        deliver_and_confirm(self.svc, self.matter, self.gc, "refuse")
        with self.assertRaises(ConflictStateError):
            self.svc.resolve_matter("att1", self.matter.id)

    def test_ethics_conclusion_resolves_with_rationale(self):
        deliver_and_confirm(self.svc, self.matter, self.gs, "consent")
        r = deliver_and_confirm(self.svc, self.matter, self.gc, "refuse")
        with self.assertRaises(ValidationError):
            self.svc.conclude_referral("eth1", r["conflict"].id,
                                      decision_stance="consent", rationale=" ")
        referral = self.svc.conclude_referral(
            "eth1", r["conflict"].id, decision_stance="consent",
            rationale="经与双方沟通，按患者最佳利益采纳同意意见",
        )
        self.assertEqual(referral.status, ReferralStatus.CONCLUDED.value)
        self.assertEqual(self.svc.get_matter(self.matter.id).status,
                         MatterStatus.RESOLVED.value)

    def test_medical_affairs_cannot_touch_ethics_referral(self):
        deliver_and_confirm(self.svc, self.matter, self.gs, "consent")
        r = deliver_and_confirm(self.svc, self.matter, self.gc, "refuse")
        with self.assertRaises(PermissionDenied):
            self.svc.conclude_referral(
                "ma1", r["conflict"].id, decision_stance="consent",
                rationale="医务处越权尝试",
            )

    def test_staff_cannot_conclude_review(self):
        deliver_and_confirm(self.svc, self.matter, self.gs, "consent")
        r = deliver_and_confirm(self.svc, self.matter, self.gc, "refuse")
        with self.assertRaises(PermissionDenied):
            self.svc.conclude_referral(
                "staff1", r["conflict"].id, decision_stance="consent",
                rationale="护士越权",
            )

    def test_all_unreachable_referral_goes_medical_affairs(self):
        # 只有一名联系人且失联
        svc, _, _ = build_world()
        add_family(svc, "only", "某人", relation=Relation.SPOUSE.value)
        g = grant_verified(svc, "p1", "only", Basis.LEGAL.value,
                           relation=Relation.SPOUSE.value)
        matter, _ = open_with_document(
            svc, MatterType.TRANSFER_DECISION.value, "转院", "KT",
            kind="transfer_proposal",
        )
        result = svc.record_attempt(
            "staff1", matter.id, g.id, "phone",
            DeliveryOutcome.UNREACHABLE.value,
        )
        referral = result["referral"]
        self.assertEqual(referral.body, "medical_affairs")
        # 医务处可登记处置结论（失联升级不要求立场）
        concluded = svc.conclude_referral(
            "ma1", referral.id, rationale="多方查找未果，按院内应急流程值守联系",
        )
        self.assertEqual(concluded.status, ReferralStatus.CONCLUDED.value)


class EmergencyExceptionTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock, self.ids = build_world()
        self.matter, _ = open_with_document(
            self.svc, MatterType.TRANSFER_DECISION.value, "紧急转院", "KE",
            kind="transfer_proposal",
        )

    def test_only_attending_or_medical_affairs_may_open(self):
        with self.assertRaises(PermissionDenied):
            self.svc.open_emergency_exception(
                "staff1", self.matter.id, "病情危急",
            )

    def test_urgency_statement_required(self):
        with self.assertRaises(ValidationError):
            self.svc.open_emergency_exception(
                "att1", self.matter.id, "   ",
            )

    def test_open_then_basis_due_and_review(self):
        exc = self.svc.open_emergency_exception(
            "att1", self.matter.id,
            "患者生命体征迅速恶化，延迟转运将危及生命，无法及时联系家属",
            basis_due_hours=6,
        )
        self.assertEqual(self.svc.get_matter(self.matter.id).status,
                         MatterStatus.EXCEPTION_USED.value)
        self.assertIsNone(exc.basis_provided_at)

        # 未到限期不报逾期
        self.clock.advance(hours=5)
        self.assertEqual(self.svc.overdue_exceptions(), [])
        # 逾期可被追踪
        self.clock.advance(hours=2)
        overdue = self.svc.overdue_exceptions()
        self.assertEqual([e.id for e in overdue], [exc.id])
        self.assertTrue(overdue[0].overdue)

        # 事后补齐依据
        with self.assertRaises(ValidationError):
            self.svc.provide_exception_basis("att1", exc.id, [])
        self.svc.provide_exception_basis(
            "att1", exc.id, ["病程记录.pdf", "抢救记录.pdf"],
            note="抢救后 6 小时内补齐",
        )
        # 医务处审核依据
        self.svc.review_exception_basis("ma1", exc.id, "依据充分，程序合规")
        refreshed = self.svc.exceptions[exc.id]
        self.assertIsNotNone(refreshed.basis_reviewed_by)

    def test_basis_only_after_provision(self):
        exc = self.svc.open_emergency_exception(
            "att1", self.matter.id, "紧迫",
        )
        with self.assertRaises(ConflictStateError):
            self.svc.review_exception_basis("ma1", exc.id, "提前审核")

    def test_staff_cannot_review_basis(self):
        exc = self.svc.open_emergency_exception(
            "att1", self.matter.id, "紧迫",
        )
        self.svc.provide_exception_basis("att1", exc.id, ["d.pdf"])
        with self.assertRaises(PermissionDenied):
            self.svc.review_exception_basis("staff1", exc.id, "越权审核")

    def test_exception_not_allowed_after_resolution(self):
        svc, _, _ = build_world()
        add_family(svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        g = grant_verified(svc, "p1", "spouse", Basis.LEGAL.value,
                           relation=Relation.SPOUSE.value)
        matter, _ = open_with_document(
            svc, MatterType.EXAM_CONSENT.value, "同意", "KQ",
        )
        deliver_and_confirm(svc, matter, g, "consent")
        svc.resolve_matter("att1", matter.id)
        with self.assertRaises(ConflictStateError):
            svc.open_emergency_exception("att1", matter.id, "紧迫")


if __name__ == "__main__":
    unittest.main()
