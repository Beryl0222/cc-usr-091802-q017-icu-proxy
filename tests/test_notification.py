"""事项发起、最小披露、逐级通知与全失联升级、跨午夜幂等。"""

import unittest

from icuproxy import (
    Basis,
    DeliveryOutcome,
    MatterStatus,
    MatterType,
    Relation,
)
from icuproxy.errors import ConflictStateError, NotFoundError, ValidationError
from tests.support import build_world, add_family, grant_verified, open_with_document


class NotificationTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock, self.ids = build_world()
        add_family(self.svc, "desig", "预先指定人")
        add_family(self.svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        add_family(self.svc, "child", "子女", relation=Relation.ADULT_CHILD.value)
        self.gd = grant_verified(
            self.svc, "p1", "desig", Basis.PATIENT_DESIGNATED.value
        )
        self.gs = grant_verified(
            self.svc, "p1", "spouse", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        self.gc = grant_verified(
            self.svc, "p1", "child", Basis.LEGAL.value,
            relation=Relation.ADULT_CHILD.value,
        )

    def test_idempotent_open_across_midnight(self):
        m1 = self.svc.open_matter(
            "staff1", "p1", MatterType.CRITICAL_NOTICE.value, "病危", "NK-1"
        )
        self.clock.advance(hours=8)  # 跨过午夜交班
        m2 = self.svc.open_matter(
            "staff1", "p1", MatterType.CRITICAL_NOTICE.value, "病危（交班重发）",
            "NK-1",
        )
        self.assertEqual(m1.id, m2.id)

    def test_requires_idempotency_key(self):
        with self.assertRaises(ValidationError):
            self.svc.open_matter(
                "staff1", "p1", MatterType.CRITICAL_NOTICE.value, "病危", "  ",
            )

    def test_must_follow_chain_order(self):
        matter, _ = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )
        # 跳过顺位最前的 desig 直接联系配偶
        with self.assertRaises(ConflictStateError):
            self.svc.record_attempt(
                "staff1", matter.id, self.gs.id, "phone",
                DeliveryOutcome.DELIVERED.value, minimal_summary="s",
                fields=["procedure"],
            )

    def test_unreachable_escalates_to_next_rank(self):
        matter, _ = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )
        r1 = self.svc.record_attempt(
            "staff1", matter.id, self.gd.id, "phone",
            DeliveryOutcome.UNREACHABLE.value, detail="三次无人接听",
        )
        self.assertFalse(r1["escalated"])
        head = self.svc.next_contact(matter.id)
        self.assertEqual(head.id, self.gs.id)

    def test_refusal_moves_to_next_rank(self):
        matter, _ = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )
        self.svc.record_attempt(
            "staff1", matter.id, self.gd.id, "phone",
            DeliveryOutcome.UNREACHABLE.value,
        )
        r = self.svc.record_attempt(
            "staff1", matter.id, self.gs.id, "phone",
            DeliveryOutcome.REFUSED.value, detail="明确拒绝沟通",
        )
        self.assertFalse(r["escalated"])
        self.assertEqual(self.svc.next_contact(matter.id).id, self.gc.id)

    def test_all_unreachable_escalates_medical_affairs(self):
        matter, _ = open_with_document(
            self.svc, MatterType.CRITICAL_NOTICE.value, "病危", "K1",
            kind="critical_notice",
        )
        self.svc.record_attempt(
            "staff1", matter.id, self.gd.id, "phone",
            DeliveryOutcome.UNREACHABLE.value,
        )
        self.svc.record_attempt(
            "staff1", matter.id, self.gs.id, "phone",
            DeliveryOutcome.UNREACHABLE.value,
        )
        result = self.svc.record_attempt(
            "staff1", matter.id, self.gc.id, "phone",
            DeliveryOutcome.REFUSED.value,
        )
        self.assertTrue(result["escalated"])
        self.assertEqual(result["referral"].reason, "all_unreachable")
        self.assertEqual(result["referral"].body, "medical_affairs")
        self.assertEqual(self.svc.get_matter(matter.id).status,
                         MatterStatus.ESCALATED.value)

    def test_only_contact_lost_escalates_immediately(self):
        svc, _, ids = build_world()
        matter, _ = open_with_document(
            svc, MatterType.CRITICAL_NOTICE.value, "病危", "K9",
            kind="critical_notice",
        )
        add_family(svc, "only", "唯一联系人")
        g = grant_verified(svc, "p1", "only", Basis.LEGAL.value,
                           relation=Relation.SPOUSE.value)
        result = svc.record_attempt(
            "staff1", matter.id, g.id, "phone",
            DeliveryOutcome.UNREACHABLE.value,
        )
        self.assertTrue(result["escalated"])
        self.assertEqual(result["attempt"].grant_id, g.id)


class MinimalDisclosureTest(unittest.TestCase):
    def setUp(self):
        self.svc, _, self.ids = build_world()
        add_family(self.svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        self.g = grant_verified(
            self.svc, "p1", "spouse", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        self.matter, self.doc = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )

    def test_delivery_freezes_minimal_packet(self):
        result = self.svc.record_attempt(
            "staff1", self.matter.id, self.g.id, "phone",
            DeliveryOutcome.DELIVERED.value,
            minimal_summary="拟行穿刺；主要风险为出血",
            fields=["procedure", "key_risks"],
        )
        attempt = result["attempt"]
        self.assertIsNotNone(attempt.disclosure_id)
        packet = self.svc.disclosures[attempt.disclosure_id]
        self.assertEqual(packet.document_sha256, self.doc.sha256)
        self.assertEqual(packet.fields, ["procedure", "key_risks"])

    def test_field_outside_whitelist_rejected(self):
        # 病危通知字段不能用于同意事项
        with self.assertRaises(ValidationError):
            self.svc.record_attempt(
                "staff1", self.matter.id, self.g.id, "phone",
                DeliveryOutcome.DELIVERED.value,
                minimal_summary="s",
                fields=["procedure", "immediate_risk"],
            )

    def test_delivered_requires_summary(self):
        with self.assertRaises(ValidationError):
            self.svc.record_attempt(
                "staff1", self.matter.id, self.g.id, "phone",
                DeliveryOutcome.DELIVERED.value,
            )

    def test_duplicate_delivery_same_version_blocked(self):
        self.svc.record_attempt(
            "staff1", self.matter.id, self.g.id, "phone",
            DeliveryOutcome.DELIVERED.value, minimal_summary="s",
            fields=["procedure"],
        )
        # 重复回调 / 交班后再次送达同一版本
        with self.assertRaises(ConflictStateError):
            self.svc.record_attempt(
                "staff1", self.matter.id, self.g.id, "phone",
                DeliveryOutcome.DELIVERED.value, minimal_summary="s2",
                fields=["procedure"],
            )

    def test_lost_after_delivery_releases_escalation(self):
        svc = self.svc
        svc.record_attempt(
            "staff1", self.matter.id, self.g.id, "phone",
            DeliveryOutcome.DELIVERED.value, minimal_summary="s",
            fields=["procedure"],
        )
        self.assertEqual(svc.next_contact(self.matter.id), None)
        # 久等无回复，补记失联
        r = svc.record_attempt(
            "staff1", self.matter.id, self.g.id, "phone",
            DeliveryOutcome.UNREACHABLE.value, detail="送达后失联",
        )
        self.assertTrue(r["escalated"])
        self.assertEqual(svc.get_matter(self.matter.id).status,
                         MatterStatus.ESCALATED.value)


if __name__ == "__main__":
    unittest.main()
