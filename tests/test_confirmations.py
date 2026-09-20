"""远程确认：版本绑定、身份校验、签署时间、旧版本自动失效。"""

import unittest

from icuproxy import (
    Basis,
    DeliveryOutcome,
    MatterStatus,
    MatterType,
    Relation,
)
from icuproxy.errors import (
    ConflictStateError,
    PermissionDenied,
    ValidationError,
)
from tests.support import build_world, add_family, grant_verified, open_with_document


class ConfirmationTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock, self.ids = build_world()
        add_family(self.svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        self.g = grant_verified(
            self.svc, "p1", "spouse", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        self.matter, self.doc = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "穿刺同意", "K1",
        )
        self.svc.record_attempt(
            "staff1", self.matter.id, self.g.id, "phone",
            DeliveryOutcome.DELIVERED.value,
            minimal_summary="拟行穿刺", fields=["procedure"],
        )

    def test_confirmation_binds_document_hash_and_time(self):
        result = self.svc.record_confirmation(
            "staff1", self.matter.id, self.g.id, "consent",
            "callback_verified_phone", "回拨号码尾号 1234",
        )
        c = result["confirmation"]
        self.assertEqual(c.document_sha256, self.doc.sha256)
        self.assertEqual(c.document_version, 1)
        self.assertEqual(c.signed_at, self.clock.now().isoformat())
        self.assertEqual(len(c.binding_hash), 64)

    def test_cannot_confirm_without_delivery(self):
        matter2, _ = open_with_document(
            self.svc, MatterType.EXAM_CONSENT.value, "另一项同意", "K2",
        )
        with self.assertRaises(ConflictStateError):
            self.svc.record_confirmation(
                "staff1", matter2.id, self.g.id, "consent",
                "callback_verified_phone", "ev",
            )

    def test_identity_evidence_required(self):
        with self.assertRaises(ValidationError):
            self.svc.record_confirmation(
                "staff1", self.matter.id, self.g.id, "consent",
                "callback_verified_phone", "   ",
            )

    def test_unknown_identity_method_rejected(self):
        with self.assertRaises(ValidationError):
            self.svc.record_confirmation(
                "staff1", self.matter.id, self.g.id, "consent",
                "verbal_claim", "ev",
            )

    def test_notice_only_accepts_acknowledged(self):
        matter, _ = open_with_document(
            self.svc, MatterType.CRITICAL_NOTICE.value, "病危通知", "KN",
            kind="critical_notice",
        )
        self.svc.record_attempt(
            "staff1", matter.id, self.g.id, "sms",
            DeliveryOutcome.DELIVERED.value,
            minimal_summary="危重", fields=["current_severity"],
        )
        with self.assertRaises(ValidationError):
            self.svc.record_confirmation(
                "staff1", matter.id, self.g.id, "consent",
                "callback_verified_phone", "ev",
            )
        result = self.svc.record_confirmation(
            "staff1", matter.id, self.g.id, "acknowledged",
            "callback_verified_phone", "ev",
        )
        self.assertEqual(result["confirmation"].stance, "acknowledged")

    def test_same_stance_same_version_is_idempotent(self):
        r1 = self.svc.record_confirmation(
            "staff1", self.matter.id, self.g.id, "consent",
            "callback_verified_phone", "ev1",
        )
        r2 = self.svc.record_confirmation(
            "staff1", self.matter.id, self.g.id, "consent",
            "callback_verified_phone", "ev2",
        )
        self.assertFalse(r1["idempotent"])
        self.assertTrue(r2["idempotent"])
        self.assertEqual(r1["confirmation"].id, r2["confirmation"].id)

    def test_family_self_service_requires_secure_link(self):
        with self.assertRaises(PermissionDenied):
            self.svc.record_confirmation(
                "spouse", self.matter.id, self.g.id, "consent",
                "callback_verified_phone", "ev",
            )
        result = self.svc.record_confirmation(
            "spouse", self.matter.id, self.g.id, "consent",
            "secure_link_token", "token-abc",
        )
        self.assertTrue(result["confirmation"].id)

    def test_family_cannot_confirm_for_other_grant(self):
        add_family(self.svc, "child", "子女",
                   relation=Relation.ADULT_CHILD.value)
        g2 = grant_verified(
            self.svc, "p1", "child", Basis.LEGAL.value,
            relation=Relation.ADULT_CHILD.value,
        )
        with self.assertRaises(PermissionDenied):
            self.svc.record_confirmation(
                "spouse", self.matter.id, g2.id, "consent",
                "secure_link_token", "t",
            )


class VersionSupersedeTest(unittest.TestCase):
    def test_new_version_supersedes_confirmation_and_reopens(self):
        svc, clock, ids = build_world()
        add_family(svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        g = grant_verified(svc, "p1", "spouse", Basis.LEGAL.value,
                           relation=Relation.SPOUSE.value)
        matter, doc1 = open_with_document(
            svc, MatterType.EXAM_CONSENT.value, "同意", "K1",
        )
        svc.record_attempt(
            "staff1", matter.id, g.id, "phone",
            DeliveryOutcome.DELIVERED.value, minimal_summary="v1",
            fields=["procedure"],
        )
        svc.record_confirmation(
            "staff1", matter.id, g.id, "consent",
            "callback_verified_phone", "ev",
        )
        svc.resolve_matter("att1", matter.id)
        self.assertEqual(svc.get_matter(matter.id).status,
                         MatterStatus.RESOLVED.value)

        doc2 = svc.publish_document("att1", matter.id, "consent_form",
                                    "同意书 v2", "更新后的内容")
        self.assertEqual(doc2.version, 2)
        self.assertEqual(doc2.supersedes, doc1.id)
        c = [c for c in svc.confirmations.values() if c.matter_id == matter.id][0]
        self.assertEqual(c.status, "superseded")
        self.assertIsNotNone(c.superseded_at)
        self.assertEqual(svc.get_matter(matter.id).status,
                         MatterStatus.OPEN.value)
        # 旧版本 hash 不能再确认
        with self.assertRaises(ConflictStateError):
            svc.record_confirmation(
                "staff1", matter.id, g.id, "consent",
                "callback_verified_phone", "ev",
            )
        # 新版本重新送达后才能确认，且确认绑定 v2 摘要
        svc.record_attempt(
            "staff1", matter.id, g.id, "phone",
            DeliveryOutcome.DELIVERED.value, minimal_summary="v2",
            fields=["procedure"],
        )
        r = svc.record_confirmation(
            "staff1", matter.id, g.id, "consent",
            "callback_verified_phone", "ev2",
        )
        self.assertEqual(r["confirmation"].document_sha256, doc2.sha256)

    def test_documents_are_immutable(self):
        svc, _, _ = build_world()
        add_family(svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        g = grant_verified(svc, "p1", "spouse", Basis.LEGAL.value,
                           relation=Relation.SPOUSE.value)
        matter, doc1 = open_with_document(
            svc, MatterType.EXAM_CONSENT.value, "同意", "K1", content="原始内容",
        )
        # 再发同名文书产生新版本记录，v1 记录保持原样不可变
        doc_same = svc.publish_document(
            "att1", matter.id, "consent_form", "再次发布", "原始内容",
        )
        self.assertNotEqual(doc_same.id, doc1.id)
        self.assertEqual(svc.documents[doc1.id].content, "原始内容")


if __name__ == "__main__":
    unittest.main()
