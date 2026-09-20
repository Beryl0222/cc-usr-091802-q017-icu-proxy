"""审计哈希链、事后复盘回放与家属隐私视图。"""

import unittest

from icuproxy import (
    Basis,
    DeliveryOutcome,
    MatterType,
    Relation,
)
from icuproxy.audit import AuditIntegrityError, GENESIS_HASH
from icuproxy.errors import NotFoundError, PermissionDenied
from tests.support import build_world, add_family, grant_verified, open_with_document


def build_conflicted_case():
    svc, clock, ids = build_world()
    add_family(svc, "desig", "指定人姓名A")
    add_family(svc, "spouse", "配偶姓名B", relation=Relation.SPOUSE.value,
               phone="SECRET-5566")
    add_family(svc, "child", "子女姓名C", relation=Relation.ADULT_CHILD.value,
               phone="SECRET-7788")
    gd = grant_verified(svc, "p1", "desig", Basis.PATIENT_DESIGNATED.value)
    gs = grant_verified(svc, "p1", "spouse", Basis.LEGAL.value,
                        relation=Relation.SPOUSE.value)
    gc = grant_verified(svc, "p1", "child", Basis.LEGAL.value,
                        relation=Relation.ADULT_CHILD.value)
    matter, doc1 = open_with_document(svc, MatterType.EXAM_CONSENT.value,
                                      "同意", "KAUDIT")
    svc.record_attempt("staff1", matter.id, gd.id, "phone",
                       DeliveryOutcome.UNREACHABLE.value, detail="无人接")
    svc.record_attempt("staff1", matter.id, gs.id, "phone",
                       DeliveryOutcome.DELIVERED.value,
                       minimal_summary="v1 摘要", fields=["procedure"])
    svc.record_confirmation("staff1", matter.id, gs.id, "consent",
                            "callback_verified_phone", "配偶证据SECRET")
    # 新版本：指定人再次失联 → 配偶拒、子女同意 → 冲突
    doc2 = svc.publish_document("att1", matter.id, "consent_form",
                                "同意书v2", "更新内容")
    svc.record_attempt("staff1", matter.id, gd.id, "phone",
                       DeliveryOutcome.UNREACHABLE.value, detail="仍无人接")
    svc.record_attempt("staff1", matter.id, gs.id, "phone",
                       DeliveryOutcome.DELIVERED.value,
                       minimal_summary="v2 摘要", fields=["procedure"])
    svc.record_confirmation("staff1", matter.id, gs.id, "refuse",
                            "callback_verified_phone", "配偶证据SECRET2")
    svc.record_attempt("staff1", matter.id, gc.id, "phone",
                       DeliveryOutcome.DELIVERED.value,
                       minimal_summary="v2 摘要", fields=["procedure"])
    result = svc.record_confirmation(
        "staff1", matter.id, gc.id, "consent",
        "callback_verified_phone", "子女本人证据",
    )
    return svc, clock, ids, matter, (gd, gs, gc), (doc1, doc2), result["conflict"]


class AuditChainTest(unittest.TestCase):
    def test_chain_links_to_genesis(self):
        svc, _, _ = build_world()
        svc.register_patient("staff1", "p2", "另一位", "M2")
        entries = svc.audit.entries
        self.assertEqual(entries[0].prev_hash, GENESIS_HASH)
        self.assertTrue(svc.audit.verify())

    def test_payload_tamper_detected(self):
        svc, _, _ = build_world()
        svc.register_patient("staff1", "p2", "另一位", "M2")
        svc.audit.entries[-1].payload["mrn"] = "篡改住院号"
        with self.assertRaises(AuditIntegrityError):
            svc.audit.verify()

    def test_entry_deletion_detected(self):
        svc, _, _ = build_world()
        svc.register_patient("staff1", "p2", "甲", "M2")
        svc.register_patient("staff1", "p3", "乙", "M3")
        del svc.audit._entries[0]
        with self.assertRaises(AuditIntegrityError):
            svc.audit.verify()

    def test_replay_runs_verify(self):
        svc, _, _, matter, _, _, _ = build_conflicted_case()
        replay = svc.replay("ma1", matter.id)
        self.assertTrue(replay["audit_verified"])
        # 篡改后复盘必须失败而不是给出"干净"报告
        svc.audit.entries[2].payload["tampered"] = True
        with self.assertRaises(AuditIntegrityError):
            svc.replay("ma1", matter.id)


class ReplayTest(unittest.TestCase):
    def test_replay_reconstructs_full_picture(self):
        svc, _, _, matter, grants, docs, conflict = build_conflicted_case()
        replay = svc.replay("eth1", matter.id)
        self.assertEqual(replay["matter"]["id"], matter.id)
        # 两个不可变版本与失效关系都在
        self.assertEqual([d["version"] for d in replay["documents"]], [1, 2])
        statuses = {c["id"]: c["status"] for c in replay["confirmations"]}
        self.assertIn("superseded", statuses.values())
        # 资格快照覆盖每次尝试与确认时点
        contexts = [s["context"] for s in replay["eligibility_snapshots"]]
        self.assertIn("attempt", contexts)
        self.assertIn("confirmation", contexts)
        # 快照能还原当时顺位：首个尝试时点 desig 在最前
        first = replay["eligibility_snapshots"][0]
        self.assertEqual(first["chain"][0]["basis"], "patient_designated")
        # 冲突复核单
        self.assertEqual(len(replay["referrals"]), 1)
        self.assertEqual(replay["referrals"][0]["id"], conflict.id)
        # 披露包冻结了不同版本摘要
        self.assertEqual(
            {d["document_sha256"] for d in replay["disclosures"]},
            {docs[0].sha256, docs[1].sha256},
        )

    def test_only_review_roles_may_replay(self):
        svc, _, _, matter, _, _, _ = build_conflicted_case()
        with self.assertRaises(PermissionDenied):
            svc.replay("spouse", matter.id)

    def test_replay_includes_exception_history(self):
        svc, clock, ids = build_world()
        matter, _ = open_with_document(
            svc, MatterType.TRANSFER_DECISION.value, "转院", "KEX",
            kind="transfer_proposal",
        )
        exc = svc.open_emergency_exception("att1", matter.id, "紧迫性说明")
        svc.provide_exception_basis("att1", exc.id, ["抢救记录.pdf"])
        svc.review_exception_basis("ma1", exc.id, "合规")
        replay = svc.replay("ma1", matter.id)
        self.assertEqual(len(replay["exceptions"]), 1)
        self.assertEqual(replay["exceptions"][0]["basis_documents"],
                         ["抢救记录.pdf"])


class FamilyViewTest(unittest.TestCase):
    def test_family_sees_only_own_records(self):
        svc, _, _, matter, _, _, _ = build_conflicted_case()
        view = svc.family_view("child", matter.id)
        blob = repr(view)
        for secret in ("spouse", "配偶姓名B", "SECRET-5566", "配偶证据SECRET",
                       "desig", "指定人姓名A"):
            self.assertNotIn(secret, blob)
        # 本人信息可见
        self.assertTrue(any(
            c["identity_evidence"] == "子女本人证据"
            for c in view["your_confirmations"]
        ))
        # 其他联系人只有脱敏计数
        self.assertGreaterEqual(
            view["other_contacts"]["total_attempts_masked"], 1
        )
        # 事项存在冲突时家属只知道"复核进行中"，不知道谁反对
        self.assertTrue(view["review_in_progress"])

    def test_unrelated_family_gets_not_found(self):
        svc, _, _ = build_world()
        add_family(svc, "outsider", "外人", relation=Relation.SIBLING.value)
        matter, _ = open_with_document(
            svc, MatterType.CRITICAL_NOTICE.value, "病危", "KX",
            kind="critical_notice",
        )
        with self.assertRaises(NotFoundError):
            svc.family_view("outsider", matter.id)

    def test_staff_cannot_use_family_view(self):
        svc, _, _, matter, _, _, _ = build_conflicted_case()
        with self.assertRaises(PermissionDenied):
            svc.family_view("staff1", matter.id)


if __name__ == "__main__":
    unittest.main()
