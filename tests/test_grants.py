"""代理资格：三重依据、顺位、有效期、终止。"""

import unittest
from datetime import datetime, timezone, timedelta

from icuproxy import (
    ActorRole,
    Basis,
    FrozenClock,
    ICUProxyService,
    MatterType,
    Relation,
    TerminationReason,
    VerificationStatus,
)
from icuproxy.errors import ConflictStateError, PermissionDenied, ValidationError
from icuproxy.models import Actor
from tests.support import build_world, add_family, grant_verified, open_with_document


class GrantBasicsTest(unittest.TestCase):
    def test_hospital_verified_cannot_stand_alone(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SIBLING.value)
        with self.assertRaises(ValidationError):
            svc.create_grant(
                ids["staff"], ids["patient"], "f1",
                Basis.HOSPITAL_VERIFIED.value,
            )

    def test_unverified_grant_is_not_effective(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        svc.create_grant(
            ids["staff"], ids["patient"], "f1", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        self.assertEqual(
            svc.effective_grants(ids["patient"], MatterType.EXAM_CONSENT.value), []
        )

    def test_rejected_verification_blocks_effectiveness(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        g = svc.create_grant(
            ids["staff"], ids["patient"], "f1", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        svc.verify_grant(ids["medical_affairs"], g.id, False, "证件不符")
        self.assertEqual(g.verification_status, VerificationStatus.REJECTED.value)
        self.assertEqual(
            svc.effective_grants(ids["patient"], MatterType.EXAM_CONSENT.value), []
        )

    def test_staff_cannot_verify_only_medical_affairs(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        g = svc.create_grant(
            ids["staff"], ids["patient"], "f1", Basis.LEGAL.value,
            relation=Relation.SPOUSE.value,
        )
        with self.assertRaises(PermissionDenied):
            svc.verify_grant(ids["staff"], g.id, True)

    def test_legal_relation_mismatch_rejected(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        with self.assertRaises(ValidationError):
            svc.create_grant(
                ids["staff"], ids["patient"], "f1", Basis.LEGAL.value,
                relation=Relation.PARENT.value,
            )


class RankOrderTest(unittest.TestCase):
    def test_designated_outranks_legal(self):
        svc, _, ids = build_world()
        add_family(svc, "spouse", "配偶", relation=Relation.SPOUSE.value)
        add_family(svc, "desig", "指定人")
        gs = grant_verified(svc, "p1", "spouse", Basis.LEGAL.value,
                            relation=Relation.SPOUSE.value)
        gd = grant_verified(svc, "p1", "desig", Basis.PATIENT_DESIGNATED.value)
        chain = svc.effective_grants("p1", MatterType.TRANSFER_DECISION.value)
        self.assertEqual([g.actor_id for g in chain], ["desig", "spouse"])

    def test_legal_order_guardian_spouse_child_parent_sibling(self):
        svc, _, ids = build_world()
        folks = [
            ("f_s", Relation.SPOUSE.value),
            ("f_g", Relation.GUARDIAN.value),
            ("f_c", Relation.ADULT_CHILD.value),
            ("f_p", Relation.PARENT.value),
            ("f_b", Relation.SIBLING.value),
        ]
        for aid, rel in folks:
            add_family(svc, aid, aid, relation=rel)
            g = svc.create_grant("staff1", "p1", aid, Basis.LEGAL.value,
                                 relation=rel)
            svc.verify_grant("ma1", g.id, True)
        chain = svc.effective_grants("p1", MatterType.CRITICAL_NOTICE.value)
        self.assertEqual(
            [g.actor_id for g in chain],
            ["f_g", "f_s", "f_c", "f_p", "f_b"],
        )

    def test_designated_order_follows_registration_sequence(self):
        svc, _, ids = build_world()
        add_family(svc, "d1", "甲")
        add_family(svc, "d2", "乙")
        grant_verified(svc, "p1", "d2", Basis.PATIENT_DESIGNATED.value)
        # 单条时 rank 默认为 1
        g1 = svc.effective_grants("p1", MatterType.EXAM_CONSENT.value)[0]
        self.assertEqual(g1.actor_id, "d2")
        grant_verified(svc, "p1", "d1", Basis.PATIENT_DESIGNATED.value)
        chain = svc.effective_grants("p1", MatterType.EXAM_CONSENT.value)
        self.assertEqual([g.actor_id for g in chain], ["d2", "d1"])


class ValidityWindowTest(unittest.TestCase):
    def test_future_grant_not_yet_effective(self):
        svc, clock, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        future = (clock.now() + timedelta(days=1)).isoformat()
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value, valid_from=future)
        self.assertEqual(
            svc.effective_grants("p1", MatterType.EXAM_CONSENT.value), []
        )
        clock.advance(days=2)
        self.assertEqual(
            [g.actor_id for g in svc.effective_grants("p1", MatterType.EXAM_CONSENT.value)],
            ["f1"],
        )

    def test_expired_grant_drops_out(self):
        svc, clock, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        valid_to = (clock.now() + timedelta(hours=12)).isoformat()
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value, valid_to=valid_to)
        self.assertEqual(
            [g.actor_id for g in svc.effective_grants("p1", MatterType.EXAM_CONSENT.value)],
            ["f1"],
        )
        clock.advance(hours=13)
        self.assertEqual(
            svc.effective_grants("p1", MatterType.EXAM_CONSENT.value), []
        )

    def test_matters_scoping(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value,
                       matters=[MatterType.CRITICAL_NOTICE.value])
        self.assertEqual(
            [g.actor_id for g in svc.effective_grants("p1", MatterType.CRITICAL_NOTICE.value)],
            ["f1"],
        )
        self.assertEqual(
            svc.effective_grants("p1", MatterType.EXAM_CONSENT.value), []
        )

    def test_invalid_window_rejected(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        with self.assertRaises(ValidationError):
            svc.create_grant(
                "staff1", "p1", "f1", Basis.LEGAL.value,
                relation=Relation.SPOUSE.value,
                valid_from="2026-09-20T10:00:00+00:00",
                valid_to="2026-09-20T09:00:00+00:00",
            )


class TerminationTest(unittest.TestCase):
    def test_patient_wide_termination_ends_all_grants(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        add_family(svc, "f2", "乙")
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value)
        grant_verified(svc, "p1", "f2", Basis.PATIENT_DESIGNATED.value)
        svc.terminate_proxy(
            "staff1", "p1", TerminationReason.PROXY_REVOKED.value,
            note="患者撤销全部代理",
        )
        self.assertEqual(
            svc.effective_grants("p1", MatterType.EXAM_CONSENT.value), []
        )

    def test_targeted_revocation_requires_grant(self):
        svc, _, ids = build_world()
        with self.assertRaises(ValidationError):
            svc.terminate_proxy(
                "staff1", "p1", TerminationReason.CONTACT_REVOKED.value,
            )

    def test_targeted_revocation_only_affects_one(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        add_family(svc, "f2", "乙")
        g1 = grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                            relation=Relation.SPOUSE.value)
        grant_verified(svc, "p1", "f2", Basis.PATIENT_DESIGNATED.value)
        svc.terminate_proxy(
            "staff1", "p1", TerminationReason.CONTACT_REVOKED.value,
            grant_id=g1.id, note="配偶资格定向撤销",
        )
        chain = svc.effective_grants("p1", MatterType.EXAM_CONSENT.value)
        self.assertEqual([g.actor_id for g in chain], ["f2"])

    def test_open_matter_without_live_record_closes_on_termination(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value)
        matter, _ = open_with_document(
            svc, MatterType.CRITICAL_NOTICE.value, "病危", "K", kind="critical_notice",
        )
        svc.terminate_proxy("staff1", "p1", TerminationReason.DISCHARGED.value)
        self.assertEqual(svc.get_matter(matter.id).status, "closed")

    def test_open_matter_with_delivery_keeps_record_for_audit(self):
        from tests.support import open_with_document
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        g1 = grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                            relation=Relation.SPOUSE.value)
        matter, _ = open_with_document(
            svc, MatterType.CRITICAL_NOTICE.value, "病危", "K",
            kind="critical_notice",
        )
        svc.record_attempt(
            "staff1", matter.id, g1.id, "phone", "delivered",
            minimal_summary="危重", fields=["current_severity"],
        )
        svc.terminate_proxy("staff1", "p1", TerminationReason.TRANSFERRED.value)
        # 有送达记录的事项不被自动关闭，交付凭证保留可审
        self.assertNotEqual(svc.get_matter(matter.id).status, "closed")

    def test_all_patient_wide_reasons_terminate(self):
        svc, _, ids = build_world()
        add_family(svc, "f1", "甲", relation=Relation.SPOUSE.value)
        grant_verified(svc, "p1", "f1", Basis.LEGAL.value,
                       relation=Relation.SPOUSE.value)
        for reason in ("transferred", "regained_capacity",
                       "proxy_revoked", "discharged"):
            # 每次重建一份有效资格
            g = svc.create_grant("staff1", "p1", "f1", Basis.LEGAL.value,
                                 relation=Relation.SPOUSE.value)
            svc.verify_grant("ma1", g.id, True)
            svc.terminate_proxy("staff1", "p1", reason)
            self.assertEqual(
                svc.effective_grants("p1", MatterType.EXAM_CONSENT.value), [],
                reason,
            )


if __name__ == "__main__":
    unittest.main()
