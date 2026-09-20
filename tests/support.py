"""测试公共夹具：搭建一套基础人员与可注入时钟。"""

from icuproxy import (
    ActorRole,
    FrozenClock,
    ICUProxyService,
    Relation,
)
from icuproxy.models import Actor


def build_world(at=None):
    """返回 (service, clock, ids)，已含四名院内角色和一名患者。"""
    clock = FrozenClock(at)
    svc = ICUProxyService(clock)
    svc.actors["staff1"] = Actor(
        id="staff1", name="值班护士甲", role=ActorRole.STAFF.value, phone="8001"
    )
    svc.actors["att1"] = Actor(
        id="att1", name="主治医生乙", role=ActorRole.ATTENDING.value, phone="8002"
    )
    svc.actors["ma1"] = Actor(
        id="ma1", name="医务处丙", role=ActorRole.MEDICAL_AFFAIRS.value, phone="8003"
    )
    svc.actors["eth1"] = Actor(
        id="eth1", name="伦理委员丁", role=ActorRole.ETHICS.value
    )
    svc.register_patient("staff1", "p1", "住院患者戊", "MRN-0001")
    ids = {
        "staff": "staff1",
        "attending": "att1",
        "medical_affairs": "ma1",
        "ethics": "eth1",
        "patient": "p1",
    }
    return svc, clock, ids


def add_family(svc, actor_id, name, relation=Relation.SPOUSE.value, phone=None):
    return svc.register_actor(
        "staff1", actor_id, name, ActorRole.FAMILY.value,
        relation=relation, phone=phone or f"phone-{actor_id}",
    )


def grant_verified(svc, patient_id, actor_id, basis, requester="staff1",
                   verifier="ma1", **kwargs):
    grant = svc.create_grant(requester, patient_id, actor_id, basis, **kwargs)
    svc.verify_grant(verifier, grant.id, True)
    return grant


def open_with_document(svc, matter_type, title, key, content="文书正文",
                       patient_id="p1", opener="staff1", publisher="att1",
                       kind="consent_form"):
    matter = svc.open_matter(opener, patient_id, matter_type, title, key)
    doc = svc.publish_document(publisher, matter.id, kind, title, content)
    return matter, doc
