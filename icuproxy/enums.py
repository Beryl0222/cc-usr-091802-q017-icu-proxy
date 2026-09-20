"""领域枚举。"""

import enum


class ActorRole(str, enum.Enum):
    """系统内操作者角色。"""

    STAFF = "staff"                    # ICU 值班医护（受权发起通知/记录送达）
    ATTENDING = "attending"            # 主治及以上（可开立抢救例外）
    MEDICAL_AFFAIRS = "medical_affairs"  # 医务处（核验、复核、升级终点）
    ETHICS = "ethics"                  # 伦理委员会
    ADMIN_REVIEWER = "admin_reviewer"  # 事后审查人员（只读复盘）
    FAMILY = "family"                  # 联系人/家属（受限视图）


# 可开立抢救例外的角色（事后须补齐依据）
EXCEPTION_AUTHORITIES = frozenset({ActorRole.ATTENDING, ActorRole.MEDICAL_AFFAIRS})
# 可查看完整复盘的角色
REVIEW_ROLES = frozenset(
    {ActorRole.MEDICAL_AFFAIRS, ActorRole.ETHICS, ActorRole.ADMIN_REVIEWER,
     ActorRole.ATTENDING}
)
# 可执行院方核验的角色
VERIFICATION_ROLES = frozenset({ActorRole.MEDICAL_AFFAIRS})


class MatterType(str, enum.Enum):
    """需要联系人家属代理的事项类别。"""

    CRITICAL_NOTICE = "critical_notice"      # 病危通知
    EXAM_CONSENT = "exam_consent"            # 检查/治疗同意
    TRANSFER_DECISION = "transfer_decision"  # 转院决定


class Basis(str, enum.Enum):
    """联系人顺位的三重依据。"""

    PATIENT_DESIGNATED = "patient_designated"  # 患者预先指定（最高优先）
    LEGAL = "legal"                            # 法定关系
    HOSPITAL_VERIFIED = "hospital_verified"    # 院方核验（生效闸门，不单独产生资格）


class Relation(str, enum.Enum):
    """法定关系（仅在 basis=LEGAL 时有意义），值即法定顺位（小者优先）。"""

    SPOUSE = "spouse"            # 配偶
    ADULT_CHILD = "adult_child"  # 成年子女
    PARENT = "parent"            # 父母
    SIBLING = "sibling"          # 其他近亲属
    GUARDIAN = "guardian"        # 法定监护人（顺位高于近亲属）


# 法定关系的默认顺位（监护人最优先，其后按近亲属顺序）
LEGAL_PRIORITY = {
    Relation.GUARDIAN: 0,
    Relation.SPOUSE: 10,
    Relation.ADULT_CHILD: 20,
    Relation.PARENT: 30,
    Relation.SIBLING: 40,
}

# 预先指定者在混合排序中的整体优先带
DESIGNATED_BAND = 0
LEGAL_BAND = 100


class VerificationStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"  # 证明材料不合格，资格不生效


class DeliveryOutcome(str, enum.Enum):
    DELIVERED = "delivered"    # 已送达（对方确认知悉）
    REFUSED = "refused"        # 明确拒收
    UNREACHABLE = "unreachable"  # 失联（无人接听/无应答/号码失效等）
    DISPATCHED = "dispatched"  # 已发出，尚未得到结果（中间态）


class ConfirmationStance(str, enum.Enum):
    """联系人对事项的立场。"""

    CONSENT = "consent"
    REFUSE = "refuse"
    ACKNOWLEDGED = "acknowledged"  # 病危通知类事项仅需知悉确认


# 每种事项允许的立场
STANCES_BY_MATTER = {
    MatterType.CRITICAL_NOTICE: frozenset({ConfirmationStance.ACKNOWLEDGED}),
    MatterType.EXAM_CONSENT: frozenset({ConfirmationStance.CONSENT, ConfirmationStance.REFUSE}),
    MatterType.TRANSFER_DECISION: frozenset(
        {ConfirmationStance.CONSENT, ConfirmationStance.REFUSE}
    ),
}


class MatterStatus(str, enum.Enum):
    OPEN = "open"                    # 通知/确认进行中
    CONFLICT = "conflict"            # 有效联系人意见相反，待复核
    RESOLVED = "resolved"            # 已形成有效确认（可能经复核）
    ESCALATED = "escalated"          # 全部联系人失联，升级医务处
    EXCEPTION_USED = "exception_used"  # 以抢救例外处置
    CLOSED = "closed"                # 因权限终止等原因关闭


class DocumentKind(str, enum.Enum):
    SUMMARY_SHEET = "summary_sheet"    # 病情摘要
    CONSENT_FORM = "consent_form"      # 同意书
    TRANSFER_PROPOSAL = "transfer_proposal"
    CRITICAL_NOTICE = "critical_notice"


class ReferralStatus(str, enum.Enum):
    OPEN = "open"
    CONCLUDED = "concluded"  # 伦理/医务复核已给出结论


class ReviewBody(str, enum.Enum):
    ETHICS = "ethics"
    MEDICAL_AFFAIRS = "medical_affairs"


class TerminationReason(str, enum.Enum):
    """代理权限终止原因。"""

    TRANSFERRED = "transferred"        # 患者转院
    REGAINED_CAPACITY = "regained_capacity"  # 恢复意识/决定能力
    PROXY_REVOKED = "proxy_revoked"    # 患者撤销代理/授权
    DISCHARGED = "discharged"          # 离院
    EXPIRED = "expired"                # 授权到期
    CONTACT_REVOKED = "contact_revoked"  # 单个联系人被撤销（可定向）


# 作用于整名患者全部代理权限的终止原因
PATIENT_WIDE_REASONS = frozenset(
    {
        TerminationReason.TRANSFERRED,
        TerminationReason.REGAINED_CAPACITY,
        TerminationReason.PROXY_REVOKED,
        TerminationReason.DISCHARGED,
    }
)
