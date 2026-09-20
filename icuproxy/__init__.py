"""重症紧急代理协作服务。

软件只维护资格、送达、确认、复核与例外的**记录**，
不替代医生作出任何医疗决定（见 EmergencyException 与 README）。
"""

from .enums import (
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
    DomainError,
    NotFoundError,
    PermissionDenied,
    StaleVersionError,
    ValidationError,
)
from .clock import Clock, SystemClock, FrozenClock
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
from .audit import AuditEntry, AuditLog
from .service import ICUProxyService

__all__ = [
    "ActorRole",
    "Basis",
    "ConfirmationStance",
    "DeliveryOutcome",
    "DocumentKind",
    "MatterStatus",
    "MatterType",
    "ReferralStatus",
    "Relation",
    "ReviewBody",
    "TerminationReason",
    "VerificationStatus",
    "ConflictStateError",
    "DomainError",
    "NotFoundError",
    "PermissionDenied",
    "StaleVersionError",
    "ValidationError",
    "Clock",
    "SystemClock",
    "FrozenClock",
    "Actor",
    "Confirmation",
    "ContactGrant",
    "DeliveryAttempt",
    "DisclosurePacket",
    "DocumentVersion",
    "EmergencyException",
    "Matter",
    "Patient",
    "Referral",
    "TerminationEvent",
    "AuditEntry",
    "AuditLog",
    "ICUProxyService",
]
