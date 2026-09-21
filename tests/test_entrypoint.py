"""让标准库测试发现器执行项目根目录的契约测试。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_service import (  # noqa: E402
    AuditChainTest,
    AuthorityAndOrderingTest,
    ConfirmationVersioningTest,
    ConflictAndReviewTest,
    DisclosureTest,
    DossierAndPrivacyTest,
    EmergencyExceptionTest,
    EscalationTest,
    FixtureTest,
    IdempotencyTest,
    PermissionTest,
    RpcAndHttpTest,
    TerminationTest,
)

__all__ = [
    "AuditChainTest",
    "AuthorityAndOrderingTest",
    "ConfirmationVersioningTest",
    "ConflictAndReviewTest",
    "DisclosureTest",
    "DossierAndPrivacyTest",
    "EmergencyExceptionTest",
    "EscalationTest",
    "FixtureTest",
    "IdempotencyTest",
    "PermissionTest",
    "RpcAndHttpTest",
    "TerminationTest",
]
