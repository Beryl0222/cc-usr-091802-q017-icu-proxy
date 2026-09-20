"""哈希链审计日志。

每条记录保存前一条记录的摘要，任何篡改、删除、重排都会在 verify() 暴露。
复盘时以本日志为准，重放当时的资格、披露、尝试、版本与例外。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .crypto import canonical_json, sha256_text

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    at: str
    event_type: str
    actor_id: str
    subject: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "subject": self.subject,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class AuditIntegrityError(RuntimeError):
    """哈希链校验失败。"""

    def __init__(self, seq: int, reason: str):
        super().__init__(f"审计链在第 {seq} 条记录处校验失败：{reason}")
        self.seq = seq
        self.reason = reason


class AuditLog:
    def __init__(self):
        self._entries: list[AuditEntry] = []

    # ---- 写入 -----------------------------------------------------------

    def append(
        self,
        event_type: str,
        actor_id: str,
        subject: str,
        payload: Optional[dict[str, Any]] = None,
        at: Optional[str] = None,
    ) -> AuditEntry:
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].hash if self._entries else GENESIS_HASH
        entry = AuditEntry(
            seq=seq,
            at=at or "",
            event_type=event_type,
            actor_id=actor_id,
            subject=subject,
            payload=dict(payload or {}),
            prev_hash=prev_hash,
            hash="",
        )
        entry.hash = self._digest(entry)
        self._entries.append(entry)
        return entry

    @staticmethod
    def _digest(entry: AuditEntry) -> str:
        material = "|".join(
            [
                str(entry.seq),
                entry.at,
                entry.event_type,
                entry.actor_id,
                entry.subject,
                canonical_json(entry.payload),
                entry.prev_hash,
            ]
        )
        return sha256_text(material)

    # ---- 读取 -----------------------------------------------------------

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def export(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries]

    def for_subject(self, subject: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.subject == subject]

    def events_of_type(self, event_type: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.event_type == event_type]

    # ---- 校验 -----------------------------------------------------------

    def verify(self) -> bool:
        """完整重算哈希链；失败抛出 AuditIntegrityError。"""
        prev = GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.seq != i + 1:
                raise AuditIntegrityError(entry.seq, "序号不连续")
            if entry.prev_hash != prev:
                raise AuditIntegrityError(entry.seq, "前链摘要不匹配")
            if self._digest(entry) != entry.hash:
                raise AuditIntegrityError(entry.seq, "记录摘要不匹配（内容可能被篡改）")
            prev = entry.hash
        return True

    def __len__(self) -> int:
        return len(self._entries)
