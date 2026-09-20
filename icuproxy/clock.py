"""可注入的时间源，便于跨午夜交班等场景测试。"""

import abc
from datetime import datetime, timezone


class Clock(abc.ABC):
    @abc.abstractmethod
    def now(self) -> datetime:
        """返回带时区的当前时间。"""

    def iso(self) -> str:
        return self.now().isoformat()


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FrozenClock(Clock):
    """固定时间，测试中可手动推进。"""

    def __init__(self, at: datetime | None = None):
        if at is None:
            at = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        self._at = at

    @property
    def now_value(self) -> datetime:
        return self._at

    def now(self) -> datetime:
        return self._at

    def advance(self, **delta) -> datetime:
        from datetime import timedelta

        self._at = self._at + timedelta(**delta)
        return self._at

    def set(self, at: datetime) -> None:
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        self._at = at
