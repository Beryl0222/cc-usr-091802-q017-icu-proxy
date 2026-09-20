"""序列化与摘要工具。"""

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """确定性 JSON：键排序、紧凑分隔、非 ASCII 原样保留。"""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_obj(obj: Any) -> str:
    return sha256_text(canonical_json(obj))
