from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any


NAMESPACE = uuid.UUID("03cb1fa5-58e6-4483-9e8e-5f5fc7d79da8")


def stable_id(*parts: object) -> str:
    return str(uuid.uuid5(NAMESPACE, ":".join(str(p) for p in parts)))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def evidence_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def json_load(raw: str | bytes | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}
