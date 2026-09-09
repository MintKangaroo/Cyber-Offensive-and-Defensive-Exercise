"""Lossless source authoring alongside the existing scenario engine.

Source text is never dumped through a model: comments, extra fields and multiple
YAML documents survive. Validation uses the actual runtime loader before publish.
"""

from __future__ import annotations
import hashlib
import json
import time
import os
import re
import threading
from pathlib import Path

import yaml
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError
from shared.rbac import require_role
from .loader import _load_doc
from .authoring import dry_run


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in keys:
                    raise yaml.YAMLError("Duplicate YAML key")
                keys.add(key)
            except TypeError as exc:
                raise yaml.YAMLError("Mapping keys must be scalar") from exc
        return super().construct_mapping(node, deep=deep)


router = APIRouter(prefix="/studio", tags=["Scenario Studio"])
_publish_lock = threading.Lock()


def authored_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "/tmp/cyber-range-scenario")) / "authored"


def documents(text: str) -> list[dict]:
    try:
        docs = list(yaml.load_all(text, Loader=UniqueLoader))
    except (yaml.YAMLError, RecursionError) as exc:
        raise HTTPException(400, "Invalid YAML syntax") from exc
    if not docs or any(not isinstance(d, dict) for d in docs):
        raise HTTPException(400, "Every YAML document must be a scenario mapping")
    if len(docs) > 50:
        raise HTTPException(400, "At most 50 scenario documents per source")
    return docs


def validate(text: str) -> dict:
    reports = []
    seen = set()
    for doc in documents(text):
        raw = doc.get("scenario") or doc.get("crossover_scenario")
        if not isinstance(raw, dict):
            raise HTTPException(400, "Expected scenario or crossover_scenario root")
        issues = []
        try:
            _load_doc(doc)
        except (
            ValidationError,
            TypeError,
            ValueError,
            AttributeError,
            RecursionError,
        ) as exc:
            issues.append(
                {
                    "level": "error",
                    "code": "schema",
                    "message": str(exc)[:2000],
                    "where": "document",
                }
            )
        sid = raw.get("id", "")
        if not isinstance(sid, str) or not re.fullmatch(r"[\w.-]{1,120}", sid):
            raise HTTPException(400, "Scenario ID must be a nonempty safe identifier")
        if sid in seen:
            issues.append(
                {
                    "level": "error",
                    "code": "duplicate_id",
                    "message": "Duplicate scenario ID",
                    "where": "id",
                }
            )
        seen.add(sid)
        phases = {
            k: v
            for k, v in raw.items()
            if isinstance(k, str) and k.startswith("phase_") and isinstance(v, dict)
        }
        order = sorted(
            phases,
            key=lambda k: int(k.split("_")[1]) if k.split("_")[1].isdigit() else 999,
        )
        for name, phase in phases.items():
            dependency = phase.get("locked_until")
            if dependency:
                parent = str(dependency).removesuffix(".completed")
                if parent not in phases or order.index(parent) >= order.index(name):
                    issues.append(
                        {
                            "level": "error",
                            "code": "phase_dependency",
                            "message": "Phase dependency must refer to a previous existing phase",
                            "where": name,
                        }
                    )
        try:
            report = dry_run(raw)
        except (TypeError, ValueError, AttributeError, RecursionError):
            report = {
                "ok": False,
                "issues": [],
                "timeline": [],
                "total_points": None,
                "stage_count": 0,
                "time_limit_sec": None,
            }
            issues.append(
                {
                    "level": "error",
                    "code": "invalid_values",
                    "message": "Stage durations, points and dependencies must have valid types",
                    "where": "stages",
                }
            )
        for stage in (
            raw.get("stages", []) if isinstance(raw.get("stages", []), list) else []
        ):
            if (
                isinstance(stage, dict)
                and "expected_sec" in stage
                and (
                    not isinstance(stage["expected_sec"], (int, float))
                    or stage["expected_sec"] < 0
                )
            ):
                issues.append(
                    {
                        "level": "error",
                        "code": "negative_duration",
                        "message": "Duration must be nonnegative",
                        "where": str(stage.get("stage")),
                    }
                )
        report["issues"] += issues
        report["ok"] = not any(i["level"] == "error" for i in report["issues"])
        report["scenario_id"] = sid
        reports.append(report)
    return {
        "ok": all(r["ok"] for r in reports),
        "documents": reports,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


class SourceRequest(BaseModel):
    yaml: str = Field(min_length=1, max_length=250000)


class PublishRequest(SourceRequest):
    reason: str = Field(min_length=3, max_length=2000)
    expected_sha256: str = ""
    confirm: bool = False


def sources():
    from . import api

    paths = sorted(Path(api.SCENARIOS_DIR).rglob("*.yaml")) + sorted(
        authored_dir().glob("*.yaml")
    )
    result = {}
    for path in paths:
        try:
            text = path.read_text()
            for doc in documents(text):
                raw = doc.get("scenario") or doc.get("crossover_scenario") or {}
                if raw.get("id"):
                    result[raw["id"]] = (path, text)
        except (OSError, HTTPException):
            continue
    return result


@router.get("/source/{sid}")
def get_source(sid: str, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"}, allow_dev=False)
    item = sources().get(sid)
    if not item:
        raise HTTPException(404, "Scenario not found")
    _, text = item
    return {
        "scenario_id": sid,
        "yaml": text,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


@router.post("/validate")
def validate_source(req: SourceRequest, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"}, allow_dev=False)
    return validate(req.yaml)


@router.post("/publish/{sid}")
def publish(sid: str, req: PublishRequest, authorization: str = Header(default="")):
    identity = require_role(authorization, {"instructor"}, allow_dev=False)
    if not req.confirm or len(req.reason.strip()) < 3:
        raise HTTPException(400, "Confirmation and reason required")
    if not re.fullmatch(r"[\w.-]{1,120}", sid):
        raise HTTPException(400, "Invalid scenario ID")
    report = validate(req.yaml)
    if not report["ok"]:
        raise HTTPException(
            422, detail="Scenario validation failed; inspect the validation report"
        )
    ids = [r["scenario_id"] for r in report["documents"]]
    if sid not in ids:
        raise HTTPException(400, "Published ID must exist in the source")
    from . import api

    with _publish_lock:
        old = sources().get(sid)
        checksum = hashlib.sha256(old[1].encode()).hexdigest() if old else ""
        if checksum != req.expected_sha256:
            raise HTTPException(409, "Source changed; reload before publishing")
        if any(key in api._active_trackers for key in ids):
            raise HTTPException(409, "End active scenarios before publishing changes")
        # Updating a multi-document source must retain every existing document.
        if old:
            old_ids = [
                (d.get("scenario") or d.get("crossover_scenario"))["id"]
                for d in documents(old[1])
            ]
            if not set(old_ids).issubset(ids):
                raise HTTPException(
                    409, "Source update would remove existing scenario documents"
                )
        target = authored_dir()
        target.mkdir(parents=True, exist_ok=True)
        existing = sources()
        allowed_path = old[0] if old else None
        if any(key in existing and existing[key][0] != allowed_path for key in ids):
            raise HTTPException(409, "An added scenario ID belongs to another source")
        file = old[0] if old and old[0].parent == target else target / (sid + ".yaml")

        def audit(action):
            # Direct authenticated Studio calls have a durable record too.
            receipt = {
                "timestamp": time.time(),
                "actor": identity.actor,
                "action": action,
                "scenario_id": sid,
                "reason": req.reason,
                "sha256": report["sha256"],
            }
            with (target.parent / "authoring-audit.jsonl").open("a") as handle:
                handle.write(json.dumps(receipt) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

        audit("publish:requested")
        temp = file.with_suffix(".tmp")
        temp.write_text(req.yaml)
        temp.replace(file)
        for doc in documents(req.yaml):
            loaded = _load_doc(doc)
            key = (loaded.single or loaded.crossover).id
            api._all_scenarios[key] = loaded
        audit("publish:completed")
    return {"published": ids, "sha256": report["sha256"]}


def load_authored():
    from . import api

    for path in sorted(authored_dir().glob("*.yaml")):
        for doc in documents(path.read_text()):
            loaded = _load_doc(doc)
            api._all_scenarios[(loaded.single or loaded.crossover).id] = loaded
