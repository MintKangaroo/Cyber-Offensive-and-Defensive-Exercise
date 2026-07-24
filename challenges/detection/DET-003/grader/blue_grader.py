"""
DET-003 Blue Grader (sequence 규칙)
=====================================
웹쉘 킬체인(.php 업로드 → 실행)을 SIEM DetectionEngine의 sequence 규칙으로 탐지하는지
채점한다. DET-000/002와 달리 sequence 규칙이므로 _rule_from_yaml_dict가 sequence 필드
(sequence_steps/group_by/within_sec)까지 Rule에 넘겨야 한다.
"""
import json
import sys
from pathlib import Path
from dataclasses import dataclass

CONTRACTS_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(CONTRACTS_ROOT))

from services.siem.detection.engine import Rule, DetectionEngine  # noqa: E402


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def _load_events(path: Path) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _rule_from_yaml_dict(d: dict) -> Rule:
    return Rule(
        id=d["id"], title=d["title"], severity=d["severity"],
        mitre=d.get("mitre", []), source_type=d.get("source_type"),
        kind=d.get("kind", "match"), match=d.get("match"),
        threshold_group_by=d.get("threshold_group_by"),
        threshold_condition=d.get("threshold_condition"),
        threshold_window_sec=d.get("threshold_window_sec", 60),
        sequence_steps=d.get("sequence_steps"),
        sequence_group_by=d.get("sequence_group_by", "src.ip"),
        sequence_within_sec=d.get("sequence_within_sec", 300),
    )


def grade_blue(context: dict) -> GradeResult:
    import yaml

    challenge_dir = Path(context.get("challenge_dir", Path(__file__).parent.parent))
    rule_path = Path(context["submitted_rule_path"]) if "submitted_rule_path" in context \
        else challenge_dir / "solution" / "answer_rule.yaml"

    with open(rule_path) as f:
        rule_dicts = yaml.safe_load(f)
    if isinstance(rule_dicts, dict):
        rule_dicts = [rule_dicts]
    rules = [_rule_from_yaml_dict(d) for d in rule_dicts]

    attack_events = _load_events(challenge_dir / "deploy" / "attack_log.jsonl")
    normal_events = _load_events(challenge_dir / "deploy" / "normal_log.jsonl")

    engine_attack = DetectionEngine(rules)
    attack_alerts = []
    for e in attack_events:
        attack_alerts.extend(engine_attack.evaluate(e))

    engine_normal = DetectionEngine(rules)
    normal_alerts = []
    for e in normal_events:
        normal_alerts.extend(engine_normal.evaluate(e))

    detected = len(attack_alerts) > 0
    no_fp = len(normal_alerts) == 0
    passed = detected and no_fp
    return GradeResult(
        passed, 90 if passed else 0,
        f"webshell_seq_detected={detected}({len(attack_alerts)} alerts) "
        f"normal_false_positive={not no_fp}({len(normal_alerts)} alerts)",
    )
