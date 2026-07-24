"""DET-001 Blue Grader - 진짜 DetectionEngine으로 포트스캔 탐지 + 노이즈 오탐 없음 확인."""
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

    scan_events = _load_events(challenge_dir / "deploy" / "scan_log.jsonl")
    noise_events = _load_events(challenge_dir / "deploy" / "noise_log.jsonl")

    scan_alerts = []
    engine1 = DetectionEngine(rules)
    for e in scan_events:
        scan_alerts.extend(engine1.evaluate(e))

    noise_alerts = []
    engine2 = DetectionEngine(rules)  # 별도 인스턴스(상태 공유 방지)
    for e in noise_events:
        noise_alerts.extend(engine2.evaluate(e))

    detected = len(scan_alerts) > 0
    no_fp = len(noise_alerts) == 0
    passed = detected and no_fp
    points = 100 if passed else (50 if detected else 0)

    return GradeResult(
        passed, points,
        f"scan_detected={detected}({len(scan_alerts)} alerts) noise_false_positive={not no_fp}({len(noise_alerts)} alerts)",
    )
