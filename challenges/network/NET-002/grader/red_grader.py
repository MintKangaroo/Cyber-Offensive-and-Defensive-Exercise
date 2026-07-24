"""
NET-002 Red Grader - 제출된 경로 문자열("dmz,jump_host,app_server,internal_db")이
실제로 시작/끝이 맞고 매 홉이 허용된 방화벽 규칙인지 검증. 유일한 정답 문자열을
강제하지 않고, 그래프상 유효한 경로는 전부 인정한다(BFS 최단경로 외에도 다른 유효
경로가 있을 수 있으므로 - 예: web_frontend를 경유하는 경로도 유효).
"""
import json
from pathlib import Path
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_red(submission: dict, context: dict) -> GradeResult:
    map_path = Path(context.get("challenge_dir", Path(__file__).parent.parent)) / "deploy" / "network_map.json"
    with open(map_path) as f:
        data = json.load(f)

    allowed_pairs = {(r["src"], r["dst"]) for r in data["firewall_rules"] if r["allowed"]}
    start, target = data["start"], data["target"]

    path_str = submission.get("path", "").strip()
    if not path_str:
        return GradeResult(False, 0, "empty path")

    nodes = [n.strip() for n in path_str.split(",")]
    if len(nodes) < 2:
        return GradeResult(False, 0, "path too short")
    if nodes[0] != start or nodes[-1] != target:
        return GradeResult(False, 0, f"path must start at '{start}' and end at '{target}'")

    for i in range(len(nodes) - 1):
        if (nodes[i], nodes[i + 1]) not in allowed_pairs:
            return GradeResult(False, 0, f"hop {nodes[i]}->{nodes[i+1]} is not an allowed firewall rule")

    return GradeResult(True, 150, f"valid path: {path_str}")
