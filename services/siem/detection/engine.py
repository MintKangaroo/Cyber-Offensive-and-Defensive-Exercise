"""
Detection Engine (22번 문서 4절, M5.4/M5.5 + beacon_detection_note.md 확장)
================================================================================
규칙 4종:
  - match: 단순 조건 매칭
  - threshold: group_by 키별 슬라이딩 윈도우에서 조건(예: distinct(dst.port) >= 15) 평가
  - sequence: group_by 키별로 여러 step이 순서대로, within_sec 이내에 전부 매치되면 발화
  - periodicity: (src,dst) 쌍별 연결 간격의 변동계수(jitter)로 C2 비콘 탐지

이벤트는 dict(NormalizedEvent.model_dump() 또는 그와 동일한 키 구조)로 받는다 —
pydantic 객체에 직접 결합하지 않아 테스트/재사용이 쉽다.
"""
from __future__ import annotations
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Optional
from collections import deque


# RFC1918 사설 + 루프백 + 링크로컬만 명시적으로 '내부'로 본다.
# 주의: ipaddress.is_private 는 최신 CPython 에서 IETF 특수용도 범위(문서용
# 192.0.2/24·198.51.100/24·203.0.113/24, 벤치마킹 등)까지 True 로 재분류했다.
# 그 범위는 훈련 데이터셋에서 '외부' C2 목적지의 스탠드인으로 쓰이므로, is_private
# 에 의존하면 정상적인 외부 비콘을 내부로 오분류해 탐지가 죽는다(DET-004/009 회귀).
_INTERNAL_NETS = tuple(ipaddress.ip_network(c) for c in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918 사설
    "127.0.0.0/8", "169.254.0.0/16",                    # 루프백·링크로컬
))


def _is_private_or_local_ip(ip: str) -> bool:
    """RFC1918 사설·루프백·링크로컬 IP면 True(감사 4.5: 내부 목적지 비콘 오탐 방지).
    호스트명 등 IP가 아니면(파싱 실패) True로 간주해 오탐을 피한다(외부 IP만 비콘 후보)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _INTERNAL_NETS)


def _get_path(obj: dict, path: str) -> Any:
    """'src.ip' 같은 dot-path로 중첩 dict 값 조회. 없으면 None."""
    cur: Any = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _event_epoch(event: dict) -> float:
    """이벤트의 timestamp를 epoch(float)로 정규화.

    ⚠️ NormalizedEvent.model_dump(mode="json")를 거치면 timestamp가 ISO 문자열이 된다.
    threshold/sequence/periodicity의 슬라이딩 윈도우 연산(`ts - window_sec`)은 float를
    가정하므로, 문자열을 그대로 넘기면 `str - int` TypeError로 탐지가 죽는다(그리고 예외가
    소비 루프까지 전파되면 인제스천 자체가 멈춘다). 여기서 float/ISO/datetime을 모두 흡수한다.
    """
    ts = event.get("timestamp")
    if ts is None:
        return time.time()
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return time.time()
    ts_method = getattr(ts, "timestamp", None)  # datetime 객체
    if callable(ts_method):
        try:
            return ts_method()
        except Exception:
            return time.time()
    return time.time()


@dataclass
class Rule:
    id: str
    title: str
    severity: int
    mitre: list[str] = field(default_factory=list)
    source_type: Any = None  # str 또는 list[str], None이면 전체 소스 대상
    kind: Literal["match", "threshold", "sequence", "periodicity"] = "match"
    match: Optional[dict[str, Any]] = None                 # kind=match/시퀀스 step에도 재사용
    threshold_group_by: Optional[str] = None               # kind=threshold
    threshold_condition: Optional[str] = None              # 예: "distinct(dst.port) >= 15"
    threshold_window_sec: int = 60
    sequence_steps: Optional[list[dict[str, Any]]] = None  # kind=sequence
    sequence_group_by: str = "src.ip"
    sequence_within_sec: int = 300
    # kind=periodicity (C2 비콘 탐지, beacon_detection_note.md의 설계를 실제 구현)
    periodicity_group_by_src: str = "src.ip"
    periodicity_group_by_dst: str = "dst.ip"
    periodicity_min_observations: int = 5
    periodicity_jitter_threshold: float = 0.1
    periodicity_window_sec: int = 3600
    periodicity_allowlist_dst: list[str] = field(default_factory=list)  # 정상 폴링 목적지 제외


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: int
    mitre: list[str]
    matched_event: dict
    timestamp: float = field(default_factory=time.time)
    detail: str = ""


def _matches(event: dict, conditions: dict[str, Any]) -> bool:
    for key, expected in conditions.items():
        actual = _get_path(event, key)
        if isinstance(expected, str) and expected.startswith("~"):
            if actual is None or expected[1:] not in str(actual):
                return False
        elif actual != expected:
            return False
    return True


class _ThresholdState:
    def __init__(self):
        self.window: dict[str, deque] = {}
        self.already_fired: dict[str, bool] = {}  # 임계 돌파 후 재알림 폭주 방지(edge-trigger)

    def add_and_evaluate(self, group_key: str, timestamp: float, distinct_value: Any,
                        window_sec: int, required_count: int) -> bool:
        dq = self.window.setdefault(group_key, deque())
        dq.append((timestamp, distinct_value))
        cutoff = timestamp - window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct_count = len({v for _, v in dq})

        breached = distinct_count >= required_count
        was_fired = self.already_fired.get(group_key, False)

        if breached and not was_fired:
            self.already_fired[group_key] = True
            return True  # 임계값을 새로 돌파한 순간에만 발화(edge)
        if not breached:
            self.already_fired[group_key] = False  # 윈도우가 지나 카운트가 줄면 재무장
        return False


class _PeriodicityState:
    """(src,dst) 쌍별 연결 시각을 기록해 주기성(비콘) 여부를 판정한다."""

    def __init__(self):
        self.timestamps: dict[tuple[str, str], deque] = {}
        self.already_fired: dict[tuple[str, str], bool] = {}

    def add_and_evaluate(self, key: tuple[str, str], timestamp: float,
                        min_observations: int, jitter_threshold: float, window_sec: int) -> Optional[float]:
        dq = self.timestamps.setdefault(key, deque())
        dq.append(timestamp)
        cutoff = timestamp - window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < min_observations:
            return None

        times = sorted(dq)
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return None
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        jitter = (variance ** 0.5) / mean

        was_fired = self.already_fired.get(key, False)
        if jitter < jitter_threshold and not was_fired:
            self.already_fired[key] = True
            return jitter  # 새로 비콘으로 판정된 순간에만 발화(edge-trigger, threshold와 동일 원칙)
        if jitter >= jitter_threshold:
            self.already_fired[key] = False  # 패턴이 깨지면 재무장
        return None


class _SequenceState:
    def __init__(self):
        self.progress: dict[str, tuple[int, float]] = {}

    def advance(self, group_key: str, timestamp: float, total_steps: int, within_sec: int) -> bool:
        idx, first_ts = self.progress.get(group_key, (0, timestamp))
        if idx > 0 and timestamp - first_ts > within_sec:
            idx, first_ts = 0, timestamp
        idx += 1
        if idx >= total_steps:
            self.progress.pop(group_key, None)
            return True
        self.progress[group_key] = (idx, first_ts if idx > 1 else timestamp)
        return False


def _parse_threshold_condition(cond: str) -> tuple[str, str, int]:
    import re
    m = re.match(r"distinct\(([\w.]+)\)\s*(>=|>|==)\s*(\d+)", cond.strip())
    if not m:
        raise ValueError(f"unsupported threshold condition: {cond}")
    return m.group(1), m.group(2), int(m.group(3))


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._threshold_states: dict[str, _ThresholdState] = {
            r.id: _ThresholdState() for r in rules if r.kind == "threshold"
        }
        self._sequence_states: dict[str, _SequenceState] = {
            r.id: _SequenceState() for r in rules if r.kind == "sequence"
        }
        self._periodicity_states: dict[str, _PeriodicityState] = {
            r.id: _PeriodicityState() for r in rules if r.kind == "periodicity"
        }

    def _source_ok(self, rule: Rule, event: dict) -> bool:
        if rule.source_type is None:
            return True
        if isinstance(rule.source_type, list):
            return event.get("source_type") in rule.source_type
        return event.get("source_type") == rule.source_type

    def evaluate(self, event: dict) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if not self._source_ok(rule, event):
                continue
            try:
                if rule.kind == "match":
                    if rule.match and _matches(event, rule.match):
                        alerts.append(Alert(rule.id, rule.title, rule.severity, rule.mitre, event,
                                            detail=f"matched {rule.match}"))
                elif rule.kind == "threshold":
                    alerts.extend(self._eval_threshold(rule, event))
                elif rule.kind == "sequence":
                    alerts.extend(self._eval_sequence(rule, event))
                elif rule.kind == "periodicity":
                    alerts.extend(self._eval_periodicity(rule, event))
            except Exception as e:
                # 한 규칙의 평가 실패가 다른 규칙/전체 인제스천 파이프라인을 죽이지 않게 격리.
                # (원인은 고치되, 방어적으로도 한 겹 막아둔다.)
                import logging
                logging.getLogger("siem.detection").warning(
                    "rule %s evaluation failed: %s", rule.id, e)
        return alerts

    def _eval_periodicity(self, rule: Rule, event: dict) -> list[Alert]:
        src = _get_path(event, rule.periodicity_group_by_src)
        dst = _get_path(event, rule.periodicity_group_by_dst)
        if src is None or dst is None:
            return []
        # 감사 4.5: allowlist를 'IP 기준'으로. 이전 allowlist는 서비스명("event_collector"…)이라
        # dst.ip(IP)와 절대 매칭되지 않아 무효였고, 내부 하트비트(트윈→코어)를 C2 비콘으로 오탐했다.
        # C2 비콘은 '외부' 목적지로 향한다 → 사설/루프백 IP(RFC1918 등)는 후보에서 제외한다.
        if _is_private_or_local_ip(str(dst)):
            return []
        if str(dst) in rule.periodicity_allowlist_dst:
            return []  # 명시 allowlist(정상 폴링 목적지 IP)도 제외

        state = self._periodicity_states[rule.id]
        key = (str(src), str(dst))
        jitter = state.add_and_evaluate(
            key, _event_epoch(event),
            rule.periodicity_min_observations, rule.periodicity_jitter_threshold,
            rule.periodicity_window_sec,
        )
        if jitter is not None:
            return [Alert(rule.id, rule.title, rule.severity, rule.mitre, event,
                          detail=f"beacon-like periodicity: {src}->{dst} jitter={jitter:.3f}")]
        return []

    def _eval_threshold(self, rule: Rule, event: dict) -> list[Alert]:
        field_path, op, required = _parse_threshold_condition(rule.threshold_condition)
        group_key = str(_get_path(event, rule.threshold_group_by))
        distinct_value = _get_path(event, field_path)
        if distinct_value is None or group_key == "None":
            return []
        state = self._threshold_states[rule.id]
        fired = state.add_and_evaluate(group_key, _event_epoch(event),
                                       distinct_value, rule.threshold_window_sec, required)
        if fired:
            return [Alert(rule.id, rule.title, rule.severity, rule.mitre, event,
                          detail=f"{field_path} distinct >= {required} for group={group_key}")]
        return []

    def _eval_sequence(self, rule: Rule, event: dict) -> list[Alert]:
        steps = rule.sequence_steps or []
        state = self._sequence_states[rule.id]
        group_key = str(_get_path(event, rule.sequence_group_by))
        if group_key == "None":
            return []

        current_idx = state.progress.get(group_key, (0, 0.0))[0]
        if current_idx >= len(steps):
            current_idx = 0
        expected_step = steps[current_idx]
        if not _matches(event, expected_step):
            return []

        fired = state.advance(group_key, _event_epoch(event), len(steps), rule.sequence_within_sec)
        if fired:
            return [Alert(rule.id, rule.title, rule.severity, rule.mitre, event,
                          detail=f"sequence completed for group={group_key}")]
        return []
