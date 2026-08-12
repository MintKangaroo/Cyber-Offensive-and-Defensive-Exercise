from __future__ import annotations

import time
from collections import Counter

from .db import Database


def _line(name: str, value: int | float, labels: dict[str, str] | None = None) -> str:
    suffix = ""
    if labels:
        suffix = "{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}"
    return f"{name}{suffix} {value}"


def render_metrics(db: Database) -> str:
    conn = db.connect()
    database_time = db.server_time(conn)
    lines = [
        "# TYPE attack_defense_database_backend_info gauge",
        _line(
            "attack_defense_database_backend_info", 1,
            {"backend": db.backend_name},
        ),
        "# TYPE attack_defense_database_clock_skew_seconds gauge",
        _line(
            "attack_defense_database_clock_skew_seconds",
            abs(time.time() - database_time),
        ),
        "# TYPE attack_defense_ha_mode gauge",
        _line(
            "attack_defense_ha_mode",
            1 if db.backend_name == "postgresql" else 0,
        ),
        "# TYPE attack_defense_round_current gauge",
    ]
    for row in conn.execute(
        """SELECT m.id,COALESCE(r.sequence,0) sequence FROM matches m
           LEFT JOIN rounds r ON r.id=m.current_round_id
           WHERE m.mode IN ('attack_defense','hybrid_live_fire')"""
    ):
        lines.append(_line("attack_defense_round_current", row["sequence"], {"match": row["id"]}))
    definitions = [
        ("attack_defense_flag_issued_total", "SELECT COUNT(*) FROM flags"),
        ("attack_defense_flag_submission_total", "SELECT COUNT(*) FROM flag_submissions"),
        ("attack_defense_flag_submission_accepted_total",
         "SELECT COUNT(*) FROM flag_submissions WHERE result='accepted'"),
        ("attack_defense_service_check_total", "SELECT COUNT(*) FROM service_checks"),
        ("attack_defense_patch_submission_total", "SELECT COUNT(*) FROM patch_submissions"),
        ("attack_defense_score_events_total", "SELECT COUNT(*) FROM score_ledger"),
        ("attack_defense_runtime_operation_total", "SELECT COUNT(*) FROM runtime_jobs"),
        ("attack_defense_koth_ownership_total", "SELECT COUNT(*) FROM koth_leases"),
        ("attack_defense_stealth_incident_total",
         "SELECT COUNT(*) FROM stealth_incidents"),
        ("attack_defense_stealth_detection_report_total",
         "SELECT COUNT(*) FROM stealth_detection_reports"),
        ("attack_defense_stealth_detected_total",
         "SELECT COUNT(*) FROM stealth_incidents WHERE detected_at IS NOT NULL"),
        ("attack_defense_tournament_total", "SELECT COUNT(*) FROM tournaments"),
        ("attack_defense_tournament_fixture_total",
         "SELECT COUNT(*) FROM tournament_fixtures"),
        ("attack_defense_tournament_fixture_finalized_total",
         "SELECT COUNT(*) FROM tournament_fixtures WHERE status='finalized'"),
        ("attack_defense_capture_ingest_total", "SELECT COUNT(*) FROM capture_artifacts"),
        ("attack_defense_capture_download_total",
         "SELECT COALESCE(SUM(download_count),0) FROM capture_releases"),
        ("attack_defense_capture_sanitizer_rejected_total",
         "SELECT COUNT(*) FROM audit_events WHERE event_type='capture_ingest' AND result='rejected'"),
        ("attack_defense_game_engine_errors_total",
         "SELECT COUNT(*) FROM audit_events WHERE event_type='game_engine_error'"),
    ]
    for name, query in definitions:
        lines.extend((f"# TYPE {name} counter", _line(name, conn.execute(query).fetchone()[0])))
    lines.extend((
        "# TYPE attack_defense_koth_hills_enabled gauge",
        _line(
            "attack_defense_koth_hills_enabled",
            conn.execute(
                "SELECT COUNT(*) FROM koth_hills WHERE enabled=1"
            ).fetchone()[0],
        ),
    ))
    lines.append("# TYPE attack_defense_flag_injection_total counter")
    for status, count in conn.execute(
        """SELECT result,COUNT(*) FROM audit_events
           WHERE event_type='flag_injection' GROUP BY result"""
    ):
        lines.append(_line("attack_defense_flag_injection_total", count, {"result": status}))
    latency = conn.execute(
        "SELECT COALESCE(SUM(latency_ms),0)/1000.0,COUNT(*) FROM service_checks"
    ).fetchone()
    lines.extend((
        "# TYPE attack_defense_service_check_latency_seconds summary",
        _line("attack_defense_service_check_latency_seconds_sum", latency[0]),
        _line("attack_defense_service_check_latency_seconds_count", latency[1]),
    ))
    durations = conn.execute(
        "SELECT COALESCE(SUM(finalized_at-starts_at),0),COUNT(*) FROM rounds WHERE finalized_at IS NOT NULL"
    ).fetchone()
    lines.extend((
        "# TYPE attack_defense_round_duration_seconds summary",
        _line("attack_defense_round_duration_seconds_sum", durations[0]),
        _line("attack_defense_round_duration_seconds_count", durations[1]),
    ))
    patch_states = Counter(dict(conn.execute(
        "SELECT status,COUNT(*) FROM patch_submissions GROUP BY status"
    ).fetchall()))
    lines.append("# TYPE attack_defense_patch_deployment_total counter")
    for status in ("deployed", "rollback", "failed"):
        lines.append(_line(
            "attack_defense_patch_deployment_total", patch_states.get(status, 0),
            {"result": status},
        ))
    validation = conn.execute(
        """SELECT COALESCE(SUM(validated_at-submitted_at),0),COUNT(*)
           FROM patch_submissions WHERE validated_at IS NOT NULL"""
    ).fetchone()
    lines.extend((
        "# TYPE attack_defense_patch_validation_seconds summary",
        _line("attack_defense_patch_validation_seconds_sum", validation[0]),
        _line("attack_defense_patch_validation_seconds_count", validation[1]),
    ))
    conn.close()
    return "\n".join(lines) + "\n"
