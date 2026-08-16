"""보존 정책(감사 4.8) — AAR PDF 개수/일수 상한, events.db 일수 상한."""
import importlib, os, time
from pathlib import Path


def test_aar_prune_count_and_age(tmp_path, monkeypatch):
    monkeypatch.setenv("AAR_PDF_DIR", str(tmp_path))
    monkeypatch.setenv("AAR_RETENTION_DAYS", "7")
    monkeypatch.setenv("AAR_MAX_REPORTS", "3")
    import services.aar_report.main as m
    importlib.reload(m)
    now = time.time()
    # 최신 5개 + 아주 오래된 1개
    for i in range(5):
        p = Path(tmp_path) / f"aar_s_{i}.pdf"; p.write_text("x")
        os.utime(p, (now - i, now - i))
    old = Path(tmp_path) / "aar_s_old.pdf"; old.write_text("x")
    os.utime(old, (now - 30 * 86400, now - 30 * 86400))
    res = m._prune_reports()
    remaining = sorted(p.name for p in Path(tmp_path).glob("aar_*.pdf"))
    assert old.name not in remaining          # 7일 초과 삭제
    assert len(remaining) == 3                 # 개수 상한 3
    assert res["remaining"] == 3


def test_events_prune_by_age(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EVENTS_RETENTION_DAYS", "1")
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    import services.event_collector.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "events.db"; m.init_db()
    conn = m.get_db()
    now = time.time()
    conn.execute("INSERT INTO events(event_id,timestamp) VALUES('fresh',?)", (now,))
    conn.execute("INSERT INTO events(event_id,timestamp) VALUES('stale',?)", (now - 3 * 86400,))
    conn.commit(); conn.close()
    removed = m._prune_old_events()
    assert removed == 1
    conn = m.get_db()
    ids = {r["event_id"] for r in conn.execute("SELECT event_id FROM events").fetchall()}
    conn.close()
    assert ids == {"fresh"}
