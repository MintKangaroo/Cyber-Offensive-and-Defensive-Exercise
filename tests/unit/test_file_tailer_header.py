"""file_tailer 최초 오픈 헤더 파싱(감사 4.2) — Zeek #fields 헤더 유실 레이스 회귀 방지."""
import asyncio
from pathlib import Path

from services.siem.ingestion.file_tailer import tail_file


def test_first_open_emits_header_then_tails(tmp_path):
    p = Path(tmp_path) / "conn.log"
    # 재기동 상황: tailer 시작 전에 이미 헤더 + 과거 데이터가 쓰여 있음.
    p.write_text("#separator \\x09\n#fields\tts\tuid\tid.orig_h\nOLD_DATA_LINE\n")

    seen = []
    async def on_line(line):
        seen.append(line)

    async def run():
        task = asyncio.create_task(tail_file(str(p), on_line, poll_interval=0.02))
        await asyncio.sleep(0.1)               # 최초 오픈 → 헤더 전달 + 끝으로 seek
        with p.open("a") as f:
            f.write("NEW_DATA_LINE\n")         # tail 대상(새 데이터)
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    # 헤더(#로 시작)는 전달됐고, 과거 데이터(OLD)는 재처리 안 됨, 새 데이터(NEW)는 tail 됨.
    assert any(s.startswith("#fields") for s in seen), seen
    assert "OLD_DATA_LINE" not in seen, seen
    assert "NEW_DATA_LINE" in seen, seen
