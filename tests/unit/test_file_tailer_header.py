"""file_tailer 최초 오픈 헤더 파싱(감사 4.2) — Zeek #fields 헤더 유실 레이스 회귀 방지.

감사 U-5는 이 레이스의 '실제 발생률'을 스택 10회 기동으로 보려 했다. 여기서는 그걸
**결정론적 테스트**로 대체한다: 다양한 startup 타이밍(헤더 선존재 / 빈 파일에 헤더 나중 /
파일 자체가 나중 생성 / 로테이션)에서 헤더가 보존되고 **Zeek 이벤트가 실제로 파싱**되는지를
end-to-end(tail → parse_zeek_line)로 고정한다."""
import asyncio
from pathlib import Path

from services.siem.ingestion.file_tailer import tail_file
from services.siem.parsers.zeek import parse_zeek_line, reset_field_cache

# 현실적인 Zeek conn 헤더/데이터(7컬럼). parse_zeek_line 은 헤더의 컬럼순으로 데이터를 매핑한다.
_HEADER = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"


def _data(ip: str) -> str:
    return f"1699999999.0\tCabc\t{ip}\t44000\t10.0.0.9\t80\ttcp"


async def _tail_collect(path: Path, driver, settle: float = 0.25) -> list[str]:
    """tail_file 을 백그라운드로 돌리며 driver() 로 파일을 조작하고, 관측된 라인을 모은다.
    (poll_interval 0.02 대비 sleep 마진을 넉넉히 둬 느린 CI 러너에서도 안정적으로 관측)."""
    seen: list[str] = []

    async def on_line(line):
        seen.append(line)

    task = asyncio.create_task(tail_file(str(path), on_line, poll_interval=0.02))
    await asyncio.sleep(0.1)    # 최초 오픈이 첫 폴에 도달하게
    await driver()
    await asyncio.sleep(settle)  # tail 배수
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return seen


def _parsed_ips(seen: list[str]) -> list[str]:
    """관측 라인들을 parse_zeek_line 에 순서대로 흘려 실제로 파싱된 이벤트의 src_ip 목록."""
    reset_field_cache("conn")
    evs = [parse_zeek_line(l, "conn") for l in seen]
    return [e.source_ip for e in evs if e is not None]


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


# --- U-5 결정론적 레이스 시나리오 (감사 §6) ---------------------------------

def test_parser_needs_header_control():
    """대조군: 헤더를 못 보면 데이터 라인은 파싱 불가(=레이스 시 Zeek 이벤트 유실).
    헤더를 본 뒤에는 정상 파싱 → 헤더 보존이 왜 중요한지 직접 보인다."""
    reset_field_cache("conn")
    assert parse_zeek_line(_data("10.0.0.5"), "conn") is None      # 헤더 전: 유실
    assert parse_zeek_line(_HEADER, "conn") is None                # 헤더는 캐싱만
    ev = parse_zeek_line(_data("10.0.0.5"), "conn")                # 헤더 후: 파싱됨
    assert ev is not None and ev.source_ip == "10.0.0.5"


def test_race_empty_file_then_header_written_after(tmp_path):
    """startup 레이스: tailer 오픈 시점엔 파일이 비어 있고, 직후 Zeek 가 헤더+데이터를 쓴다.
    빈 파일의 seek(0,END)=0 이라 이후 append 를 처음부터 읽어 헤더도 보존된다."""
    p = Path(tmp_path) / "conn.log"
    p.write_text("")  # 존재하나 비어 있음

    async def driver():
        with p.open("a") as f:
            f.write(_HEADER + "\n")
            f.write(_data("10.0.0.5") + "\n")

    seen = asyncio.run(_tail_collect(p, driver))
    assert any(s.startswith("#fields") for s in seen), seen
    assert _parsed_ips(seen) == ["10.0.0.5"], seen


def test_file_created_after_tailer_start(tmp_path):
    """파일 자체가 tailer 시작 후 생성되는 레이스. 생성 시 헤더+과거데이터가 함께 있어도
    헤더는 보존, 과거데이터는 스킵, 이후 신규 데이터는 파싱된다."""
    p = Path(tmp_path) / "conn.log"  # 아직 없음

    async def driver():
        p.write_text(_HEADER + "\n" + _data("10.0.0.7") + "\n")  # 헤더 + 과거 데이터
        await asyncio.sleep(0.08)
        with p.open("a") as f:
            f.write(_data("10.0.0.8") + "\n")                     # 신규 데이터

    seen = asyncio.run(_tail_collect(p, driver, settle=0.35))
    assert any(s.startswith("#fields") for s in seen), seen
    ips = _parsed_ips(seen)
    assert ips == ["10.0.0.8"], seen        # 과거(.7) 스킵, 신규(.8) 파싱


def test_rotation_rereads_new_header_from_start(tmp_path):
    """logrotate: 새 inode 파일은 처음부터 읽어 새 헤더+데이터를 놓치지 않는다."""
    p = Path(tmp_path) / "conn.log"
    p.write_text(_HEADER + "\n" + _data("10.0.0.1") + "\n")  # 초기 파일(헤더+과거)

    async def driver():
        with p.open("a") as f:
            f.write(_data("10.0.0.2") + "\n")                # 첫 파일에서 tail
        await asyncio.sleep(0.1)
        p.unlink()                                          # 로테이션(교체)
        p.write_text(_HEADER + "\n" + _data("10.0.0.3") + "\n")

    seen = asyncio.run(_tail_collect(p, driver, settle=0.4))
    ips = _parsed_ips(seen)
    assert "10.0.0.2" in ips and "10.0.0.3" in ips, seen     # 과거(.1)만 스킵
