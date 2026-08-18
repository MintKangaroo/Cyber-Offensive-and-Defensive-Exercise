"""
File Tailer (22번 문서 1절, M5.1)
====================================
트윈이 남기는 access log 파일을 tail -f 방식으로 읽어 파서에 넘긴다.
logrotate 대응: inode가 바뀌면(파일이 교체되면) 재오픈.
"""
from __future__ import annotations
import asyncio
import os
from pathlib import Path
from typing import Callable, Awaitable


async def tail_file(
    path: str,
    on_line: Callable[[str], Awaitable[None]],
    poll_interval: float = 0.5,
) -> None:
    """path가 아직 없으면 생길 때까지 대기(에러로 죽지 않음). 최초 오픈 시에는 파일 끝에서부터
    시작(과거 로그 전체를 재처리하지 않음). 단, logrotate로 파일이 교체된 경우는 새 파일이므로
    처음부터 읽어야 함(끝으로 seek하면 이미 다 쓰여진 내용을 통째로 놓친다)."""
    file_path = Path(path)
    inode = None
    f = None
    is_first_open = True

    while True:
        try:
            if not file_path.exists():
                await asyncio.sleep(poll_interval)
                continue

            current_inode = file_path.stat().st_ino
            if f is None or inode != current_inode:
                if f:
                    f.close()
                f = open(file_path, "r")
                if is_first_open:
                    # 감사 4.2: Zeek 로그는 파일 맨 앞의 '#fields' 등 헤더로 컬럼 스키마를 정의한다.
                    # 예전엔 최초 오픈 시 곧장 끝으로 seek해 헤더를 놓쳐, 재기동 직후 Zeek 라인을
                    # 파싱하지 못했다(헤더 유실 레이스). 이제 선두의 '#' 헤더 구간을 먼저 파서에
                    # 전달한 뒤 끝으로 seek한다(과거 데이터는 재처리하지 않되 헤더 문맥은 확보).
                    while True:
                        hline = f.readline()
                        if not hline:
                            break
                        if hline.startswith("#"):
                            await on_line(hline.rstrip("\n"))
                        else:
                            break  # 헤더 구간 끝(첫 데이터 라인은 버리고 끝에서 tail)
                    f.seek(0, os.SEEK_END)  # 최초 오픈은 헤더 파싱 후 끝에서 tail
                    is_first_open = False
                else:
                    f.seek(0)  # rotation으로 교체된 새 파일은 처음부터 읽어야 내용을 놓치지 않음
                inode = current_inode

            line = f.readline()
            if not line:
                await asyncio.sleep(poll_interval)
                # 파일이 교체됐는지(logrotate) 다음 루프에서 inode 비교로 감지
                continue

            await on_line(line.rstrip("\n"))

        except FileNotFoundError:
            f = None
            await asyncio.sleep(poll_interval)
        except Exception:
            # 예기치 못한 에러도 tailer 자체가 죽지 않게(SIEM 수집 중단 방지)
            await asyncio.sleep(poll_interval)


async def tail_multiple(paths: list[str], on_line: Callable[[str, str], Awaitable[None]]) -> None:
    """여러 파일을 동시에 tail. on_line(path, line) 형태로 어느 파일에서 왔는지 함께 전달."""
    async def _wrap(p: str):
        async def handler(line: str):
            await on_line(p, line)
        await tail_file(p, handler)

    await asyncio.gather(*[_wrap(p) for p in paths])
