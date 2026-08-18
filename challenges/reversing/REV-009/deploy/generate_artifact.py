"""REV-009 배포 - 팀별 플래그를 커스텀 핸들러테이블 VM 바이트코드로 컴파일해 vm_image.json 생성.

REV-004(4-op 스택 VM)의 상위판(insane). 난이도 상승 요소 세 가지:
  1) dispatch 순열: program의 raw opcode는 dispatch[raw]=canonical 로 매핑돼야 실제 연산이 된다
     (핸들러 점프 테이블 리버싱). raw를 그대로 믿으면 완전히 어긋난다.
  2) LCG 키스트림: XORK 연산은 이미지의 seed로 구동되는 LCG(state=(A*state+C)&0xFF)를 소비한다.
     호출마다 1바이트 전진하므로 키스트림 순서를 정확히 맞춰야 한다.
  3) 스택 VM 8개 연산(PUSHI/DUP/ADD/SUB/XORK/ROL/MOD256/EMIT)을 전부 구현해야 한다.

canonical opcode(0..7):
  0 PUSHI n : stack.push(n)
  1 DUP     : stack.push(top)
  2 ADD     : b=pop, a=pop, push(a+b)
  3 SUB     : b=pop, a=pop, push(a-b)
  4 XORK    : a=pop, push(a ^ next_keystream())
  5 ROL n   : a=pop, push(rol8(a & 0xFF, n))
  6 MOD256  : a=pop, push(a & 0xFF)
  7 EMIT    : out.append(pop() & 0xFF)

각 플래그 문자 c에 대한 방출 시퀀스(역산 가능하게 컴파일):
  PUSHI a, PUSHI b, ADD, XORK, ROL r, MOD256, EMIT
  최종 방출 = rol8(((a+b) ^ k) & 0xFF, r) & 0xFF == c 가 되도록 a,b,r 선택.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

# LCG 파라미터(mod 256 전주기: A%4==1, C 홀수)
LCG_A = 181
LCG_C = 77

# canonical opcode 상수
PUSHI, DUP, ADD, SUB, XORK, ROL, MOD256, EMIT = range(8)


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{vmhandler_{sig}}}"


def _rol8(v: int, r: int) -> int:
    v &= 0xFF
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF if r else v


def _ror8(v: int, r: int) -> int:
    v &= 0xFF
    r &= 7
    return ((v >> r) | (v << (8 - r))) & 0xFF if r else v


def _dispatch_perm(team_id: str) -> list:
    """팀별 결정론적 opcode 순열. dispatch[raw] = canonical.
    canonical i 를 배치할 raw 슬롯을 secret 기반으로 셔플."""
    order = list(range(8))
    seed = int(hmac.new(CHALLENGE_SECRET.encode(), f"REV-009-perm:{team_id}".encode(),
                        hashlib.sha256).hexdigest(), 16)
    # 결정론적 Fisher-Yates
    for i in range(7, 0, -1):
        seed, j = divmod(seed, i + 1)
        order[i], order[j] = order[j], order[i]
    # order[raw] = canonical
    return order


def _seed_byte(team_id: str) -> int:
    return int(hmac.new(CHALLENGE_SECRET.encode(), f"REV-009-seed:{team_id}".encode(),
                        hashlib.sha256).hexdigest()[:2], 16)


class _Keystream:
    def __init__(self, seed: int):
        self.state = seed & 0xFF

    def next(self) -> int:
        self.state = (LCG_A * self.state + LCG_C) & 0xFF
        return self.state


def compile_flag(flag: str, team_id: str) -> dict:
    dispatch = _dispatch_perm(team_id)          # dispatch[raw] = canonical
    raw_of = {canon: raw for raw, canon in enumerate(dispatch)}  # canonical -> raw
    seed = _seed_byte(team_id)
    ks = _Keystream(seed)

    program = []

    def emit(canon, arg=0):
        program.append([raw_of[canon], arg])

    for idx, ch in enumerate(flag.encode()):
        r = (idx % 7) + 1                        # 1..7 회전량(0 회전은 무의미하므로 배제)
        k = ks.next()                            # 이 문자에서 XORK가 소비할 키스트림 바이트
        w0 = _ror8(ch, r)                        # ROL r 이전 값(=XORK 직후 하위바이트)
        x = w0 ^ k                               # ADD 결과(=a+b)의 하위바이트 목표. x<256 보장
        b = x // 2
        a = x - b
        emit(PUSHI, a)
        emit(PUSHI, b)
        emit(ADD)
        emit(XORK)
        emit(ROL, r)
        emit(MOD256)
        emit(EMIT)

    return {
        "vm": "stack8-handlertable-v1",
        "dispatch": dispatch,                    # raw -> canonical (핸들러 테이블)
        "lcg": {"a": LCG_A, "c": LCG_C, "seed": seed},
        "program": program,
        "flag_len": len(flag),
    }


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        json.dump(compile_flag(dynamic_flag(team_id), team_id), f)


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("vm_image.json", team_id)
    print(f"생성 완료: vm_image.json (team={team_id})")
