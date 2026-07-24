# NET-009 — OT 사보타주 트레이스 재구성 풀이

## 개요
`ot_trace.json`은 Modbus/TCP 트레이스다. `assets.authorized`에 인가된 소스(HMI/EWS)가 있고
`events`에 요청이 담겨 있다. 공격자가 인가되지 않은 호스트에서 다단계 사보타주를 했다.

## 1단계 — 인가되지 않은 쓰기 소스(rogue_ip)
`func` 6(write single)/16(write multiple)을 발행했으면서 `assets.authorized`에 없는 src_ip.

```python
rogue = {e["src_ip"] for e in events if e["func"] in (6,16) and e["src_ip"] not in authorized}
```

## 2단계 — 커버트 레지스터
rogue의 쓰기 중 정상 공정 레지스터(`process_registers`)도 안전 레지스터(`safety_register`)도
아닌, 반복 쓰기가 몰린 레지스터가 은닉 채널이다(최다 쓰기).

## 3단계 — 페이로드 복원
커버트 레지스터에 시간순으로 쓰인 value 들의 **하위 바이트**(`value & 0xFF`)를 이어붙이면
base64 문자열이 되고, 디코드하면 플래그가 나온다. (상위 바이트는 잡음.)

```python
b64 = "".join(chr(e["value"] & 0xFF) for e in sorted(covert_writes, key=lambda e: e["ts"]))
flag = base64.b64decode(b64).decode()
```

## 자동 해법
```bash
python3 solution/exploit.py deploy/ot_trace.json
# {'rogue_ip': '10.10.0.x', 'covert_register': 400xx, 'flag': 'flag{ot_sabotage_...}'}
```

## 방어 관점(blue)
OT 세그먼트는 화이트리스트 기반(인가된 EWS/HMI만 쓰기)이어야 하고, 안전 세트포인트
레지스터 쓰기·비정상 레지스터 접근은 즉시 경보 대상이다. 정상 공정과 무관한 레지스터에
대한 반복 쓰기는 은닉 채널 지표다.
