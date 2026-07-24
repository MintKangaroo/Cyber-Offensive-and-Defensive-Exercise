# REV-006 풀이 (Writeup)

## 개요
`encoded.bin`의 각 바이트: `enc = ROL((b XOR K), R)` (K/R 미노출).

## 풀이 - known-plaintext + 회전량 브루트포스
회전량 R은 0~7 뿐이므로 전수 탐색한다. 각 R에 대해 알려진 평문 `flag{`로 키 후보를 구한다:
```
K_candidate = ROR(enc[i], R) XOR "flag{"[i]
```
모든 i에서 K가 일치하는 R이 정답. 그 (R,K)로 전체를 `ROR` 후 `XOR K` 하면 `flag{rol_...}`.

## 방어 관점
비트 회전 + XOR는 고전 난독화로, 키 공간이 작고(R은 8가지) known-plaintext 한 조각이면 즉시
복원된다. 기밀은 표준 대칭키 암호로 보호해야 한다.
