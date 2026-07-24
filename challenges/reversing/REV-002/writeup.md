# REV-002 풀이 (Writeup)

## 개요
`encoded.bin`은 플래그를 **4바이트 반복키 XOR**로 인코딩한 것이다. 단일바이트 XOR(REV-000)과
달리 256가지 브루트포스로 풀리지 않는다.

## 풀이 - known-plaintext
플래그가 `flag{`로 시작한다는 사실을 이용한다. 반복키 길이가 4이므로, 알려진 평문 5바이트
(`flag{`)만 있으면 키 4바이트를 전부 복원하고 5번째 바이트로 반복 가정을 검증할 수 있다.

```
key[i] = encoded[i] XOR "flag{"[i]   (i = 0..3)
assert encoded[4] XOR '{' == key[0]  # 반복키 일관성
```

키를 복원한 뒤 전체를 XOR 복호화하면 `flag{rvx_<sig>}`가 나온다.

## 방어 관점
XOR 인코딩은 난독화일 뿐 암호화가 아니다. known-plaintext 한 조각이면 키가 드러난다 —
민감 데이터는 표준 대칭키 암호(AES-GCM 등)와 적절한 키 관리로 보호해야 한다.
