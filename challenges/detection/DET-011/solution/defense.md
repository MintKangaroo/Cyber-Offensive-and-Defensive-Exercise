# DET-011 방어 노트 — S7comm 안전 DB(62) 무단 WRITE_VAR 탐지

## 핵심
s7_function=WRITE_VAR AND area=DB AND db_number=62 동시 매칭. 단일조건(WRITE_VAR만/db=62만)은 정상 db10 write/db62 read에 오탐 → AND 결합 필수.
