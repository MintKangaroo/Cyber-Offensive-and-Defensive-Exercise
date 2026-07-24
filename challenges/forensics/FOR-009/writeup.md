# FOR-009 — 안티포렌식 다단계 풀이

## 개요
`disk_image.json`은 합성 NTFS 스냅샷이다. 파일마다 `mft_modified`($STANDARD_INFORMATION)와
`journal_write`($LogFile)가 있다. 공격자는 세 겹의 안티포렌식을 남겼다.

## 1단계 — 타임라인 모순으로 타임스톰프 탐지
정상 쓰기는 저널 기록이 MFT 수정 시각과 같거나 이전이다: `journal_write <= mft_modified`.
공격자가 MFT를 과거로 되돌리면(백데이팅) `journal_write > mft_modified` 라는 모순이 남는다.
이 조건을 만족하는 **단 하나**의 파일이 타임스톰프 대상이다.

```python
suspects = [f for f in files if f["journal_write"] > f["mft_modified"]]
```

## 2단계 — 슬랙 은닉채널 디코드
대상 파일의 `slack`은 base64다. 디코드하면:
```
channel:ch_xxxxxxxx
payload:<hex>
```
`channel`(CHID)과 `payload`(hex)를 추출한다. (다른 파일의 slack은 무의미한 잡음이다.)

## 3단계 — 반복키 XOR 복호
`payload` 바이트열을 CHID 문자열을 키로 반복 XOR 하면 플래그가 나온다.
```python
flag = bytes(b ^ chid.encode()[i % len(chid)] for i, b in enumerate(payload))
```

## 자동 해법
```bash
python3 solution/exploit.py deploy/disk_image.json
# {'timestomped_file': '...', 'channel_id': 'ch_...', 'flag': 'flag{antiforensic_...}'}
```

## 방어 관점(blue)
타임스톰핑은 $STANDARD_INFORMATION만 조작하고 $FILE_NAME/$LogFile은 놓치는 경우가 많다.
MFT 속성 간·저널 간 시간 교차검증(cross-timeline analysis)으로 조작을 탐지할 수 있다.
