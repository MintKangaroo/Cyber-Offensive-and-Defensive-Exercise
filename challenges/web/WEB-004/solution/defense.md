# WEB-004 방어 노트 (Blue)

## 취약점
`/api/files/download` 가 사용자 입력 `name` 을 공개 디렉토리에 그대로 이어붙여
(`/app/public/{name}`) 열기 때문에 `../flag.txt` 로 상위 디렉토리 파일을 읽을 수 있다
(ATT&CK **T1083** File and Directory Discovery / Path Traversal).

## 패치 (PATCH_WEB_004=true)
- **파일명만 취한다**: `os.path.basename(name)` 로 디렉토리 구성요소 제거 → 공개 디렉토리로 한정.
- 또는 **정규화 후 검증**: `Path(base, name).resolve()` 가 공개 디렉토리 하위인지 확인, 아니면 거부.

## 탐지
- 다운로드 파라미터에 `..`, 절대경로(`/`), 인코딩된 순회(`%2e%2e`) 패턴이 오면 알림.
- 웹 프로세스가 공개 디렉토리 밖 민감 파일(`/app/flag.txt`, `/etc/passwd` 등)을 여는지 감시.
