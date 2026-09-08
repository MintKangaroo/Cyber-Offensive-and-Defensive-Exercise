# WEB-026 방어 — YAML 역직렬화 RCE 차단

## 취약점
설정 임포트가 PyYAML 의 UnsafeLoader(구 `yaml.load` 기본)를 사용해 `!!python/object/apply:...`
태그로 임의 파이썬 호출이 발생한다. `subprocess.check_output(["cat","/app/flag.txt"])` 로 로컬
파일이 유출된다.

## 패치 (`PATCH_WEB_026=true`)
- `yaml.safe_load` (SafeLoader) 사용 — 파이썬 객체/호출 태그를 실행하지 않음.
- 신뢰할 수 없는 입력은 스키마 검증. 필요한 타입만 허용.

## 탐지 관점(blue)
- 업로드 YAML 에 `!!python/`, `object/apply`, `subprocess`, `os.system` 등 태그 포함 시 경보.
