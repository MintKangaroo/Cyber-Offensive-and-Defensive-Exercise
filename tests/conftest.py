"""pytest 공통 설정: 리포 루트를 sys.path에 추가해 services/·shared/ 절대 임포트를 허용.
(각 서비스가 컨테이너 안에서 /app 기준 절대 임포트를 쓰므로 테스트도 동일 기준으로 맞춘다.)"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
