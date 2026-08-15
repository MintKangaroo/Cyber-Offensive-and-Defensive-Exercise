FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/challenge_portal/ services/challenge_portal/
# 챌린지 카탈로그/그레이더/생성기 — 이미지에 복사(생성기가 컨테이너 내 사본에 아티팩트 기록).
COPY challenges/ challenges/
# 풀이·익스플로잇·라이트업은 참가자에게 노출되면 안 되므로 빌드 이미지에서 제거한다.
# challenge_portal은 grader/ + challenge.yaml + deploy 생성기만 사용하므로 solution/·writeup은
# 런타임에 불필요하다. (감사 1.7 DoD: 이미지 내 exploit.py 0건)
RUN find challenges -type d -name solution -prune -exec rm -rf {} + \
 && find challenges -type f \( -name 'writeup.md' -o -name 'exploit.py' -o -name 'exploit.*.pyc' -o -name 'defense.md' \) -delete \
 && find challenges -type d -name __pycache__ -prune -exec rm -rf {} + \
 && ( [ -z "$(find challenges -name 'exploit.py' -o -name 'writeup.md' -o -type d -name solution)" ] \
      || (echo 'FATAL: 민감 파일이 이미지에 남아있음' && exit 1) )
EXPOSE 8060
CMD ["uvicorn", "services.challenge_portal.main:app", "--host", "0.0.0.0", "--port", "8060"]
