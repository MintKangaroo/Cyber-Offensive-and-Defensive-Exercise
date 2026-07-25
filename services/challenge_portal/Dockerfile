FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/challenge_portal/ services/challenge_portal/
# 챌린지 카탈로그/그레이더/생성기 — 이미지에 복사(생성기가 컨테이너 내 사본에 아티팩트 기록).
COPY challenges/ challenges/
EXPOSE 8060
CMD ["uvicorn", "services.challenge_portal.main:app", "--host", "0.0.0.0", "--port", "8060"]
