# 빌드 컨텍스트 = 레포 루트 (shared/ics/opcua.py 재사용).
#   docker build -f challenges/ics/ICS-001/deploy/Dockerfile .
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 1.4).
FROM python:3.11-slim
WORKDIR /app
COPY shared/ shared/
COPY challenges/ics/ICS-001/deploy/main.py .
EXPOSE 4840
CMD ["python", "main.py"]
