# 빌드 컨텍스트 = 레포 루트 (shared/ics/modbus.py 재사용을 위해).
#   docker build -f challenges/ics/ICS-000/deploy/Dockerfile .
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 1.4).
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]"
COPY shared/ shared/
COPY challenges/ics/ICS-000/deploy/main.py .
EXPOSE 8110
EXPOSE 5020
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8110"]
