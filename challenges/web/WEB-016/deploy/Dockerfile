FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=web016-dev-secret
ENV PATCH_WEB_016=false
EXPOSE 8116
# 레이스 재현을 위해 워커/스레드 동시성 확보(uvicorn 기본 threadpool + 다중 요청)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8116"]
