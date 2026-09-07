FROM python:3.11-slim
WORKDIR /app
# 결정론적 주소를 위해 사전 컴파일된 정적 바이너리를 그대로 사용(재컴파일 환경차 배제).
COPY lng /app/lng
COPY server.py /app/server.py
RUN chmod +x /app/lng
ENV CHALLENGE_SECRET=pwn000-dev-secret
ENV PORT=9010
EXPOSE 9010
CMD ["python", "server.py"]
