FROM python:3.11-slim
WORKDIR /app
COPY logd /app/logd
COPY server.py /app/server.py
RUN chmod +x /app/logd
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9017
EXPOSE 9017
CMD ["python","server.py"]
