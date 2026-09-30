FROM python:3.11-slim
WORKDIR /app
COPY reactor /app/reactor
COPY server.py /app/server.py
RUN chmod +x /app/reactor
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9016
EXPOSE 9016
CMD ["python","server.py"]
