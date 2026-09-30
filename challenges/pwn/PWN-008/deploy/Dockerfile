FROM python:3.11-slim
WORKDIR /app
COPY gasctl /app/gasctl
COPY server.py /app/server.py
RUN chmod +x /app/gasctl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9018
EXPOSE 9018
CMD ["python","server.py"]
