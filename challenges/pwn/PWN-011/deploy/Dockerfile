FROM python:3.11-slim
WORKDIR /app
COPY relayctl /app/relayctl
COPY server.py /app/server.py
RUN chmod +x /app/relayctl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9021
EXPOSE 9021
CMD ["python","server.py"]
