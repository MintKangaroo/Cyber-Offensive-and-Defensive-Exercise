FROM python:3.11-slim
WORKDIR /app
COPY valve /app/valve
COPY server.py /app/server.py
RUN chmod +x /app/valve
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9012
EXPOSE 9012
CMD ["python","server.py"]
