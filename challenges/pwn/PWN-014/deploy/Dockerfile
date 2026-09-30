FROM python:3.11-slim-bookworm
WORKDIR /app
COPY pumpctl /app/pumpctl
COPY server.py /app/server.py
RUN chmod +x /app/pumpctl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9024
EXPOSE 9024
CMD ["python","server.py"]
