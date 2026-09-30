FROM python:3.11-slim
WORKDIR /app
COPY ptp /app/ptp
COPY server.py /app/server.py
RUN chmod +x /app/ptp
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9011
EXPOSE 9011
CMD ["python", "server.py"]
