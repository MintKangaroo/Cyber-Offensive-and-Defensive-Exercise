FROM python:3.11-slim
WORKDIR /app
COPY damctl /app/damctl
COPY server.py /app/server.py
RUN chmod +x /app/damctl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9019
EXPOSE 9019
CMD ["python","server.py"]
