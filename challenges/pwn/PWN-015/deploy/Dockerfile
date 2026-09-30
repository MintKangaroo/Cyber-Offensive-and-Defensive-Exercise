FROM python:3.11-slim-bookworm
WORKDIR /app
COPY valvectl /app/valvectl
COPY server.py /app/server.py
RUN chmod +x /app/valvectl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9025
EXPOSE 9025
CMD ["python","server.py"]
