FROM python:3.11-slim-bookworm
WORKDIR /app
COPY scadaheap /app/scadaheap
COPY server.py /app/server.py
RUN chmod +x /app/scadaheap
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9026
EXPOSE 9026
CMD ["python","server.py"]
