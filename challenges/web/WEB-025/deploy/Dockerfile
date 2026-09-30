FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx
COPY main.py .
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PATCH_WEB_025=false
ENV PORT=8131
EXPOSE 8131
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8131"]
