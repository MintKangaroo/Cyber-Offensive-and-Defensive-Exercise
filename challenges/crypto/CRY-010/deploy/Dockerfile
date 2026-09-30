FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PATCH_CRY_010=false
EXPOSE 8142
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8142"]
