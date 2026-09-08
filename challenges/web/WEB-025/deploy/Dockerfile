FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx
COPY main.py .
ENV CHALLENGE_SECRET=web025-dev-secret
ENV PATCH_WEB_025=false
ENV PORT=8131
EXPOSE 8131
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8131"]
