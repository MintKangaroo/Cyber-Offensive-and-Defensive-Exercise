FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=web012-dev-secret
ENV STAGE_TIMEOUT=10
EXPOSE 8112
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8112"]
