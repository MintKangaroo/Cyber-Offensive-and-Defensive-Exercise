FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=web001-dev-secret
ENV PATCH_WEB_001=false
EXPOSE 8103
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8103"]
