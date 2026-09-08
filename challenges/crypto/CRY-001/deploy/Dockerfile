FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn cryptography
COPY main.py .
ENV CHALLENGE_SECRET=cry001-dev-secret
ENV PATCH_CRY_001=false
EXPOSE 8133
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8133"]
