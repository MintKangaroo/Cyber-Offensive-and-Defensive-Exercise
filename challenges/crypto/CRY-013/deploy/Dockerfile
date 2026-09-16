FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn cryptography
COPY main.py .
ENV CHALLENGE_SECRET=cry013-dev-secret
ENV PATCH_CRY_013=false
EXPOSE 8145
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8145"]
