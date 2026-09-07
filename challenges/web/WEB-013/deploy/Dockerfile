FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx
COPY main.py .
ENV CHALLENGE_SECRET=web013-dev-secret
ENV PATCH_WEB_013=false
EXPOSE 8113
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8113"]
