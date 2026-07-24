FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn pydantic
COPY main.py .
ENV CHALLENGE_SECRET=web005-dev-secret
ENV PATCH_WEB_005=false
ENV FLAG_PATH=/tmp/flag.txt
EXPOSE 8100
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
