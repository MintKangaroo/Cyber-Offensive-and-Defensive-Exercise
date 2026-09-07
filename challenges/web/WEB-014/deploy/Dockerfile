FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn lxml
COPY main.py .
ENV CHALLENGE_SECRET=web014-dev-secret
ENV PATCH_WEB_014=false
EXPOSE 8114
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8114"]
