FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn pyyaml
COPY main.py .
ENV CHALLENGE_SECRET=web026-dev-secret
ENV PATCH_WEB_026=false
EXPOSE 8132
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8132"]
