FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn jinja2
COPY main.py .
ENV CHALLENGE_SECRET=web017-dev-secret
ENV PATCH_WEB_017=false
EXPOSE 8117
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8117"]
