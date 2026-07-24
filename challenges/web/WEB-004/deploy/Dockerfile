FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=web004-dev-secret
ENV PATCH_WEB_004=false
EXPOSE 8104
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8104"]
