FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn pyjwt
COPY main.py .
ENV CHALLENGE_SECRET=web002-dev-secret
ENV PATCH_WEB_002=false
EXPOSE 8100
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
