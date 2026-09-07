FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn "pyjwt[crypto]"
COPY main.py .
ENV CHALLENGE_SECRET=web015-dev-secret
ENV PATCH_WEB_015=false
EXPOSE 8115
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8115"]
