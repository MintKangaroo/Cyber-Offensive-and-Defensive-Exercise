FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn graphql-core
COPY main.py .
ENV CHALLENGE_SECRET=web019-dev-secret
ENV PATCH_WEB_019=false
EXPOSE 8119
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8119"]
