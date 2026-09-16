FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=cry014-dev-secret
ENV PATCH_CRY_014=false
EXPOSE 8146
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8146"]
