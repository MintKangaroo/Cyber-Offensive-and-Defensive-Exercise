FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
ENV CHALLENGE_SECRET=cry008-dev-secret
ENV PATCH_CRY_008=false
EXPOSE 8140
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8140"]
