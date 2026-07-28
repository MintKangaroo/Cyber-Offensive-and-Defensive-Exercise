FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/railway_signaling/ services/railway_signaling/
WORKDIR /app/services/railway_signaling
EXPOSE 8205
EXPOSE 502
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8205"]
