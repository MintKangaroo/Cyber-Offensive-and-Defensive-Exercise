FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/cloud_native/ services/cloud_native/
WORKDIR /app/services/cloud_native
EXPOSE 8209
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8209"]
