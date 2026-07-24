FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/config_service/ services/config_service/
WORKDIR /app/services/config_service
EXPOSE 8030
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8030"]
