FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/traffic_generator/ services/traffic_generator/
EXPOSE 8098
CMD ["uvicorn", "services.traffic_generator.main:app", "--host", "0.0.0.0", "--port", "8098"]
