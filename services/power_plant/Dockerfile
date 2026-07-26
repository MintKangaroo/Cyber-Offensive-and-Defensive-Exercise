FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
COPY shared/ shared/
COPY services/power_plant/ services/power_plant/
WORKDIR /app/services/power_plant
EXPOSE 8002
EXPOSE 502
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
