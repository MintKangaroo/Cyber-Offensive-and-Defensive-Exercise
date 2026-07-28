FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/refinery_plant/ services/refinery_plant/
WORKDIR /app/services/refinery_plant
EXPOSE 8201
EXPOSE 502
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8201"]
