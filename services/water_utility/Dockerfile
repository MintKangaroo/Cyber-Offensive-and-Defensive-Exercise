FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/water_utility/ services/water_utility/
WORKDIR /app/services/water_utility
EXPOSE 8203
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8203"]
