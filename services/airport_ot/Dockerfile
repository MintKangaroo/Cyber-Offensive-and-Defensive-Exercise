FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/airport_ot/ services/airport_ot/
WORKDIR /app/services/airport_ot
EXPOSE 8206
EXPOSE 502
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8206"]
