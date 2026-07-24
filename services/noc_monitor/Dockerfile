FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/core/ services/core/
COPY services/noc_monitor/ services/noc_monitor/
WORKDIR /app/services/noc_monitor/api
EXPOSE 8070
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8070"]
