FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/aar_report/ services/aar_report/
EXPOSE 8090
CMD ["uvicorn", "services.aar_report.main:app", "--host", "0.0.0.0", "--port", "8090"]
