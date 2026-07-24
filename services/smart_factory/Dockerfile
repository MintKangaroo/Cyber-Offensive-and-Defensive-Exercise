FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/smart_factory/ services/smart_factory/
WORKDIR /app/services/smart_factory
EXPOSE 8202
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8202"]
