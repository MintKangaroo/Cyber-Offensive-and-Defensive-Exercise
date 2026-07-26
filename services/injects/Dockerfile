FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/injects/ services/injects/
EXPOSE 8096
CMD ["uvicorn", "services.injects.main:app", "--host", "0.0.0.0", "--port", "8096"]
