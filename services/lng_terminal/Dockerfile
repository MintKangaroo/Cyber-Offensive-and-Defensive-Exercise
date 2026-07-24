FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/lng_terminal/ services/lng_terminal/
WORKDIR /app/services/lng_terminal
EXPOSE 8204
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8204"]
