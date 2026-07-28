FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/hospital_ot/ services/hospital_ot/
WORKDIR /app/services/hospital_ot
EXPOSE 8208
EXPOSE 502
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8208"]
