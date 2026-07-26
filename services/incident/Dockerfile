FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/incident/ services/incident/
EXPOSE 8095
CMD ["uvicorn", "services.incident.main:app", "--host", "0.0.0.0", "--port", "8095"]
