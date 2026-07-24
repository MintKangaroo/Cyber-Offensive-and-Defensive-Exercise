FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY scenarios/ scenarios/
COPY services/scenario_engine/ services/scenario_engine/
EXPOSE 8045
CMD ["uvicorn", "services.scenario_engine.api:app", "--host", "0.0.0.0", "--port", "8045"]
