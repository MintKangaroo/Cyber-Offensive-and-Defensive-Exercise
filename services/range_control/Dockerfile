FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/range_control/ services/range_control/
EXPOSE 8055
CMD ["uvicorn", "services.range_control.main:app", "--host", "0.0.0.0", "--port", "8055"]
