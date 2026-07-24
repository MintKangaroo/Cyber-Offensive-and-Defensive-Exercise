FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ shared/
COPY services/instructor_api/ services/instructor_api/
EXPOSE 8050
CMD ["uvicorn", "services.instructor_api.main:app", "--host", "0.0.0.0", "--port", "8050"]
