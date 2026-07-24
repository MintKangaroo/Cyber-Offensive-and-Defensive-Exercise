FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic
COPY main.py .
ENV CHALLENGE_SECRET=ics000-dev-secret
EXPOSE 8110
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8110"]
