FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" numpy pydantic
COPY train_model.py .
RUN python3 train_model.py
COPY main.py .
ENV CHALLENGE_SECRET=ai007-dev-secret
EXPOSE 8107
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8107"]
