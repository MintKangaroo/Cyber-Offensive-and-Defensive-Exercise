FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir scikit-learn numpy
COPY train_victim.py .
RUN python3 train_victim.py
