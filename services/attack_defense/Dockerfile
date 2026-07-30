FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY shared /app/shared
COPY services/__init__.py /app/services/__init__.py
COPY services/attack_defense /app/services/attack_defense
RUN mkdir -p /data && chown 65532:65532 /data
ENV PYTHONPATH=/app
USER 65532:65532
EXPOSE 8100
CMD ["uvicorn", "services.attack_defense.main:app", "--host", "0.0.0.0", "--port", "8100", "--no-access-log"]
