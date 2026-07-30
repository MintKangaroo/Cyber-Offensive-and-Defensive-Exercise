FROM python:3.12-slim
ARG CYBER_RANGE_BASE_DIGEST=""
ARG PATCH_TRAVERSAL=false
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY services/__init__.py /app/services/__init__.py
COPY services/attack_defense /app/services/attack_defense
RUN mkdir -p /data && chown 65532:65532 /data
ENV PYTHONPATH=/app \
    SERVICE_DATA_DIR=/data \
    PATCH_TRAVERSAL=${PATCH_TRAVERSAL} \
    DEMO_SERVICE_MODULE=services.attack_defense.demo_services.file_vault.main
LABEL org.cyber-range.service="file-vault" \
      org.cyber-range.base-digest="${CYBER_RANGE_BASE_DIGEST}"
USER 65532:65532
EXPOSE 9000 9001
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["python", "-m", "services.attack_defense.demo_services.healthcheck"]
CMD ["python", "-m", "services.attack_defense.demo_services.serve"]
