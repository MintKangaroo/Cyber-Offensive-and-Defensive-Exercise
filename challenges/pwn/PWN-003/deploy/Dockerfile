FROM python:3.11-slim
WORKDIR /app
COPY scada /app/scada
COPY server.py /app/server.py
RUN chmod +x /app/scada
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9013
EXPOSE 9013
CMD ["python","server.py"]
