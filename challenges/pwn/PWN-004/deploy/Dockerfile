FROM python:3.11-slim
WORKDIR /app
COPY flow /app/flow
COPY server.py /app/server.py
RUN chmod +x /app/flow
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9014
EXPOSE 9014
CMD ["python","server.py"]
