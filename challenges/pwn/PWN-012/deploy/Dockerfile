FROM python:3.11-slim
WORKDIR /app
COPY plcsafe /app/plcsafe
COPY server.py /app/server.py
RUN chmod +x /app/plcsafe
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9022
EXPOSE 9022
CMD ["python","server.py"]
