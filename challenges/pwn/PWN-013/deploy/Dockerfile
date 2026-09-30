FROM python:3.11-slim
WORKDIR /app
COPY hmicon /app/hmicon
COPY server.py /app/server.py
RUN chmod +x /app/hmicon
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9023
EXPOSE 9023
CMD ["python","server.py"]
