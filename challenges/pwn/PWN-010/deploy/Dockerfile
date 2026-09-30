FROM python:3.11-slim
WORKDIR /app
COPY gridreg /app/gridreg
COPY server.py /app/server.py
RUN chmod +x /app/gridreg
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9020
EXPOSE 9020
CMD ["python","server.py"]
