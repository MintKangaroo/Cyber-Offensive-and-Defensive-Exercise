FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY turbinectl /app/turbinectl
COPY server.py /app/server.py
RUN chmod +x /app/turbinectl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9028
EXPOSE 9028
CMD ["python3","server.py"]
