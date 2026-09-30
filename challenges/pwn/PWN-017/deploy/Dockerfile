FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY feederctl /app/feederctl
COPY server.py /app/server.py
RUN chmod +x /app/feederctl
# CHALLENGE_SECRET 은 런타임 주입(기본값 없음, fail-closed — 감사 S-3).
ENV PORT=9027
EXPOSE 9027
CMD ["python3","server.py"]
