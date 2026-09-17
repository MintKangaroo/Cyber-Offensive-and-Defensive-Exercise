FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY turbinectl /app/turbinectl
COPY server.py /app/server.py
RUN chmod +x /app/turbinectl
ENV CHALLENGE_SECRET=pwn018-dev-secret
ENV PORT=9028
EXPOSE 9028
CMD ["python3","server.py"]
