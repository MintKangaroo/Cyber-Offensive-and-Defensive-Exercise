FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY feederctl /app/feederctl
COPY server.py /app/server.py
RUN chmod +x /app/feederctl
ENV CHALLENGE_SECRET=pwn017-dev-secret
ENV PORT=9027
EXPOSE 9027
CMD ["python3","server.py"]
