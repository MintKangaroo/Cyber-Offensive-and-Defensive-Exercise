FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scadaunlink /app/scadaunlink
COPY server.py /app/server.py
RUN chmod +x /app/scadaunlink
ENV CHALLENGE_SECRET=pwn021-dev-secret
ENV PORT=9031
EXPOSE 9031
CMD ["python3","server.py"]
