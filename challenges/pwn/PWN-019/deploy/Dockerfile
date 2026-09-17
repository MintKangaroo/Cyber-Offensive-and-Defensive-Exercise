FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY gridalloc /app/gridalloc
COPY server.py /app/server.py
RUN chmod +x /app/gridalloc
ENV CHALLENGE_SECRET=pwn019-dev-secret
ENV PORT=9029
EXPOSE 9029
CMD ["python3","server.py"]
