FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
RUN apt-get update -qq && apt-get install -y -qq python3 >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY rtupivot /app/rtupivot
COPY server.py /app/server.py
RUN chmod +x /app/rtupivot
ENV CHALLENGE_SECRET=pwn022-dev-secret
ENV PORT=9032
EXPOSE 9032
CMD ["python3","server.py"]
