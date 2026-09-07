FROM python:3.11-slim
WORKDIR /app
COPY valve /app/valve
COPY server.py /app/server.py
RUN chmod +x /app/valve
ENV CHALLENGE_SECRET=pwn002-dev-secret
ENV PORT=9012
EXPOSE 9012
CMD ["python","server.py"]
