FROM python:3.11-slim
WORKDIR /app
COPY reactor /app/reactor
COPY server.py /app/server.py
RUN chmod +x /app/reactor
ENV CHALLENGE_SECRET=pwn006-dev-secret
ENV PORT=9016
EXPOSE 9016
CMD ["python","server.py"]
