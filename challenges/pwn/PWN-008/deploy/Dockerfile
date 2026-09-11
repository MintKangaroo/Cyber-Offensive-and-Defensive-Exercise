FROM python:3.11-slim
WORKDIR /app
COPY gasctl /app/gasctl
COPY server.py /app/server.py
RUN chmod +x /app/gasctl
ENV CHALLENGE_SECRET=pwn008-dev-secret
ENV PORT=9018
EXPOSE 9018
CMD ["python","server.py"]
