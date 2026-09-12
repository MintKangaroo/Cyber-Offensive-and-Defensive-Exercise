FROM python:3.11-slim
WORKDIR /app
COPY relayctl /app/relayctl
COPY server.py /app/server.py
RUN chmod +x /app/relayctl
ENV CHALLENGE_SECRET=pwn011-dev-secret
ENV PORT=9021
EXPOSE 9021
CMD ["python","server.py"]
