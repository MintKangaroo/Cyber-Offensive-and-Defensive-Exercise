FROM python:3.11-slim-bookworm
WORKDIR /app
COPY pumpctl /app/pumpctl
COPY server.py /app/server.py
RUN chmod +x /app/pumpctl
ENV CHALLENGE_SECRET=pwn014-dev-secret
ENV PORT=9024
EXPOSE 9024
CMD ["python","server.py"]
