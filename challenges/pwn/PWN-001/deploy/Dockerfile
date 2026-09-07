FROM python:3.11-slim
WORKDIR /app
COPY ptp /app/ptp
COPY server.py /app/server.py
RUN chmod +x /app/ptp
ENV CHALLENGE_SECRET=pwn001-dev-secret
ENV PORT=9011
EXPOSE 9011
CMD ["python", "server.py"]
