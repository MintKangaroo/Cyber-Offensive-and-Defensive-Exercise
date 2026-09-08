FROM python:3.11-slim
WORKDIR /app
COPY sat /app/sat
COPY server.py /app/server.py
RUN chmod +x /app/sat
ENV CHALLENGE_SECRET=pwn005-dev-secret
ENV PORT=9015
EXPOSE 9015
CMD ["python","server.py"]
