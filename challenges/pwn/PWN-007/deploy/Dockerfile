FROM python:3.11-slim
WORKDIR /app
COPY logd /app/logd
COPY server.py /app/server.py
RUN chmod +x /app/logd
ENV CHALLENGE_SECRET=pwn007-dev-secret
ENV PORT=9017
EXPOSE 9017
CMD ["python","server.py"]
