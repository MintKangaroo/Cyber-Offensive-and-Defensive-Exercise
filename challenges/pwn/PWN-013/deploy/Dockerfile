FROM python:3.11-slim
WORKDIR /app
COPY hmicon /app/hmicon
COPY server.py /app/server.py
RUN chmod +x /app/hmicon
ENV CHALLENGE_SECRET=pwn013-dev-secret
ENV PORT=9023
EXPOSE 9023
CMD ["python","server.py"]
