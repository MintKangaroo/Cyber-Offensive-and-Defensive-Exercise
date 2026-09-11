FROM python:3.11-slim
WORKDIR /app
COPY damctl /app/damctl
COPY server.py /app/server.py
RUN chmod +x /app/damctl
ENV CHALLENGE_SECRET=pwn009-dev-secret
ENV PORT=9019
EXPOSE 9019
CMD ["python","server.py"]
