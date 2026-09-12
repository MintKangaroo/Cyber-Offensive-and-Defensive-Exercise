FROM python:3.11-slim
WORKDIR /app
COPY plcsafe /app/plcsafe
COPY server.py /app/server.py
RUN chmod +x /app/plcsafe
ENV CHALLENGE_SECRET=pwn012-dev-secret
ENV PORT=9022
EXPOSE 9022
CMD ["python","server.py"]
