FROM python:3.11-slim
WORKDIR /app
COPY flow /app/flow
COPY server.py /app/server.py
RUN chmod +x /app/flow
ENV CHALLENGE_SECRET=pwn004-dev-secret
ENV PORT=9014
EXPOSE 9014
CMD ["python","server.py"]
