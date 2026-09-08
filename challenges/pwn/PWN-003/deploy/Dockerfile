FROM python:3.11-slim
WORKDIR /app
COPY scada /app/scada
COPY server.py /app/server.py
RUN chmod +x /app/scada
ENV CHALLENGE_SECRET=pwn003-dev-secret
ENV PORT=9013
EXPOSE 9013
CMD ["python","server.py"]
