FROM python:3.11-slim
WORKDIR /app
COPY gridreg /app/gridreg
COPY server.py /app/server.py
RUN chmod +x /app/gridreg
ENV CHALLENGE_SECRET=pwn010-dev-secret
ENV PORT=9020
EXPOSE 9020
CMD ["python","server.py"]
