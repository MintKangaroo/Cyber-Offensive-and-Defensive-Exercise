FROM python:3.11-slim-bookworm
WORKDIR /app
COPY valvectl /app/valvectl
COPY server.py /app/server.py
RUN chmod +x /app/valvectl
ENV CHALLENGE_SECRET=pwn015-dev-secret
ENV PORT=9025
EXPOSE 9025
CMD ["python","server.py"]
