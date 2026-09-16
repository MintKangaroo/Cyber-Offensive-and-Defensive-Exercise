FROM python:3.11-slim-bookworm
WORKDIR /app
COPY scadaheap /app/scadaheap
COPY server.py /app/server.py
RUN chmod +x /app/scadaheap
ENV CHALLENGE_SECRET=pwn016-dev-secret
ENV PORT=9026
EXPOSE 9026
CMD ["python","server.py"]
