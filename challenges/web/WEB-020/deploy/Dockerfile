FROM node:20-slim
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
ENV CHALLENGE_SECRET=web020-dev-secret
ENV PATCH_WEB_020=false
EXPOSE 8120
CMD ["node", "server.js"]
