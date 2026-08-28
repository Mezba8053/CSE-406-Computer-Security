FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 3100 3101

CMD ["sh", "-c", "node academy-site/server.js & node community-site/server.js & wait"]
