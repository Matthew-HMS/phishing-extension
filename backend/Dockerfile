# Phishing Guard backend — runs on Cloud Run, or any Docker host (e.g. a VM).
FROM node:24-alpine

WORKDIR /app

# Install production deps first (better layer caching).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source.
COPY . .

# Cloud Run injects PORT (usually 8080); server.js reads process.env.PORT.
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.js"]
