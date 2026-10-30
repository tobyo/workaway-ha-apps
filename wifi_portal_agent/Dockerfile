FROM node:22-alpine

WORKDIR /app
COPY app/ /app/

# No npm dependencies: Node's built-in http/https/crypto only.
CMD ["node", "/app/server.mjs"]
