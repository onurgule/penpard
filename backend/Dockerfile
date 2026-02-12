FROM node:20-alpine

WORKDIR /app

# Install build dependencies for better-sqlite3 and native modules
RUN apk add --no-cache python3 make g++

# Install dependencies first (layer caching)
COPY package*.json ./
RUN npm ci --build-from-source

# Copy source
COPY . .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 4000

# Development mode
CMD ["npm", "run", "dev"]
