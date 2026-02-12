FROM node:20-alpine

WORKDIR /app

# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

# Build for production (commented for dev)
# RUN npm run build

EXPOSE 3000

# Development mode
CMD ["npm", "run", "dev"]
