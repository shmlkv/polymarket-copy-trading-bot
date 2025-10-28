# ==============================================================================
# POLYMARKET COPY TRADING BOT - DOCKER BUILD
# ==============================================================================
# Multi-stage build for optimized production image

# --- Build Stage ---
FROM node:18 AS build
WORKDIR /app

# Copy package manifests
COPY package*.json ./

# Install dependencies
# Use npm ci if package-lock.json exists, otherwise npm install
RUN npm ci || npm install

# Install TypeScript and fix chalk compatibility
# Note: chalk@5+ is ESM-only, so we use chalk@4 for CommonJS compatibility
RUN npm install --save-dev typescript && \
    npm uninstall chalk || true && \
    npm install chalk@4 --save

# Copy source code
COPY . .

# Build TypeScript to JavaScript
RUN npm run build

# --- Runtime Stage ---
FROM node:18
WORKDIR /app

# Copy built application from build stage
COPY --from=build /app /app

# Set production environment
ENV NODE_ENV=production

# Run allowance check before starting the bot
# This ensures USDC approval is set for Polymarket trading
CMD bash -c "npm run check-allowance && npm start"
