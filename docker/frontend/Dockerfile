# =============================================================================
# Secret Leak Guard v2.0 - Frontend Dashboard Dockerfile
# Multi-Stage Build: Node.js 20 Alpine Builder -> Nginx 1.27.5 Alpine Runtime
# Enforces non-root execution as UID 10001 on port 3000
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build & Compilation Stage
# -----------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY frontend/package.json ./

# Install build dependencies
RUN npm install --no-audit --no-fund

# Copy frontend source code & assets
COPY frontend/ ./

# Compile optimized static bundle
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Hardened Nginx 1.27.5 Static Runtime Stage
# -----------------------------------------------------------------------------
FROM nginx:1.27.5-alpine AS runtime

LABEL maintainer="DevOps Team <devops@secretleakguard.io>" \
      version="2.0.0" \
      service="frontend-dashboard" \
      description="Production hardened React 18.2 dashboard for Secret Leak Guard v2.0"

# Install curl / wget for healthcheck
RUN apk add --no-cache curl ca-certificates

# Create non-root group and user UID 10001
RUN addgroup -g 10001 -S slggroup && \
    adduser -u 10001 -S -D -G slggroup -h /home/slguser slguser

# Copy custom non-root Nginx configuration
COPY frontend/nginx.conf /etc/nginx/nginx.conf

# Copy compiled React production distribution from builder
COPY --from=builder --chown=10001:10001 /app/dist /usr/share/nginx/html

# Prepare temporary directories with correct non-root permissions
RUN mkdir -p /var/cache/nginx /var/run /var/log/nginx /tmp/nginx && \
    chown -R 10001:10001 /var/cache/nginx /var/run /var/log/nginx /tmp /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

# Switch to unprivileged non-root user UID 10001
USER 10001:10001

# Expose internal frontend service port
EXPOSE 3000

# Explicit container healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
