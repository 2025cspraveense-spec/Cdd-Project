# =============================================================================
# Secret Leak Guard v2.0 - Unified Reverse Proxy Gateway Dockerfile
# Base Image: Nginx 1.27.5 Alpine with Non-Root Security Hardening (UID 10001)
# =============================================================================

FROM nginx:1.27.5-alpine AS config

COPY docker/gateway/nginx.conf /etc/nginx/nginx.conf

FROM nginx:1.27.5-alpine AS runtime

LABEL maintainer="DevOps Team <devops@secretleakguard.io>" \
      version="2.0.0" \
      service="unified-gateway" \
      description="Production hardened Nginx 1.27.5 reverse proxy gateway for Secret Leak Guard v2.0"

# Install curl and ca-certificates for health checks
RUN apk add --no-cache curl ca-certificates

# Create non-root group and user UID 10001
RUN addgroup -g 10001 -S slggroup && \
    adduser -u 10001 -S -D -G slggroup -h /home/slguser slguser

# Copy hardened Nginx configuration from the configuration stage
COPY --from=config /etc/nginx/nginx.conf /etc/nginx/nginx.conf

# Prepare permissions for non-root execution
RUN mkdir -p /var/cache/nginx /var/run /var/log/nginx /tmp/nginx && \
    touch /tmp/nginx.pid && \
    chown -R 10001:10001 /var/cache/nginx /var/run /var/log/nginx /etc/nginx /tmp /home/slguser && \
    chmod -R 755 /var/cache/nginx /var/log/nginx

# Switch to unprivileged non-root user UID 10001
USER 10001:10001

# Expose both proxy ports
EXPOSE 80 8080

# Explicit container healthcheck instruction
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

# Start Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
