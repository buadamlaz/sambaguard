# ═══════════════════════════════════════════════════════════════
# Stage 1: Build the Go binary
# ═══════════════════════════════════════════════════════════════
FROM golang:1.21-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies first (Docker layer caching)
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source
COPY . .

# Build the binary
# CGO disabled for modernc sqlite (pure Go)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -trimpath \
    -o sambaguard \
    ./cmd/server

# ═══════════════════════════════════════════════════════════════
# Stage 2: Runtime image
# ═══════════════════════════════════════════════════════════════
FROM debian:bookworm-slim

# Install Samba and runtime dependencies
# Note: smbpasswd is part of samba-common-bin, not a separate package on Debian
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    samba-common \
    samba-common-bin \
    ca-certificates \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root panel user
# Note: the panel itself needs to run as root to manage OS users/Samba
# However, we restrict capabilities where possible
RUN groupadd -r sambaguard && \
    useradd -r -g sambaguard -s /sbin/nologin -M sambaguard

# Create application directories
RUN mkdir -p \
    /var/lib/sambaguard/backups \
    /var/log/sambaguard \
    /etc/samba

# Copy the binary
COPY --from=builder /build/sambaguard /usr/local/bin/sambaguard
RUN chmod 755 /usr/local/bin/sambaguard

# Default smb.conf (minimal, will be managed by the panel)
COPY scripts/smb.conf.default /etc/samba/smb.conf

# Entrypoint script
COPY scripts/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8090/healthz || exit 1

# Use tini as init to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--", "/docker-entrypoint.sh"]
