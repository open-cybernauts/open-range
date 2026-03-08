# =============================================================================
# OpenRange — Production All-in-One Dockerfile
# =============================================================================
# Multi-stage build:
#   Stage 1 (builder): OpenEnv base image, install Python deps via uv sync
#   Stage 2 (runtime): Ubuntu 22.04 with all range services + Python env
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — install Python dependencies using the OpenEnv base image
# ---------------------------------------------------------------------------
ARG BASE_IMAGE=ghcr.io/meta-pytorch/openenv-base:latest
FROM ${BASE_IMAGE} AS builder

WORKDIR /app

COPY . /app/env
WORKDIR /app/env

# Install git for git+ dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Two-pass install for better layer caching
RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -f uv.lock ]; then \
        uv sync --frozen --no-install-project --no-editable; \
    else \
        uv sync --no-install-project --no-editable; \
    fi

RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

# ---------------------------------------------------------------------------
# Stage 2: Runtime — same base image (Python 3.11) + range services
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# Install ALL service packages in one RUN layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    php-fpm php-mysql php-ldap php-xml php-mbstring \
    default-mysql-server \
    slapd ldap-utils \
    rsyslog \
    samba \
    postfix \
    openssh-server \
    nmap sqlmap hydra nikto \
    netcat-openbsd dnsutils tcpdump curl wget sshpass \
    iputils-ping whois \
    jq procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create directories and fix permissions for services
RUN mkdir -p /var/log/siem/consolidated /run/sshd /run/php /var/run/mysqld /var/log/mysql \
    && (chown mysql:mysql /var/log/siem /var/run/mysqld /var/log/mysql 2>/dev/null || true) \
    && chmod 755 /var/log/siem

WORKDIR /app

# Copy the Python virtual environment from builder
COPY --from=builder /app/env/.venv /app/.venv

# Copy the application code from builder
COPY --from=builder /app/env /app/env

# Copy start.sh
COPY start.sh /app/env/start.sh
RUN chmod +x /app/env/start.sh

# Environment configuration
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env:$PYTHONPATH"
ENV OPENRANGE_EXECUTION_MODE=subprocess

# Health check — services need time to boot
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

CMD ["bash", "/app/env/start.sh"]
