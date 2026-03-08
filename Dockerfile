# =============================================================================
# OpenRange — Production All-in-One Dockerfile
# =============================================================================
# Python 3.11 base + all range services installed via apt.
# No PPA needed — python:3.11-slim-bookworm ships Python 3.11 natively.
# =============================================================================

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System packages: services + security tools ────────────────────────────

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Web
    nginx \
    # Database
    default-mysql-server default-mysql-client \
    # LDAP
    slapd ldap-utils \
    # Logging
    rsyslog \
    # File sharing
    samba \
    # Mail
    postfix \
    # SSH
    openssh-server \
    # Security tools (agent toolkit — no artificial allowlists)
    nmap sqlmap hydra nikto \
    netcat-openbsd dnsutils tcpdump curl wget sshpass \
    iputils-ping whois \
    # Utilities
    jq procps iproute2 git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Install uv for Python dependency management ──────────────────────────

RUN pip install --no-cache-dir uv

# ── 3. Create directories and fix permissions ────────────────────────────────

RUN mkdir -p /var/log/siem/consolidated /run/sshd /run/php \
    /var/run/mysqld /var/log/mysql /var/log/nginx \
    && chown mysql:mysql /var/run/mysqld /var/log/mysql 2>/dev/null || true \
    && chmod 755 /var/log/siem

# ── 4. Copy application code and install Python deps ────────────────────────

WORKDIR /app
COPY . /app/env
WORKDIR /app/env

RUN uv venv --python python3.11 /app/.venv \
    && . /app/.venv/bin/activate \
    && if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

RUN chmod +x /app/env/start.sh 2>/dev/null || true

# ── 5. Environment ──────────────────────────────────────────────────────────

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env:$PYTHONPATH"
ENV OPENRANGE_EXECUTION_MODE=subprocess

# ── 6. Health check (60s start-period for service boot) ─────────────────────

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

CMD ["bash", "/app/env/start.sh"]
