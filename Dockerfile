# =============================================================================
# OpenRange — Production All-in-One Dockerfile
# =============================================================================
# Python 3.11 base image with system packages available for procedural
# service provisioning.  The OpenEnv server (uvicorn) is the only process
# started at boot — individual services (mysql, nginx, slapd, …) are
# started/stopped dynamically by RangeEnvironment.reset() based on the
# active snapshot manifest.  No services are hardcoded.
# =============================================================================

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System packages ───────────────────────────────────────────────────────
# Install base packages that all tiers need.  Higher tiers add extras via
# the TIER_PACKAGES build arg (tier1, tier2, tier3).
# The Builder/manifest decides which ones actually run per episode.

ARG TIER_PACKAGES="tier1"

# --- Tier 1 (base) ---
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
    # SMB client (for agent enumeration)
    smbclient \
    # Recon & exploitation (available to agents via subprocess)
    nmap \
    netcat-openbsd dnsutils tcpdump curl wget sshpass \
    iputils-ping whois \
    # Utilities
    jq procps iproute2 git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# --- Tier 2 (+ VPN, cron) ---
RUN if echo "${TIER_PACKAGES}" | grep -qE "tier[2-9]"; then \
        apt-get update && apt-get install -y --no-install-recommends \
            openvpn easy-rsa cron \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# --- Tier 3 (+ Redis, PostgreSQL, CI tooling) ---
RUN if echo "${TIER_PACKAGES}" | grep -qE "tier[3-9]"; then \
        apt-get update && apt-get install -y --no-install-recommends \
            redis-server postgresql postgresql-client \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Python-based security tools (not in Debian repos)
RUN pip install --no-cache-dir sqlmap

# ── 2. Install uv for dependency management ──────────────────────────────────

RUN pip install --no-cache-dir uv

# ── 3. Create base directories ───────────────────────────────────────────────

RUN mkdir -p /var/log/siem/consolidated /run/sshd \
    /var/run/mysqld /var/log/mysql /var/log/nginx \
    && chown mysql:mysql /var/run/mysqld /var/log/mysql 2>/dev/null || true \
    && chmod 755 /var/log/siem

# ── 4. Copy application code and install Python deps ─────────────────────────

WORKDIR /app
COPY . /app/env
WORKDIR /app/env

ENV UV_PROJECT_ENVIRONMENT=/app/.venv
RUN uv venv --python python3.11 /app/.venv \
    && if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

# ── 5. Environment ───────────────────────────────────────────────────────────

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env:$PYTHONPATH"
ENV OPENRANGE_EXECUTION_MODE=subprocess
# Enable the managed runtime so reset() boots real services from the manifest
ENV OPENRANGE_RUNTIME_MANIFEST=manifests/tier1_basic.yaml
ENV OPENRANGE_RUNTIME_VALIDATOR_PROFILE=offline
ENV OPENRANGE_SNAPSHOT_POOL_SIZE=1

# ── 6. Health check ──────────────────────────────────────────────────────────

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# ── 7. Start only the OpenEnv server — services are snapshot-driven ──────────

CMD ["python3", "-m", "uvicorn", "open_range.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
