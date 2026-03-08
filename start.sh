#!/usr/bin/env bash
# =============================================================================
# OpenRange — All-in-One Service Startup Script
# =============================================================================
# Follows the OpenEnv openapp_env pattern:
#   1. Create required directories
#   2. Start background services with readiness polling
#   3. exec uvicorn as PID 1
# =============================================================================

set -uo pipefail

LOGDIR="/var/log/siem"
CONSOLIDATED="${LOGDIR}/consolidated"

# Track background PIDs for cleanup
PIDS=()

cleanup() {
    echo "[start.sh] Shutting down services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[start.sh] All services stopped."
}
trap cleanup EXIT INT TERM

# ── 1. Create required directories ──────────────────────────────────────────

echo "[start.sh] Creating required directories..."
mkdir -p "${CONSOLIDATED}"
mkdir -p /run/php
mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld
chown mysql:mysql "${LOGDIR}" /var/log/mysql 2>/dev/null || true
mkdir -p /var/run/sshd
mkdir -p /var/run/slapd
mkdir -p /var/lib/samba/private
mkdir -p /var/log/nginx
mkdir -p /var/log/mysql

# ── 2. MySQL / MariaDB ────────────────────────────────────────────────────

echo "[start.sh] Starting MySQL/MariaDB..."
# Detect which daemon is available (MariaDB on Bookworm, MySQL on Jammy)
MYSQLD=$(command -v mariadbd || command -v mysqld || echo "")
if [ -n "$MYSQLD" ]; then
    if [ ! -d /var/lib/mysql/mysql ]; then
        echo "[start.sh]   Initializing database data directory..."
        if command -v mariadb-install-db >/dev/null 2>&1; then
            mariadb-install-db --user=mysql 2>&1 | tee "${LOGDIR}/mysql.log"
        else
            mysqld --initialize-insecure --user=mysql 2>&1 | tee "${LOGDIR}/mysql.log"
        fi
    fi

    $MYSQLD --user=mysql --log-error="${LOGDIR}/mysql.log" &
    PIDS+=($!)

    echo -n "[start.sh]   Waiting for database readiness"
    ADMIN_CMD=$(command -v mariadb-admin || command -v mysqladmin || echo "")
    for i in $(seq 1 30); do
        if [ -n "$ADMIN_CMD" ] && $ADMIN_CMD ping --silent 2>/dev/null; then
            echo " ready (${i}s)"
            break
        fi
        echo -n "."
        sleep 1
        if [ "$i" -eq 30 ]; then
            echo " TIMEOUT"
            echo "[start.sh]   WARNING: Database did not become ready in 30s"
        fi
    done
else
    echo "[start.sh]   MySQL/MariaDB not installed, skipping"
fi

# ── 3. PHP-FPM ──────────────────────────────────────────────────────────────

echo "[start.sh] Starting PHP-FPM..."
# Find the correct php-fpm binary (varies by distro)
PHP_FPM=$(command -v php-fpm8.2 || command -v php-fpm8.1 || command -v php-fpm || echo "")
if [ -n "$PHP_FPM" ]; then
    $PHP_FPM --nodaemonize --force-stderr \
        > "${LOGDIR}/php-fpm.log" 2>&1 &
    PIDS+=($!)

    # Poll for PHP-FPM socket (path varies)
    echo -n "[start.sh]   Waiting for PHP-FPM readiness"
    for i in $(seq 1 15); do
        if ls /run/php/php*-fpm.sock >/dev/null 2>&1; then
            echo " ready (${i}s)"
            break
        fi
        echo -n "."
        sleep 1
        if [ "$i" -eq 15 ]; then
            echo " TIMEOUT"
            echo "[start.sh]   WARNING: PHP-FPM socket not found after 15s"
        fi
    done
else
    echo "[start.sh]   PHP-FPM not installed, skipping"
fi

# ── 4. Nginx ────────────────────────────────────────────────────────────────

echo "[start.sh] Starting Nginx..."
nginx -g "daemon off;" \
    > "${LOGDIR}/nginx.log" 2>&1 &
PIDS+=($!)

echo -n "[start.sh]   Waiting for Nginx readiness"
for i in $(seq 1 10); do
    if curl -sf http://localhost:80/ >/dev/null 2>&1 || \
       curl -sf http://localhost:80/ 2>&1 | grep -q ""; then
        echo " ready (${i}s)"
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 10 ]; then
        echo " TIMEOUT"
        echo "[start.sh]   WARNING: Nginx did not respond within 10s"
    fi
done

# ── 5. rsyslog ──────────────────────────────────────────────────────────────

echo "[start.sh] Starting rsyslog..."
rsyslogd -n \
    > "${LOGDIR}/rsyslog.log" 2>&1 &
PIDS+=($!)
echo "[start.sh]   rsyslog started (PID $!)"

# ── 6. slapd (OpenLDAP) ────────────────────────────────────────────────────

echo "[start.sh] Starting slapd..."
if command -v slapd >/dev/null 2>&1; then
    slapd -h "ldap:/// ldapi:///" -u openldap -g openldap \
        > "${LOGDIR}/slapd.log" 2>&1 &
    PIDS+=($!)

    echo -n "[start.sh]   Waiting for slapd readiness"
    for i in $(seq 1 10); do
        if ldapsearch -x -H ldap://localhost -b "" -s base namingContexts >/dev/null 2>&1; then
            echo " ready (${i}s)"
            break
        fi
        echo -n "."
        sleep 1
        if [ "$i" -eq 10 ]; then
            echo " TIMEOUT"
            echo "[start.sh]   WARNING: slapd did not respond within 10s"
        fi
    done
else
    echo "[start.sh]   slapd not installed, skipping"
fi

# ── 7. Samba (smbd) ─────────────────────────────────────────────────────────

echo "[start.sh] Starting Samba..."
if command -v smbd >/dev/null 2>&1; then
    smbd --foreground --no-process-group \
        > "${LOGDIR}/smbd.log" 2>&1 &
    PIDS+=($!)

    echo -n "[start.sh]   Waiting for smbd readiness"
    for i in $(seq 1 10); do
        if smbclient -L localhost -N >/dev/null 2>&1; then
            echo " ready (${i}s)"
            break
        fi
        echo -n "."
        sleep 1
        if [ "$i" -eq 10 ]; then
            echo " TIMEOUT"
            echo "[start.sh]   WARNING: smbd did not respond within 10s"
        fi
    done
else
    echo "[start.sh]   smbd not installed, skipping"
fi

# ── 8. Postfix ──────────────────────────────────────────────────────────────

echo "[start.sh] Starting Postfix..."
if command -v postfix >/dev/null 2>&1; then
    postfix start > "${LOGDIR}/postfix.log" 2>&1 || true
    echo "[start.sh]   Postfix started"
else
    echo "[start.sh]   postfix not installed, skipping"
fi

# ── 9. SSH ──────────────────────────────────────────────────────────────────

echo "[start.sh] Starting SSH..."
if command -v sshd >/dev/null 2>&1; then
    /usr/sbin/sshd -E "${LOGDIR}/sshd.log" &
    PIDS+=($!)
    echo "[start.sh]   sshd started (PID $!)"
else
    echo "[start.sh]   sshd not installed, skipping"
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo "============================================================"
echo "[start.sh] All services started. PIDs: ${PIDS[*]}"
echo "[start.sh] Logs at: ${LOGDIR}/"
echo "[start.sh] Starting uvicorn on port 8000..."
echo "============================================================"

# ── 10. exec uvicorn as PID 1 ──────────────────────────────────────────────

cd /app/env
exec python3 -m uvicorn open_range.server.app:app --host 0.0.0.0 --port 8000
