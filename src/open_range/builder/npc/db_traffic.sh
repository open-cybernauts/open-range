#!/usr/bin/env bash
# Level 0 NPC: Database traffic generator (mysql query loop)
#
# Simulates application database queries -- SELECT, INSERT operations
# that a normal web application backend would generate.
#
# Environment variables:
#   DB_HOST    - hostname of the database server (default: db)
#   RATE_LAMBDA - queries per minute (default: 20)

set -euo pipefail

DB_HOST="${DB_HOST:-db}"
RATE_LAMBDA="${RATE_LAMBDA:-20}"

INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

DB_NAME="referral_db"

# Application-level queries that a normal app would run
QUERIES=(
    "SELECT id, first_name, last_name FROM ${DB_NAME}.patients LIMIT 5"
    "SELECT id, status, specialist FROM ${DB_NAME}.patient_referrals ORDER BY created_at DESC LIMIT 3"
    "SELECT COUNT(*) FROM ${DB_NAME}.patient_referrals WHERE status='Pending'"
    "SELECT id, amount_due, status FROM ${DB_NAME}.billing WHERE status='Open'"
    "SELECT username, role, department FROM ${DB_NAME}.users LIMIT 10"
    "UPDATE ${DB_NAME}.billing SET last_updated=CURDATE() WHERE id=5001"
    "SELECT p.first_name, p.last_name, r.status FROM ${DB_NAME}.patients p JOIN ${DB_NAME}.patient_referrals r ON p.id=r.patient_id LIMIT 5"
    "INSERT INTO ${DB_NAME}.access_log (user_id, action, ip) VALUES (3, 'view_referrals', '10.0.1.10')"
)

# App database credentials (non-privileged)
DB_USER="app_user"
DB_PASS="AppUs3r!2024"

echo "[NPC-DB] Starting DB traffic to ${DB_HOST} at ${RATE_LAMBDA} queries/min"

while true; do
    IDX=$(( RANDOM % ${#QUERIES[@]} ))
    QUERY="${QUERIES[$IDX]}"

    mysql -h "${DB_HOST}" \
          -u "${DB_USER}" \
          -p"${DB_PASS}" \
          -e "${QUERY}" 2>/dev/null || true

    sleep "${INTERVAL}"
done
