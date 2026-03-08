"""Level 0 NPC traffic generators.

Each function returns a shell script string that can be injected into
containers via ``docker exec``. The scripts generate realistic background
traffic at configurable rates, labeled with ``# NPC_TRAFFIC`` comments
and custom headers/markers so the FP scoring system can distinguish NPC
traffic from real attack traffic.

All generated scripts:
- Run in an infinite loop with configurable rate
- Include ``X-NPC-Traffic: true`` headers (HTTP) or comment markers
- Use ``sleep`` with jitter for realistic timing
- Are safe to run concurrently
"""

from __future__ import annotations


def generate_http_traffic_script(rate: int = 10) -> str:
    """Generate a shell script that produces HTTP traffic via curl.

    The script hits common web endpoints at the given rate (requests/minute)
    with an ``X-NPC-Traffic: true`` header for FP scoring.

    Args:
        rate: Target requests per minute. Must be >= 1.

    Returns:
        A bash script string ready for injection into a container.
    """
    rate = max(1, rate)
    # Sleep interval in seconds between requests, with jitter
    interval = 60 / rate

    return f"""\
#!/bin/bash
# NPC_TRAFFIC: HTTP background traffic generator
# Rate: {rate} requests/minute
# Label: X-NPC-Traffic header for FP scoring

ENDPOINTS=(
    "/"
    "/index.html"
    "/login"
    "/search?q=quarterly+report"
    "/search?q=meeting+notes"
    "/api/users/me"
    "/api/products"
    "/dashboard"
    "/about"
    "/contact"
)

METHODS=("GET" "GET" "GET" "GET" "POST")

while true; do
    # Pick a random endpoint
    IDX=$((RANDOM % ${{#ENDPOINTS[@]}}))
    ENDPOINT="${{ENDPOINTS[$IDX]}}"

    # Pick a random method (weighted toward GET)
    MIDX=$((RANDOM % ${{#METHODS[@]}}))
    METHOD="${{METHODS[$MIDX]}}"

    # Add NPC_TRAFFIC label via custom header
    if [ "$METHOD" = "POST" ]; then
        curl -s -o /dev/null -X POST \\
            -H "X-NPC-Traffic: true" \\
            -H "User-Agent: Mozilla/5.0 (NPC Employee Browser)" \\
            -H "Content-Type: application/x-www-form-urlencoded" \\
            -d "username=npc_user&query=test" \\
            "http://localhost$ENDPOINT" 2>/dev/null || true
    else
        curl -s -o /dev/null \\
            -H "X-NPC-Traffic: true" \\
            -H "User-Agent: Mozilla/5.0 (NPC Employee Browser)" \\
            "http://localhost$ENDPOINT" 2>/dev/null || true
    fi

    # Sleep with jitter: base interval +/- 30%
    JITTER=$(awk "BEGIN {{printf \\"%.1f\\", {interval} * (0.7 + 0.6 * rand())}}")
    sleep "$JITTER"
done
"""


def generate_ssh_traffic_script(rate: int = 2) -> str:
    """Generate a shell script that produces SSH traffic via sshpass.

    Simulates employees performing routine SSH operations (file checks,
    system status, etc.) at the given rate.

    Args:
        rate: Target SSH sessions per minute. Must be >= 1.

    Returns:
        A bash script string ready for injection into a container.
    """
    rate = max(1, rate)
    interval = 60 / rate

    return f"""\
#!/bin/bash
# NPC_TRAFFIC: SSH background traffic generator
# Rate: {rate} sessions/minute
# Label: NPC_TRAFFIC marker in command output

COMMANDS=(
    "uptime"
    "df -h"
    "who"
    "ls -la /var/log/"
    "cat /etc/hostname"
    "ps aux --sort=-pcpu | head -5"
    "free -m"
    "last -5"
)

SSH_USERS=("npc_admin" "npc_operator" "npc_support")
SSH_HOST="localhost"

while true; do
    # Pick a random command and user
    CIDX=$((RANDOM % ${{#COMMANDS[@]}}))
    CMD="${{COMMANDS[$CIDX]}}"
    UIDX=$((RANDOM % ${{#SSH_USERS[@]}}))
    USER="${{SSH_USERS[$UIDX]}}"

    # NPC_TRAFFIC: SSH session from $USER
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "npc_password" ssh -o StrictHostKeyChecking=no \\
            -o UserKnownHostsFile=/dev/null \\
            "$USER@$SSH_HOST" "$CMD" 2>/dev/null || true
    else
        # Fallback: just run the command locally with NPC_TRAFFIC marker
        echo "# NPC_TRAFFIC: SSH simulation by $USER"
        $CMD 2>/dev/null || true
    fi

    # Sleep with jitter
    JITTER=$(awk "BEGIN {{printf \\"%.1f\\", {interval} * (0.7 + 0.6 * rand())}}")
    sleep "$JITTER"
done
"""


def generate_db_traffic_script(rate: int = 5) -> str:
    """Generate a shell script that produces MySQL query traffic.

    Simulates application queries (SELECTs, INSERTs) at the given rate.
    Uses a ``-- NPC_TRAFFIC`` SQL comment for FP scoring.

    Args:
        rate: Target queries per minute. Must be >= 1.

    Returns:
        A bash script string ready for injection into a container.
    """
    rate = max(1, rate)
    interval = 60 / rate

    return f"""\
#!/bin/bash
# NPC_TRAFFIC: Database background traffic generator
# Rate: {rate} queries/minute
# Label: -- NPC_TRAFFIC SQL comment for FP scoring

DB_HOST="localhost"
DB_USER="app_user"
DB_PASS="app_password"
DB_NAME="app_db"

QUERIES=(
    "SELECT /* NPC_TRAFFIC */ COUNT(*) FROM users;"
    "SELECT /* NPC_TRAFFIC */ id, username FROM users ORDER BY last_login DESC LIMIT 10;"
    "SELECT /* NPC_TRAFFIC */ * FROM products WHERE active = 1 LIMIT 20;"
    "SELECT /* NPC_TRAFFIC */ COUNT(*) FROM sessions WHERE created_at > NOW() - INTERVAL 1 HOUR;"
    "INSERT /* NPC_TRAFFIC */ INTO audit_log (action, user, ts) VALUES ('page_view', 'npc_user', NOW());"
    "SELECT /* NPC_TRAFFIC */ table_name FROM information_schema.tables WHERE table_schema = '$DB_NAME' LIMIT 5;"
    "SELECT /* NPC_TRAFFIC */ 1;"
    "SHOW /* NPC_TRAFFIC */ PROCESSLIST;"
)

while true; do
    # Pick a random query
    QIDX=$((RANDOM % ${{#QUERIES[@]}}))
    QUERY="${{QUERIES[$QIDX]}}"

    # Execute query with NPC_TRAFFIC label
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" \\
        -e "$QUERY" 2>/dev/null || true

    # Sleep with jitter
    JITTER=$(awk "BEGIN {{printf \\"%.1f\\", {interval} * (0.7 + 0.6 * rand())}}")
    sleep "$JITTER"
done
"""
