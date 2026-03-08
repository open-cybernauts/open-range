"""NPC action executor -- bridges NPC decisions to container state changes.

All actions are derived from the SnapshotSpec at init time, so they adapt
to whatever environment the Builder LLM generated.  No hardcoded pages,
tables, or endpoints.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from open_range.protocols import ContainerSet, NPCAction, NPCPersona, SnapshotSpec

logger = logging.getLogger(__name__)


class NPCActionExecutor:
    """Execute NPC actions inside Docker containers.

    At init, extracts available pages, shares, DB tables, and users from
    the snapshot so every action targets real resources in this environment.
    """

    def __init__(self, containers: ContainerSet, snapshot: SnapshotSpec) -> None:
        self.containers = containers
        # Derive available targets from the snapshot
        self._pages = _extract_web_pages(snapshot)
        self._shares = _extract_shares(snapshot)
        self._db_tables = _extract_db_tables(snapshot)
        self._users = _extract_users(snapshot)
        self._domain = snapshot.topology.get("domain", "corp.local")

    # ------------------------------------------------------------------
    # Routine actions (autonomous workday)
    # ------------------------------------------------------------------

    async def execute_routine(
        self,
        persona: NPCPersona,
        action: str,
        target: str,
        detail: str,
        email_body: str = "",
    ) -> dict[str, Any]:
        """Execute an autonomous work action derived from the snapshot."""
        username = _username_from_persona(persona)

        handler = {
            "browse": self._routine_browse,
            "send_email": self._routine_email,
            "lookup": self._routine_lookup,
            "access_share": self._routine_share,
            "login": self._routine_login,
            "query_db": self._routine_query_db,
            "idle": self._routine_idle,
        }.get(action, self._routine_idle)

        return await handler(persona, username, target, detail, email_body)

    async def _routine_browse(self, persona, username, target, detail, _eb):
        """Browse a page that exists in this snapshot."""
        path = target if target.startswith("/") else f"/{target}" if target else "/"
        # Fall back to a known page if target isn't in snapshot
        if path == "/" and self._pages:
            import random
            path = random.choice(self._pages)
        await self.containers.exec(
            "web",
            f'curl -s -o /dev/null -A "Mozilla/5.0 ({username})" "http://localhost{path}"',
        )
        return _log(persona, "browse", detail or f"Browsed {path}", f"web:{path}")

    async def _routine_email(self, persona, username, target, detail, body):
        """Send email to a colleague (picks a real user from topology)."""
        import random
        recipient = target
        if not recipient and self._users:
            recipient = random.choice(self._users)
        elif not recipient:
            recipient = "colleague"

        ts_i = int(time.time())
        content = body or f"Hi {recipient}, quick update: {detail or 'checking in'}."
        msg = (
            f"From: {username}@{self._domain}\\n"
            f"To: {recipient}@{self._domain}\\n"
            f"Subject: {detail or 'Update'}\\n\\n{content}"
        )
        await self.containers.exec(
            "mail",
            f"mkdir -p /var/mail/{username} "
            f"&& echo '{msg}' > /var/mail/{username}/sent_{ts_i}.eml",
        )
        return _log(persona, "send_email", detail or f"Emailed {recipient}", f"mail:{username}")

    async def _routine_lookup(self, persona, username, target, detail, _eb):
        """Look up data on the web app -- uses whatever search/lookup page exists."""
        # Find a page with query params in the snapshot
        lookup_pages = [p for p in self._pages if "?" in p or "lookup" in p or "search" in p]
        if lookup_pages:
            import random
            page = random.choice(lookup_pages)
        elif self._pages:
            import random
            page = random.choice(self._pages) + "?q=" + (target or "status")
        else:
            page = f"/?q={target or 'data'}"

        await self.containers.exec(
            "web",
            f'curl -s -o /dev/null -A "Mozilla/5.0 ({username})" "http://localhost{page}"',
        )
        return _log(persona, "lookup", detail or f"Searched: {target}", f"web:{page}")

    async def _routine_share(self, persona, username, target, detail, _eb):
        """Access a file share that exists in this snapshot."""
        import random
        share = target or (random.choice(self._shares) if self._shares else "general")
        await self.containers.exec(
            "files",
            f"ls /srv/shares/{share}/ 2>/dev/null || true",
        )
        return _log(persona, "access_share", detail or f"Browsed {share} share", f"files:{share}")

    async def _routine_login(self, persona, username, target, detail, _eb):
        """Log into the web portal."""
        # Find the login page from snapshot
        login_pages = [p for p in self._pages if "login" in p or "index" in p]
        page = login_pages[0] if login_pages else "/"
        await self.containers.exec(
            "web",
            f'curl -s -o /dev/null -A "Mozilla/5.0 ({username})" '
            f'-d "username={username}&password=placeholder" '
            f'"http://localhost{page}"',
        )
        return _log(persona, "login", detail or "Portal login", "web:access_log")

    async def _routine_query_db(self, persona, username, target, detail, _eb):
        """Query the database -- uses tables that exist in this snapshot."""
        import random
        if self._db_tables:
            table = random.choice(self._db_tables)
            query = f"SELECT * FROM {table} LIMIT 5"
        else:
            query = "SHOW TABLES"
        await self.containers.exec(
            "db",
            f'mysql -u app_user -p\'AppUs3r!2024\' -e "{query}" 2>/dev/null || true',
        )
        return _log(persona, "query_db", detail or f"Queried {target or 'database'}", "db:query_log")

    async def _routine_idle(self, persona, username, target, detail, _eb):
        return _log(persona, "idle", detail or "Away from desk", "none")

    # ------------------------------------------------------------------
    # Reactive actions (response to stimuli from Red)
    # ------------------------------------------------------------------

    async def execute(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        """Execute a reactive NPC action (response to stimulus)."""
        handler = {
            "click_link": self._react_click,
            "open_attachment": self._react_click,
            "reply": self._react_email,
            "forward": self._react_email,
            "share_credentials": self._react_share_creds,
            "report_to_IT": self._react_report,
            "ignore": self._react_ignore,
        }.get(action.action, self._react_ignore)
        return await handler(persona, action)

    async def _react_click(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        url = "http://localhost/"
        for effect in action.side_effects:
            urls = re.findall(r"https?://\S+", effect)
            if urls:
                url = urls[0].rstrip(".")
                break
        username = _username_from_persona(persona)
        await self.containers.exec(
            "web",
            f'curl -s -o /dev/null -A "Mozilla/5.0 ({username})" "{url}"',
        )
        return _log(persona, "click_link", f"Clicked: {url}", "web:access_log")

    async def _react_email(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        username = _username_from_persona(persona)
        ts_i = int(time.time())
        body = (action.response_content or "acknowledged")[:500]
        await self.containers.exec(
            "mail",
            f"mkdir -p /var/mail/{username} "
            f"&& echo 'From: {username}@{self._domain}\\nSubject: Re\\n\\n{body}' "
            f"> /var/mail/{username}/sent_{ts_i}.eml",
        )
        return _log(persona, action.action, "Replied to message", "mail:spool")

    async def _react_share_creds(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        username = _username_from_persona(persona)
        content = action.response_content or f"username: {username}"
        ts_i = int(time.time())
        # Leaked creds file
        await self.containers.exec("web", f"echo '{content}' >> /tmp/leaked_{ts_i}.txt")
        # Suspicious login
        await self.containers.exec(
            "web",
            f'curl -s -o /dev/null -A "Mozilla/5.0 (external)" '
            f'-d "username={username}&password=leaked" "http://localhost/"',
        )
        # SIEM alert
        await self.containers.exec(
            "siem",
            f'echo "[$(date)] CRED-LEAK: {persona.name} shared credentials" '
            f">> /var/log/siem/consolidated/all.log",
        )
        return _log(persona, "share_credentials", f"{persona.name} leaked credentials", "web+siem")

    async def _react_report(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        detail = "; ".join(action.side_effects) if action.side_effects else "suspicious activity"
        await self.containers.exec(
            "siem",
            f'echo "[$(date)] NPC-REPORT: {persona.name}: {detail}" '
            f">> /var/log/siem/consolidated/all.log",
        )
        return _log(persona, "report_to_IT", detail, "siem:alert")

    async def _react_ignore(self, persona: NPCPersona, action: NPCAction) -> dict[str, Any]:
        return _log(persona, "ignore", "Ignored stimulus", "none")


# ---------------------------------------------------------------------------
# Snapshot introspection -- derive available targets from the generated env
# ---------------------------------------------------------------------------


def _extract_web_pages(snapshot: SnapshotSpec) -> list[str]:
    """Extract URL paths from snapshot files dict (web:*.php -> /path)."""
    pages: list[str] = []
    for key in snapshot.files:
        if not key.startswith("web:"):
            continue
        path = key.split(":", 1)[1]
        # Convert filesystem path to URL path
        if "/var/www/" in path and path.endswith(".php"):
            url_path = path.replace("/var/www/portal", "").replace("/var/www/html", "")
            if url_path:
                pages.append(url_path)
    return pages or ["/"]


def _extract_shares(snapshot: SnapshotSpec) -> list[str]:
    """Extract Samba share names from snapshot files dict."""
    shares: set[str] = set()
    for key in snapshot.files:
        if not key.startswith("files:"):
            continue
        path = key.split(":", 1)[1]
        # /srv/shares/<share_name>/file.txt -> share_name
        if "/srv/shares/" in path:
            parts = path.split("/srv/shares/")[1].split("/")
            if parts:
                shares.add(parts[0])
    return list(shares) or ["general"]


def _extract_db_tables(snapshot: SnapshotSpec) -> list[str]:
    """Extract table names from SQL in the snapshot files dict."""
    tables: set[str] = set()
    for key, content in snapshot.files.items():
        if key != "db:sql":
            continue
        # Find table names from INSERT INTO / SELECT FROM statements
        for match in re.finditer(r"(?:INSERT INTO|FROM|UPDATE)\s+(\w+\.?\w*)", content, re.IGNORECASE):
            table = match.group(1)
            # Skip system tables
            if table.lower() not in ("information_schema", "mysql", "performance_schema"):
                tables.add(table)
    return list(tables) or []


def _extract_users(snapshot: SnapshotSpec) -> list[str]:
    """Extract usernames from topology."""
    users = snapshot.topology.get("users", [])
    return [u["username"] for u in users if isinstance(u, dict) and "username" in u]


def _username_from_persona(persona: NPCPersona) -> str:
    email = persona.accounts.get("email", "")
    if "@" in email:
        return email.split("@")[0]
    return persona.name.lower().split()[0]


def _log(persona: NPCPersona, action: str, detail: str, source: str) -> dict[str, Any]:
    return {
        "timestamp": time.time(),
        "type": f"npc_{action}",
        "persona": persona.name,
        "department": persona.department,
        "action": action,
        "detail": detail,
        "source": source,
    }
