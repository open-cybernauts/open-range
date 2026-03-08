"""Render SnapshotSpec into a Helm chart targeting Kind (Kubernetes-in-Docker).

Takes a validated SnapshotSpec and produces:
  - A Helm chart (openrange/) with generated values.yaml
  - A Kind cluster config (kind-config.yaml)

Zone isolation is achieved via namespace-per-zone with NetworkPolicies.
Payload files (PHP code, SQL seeds, configs) are injected as ConfigMaps.
"""

from __future__ import annotations

import logging
import re
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from open_range.protocols import SnapshotSpec

logger = logging.getLogger(__name__)

# Static Helm chart shipped alongside this module
_CHART_DIR = Path(__file__).parent / "chart"

# Default zone CIDR mappings (used for documentation / NetworkPolicy context)
_ZONE_CIDRS: dict[str, str] = {
    "external": "10.0.0.0/24",
    "dmz": "10.0.1.0/24",
    "internal": "10.0.2.0/24",
    "management": "10.0.3.0/24",
}

_GENERIC_LINUX_IMAGE = "ubuntu:22.04"
_KALI_IMAGE = "kalilinux/kali-rolling"
_WEB_IMAGE = "php:8.1-apache"
_MYSQL_IMAGE = "mysql:8.0"
_POSTGRES_IMAGE = "postgres:15"
_SAMBA_IMAGE = "dperson/samba:latest"
_MAIL_IMAGE = "mailhog/mailhog:latest"
_LDAP_IMAGE = "osixia/openldap:1.5.0"
_SYSLOG_IMAGE = "balabit/syslog-ng:latest"
_REDIS_IMAGE = "redis:7-alpine"
_JENKINS_IMAGE = "jenkins/jenkins:lts"
_GITEA_IMAGE = "gitea/gitea:1.22.0"
_PROMETHEUS_IMAGE = "prom/prometheus:latest"
_GRAFANA_IMAGE = "grafana/grafana:latest"
_DMZ_NODEPORT_BASE = 30080

_SERVICE_PORT_HINTS: dict[str, list[dict[str, Any]]] = {
    "nginx": [{"name": "http", "port": 80}, {"name": "https", "port": 443}],
    "apache": [{"name": "http", "port": 80}, {"name": "https", "port": 443}],
    "http": [{"name": "http", "port": 80}],
    "php-fpm": [{"name": "php-fpm", "port": 9000}],
    "nodejs": [{"name": "nodejs", "port": 3000}],
    "python3": [{"name": "python", "port": 8000}],
    "django": [{"name": "django", "port": 8000}],
    "mysql": [{"name": "mysql", "port": 3306}],
    "mariadb": [{"name": "mysql", "port": 3306}],
    "postgresql": [{"name": "postgres", "port": 5432}],
    "redis": [{"name": "redis", "port": 6379}],
    "memcached": [{"name": "memcached", "port": 11211}],
    "samba": [{"name": "smb", "port": 445}],
    "nfs": [{"name": "nfs", "port": 2049}],
    "postfix": [{"name": "smtp", "port": 25}],
    "dovecot": [{"name": "imap", "port": 143}],
    "openldap": [{"name": "ldap", "port": 389}, {"name": "ldaps", "port": 636}],
    "kerberos": [{"name": "kerberos", "port": 88}],
    "rsyslog": [{"name": "syslog", "port": 514}],
    "elasticsearch": [{"name": "elasticsearch", "port": 9200}],
    "kibana": [{"name": "kibana", "port": 5601}],
    "prometheus": [{"name": "prometheus", "port": 9090}],
    "grafana": [{"name": "grafana", "port": 3000}],
    "alertmanager": [{"name": "alertmanager", "port": 9093}],
    "jenkins": [{"name": "jenkins", "port": 8080}],
    "gitea": [{"name": "gitea", "port": 3000}, {"name": "gitea-ssh", "port": 22}],
    "sonarqube": [{"name": "sonarqube", "port": 9000}],
    "openvpn": [{"name": "openvpn", "port": 1194}],
    "sshd": [{"name": "ssh", "port": 22}],
    "ssh-client": [{"name": "ssh", "port": 22}],
    "snort": [{"name": "snort", "port": 514}],
}


def _sanitize_key(path: str) -> str:
    """Convert a file path to a ConfigMap-safe key (RFC 1123 subdomain)."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", path.strip("/"))


def _host_name(raw_host: dict[str, Any] | str) -> str:
    if isinstance(raw_host, dict):
        return str(raw_host.get("name", "")).strip()
    return str(raw_host).strip()


def _host_services(raw_host: dict[str, Any] | str | None) -> list[str]:
    if not isinstance(raw_host, dict):
        return []
    raw_services = raw_host.get("services", [])
    if not isinstance(raw_services, list):
        return []
    services: list[str] = []
    seen: set[str] = set()
    for raw_service in raw_services:
        service_name = str(raw_service).strip().lower()
        if not service_name or service_name in seen:
            continue
        seen.add(service_name)
        services.append(service_name)
    return services


def _find_host_record(
    host_entries: list[dict[str, Any] | str],
    host_name: str,
) -> dict[str, Any] | str:
    for raw_host in host_entries:
        if _host_name(raw_host) == host_name:
            return raw_host
    return host_name


class KindRenderer:
    """Render a SnapshotSpec into a Helm chart and Kind cluster config.

    The chart uses namespace-per-zone isolation with NetworkPolicies
    replacing iptables rules.  Payload files are mounted via ConfigMaps.
    """

    def __init__(self, chart_dir: Path | None = None) -> None:
        self.chart_dir = chart_dir or _CHART_DIR

    def render(self, spec: SnapshotSpec, output_dir: Path) -> Path:
        """Render the Helm chart and Kind config to *output_dir*.

        Returns the output directory path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Kind cluster config
        kind_config = self._build_kind_config(spec)
        (output_dir / "kind-config.yaml").write_text(
            yaml.dump(kind_config, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        # 2. Copy static chart structure
        chart_out = output_dir / "openrange"
        if chart_out.exists():
            shutil.rmtree(chart_out)
        shutil.copytree(self.chart_dir, chart_out)

        # 3. Generate values.yaml from SnapshotSpec
        values = self._build_values(spec)
        (chart_out / "values.yaml").write_text(
            yaml.dump(values, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        logger.info(
            "KindRenderer: rendered chart to %s (%d services, %d zones)",
            chart_out,
            len(values.get("services", {})),
            len(values.get("zones", {})),
        )
        return output_dir

    # ------------------------------------------------------------------
    # Values generation
    # ------------------------------------------------------------------

    def _build_values(self, spec: SnapshotSpec) -> dict[str, Any]:
        """Convert a SnapshotSpec into the Helm values dict."""
        topology = spec.topology
        zones = topology.get("zones", {})
        users = topology.get("users", [])
        hosts_raw = topology.get("hosts", [])
        host_entries = [
            raw for raw in hosts_raw
            if isinstance(raw, (dict, str))
        ]

        # Zone config
        zone_config: dict[str, dict[str, Any]] = {}
        for zone_name, zone_hosts in zones.items():
            zone_config[zone_name] = {
                "hosts": list(zone_hosts) if isinstance(zone_hosts, list) else [],
                "cidr": _ZONE_CIDRS.get(zone_name, "10.0.0.0/24"),
            }

        # Host → zone reverse map
        host_to_zone: dict[str, str] = {}
        for zone_name, zone_hosts in zones.items():
            if isinstance(zone_hosts, list):
                for h in zone_hosts:
                    host_to_zone[h] = zone_name

        public_node_ports = self._public_node_ports(host_entries, host_to_zone)

        # Service configs
        services: dict[str, dict[str, Any]] = {}
        for h in host_entries:
            name = _host_name(h)
            if not name:
                continue
            zone = host_to_zone.get(name, "default")
            host_services = _host_services(h)
            image = self._service_image(name=name, host_services=host_services, raw_host=h)
            ports = self._service_ports(name=name, host_services=host_services)
            if zone == "dmz":
                for port_info in ports:
                    node_port = public_node_ports.get((name, int(port_info["port"])))
                    if node_port is not None:
                        port_info["nodePort"] = node_port

            svc: dict[str, Any] = {
                "enabled": True,
                "image": image,
                "zone": zone,
                "ports": ports,
                "env": self._service_env(name, topology, host_services),
            }
            if zone == "dmz" and ports:
                svc["serviceType"] = "NodePort"

            cmd = self._service_command(name, image=image, host_services=host_services)
            if cmd:
                svc["command"] = cmd

            payloads = self._service_payloads(name, spec)
            if payloads:
                svc["payloads"] = payloads

            services[name] = svc

        # Firewall rules
        fw_rules: list[dict[str, Any]] = []
        for rule in topology.get("firewall_rules", []):
            if isinstance(rule, dict):
                fw_rules.append({
                    "action": rule.get("action", "allow"),
                    "fromZone": rule.get("from_zone", ""),
                    "toZone": rule.get("to_zone", ""),
                    "ports": rule.get("ports", []),
                })

        return {
            "global": {
                "namePrefix": "openrange",
                "domain": topology.get("domain", "acmecorp.local"),
                "orgName": topology.get("org_name", "AcmeCorp"),
                "snapshotId": topology.get("snapshot_id", "generated"),
            },
            "zones": zone_config,
            "services": services,
            "users": deepcopy(users) if isinstance(users, list) else [],
            "flags": [f.model_dump() for f in spec.flags],
            "firewallRules": fw_rules,
        }

    # ------------------------------------------------------------------
    # Per-service helpers
    # ------------------------------------------------------------------

    def _service_env(
        self,
        name: str,
        topology: dict[str, Any],
        host_services: list[str],
    ) -> dict[str, str]:
        """Build environment variables for a service."""
        domain = topology.get("domain", "acmecorp.local")
        org_name = topology.get("org_name", "AcmeCorp")
        users = topology.get("users", [])
        users = users if isinstance(users, list) else []
        service_set = set(host_services)

        env: dict[str, str] = {}
        if name in {"web", "partner_portal"} or "nginx" in service_set:
            env.update({
                "DB_HOST": "db",
                "DB_USER": _find_db_user(users),
                "DB_PASS": _find_db_pass(users),
                "DB_NAME": "referral_db",
                "LDAP_HOST": "ldap",
                "LDAP_BASE_DN": ",".join(f"dc={p}" for p in domain.split(".")),
            })
        elif name == "db" or "mysql" in service_set:
            env.update({
                "MYSQL_ROOT_PASSWORD": str(
                    topology.get("mysql_root_password", "r00tP@ss!")
                ),
                "MYSQL_DATABASE": "referral_db",
                "MYSQL_USER": _find_db_user(users),
                "MYSQL_PASSWORD": _find_db_pass(users),
            })
        elif name == "ldap" or "openldap" in service_set:
            env.update({
                "LDAP_ORGANISATION": org_name,
                "LDAP_DOMAIN": domain,
                "LDAP_ADMIN_PASSWORD": "LdapAdm1n!",
                "HOSTNAME": "ldap",
                # K8s auto-injects LDAP_PORT from the Service named "ldap",
                # which collides with osixia/openldap's own LDAP_PORT env var.
                # Override to the correct value.
                "LDAP_PORT": "389",
            })
        elif name == "attacker":
            env["TERM"] = "xterm-256color"
        return env

    @staticmethod
    def _service_command(
        name: str,
        *,
        image: str,
        host_services: list[str],
    ) -> list[str] | None:
        """Return a startup command override, or ``None``."""
        if image == _WEB_IMAGE:
            return [
                "bash", "-c",
                (
                    "docker-php-ext-install mysqli pdo_mysql > /dev/null 2>&1; "
                    "apache2-foreground"
                ),
            ]
        if image == _KALI_IMAGE or name == "attacker":
            return [
                "bash", "-c",
                (
                    "apt-get update -qq > /dev/null 2>&1 && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "nmap curl wget smbclient netcat-openbsd openssh-client "
                    "dnsutils mysql-client python3 > /dev/null 2>&1; "
                    "echo '[openrange] attacker tools ready'; "
                    "sleep infinity"
                ),
            ]
        if image == _GENERIC_LINUX_IMAGE:
            return ["bash", "-c", "sleep infinity"]
        return None

    @staticmethod
    def _service_payloads(
        name: str,
        spec: SnapshotSpec,
    ) -> list[dict[str, str]]:
        """Extract payload file mounts for a given container.

        Deduplicates by mountPath — last writer wins for content, but
        each mountPath appears only once (K8s rejects duplicate volumeMounts).
        """
        by_mount: dict[str, dict[str, str]] = {}

        # Inject base DB schema so LLM-generated SQL can reference tables
        if name == "db":
            mp = "/docker-entrypoint-initdb.d/00-base-schema.sql"
            by_mount[mp] = {
                "key": "00-base-schema.sql",
                "mountPath": mp,
                "content": _BASE_DB_SCHEMA,
            }

        for file_key, content in spec.files.items():
            if ":" not in file_key:
                continue
            container, path = file_key.split(":", 1)
            if container != name:
                continue

            # db:sql → shell wrapper that runs LLM SQL with --force
            # so MySQL continues past individual statement errors
            # (LLM may generate slightly wrong column names).
            if name == "db" and path == "sql":
                mount_path = "/docker-entrypoint-initdb.d/99-openrange-init.sh"
                content = _wrap_sql_in_shell(content)
            else:
                mount_path = path if path.startswith("/") else f"/{path}"

            by_mount[mount_path] = {
                "key": _sanitize_key(path),
                "mountPath": mount_path,
                "content": content,
            }

        # Flag files for this host
        for flag in spec.flags:
            if (
                flag.host == name
                and "/" in flag.path
                and not flag.path.startswith("db:")
            ):
                by_mount.setdefault(flag.path, {
                    "key": _sanitize_key(flag.path),
                    "mountPath": flag.path,
                    "content": f"{flag.value}\n",
                })

        return list(by_mount.values())

    # ------------------------------------------------------------------
    # Kind cluster config
    # ------------------------------------------------------------------

    def _build_kind_config(self, spec: SnapshotSpec) -> dict[str, Any]:
        """Generate a Kind cluster config with port mappings for DMZ access."""
        zones = spec.topology.get("zones", {})
        dmz_hosts = zones.get("dmz", [])
        if not isinstance(dmz_hosts, list):
            dmz_hosts = []

        host_entries = [
            raw for raw in spec.topology.get("hosts", [])
            if isinstance(raw, (dict, str))
        ]
        host_to_zone: dict[str, str] = {}
        for zone_name, zone_hosts in zones.items():
            if isinstance(zone_hosts, list):
                for host in zone_hosts:
                    host_to_zone[str(host)] = str(zone_name)
        public_node_ports = self._public_node_ports(host_entries, host_to_zone)

        port_mappings: list[dict[str, Any]] = []
        for host_name in dmz_hosts:
            for port_info in self._service_ports(
                name=str(host_name),
                host_services=_host_services(_find_host_record(host_entries, str(host_name))),
            ):
                node_port = public_node_ports.get((str(host_name), int(port_info["port"])))
                if node_port is None:
                    continue
                port_mappings.append({
                    "containerPort": node_port,
                    "hostPort": node_port,
                    "protocol": "TCP",
                })

        if not port_mappings:
            port_mappings = [
                {"containerPort": 30080, "hostPort": 30080, "protocol": "TCP"},
            ]

        return {
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "kind": "Cluster",
            "name": "openrange",
            "networking": {
                "disableDefaultCNI": True,
                "podSubnet": "192.168.0.0/16",
            },
            "nodes": [
                {
                    "role": "control-plane",
                    "extraPortMappings": port_mappings,
                },
            ],
        }

    @staticmethod
    def _service_image(
        *,
        name: str,
        host_services: list[str],
        raw_host: dict[str, Any] | str,
    ) -> str:
        service_set = set(host_services)
        host_os = ""
        if isinstance(raw_host, dict):
            host_os = str(raw_host.get("os", "")).strip().lower()

        if name == "attacker" or "kali" in host_os:
            return _KALI_IMAGE
        if "mysql" in service_set or name == "db":
            return _MYSQL_IMAGE
        if "postgresql" in service_set:
            return _POSTGRES_IMAGE
        if "openldap" in service_set or name == "ldap":
            return _LDAP_IMAGE
        if "jenkins" in service_set:
            return _JENKINS_IMAGE
        if "gitea" in service_set:
            return _GITEA_IMAGE
        if "prometheus" in service_set:
            return _PROMETHEUS_IMAGE
        if "grafana" in service_set:
            return _GRAFANA_IMAGE
        if "redis" in service_set or "memcached" in service_set or name == "cache":
            return _REDIS_IMAGE
        if "samba" in service_set or "nfs" in service_set or name == "files":
            return _SAMBA_IMAGE
        if "postfix" in service_set or "dovecot" in service_set or name == "mail":
            return _MAIL_IMAGE
        if (
            {"nginx", "php-fpm", "nodejs", "python3", "django", "react"}.intersection(service_set)
            or name in {"web", "partner_portal"}
        ):
            return _WEB_IMAGE
        if (
            {"rsyslog", "elasticsearch", "kibana", "snort"}.intersection(service_set)
            or name == "siem"
        ):
            return _SYSLOG_IMAGE
        return _GENERIC_LINUX_IMAGE

    @staticmethod
    def _service_ports(
        *,
        name: str,
        host_services: list[str],
    ) -> list[dict[str, Any]]:
        ports: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for service_name in host_services:
            for port_info in _SERVICE_PORT_HINTS.get(service_name, []):
                key = (str(port_info["name"]), int(port_info["port"]))
                if key in seen:
                    continue
                seen.add(key)
                ports.append(deepcopy(port_info))

        if ports:
            return ports

        if name == "web":
            return deepcopy(_SERVICE_PORT_HINTS["nginx"])
        if name == "db":
            return deepcopy(_SERVICE_PORT_HINTS["mysql"])
        if name == "mail":
            return (
                deepcopy(_SERVICE_PORT_HINTS["postfix"])
                + deepcopy(_SERVICE_PORT_HINTS["dovecot"])
            )
        if name == "ldap":
            return deepcopy(_SERVICE_PORT_HINTS["openldap"])
        if name == "siem":
            return deepcopy(_SERVICE_PORT_HINTS["rsyslog"])
        if name == "files":
            return deepcopy(_SERVICE_PORT_HINTS["samba"])
        return []

    @staticmethod
    def _public_node_ports(
        host_entries: list[dict[str, Any] | str],
        host_to_zone: dict[str, str],
    ) -> dict[tuple[str, int], int]:
        assignments: dict[tuple[str, int], int] = {}
        next_port = _DMZ_NODEPORT_BASE
        for raw_host in host_entries:
            name = _host_name(raw_host)
            if not name or host_to_zone.get(name) != "dmz":
                continue
            for port_info in KindRenderer._service_ports(
                name=name,
                host_services=_host_services(raw_host),
            ):
                port = int(port_info["port"])
                key = (name, port)
                if key in assignments:
                    continue
                assignments[key] = next_port
                next_port += 1
        return assignments


# ---------------------------------------------------------------------------
# Helpers (ported from old renderer, used by _build_values)
# ---------------------------------------------------------------------------


def _find_db_user(users: list[dict[str, Any]]) -> str:
    """Find the database user from topology users, default to app_user."""
    for u in users:
        hosts = u.get("hosts", [])
        if "db" in hosts and "admins" not in u.get("groups", []):
            return u.get("username", "app_user")
    return "app_user"


def _find_db_pass(users: list[dict[str, Any]]) -> str:
    """Find the database user password."""
    for u in users:
        hosts = u.get("hosts", [])
        if "db" in hosts and "admins" not in u.get("groups", []):
            return u.get("password", "AppUs3r!2024")
    return "AppUs3r!2024"


# Base MySQL schema — runs as 00-base-schema.sql so LLM-generated SQL
# (99-openrange-init.sql) can INSERT into these tables safely.
_BASE_DB_SCHEMA = """\
CREATE DATABASE IF NOT EXISTS referral_db;
CREATE DATABASE IF NOT EXISTS flags;
USE referral_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(128),
    full_name VARCHAR(128),
    role VARCHAR(64),
    department VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(64),
    last_name VARCHAR(64),
    dob DATE,
    phone VARCHAR(20),
    email VARCHAR(128),
    insurance_id VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patient_referrals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    referring_physician VARCHAR(128),
    specialist VARCHAR(128),
    reason TEXT,
    status VARCHAR(32) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS billing (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    amount DECIMAL(10,2),
    insurance_claim VARCHAR(64),
    status VARCHAR(32) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

CREATE TABLE IF NOT EXISTS access_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(64),
    resource VARCHAR(128),
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

USE flags;
CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(64),
    flag VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

USE referral_db;
"""


def _wrap_sql_in_shell(sql: str) -> str:
    """Wrap LLM-generated SQL in a shell script that tolerates errors.

    MySQL's docker-entrypoint runs ``.sql`` files via ``mysql < file``
    which aborts on the first error.  By using a ``.sh`` wrapper with
    ``mysql --force``, individual bad statements (wrong column names,
    duplicate keys, etc.) are logged but don't crash the pod.

    NOTE: MySQL entrypoint ``source``s ``.sh`` files (same process),
    so we must NOT use ``exit`` — that would kill the entrypoint.
    We just let the script return naturally.
    """
    return (
        'echo "[openrange] Running LLM-generated seed SQL (--force) ..."\n'
        "mysql --force -u root -p\"$MYSQL_ROOT_PASSWORD\" <<'OPENRANGE_SQL_EOF'\n"
        f"{sql}\n"
        "OPENRANGE_SQL_EOF\n"
        'echo "[openrange] Seed SQL complete (errors above are non-fatal)"\n'
    )
