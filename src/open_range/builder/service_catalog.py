"""Reusable service archetype registry for snapshot materialization.

This module is the bridge from snapshot-level service instances to concrete
runtime daemons. It centralizes image hints, host/service-name hints, and
lifecycle declarations so the renderer and validator do not have to re-encode
service semantics in multiple places.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from open_range.protocols import ReadinessCheck, ServiceInstance, ServiceSpec

_LegacyHint = tuple[
    str,
    list[str],
    list[str],
    str,
    ReadinessCheck,
]


@dataclass(frozen=True)
class ServiceArchetype:
    """Reusable deployment primitive for a service family."""

    name: str
    daemon: str
    packages: tuple[str, ...]
    init_commands: tuple[str, ...]
    start_command: str
    readiness: ReadinessCheck
    image_prefixes: tuple[str, ...] = ()
    service_names: tuple[str, ...] = ()
    host_hints: tuple[str, ...] = ()

    def matches_image(self, image: str) -> bool:
        if not image:
            return False
        base = image.split(":", 1)[0].strip()
        basename = base.rsplit("/", 1)[-1]
        return any(
            prefix == base
            or prefix == basename
            or ("/" not in prefix and prefix in basename)
            for prefix in self.image_prefixes
        )

    def matches_service_name(self, service_name: str) -> bool:
        lowered = service_name.strip().lower()
        return bool(lowered) and lowered in self.service_names

    def matches_host_name(self, host_name: str) -> bool:
        lowered = host_name.strip().lower()
        return bool(lowered) and lowered in self.host_hints

    def default_ports(self) -> list[int]:
        if self.readiness.type == "tcp" and self.readiness.port:
            return [self.readiness.port]
        return []

    def build_service_spec(
        self,
        *,
        host: str,
        log_dir: str,
        env_vars: dict[str, str] | None = None,
    ) -> ServiceSpec:
        return ServiceSpec(
            host=host,
            daemon=self.daemon,
            packages=list(self.packages),
            init_commands=list(self.init_commands),
            start_command=self.start_command.format(log_dir=log_dir),
            readiness=self.readiness.model_copy(),
            log_dir=log_dir,
            env_vars=env_vars or {},
        )

    def to_legacy_hint(self) -> _LegacyHint:
        return (
            self.daemon,
            list(self.packages),
            list(self.init_commands),
            self.start_command,
            self.readiness.model_copy(),
        )


DEFAULT_SERVICE_ARCHETYPES: tuple[ServiceArchetype, ...] = (
    ServiceArchetype(
        name="nginx",
        daemon="nginx",
        packages=("nginx",),
        init_commands=("mkdir -p /var/log/nginx",),
        start_command="nginx -g 'daemon off;' > {log_dir}/nginx.log 2>&1 &",
        readiness=ReadinessCheck(type="tcp", port=80, timeout_s=10),
        image_prefixes=("nginx",),
        service_names=("nginx", "apache", "http"),
        host_hints=("web",),
    ),
    ServiceArchetype(
        name="mysql",
        daemon="mysqld",
        packages=("default-mysql-server", "default-mysql-client"),
        init_commands=(
            "mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld 2>/dev/null || true",
            "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true",
            "test -d /var/lib/mysql/mysql || mysql_install_db --user=mysql --datadir=/var/lib/mysql 2>/dev/null || true",
        ),
        start_command="mysqld --user=mysql --log-error={log_dir}/mysql.log &",
        readiness=ReadinessCheck(
            type="command",
            command="mysqladmin ping --silent 2>/dev/null || mariadb-admin ping --silent 2>/dev/null",
            timeout_s=30,
        ),
        image_prefixes=("mysql",),
        service_names=("mysql", "mariadb", "database"),
        host_hints=("db",),
    ),
    ServiceArchetype(
        name="mariadb",
        daemon="mariadbd",
        packages=("default-mysql-server", "default-mysql-client"),
        init_commands=(
            "mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld 2>/dev/null || true",
            "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true",
            "test -d /var/lib/mysql/mysql || mariadb-install-db --user=mysql --datadir=/var/lib/mysql 2>/dev/null || mysql_install_db --user=mysql --datadir=/var/lib/mysql 2>/dev/null || true",
        ),
        start_command="mariadbd --user=mysql --log-error={log_dir}/mysql.log &",
        readiness=ReadinessCheck(
            type="command",
            command="mariadb-admin ping --silent 2>/dev/null || mysqladmin ping --silent 2>/dev/null",
            timeout_s=30,
        ),
        image_prefixes=("mariadb",),
        service_names=("mariadb",),
    ),
    ServiceArchetype(
        name="postgres",
        daemon="postgres",
        packages=("postgresql",),
        init_commands=("mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql 2>/dev/null || true",),
        start_command="su - postgres -c 'pg_ctl start -D /var/lib/postgresql/data -l {log_dir}/postgres.log' &",
        readiness=ReadinessCheck(type="tcp", port=5432, timeout_s=30),
        image_prefixes=("postgres",),
        service_names=("postgres", "postgresql"),
    ),
    ServiceArchetype(
        name="openldap",
        daemon="slapd",
        packages=("slapd", "ldap-utils"),
        init_commands=("mkdir -p /var/run/slapd",),
        start_command="slapd -h 'ldap:/// ldapi:///' -u openldap -g openldap > {log_dir}/slapd.log 2>&1 &",
        readiness=ReadinessCheck(
            type="command",
            command="ldapsearch -x -H ldap://localhost -b '' -s base namingContexts >/dev/null 2>&1",
            timeout_s=10,
        ),
        image_prefixes=("openldap", "osixia/openldap"),
        service_names=("openldap", "ldap"),
        host_hints=("ldap",),
    ),
    ServiceArchetype(
        name="rsyslog",
        daemon="rsyslogd",
        packages=("rsyslog",),
        init_commands=(
            "sed -i '/imklog/s/^/#/' /etc/rsyslog.conf 2>/dev/null || true",
            "rm -f /run/rsyslogd.pid 2>/dev/null || true",
        ),
        start_command="rsyslogd -n > {log_dir}/rsyslog.log 2>&1 &",
        readiness=ReadinessCheck(type="command", command="pgrep -x rsyslogd", timeout_s=5),
        image_prefixes=("rsyslog",),
        service_names=("rsyslog", "syslog", "siem"),
        host_hints=("siem", "firewall"),
    ),
    ServiceArchetype(
        name="samba",
        daemon="smbd",
        packages=("samba",),
        init_commands=("mkdir -p /var/lib/samba/private",),
        start_command="smbd --foreground --no-process-group > {log_dir}/smbd.log 2>&1 &",
        readiness=ReadinessCheck(type="tcp", port=445, timeout_s=10),
        image_prefixes=("samba",),
        service_names=("samba", "smb", "nfs"),
        host_hints=("files",),
    ),
    ServiceArchetype(
        name="postfix",
        daemon="master",
        packages=("postfix",),
        init_commands=(
            "newaliases 2>/dev/null || true",
            "mkdir -p /var/spool/postfix/pid 2>/dev/null || true",
        ),
        start_command="postfix start > {log_dir}/postfix.log 2>&1 || true",
        readiness=ReadinessCheck(type="tcp", port=25, timeout_s=10),
        image_prefixes=("postfix",),
        service_names=("postfix", "dovecot", "smtp", "imap", "mail"),
        host_hints=("mail",),
    ),
    ServiceArchetype(
        name="redis",
        daemon="redis-server",
        packages=("redis-server",),
        init_commands=(),
        start_command="redis-server --daemonize yes --logfile {log_dir}/redis.log",
        readiness=ReadinessCheck(type="tcp", port=6379, timeout_s=10),
        image_prefixes=("redis",),
        service_names=("redis", "memcached", "cache"),
        host_hints=("cache", "redis"),
    ),
    ServiceArchetype(
        name="jenkins",
        daemon="java",
        packages=("default-jdk",),
        init_commands=(),
        start_command="java -jar /usr/share/jenkins/jenkins.war --httpPort=8080 > {log_dir}/jenkins.log 2>&1 &",
        readiness=ReadinessCheck(type="http", url="http://localhost:8080/login", timeout_s=60),
        image_prefixes=("jenkins",),
        service_names=("jenkins", "ci", "ci_cd"),
        host_hints=("ci_cd", "ci"),
    ),
    ServiceArchetype(
        name="prometheus",
        daemon="prometheus",
        packages=("prometheus",),
        init_commands=(),
        start_command="prometheus --config.file=/etc/prometheus/prometheus.yml --web.listen-address=:9090 > {log_dir}/prometheus.log 2>&1 &",
        readiness=ReadinessCheck(type="http", url="http://localhost:9090/-/ready", timeout_s=15),
        image_prefixes=("prometheus",),
        service_names=("prometheus", "alertmanager", "monitoring"),
        host_hints=("monitoring",),
    ),
    ServiceArchetype(
        name="grafana",
        daemon="grafana-server",
        packages=("grafana",),
        init_commands=(),
        start_command="grafana-server --homepath=/usr/share/grafana > {log_dir}/grafana.log 2>&1 &",
        readiness=ReadinessCheck(type="http", url="http://localhost:3000/api/health", timeout_s=15),
        image_prefixes=("grafana",),
        service_names=("grafana", "kibana"),
    ),
    ServiceArchetype(
        name="openssh",
        daemon="sshd",
        packages=("openssh-server",),
        init_commands=("mkdir -p /var/run/sshd",),
        start_command="/usr/sbin/sshd -E {log_dir}/sshd.log",
        readiness=ReadinessCheck(type="tcp", port=22, timeout_s=5),
        image_prefixes=("openssh", "linuxserver/openssh-server"),
        service_names=("sshd", "ssh"),
        host_hints=("ssh", "jumpbox"),
    ),
)


def resolve_service_archetype(
    *,
    image: str = "",
    service_name: str = "",
    host_name: str = "",
) -> ServiceArchetype | None:
    """Resolve the best matching archetype from image, service, or host signals."""
    for archetype in DEFAULT_SERVICE_ARCHETYPES:
        if image and archetype.matches_image(image):
            return archetype
    for archetype in DEFAULT_SERVICE_ARCHETYPES:
        if service_name and archetype.matches_service_name(service_name):
            return archetype
    for archetype in DEFAULT_SERVICE_ARCHETYPES:
        if host_name and archetype.matches_host_name(host_name):
            return archetype
    return None


def infer_service_instances(
    compose: dict[str, Any] | None,
    topology: dict[str, Any] | None,
    existing: list[ServiceInstance] | None = None,
) -> list[ServiceInstance]:
    """Infer service instances from compose or compiled topology state."""
    if existing:
        return [_normalize_service_instance(instance) for instance in existing]

    compose_services = compose.get("services", {}) if isinstance(compose, dict) else {}
    if isinstance(compose_services, dict) and compose_services:
        return _service_instances_from_compose(compose_services)
    return _service_instances_from_topology(topology or {})


def legacy_image_hints() -> dict[str, _LegacyHint]:
    """Expose legacy image hint tuples for compatibility/tests."""
    hints: dict[str, _LegacyHint] = {}
    for archetype in DEFAULT_SERVICE_ARCHETYPES:
        for prefix in archetype.image_prefixes:
            hints[prefix] = archetype.to_legacy_hint()
    return hints


def legacy_host_hints() -> dict[str, str]:
    """Expose host-name -> archetype-name hints for compatibility/tests."""
    hints: dict[str, str] = {}
    for archetype in DEFAULT_SERVICE_ARCHETYPES:
        for host_hint in archetype.host_hints:
            hints[host_hint] = archetype.name
    return hints


def _normalize_service_instance(instance: ServiceInstance) -> ServiceInstance:
    archetype = instance.archetype
    if not archetype:
        resolved = resolve_service_archetype(
            image=instance.image,
            service_name=instance.service_name,
            host_name=instance.host,
        )
        archetype = resolved.name if resolved else ""
    instance_id = instance.instance_id or f"{instance.host}:{instance.service_name or archetype or 'service'}"
    ports = list(instance.ports)
    if not ports and archetype:
        resolved = resolve_service_archetype(
            image=instance.image,
            service_name=instance.service_name or archetype,
            host_name=instance.host,
        )
        if resolved is not None:
            ports = resolved.default_ports()
    return instance.model_copy(
        update={
            "instance_id": instance_id,
            "archetype": archetype,
            "ports": ports,
        }
    )


def _service_instances_from_compose(services: dict[str, Any]) -> list[ServiceInstance]:
    instances: list[ServiceInstance] = []
    for service_name, raw_service in services.items():
        if not isinstance(raw_service, dict):
            continue
        image = str(raw_service.get("image", "")).strip()
        archetype = resolve_service_archetype(image=image, service_name=service_name, host_name=service_name)
        ports = _extract_ports(raw_service)
        if archetype is not None and not ports:
            ports = archetype.default_ports()
        instance = ServiceInstance(
            instance_id=service_name,
            host=service_name,
            service_name=service_name,
            archetype=archetype.name if archetype else "",
            image=image,
            ports=ports,
            env_vars=_env_from_compose_service(raw_service),
            startup_contract={},
            metadata={"source": "compose"},
        )
        instances.append(_normalize_service_instance(instance))
    return _dedupe_service_instances(instances)


def _service_instances_from_topology(topology: dict[str, Any]) -> list[ServiceInstance]:
    instances: list[ServiceInstance] = []
    host_details = topology.get("host_details", {})
    if not isinstance(host_details, dict):
        host_details = {}
    host_catalog = topology.get("host_catalog", {})
    if not isinstance(host_catalog, dict):
        host_catalog = {}
    hosts = topology.get("hosts", [])
    for raw_host in hosts if isinstance(hosts, list) else []:
        host_name = str(raw_host.get("name", "") if isinstance(raw_host, dict) else raw_host).strip()
        if not host_name:
            continue
        detail = host_details.get(host_name, {})
        if not isinstance(detail, dict):
            detail = {}
        catalog_detail = host_catalog.get(host_name, {})
        if not isinstance(catalog_detail, dict):
            catalog_detail = {}
        raw_services = []
        for source in (detail.get("services", []), catalog_detail.get("services", [])):
            if not isinstance(source, list):
                continue
            raw_services.extend(source)
        created_for_host = False
        for raw_service in raw_services:
            service_name = str(raw_service).strip().lower()
            if not service_name:
                continue
            archetype = resolve_service_archetype(service_name=service_name, host_name=host_name)
            if archetype is None:
                continue
            created_for_host = True
            instances.append(
                _normalize_service_instance(
                    ServiceInstance(
                        instance_id=f"{host_name}:{service_name}",
                        host=host_name,
                        service_name=service_name,
                        archetype=archetype.name,
                        image="",
                        ports=archetype.default_ports(),
                        startup_contract={},
                        metadata={"source": "topology"},
                    )
                )
            )
        if created_for_host:
            continue
        archetype = resolve_service_archetype(host_name=host_name)
        if archetype is None:
            continue
        instances.append(
            _normalize_service_instance(
                ServiceInstance(
                    instance_id=f"{host_name}:{archetype.name}",
                    host=host_name,
                    service_name=archetype.name,
                    archetype=archetype.name,
                    image="",
                    ports=archetype.default_ports(),
                    startup_contract={},
                    metadata={"source": "host_hint"},
                )
            )
        )
    return _dedupe_service_instances(instances)


def _dedupe_service_instances(instances: list[ServiceInstance]) -> list[ServiceInstance]:
    deduped: list[ServiceInstance] = []
    seen: set[tuple[str, str, str]] = set()
    for instance in instances:
        key = (
            instance.host,
            instance.service_name or instance.archetype,
            instance.archetype,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(instance)
    return deduped


def _env_from_compose_service(service_def: dict[str, Any]) -> dict[str, str]:
    raw = service_def.get("environment", {})
    if isinstance(raw, list):
        env: dict[str, str] = {}
        for entry in raw:
            text = str(entry)
            if "=" not in text:
                continue
            key, value = text.split("=", 1)
            env[key] = value
        return env
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    return {}


def _extract_ports(service_def: dict[str, Any]) -> list[int]:
    raw_ports = service_def.get("ports", [])
    ports: list[int] = []
    if not isinstance(raw_ports, list):
        return ports
    for raw_port in raw_ports:
        if isinstance(raw_port, int):
            ports.append(raw_port)
            continue
        text = str(raw_port).strip()
        if not text:
            continue
        target = text.split(":")[-1].split("/")[0]
        if target.isdigit():
            ports.append(int(target))
    return ports
