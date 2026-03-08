"""Boot and tear down rendered snapshot Helm releases on a Kind cluster."""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from open_range.protocols import ContainerSet

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# K8s-aware ContainerSet -- uses kubectl exec instead of docker exec
# ---------------------------------------------------------------------------


class KubePodSet(ContainerSet):
    """Handle to live K8s pods for a snapshot.

    Drop-in replacement for the docker-backed ``ContainerSet``.
    ``container_ids`` maps service name → ``namespace/pod-name``.
    """

    async def exec(self, container: str, cmd: str, timeout: float = 30.0) -> str:
        """Run *cmd* inside *container* pod via ``kubectl exec``."""
        import asyncio

        namespace, pod = self._resolve(container)
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "exec", pod,
            "-n", namespace,
            "--", "sh", "-c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return "<timeout>"
        return (stdout or b"").decode(errors="replace")

    async def is_healthy(self, container: str) -> bool:
        """Return True when the pod is Running and Ready."""
        import asyncio

        namespace, pod = self._resolve(container)
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "get", "pod", pod,
            "-n", namespace,
            "-o", "jsonpath={.status.phase}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        phase = (stdout or b"").decode().strip()
        if phase != "Running":
            return False

        # Check container readiness
        proc2 = await asyncio.create_subprocess_exec(
            "kubectl", "get", "pod", pod,
            "-n", namespace,
            "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout2, _ = await proc2.communicate()
        return (stdout2 or b"").decode().strip() == "True"

    async def cp(self, container: str, src: str, dest: str) -> None:
        """Copy a file into a pod via ``kubectl cp``."""
        import asyncio

        namespace, pod = self._resolve(container)
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "cp", src, f"{namespace}/{pod}:{dest}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    async def restart(self, container: str, timeout: float = 30.0) -> None:
        """Restart a pod by deleting it (the Deployment recreates it)."""
        import asyncio

        namespace, pod = self._resolve(container)
        proc = await asyncio.create_subprocess_exec(
            "kubectl", "delete", "pod", pod,
            "-n", namespace,
            "--grace-period=5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()

    def _resolve(self, container: str) -> tuple[str, str]:
        """Return ``(namespace, pod_name)`` for a service name.

        If the value in ``container_ids`` contains a ``/`` it is treated as
        ``namespace/pod``.  Otherwise *container* is looked up by label in
        the release namespace.
        """
        entry = self.container_ids.get(container, container)
        if "/" in entry:
            parts = entry.split("/", 1)
            return parts[0], parts[1]
        # Fallback: assume namespace from project_name pattern
        return self.project_name, entry


# ---------------------------------------------------------------------------
# Booted release metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BootedRelease:
    """Metadata for a Helm release booted on Kind."""

    release_name: str
    chart_dir: Path
    artifacts_dir: Path
    containers: KubePodSet


# Keep the old name importable for callers that haven't migrated yet.
BootedSnapshotProject = BootedRelease


# ---------------------------------------------------------------------------
# HelmRunner
# ---------------------------------------------------------------------------


class HelmRunner:
    """Boot and tear down rendered snapshot Helm charts on Kind."""

    def __init__(
        self,
        *,
        install_timeout_s: float = 300.0,
        uninstall_timeout_s: float = 120.0,
        health_timeout_s: float = 120.0,
        health_poll_interval_s: float = 2.0,
        kind_cluster: str = "openrange",
    ) -> None:
        self.install_timeout_s = install_timeout_s
        self.uninstall_timeout_s = uninstall_timeout_s
        self.health_timeout_s = health_timeout_s
        self.health_poll_interval_s = health_poll_interval_s
        self.kind_cluster = kind_cluster

    def boot(
        self,
        *,
        snapshot_id: str,
        artifacts_dir: Path,
        compose: dict[str, Any] | None = None,
        project_name: str | None = None,
    ) -> BootedRelease:
        """Install the Helm chart and wait for pods to become ready.

        The *compose* parameter is accepted for interface compatibility
        with the old ``ComposeProjectRunner`` but is ignored.
        """
        release_name = project_name or self.release_name_for(snapshot_id)
        chart_dir = artifacts_dir / "openrange"
        if not chart_dir.exists():
            # Older layout: artifacts_dir is already the render output dir
            chart_dir = artifacts_dir

        self._helm_install(release_name, chart_dir, artifacts_dir)

        # Discover pods across namespaces
        pod_map = self._discover_pods(release_name)
        pod_set = KubePodSet(
            project_name=release_name,
            container_ids=pod_map,
        )

        release = BootedRelease(
            release_name=release_name,
            chart_dir=chart_dir,
            artifacts_dir=artifacts_dir,
            containers=pod_set,
        )
        services = list(pod_map.keys())
        self._wait_until_healthy(release, services)
        return release

    def teardown(self, project: BootedRelease | BootedSnapshotProject) -> None:
        """Uninstall the Helm release."""
        release_name = (
            project.release_name
            if isinstance(project, BootedRelease)
            else project.release_name
        )
        self._run(
            ["helm", "uninstall", release_name, "--wait"],
            timeout=self.uninstall_timeout_s,
        )
        logger.info("Uninstalled Helm release %s", release_name)

    @staticmethod
    def release_name_for(snapshot_id: str) -> str:
        """Generate a Helm release name from a snapshot ID."""
        safe = "".join(
            ch.lower() if ch.isalnum() else "-" for ch in snapshot_id
        ).strip("-")
        return f"or-{safe}"[:53]

    # Alias for callers that still use the old name.
    project_name_for = release_name_for

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _helm_install(
        self,
        release_name: str,
        chart_dir: Path,
        cwd: Path,
    ) -> None:
        """Run ``helm install`` (or ``helm upgrade --install``)."""
        self._run(
            [
                "helm", "upgrade", "--install",
                release_name,
                str(chart_dir),
                "--wait",
                "--timeout", f"{int(self.install_timeout_s)}s",
            ],
            timeout=self.install_timeout_s + 30,
        )
        logger.info("Installed Helm release %s from %s", release_name, chart_dir)

    def _discover_pods(self, release_name: str) -> dict[str, str]:
        """Discover running pods labelled ``app.kubernetes.io/part-of=openrange``.

        Returns a mapping of ``service_name -> namespace/pod_name``.
        """
        result = self._run(
            [
                "kubectl", "get", "pods",
                "--all-namespaces",
                "-l", "app.kubernetes.io/part-of=openrange",
                "-o", "jsonpath="
                "{range .items[*]}"
                "{.metadata.namespace}/{.metadata.name} "
                "{.metadata.labels.app}\\n"
                "{end}",
            ],
            timeout=30.0,
        )
        pod_map: dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                ns_pod, app_label = parts[0], parts[1]
                pod_map[app_label] = ns_pod
        return pod_map

    def _wait_until_healthy(
        self,
        release: BootedRelease,
        services: list[str],
    ) -> None:
        """Poll pods until all are Running+Ready or timeout."""
        deadline = time.monotonic() + self.health_timeout_s
        pending = list(services)
        while pending and time.monotonic() < deadline:
            still_pending: list[str] = []
            for service in pending:
                try:
                    healthy = _run_async(release.containers.is_healthy(service))
                except Exception:
                    healthy = False
                if not healthy:
                    still_pending.append(service)
            if not still_pending:
                return
            pending = still_pending
            time.sleep(self.health_poll_interval_s)
        if pending:
            raise RuntimeError(
                "Timed out waiting for healthy pods: " + ", ".join(pending)
            )

    @staticmethod
    def _run(
        args: list[str],
        *,
        timeout: float,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or "unknown failure"
            raise RuntimeError(
                f"{' '.join(args[:4])}... failed (exit {result.returncode}): {detail}"
            )
        return result


def _run_async(coro):  # type: ignore[no-untyped-def]
    import asyncio

    return asyncio.run(coro)
