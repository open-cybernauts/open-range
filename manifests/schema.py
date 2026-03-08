"""Backward-compatible re-export.

The canonical module is ``open_range.manifests.schema``.  This shim keeps
``from manifests.schema import ...`` working when running from the repo root.
"""

from open_range.manifests.schema import *  # noqa: F401,F403
from open_range.manifests.schema import Manifest, load_manifest

__all__ = [
    "Company",
    "BusinessProcess",
    "CredentialPolicy",
    "DataAsset",
    "Department",
    "Difficulty",
    "ExposurePolicy",
    "FirewallRule",
    "Host",
    "Manifest",
    "MonitoringCoverage",
    "NPCProfile",
    "Network",
    "OperationalContext",
    "TechStack",
    "Topology",
    "TrustRelationship",
    "User",
    "load_manifest",
]
