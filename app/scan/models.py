"""Data models for scan results."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiscoveredArtifact:
    """A single discovered container-related artifact."""
    kind: str       # dockerfile | actions | compose | k8s
    path: str       # relative to scan root
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        """One-line summary for display."""
        if self.kind == "dockerfile":
            bases = self.details.get("base_images", [])
            return f"base: {', '.join(bases)}" if bases else "no base images"
        if self.kind == "actions":
            refs = self.details.get("action_refs", [])
            unpinned = sum(1 for r in refs if not r.get("pinned", False))
            return f"{len(refs)} actions, {unpinned} unpinned"
        if self.kind == "compose":
            svcs = self.details.get("services", [])
            imgs = self.details.get("image_refs", [])
            return f"{len(svcs)} services, {len(imgs)} image refs"
        if self.kind == "helm":
            name = self.details.get("chart_name", "")
            ver = self.details.get("chart_version", "")
            imgs = self.details.get("image_refs", [])
            label = f"{name}"
            if ver:
                label += f" {ver}"
            return f"{label}, {len(imgs)} image refs"
        if self.kind == "kustomize":
            imgs = self.details.get("image_refs", [])
            transformer = self.details.get("images_transformer", [])
            return f"{len(transformer)} image overrides, {len(imgs)} image refs"
        if self.kind == "k8s":
            imgs = self.details.get("image_refs", [])
            k = self.details.get("resource_kind", "")
            return f"{k}, {len(imgs)} containers" if k else f"{len(imgs)} containers"
        return ""


@dataclass
class ArtifactAnalysis:
    """Analysis result for a single artifact."""
    artifact: DiscoveredArtifact
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_level: str = "info"  # info | low | medium | high


@dataclass
class ScanSummary:
    """Aggregate summary of a scan."""
    total_discovered: int = 0
    total_selected: int = 0
    total_images: int = 0
    total_actions: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    by_risk: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan output."""
    root_dir: str
    discovered: list[DiscoveredArtifact] = field(default_factory=list)
    selected: list[DiscoveredArtifact] = field(default_factory=list)
    analysis: list[ArtifactAnalysis] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
