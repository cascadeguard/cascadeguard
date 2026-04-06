"""Discovery modules for container-related artifacts."""

from __future__ import annotations
import re
from pathlib import Path
from typing import Protocol

import yaml

from .models import DiscoveredArtifact

# Directories to skip during discovery
_EXCLUDED_DIRS = frozenset({
    ".git", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".ruff_cache",
    "dist", "build", ".terraform",
})

# Reuse the same regex from app.py ActionsPinner
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s+([^@\n\s]+)@([^\s\n#]+)")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class Discoverer(Protocol):
    """Protocol for artifact discoverers."""
    name: str
    def discover(self, root: Path) -> list[DiscoveredArtifact]: ...


def _is_excluded(path: Path) -> bool:
    """Check if any path component is in the exclusion set."""
    return bool(_EXCLUDED_DIRS & set(path.parts))


def _rglob_filtered(root: Path, pattern: str) -> list[Path]:
    """rglob with excluded directory filtering."""
    return [p for p in root.rglob(pattern) if not _is_excluded(p.relative_to(root))]


# ---------------------------------------------------------------------------
# Dockerfile Discoverer
# ---------------------------------------------------------------------------

class DockerfileDiscoverer:
    name = "Dockerfiles"

    _PATTERNS = [
        "**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile",
        "**/Containerfile", "**/Containerfile.*",
    ]

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        seen: set[Path] = set()
        artifacts: list[DiscoveredArtifact] = []

        for pattern in self._PATTERNS:
            for path in _rglob_filtered(root, pattern):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)

                base_images, stages = self._parse_dockerfile(path)
                artifacts.append(DiscoveredArtifact(
                    kind="dockerfile",
                    path=str(path.relative_to(root)),
                    details={
                        "base_images": base_images,
                        "stages": stages,
                    },
                ))
        return artifacts

    @staticmethod
    def _parse_dockerfile(path: Path) -> tuple[list[str], list[str]]:
        """Extract base images and stage names from a Dockerfile."""
        base_images: list[str] = []
        stages: list[str] = []
        stage_names: set[str] = set()

        try:
            text = path.read_text(errors="replace")
        except OSError:
            return [], []

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue

            parts = stripped.split()
            if len(parts) < 2:
                continue

            image_ref = parts[1]

            # Capture AS alias
            if len(parts) >= 4 and parts[2].upper() == "AS":
                stage_names.add(parts[3])
                stages.append(parts[3])

            # Skip scratch and references to earlier stages
            if image_ref.lower() == "scratch":
                continue
            if image_ref in stage_names:
                continue
            # Heuristic: stage refs are simple lowercase identifiers
            if "/" not in image_ref and ":" not in image_ref and "." not in image_ref:
                if image_ref.islower() and len(image_ref) < 20:
                    continue

            base_images.append(image_ref)

        return base_images, stages


# ---------------------------------------------------------------------------
# GitHub Actions Discoverer
# ---------------------------------------------------------------------------

class ActionsDiscoverer:
    name = "GitHub Actions"

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        workflows_dir = root / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return []

        artifacts: list[DiscoveredArtifact] = []
        for pattern in ("*.yml", "*.yaml"):
            for path in sorted(workflows_dir.glob(pattern)):
                refs = self._parse_workflow(path)
                if not refs:
                    continue

                # Try to get workflow name
                wf_name = self._get_workflow_name(path)

                artifacts.append(DiscoveredArtifact(
                    kind="actions",
                    path=str(path.relative_to(root)),
                    details={
                        "workflow_name": wf_name,
                        "action_refs": refs,
                    },
                ))
        return artifacts

    @staticmethod
    def _parse_workflow(path: Path) -> list[dict]:
        """Extract action references from a workflow file."""
        refs: list[dict] = []
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return []

        for line in text.splitlines():
            m = _USES_RE.match(line)
            if not m:
                continue
            action, ref = m.group(1), m.group(2)
            # Skip local actions
            if action.startswith("./") or "/" not in action:
                continue
            pinned = bool(_SHA_RE.match(ref))
            refs.append({"action": action, "ref": ref, "pinned": pinned})
        return refs

    @staticmethod
    def _get_workflow_name(path: Path) -> str:
        """Extract the 'name' field from a workflow YAML."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data.get("name", path.stem)
        except Exception:
            pass
        return path.stem


# ---------------------------------------------------------------------------
# Docker Compose Discoverer
# ---------------------------------------------------------------------------

class ComposeDiscoverer:
    name = "Docker Compose"

    _PATTERNS = [
        "**/docker-compose*.yml", "**/docker-compose*.yaml",
        "**/compose*.yml", "**/compose*.yaml",
    ]

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        seen: set[Path] = set()
        artifacts: list[DiscoveredArtifact] = []

        for pattern in self._PATTERNS:
            for path in _rglob_filtered(root, pattern):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)

                services, image_refs = self._parse_compose(path)
                if not services:
                    continue

                artifacts.append(DiscoveredArtifact(
                    kind="compose",
                    path=str(path.relative_to(root)),
                    details={
                        "services": services,
                        "image_refs": image_refs,
                    },
                ))
        return artifacts

    @staticmethod
    def _parse_compose(path: Path) -> tuple[list[str], list[str]]:
        """Extract service names and image references from a compose file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except Exception:
            return [], []

        if not isinstance(data, dict):
            return [], []

        services_block = data.get("services", {})
        if not isinstance(services_block, dict):
            return [], []

        services: list[str] = list(services_block.keys())
        image_refs: list[str] = []

        for svc_config in services_block.values():
            if isinstance(svc_config, dict) and "image" in svc_config:
                image_refs.append(str(svc_config["image"]))

        return services, image_refs


# ---------------------------------------------------------------------------
# Kubernetes Manifest Discoverer
# ---------------------------------------------------------------------------

class KubernetesDiscoverer:
    name = "Kubernetes Manifests"

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        seen: set[Path] = set()

        for pattern in ("**/*.yaml", "**/*.yml"):
            for path in _rglob_filtered(root, pattern):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)

                # Skip files that are clearly not k8s
                rel = str(path.relative_to(root))
                if rel.startswith(".github/"):
                    continue
                if any(p in path.name.lower() for p in ("docker-compose", "compose")):
                    continue

                for doc in self._load_yaml_docs(path):
                    if not self._is_k8s_manifest(doc):
                        continue
                    images = self._extract_images(doc)
                    if not images:
                        continue

                    artifacts.append(DiscoveredArtifact(
                        kind="k8s",
                        path=rel,
                        details={
                            "api_version": doc.get("apiVersion", ""),
                            "resource_kind": doc.get("kind", ""),
                            "image_refs": images,
                            "namespace": doc.get("metadata", {}).get("namespace", ""),
                        },
                    ))
        return artifacts

    @staticmethod
    def _load_yaml_docs(path: Path) -> list[dict]:
        """Load all YAML documents from a file (multi-doc support)."""
        try:
            with open(path) as f:
                docs = list(yaml.safe_load_all(f))
            return [d for d in docs if isinstance(d, dict)]
        except Exception:
            return []

    @staticmethod
    def _is_k8s_manifest(doc: dict) -> bool:
        """Check if a YAML document looks like a Kubernetes manifest."""
        return "apiVersion" in doc and "kind" in doc

    @classmethod
    def _extract_images(cls, doc: dict) -> list[str]:
        """Extract container image references from a k8s manifest."""
        images: list[str] = []
        cls._walk_containers(doc, images)
        return list(dict.fromkeys(images))  # dedupe, preserve order

    @classmethod
    def _walk_containers(cls, obj: Any, images: list[str]) -> None:
        """Recursively find container image fields."""
        if isinstance(obj, dict):
            # Direct container spec
            if "image" in obj and isinstance(obj["image"], str):
                images.append(obj["image"])
            for v in obj.values():
                cls._walk_containers(v, images)
        elif isinstance(obj, list):
            for item in obj:
                cls._walk_containers(item, images)


# ---------------------------------------------------------------------------
# Registry of all discoverers
# ---------------------------------------------------------------------------

ALL_DISCOVERERS: list[Discoverer] = [
    DockerfileDiscoverer(),
    ActionsDiscoverer(),
    ComposeDiscoverer(),
    KubernetesDiscoverer(),
]
