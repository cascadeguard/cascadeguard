"""Discovery modules for container-related artifacts."""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Protocol

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
# Helm Chart Discoverer
# ---------------------------------------------------------------------------

class HelmDiscoverer:
    name = "Helm Charts"

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        seen_charts: set[Path] = set()

        for chart_yaml in _rglob_filtered(root, "**/Chart.yaml"):
            chart_dir = chart_yaml.parent.resolve()
            if chart_dir in seen_charts:
                continue
            seen_charts.add(chart_dir)

            chart_meta = self._parse_chart_yaml(chart_yaml)
            values_images = self._parse_values(chart_dir)
            template_images = self._scan_templates(chart_dir)

            artifacts.append(DiscoveredArtifact(
                kind="helm",
                path=str(chart_yaml.parent.relative_to(root)),
                details={
                    "chart_name": chart_meta.get("name", chart_dir.name),
                    "chart_version": chart_meta.get("version", ""),
                    "values_images": values_images,
                    "template_images": template_images,
                    "image_refs": list(dict.fromkeys(values_images + template_images)),
                },
            ))
        return artifacts

    @staticmethod
    def _parse_chart_yaml(path: Path) -> dict:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _parse_values(chart_dir: Path) -> list[str]:
        """Extract image references from values.yaml."""
        images: list[str] = []
        values_file = chart_dir / "values.yaml"
        if not values_file.exists():
            return images

        try:
            with open(values_file) as f:
                data = yaml.safe_load(f)
        except Exception:
            return images

        if not isinstance(data, dict):
            return images

        HelmDiscoverer._walk_values_images(data, images)
        return list(dict.fromkeys(images))

    @staticmethod
    def _walk_values_images(obj: Any, images: list[str], key_path: str = "") -> None:
        """Find image.repository + image.tag patterns in values."""
        if isinstance(obj, dict):
            # Common helm pattern: image.repository + image.tag
            if "repository" in obj and isinstance(obj["repository"], str):
                repo = obj["repository"]
                tag = obj.get("tag", "latest")
                if "/" in repo or "." in repo:
                    images.append(f"{repo}:{tag}" if tag else repo)
            # Also check for direct "image" string fields
            if "image" in obj and isinstance(obj["image"], str):
                img = obj["image"]
                if "/" in img or ":" in img:
                    images.append(img)
            for k, v in obj.items():
                HelmDiscoverer._walk_values_images(v, images, f"{key_path}.{k}")
        elif isinstance(obj, list):
            for item in obj:
                HelmDiscoverer._walk_values_images(item, images, key_path)

    @staticmethod
    def _scan_templates(chart_dir: Path) -> list[str]:
        """Find hardcoded image refs in templates (not Go template expressions)."""
        images: list[str] = []
        templates_dir = chart_dir / "templates"
        if not templates_dir.is_dir():
            return images

        image_re = re.compile(r'image:\s*["\']?([^"\'\s{]+)')
        for tpl in templates_dir.rglob("*.yaml"):
            try:
                for line in tpl.read_text(errors="replace").splitlines():
                    m = image_re.search(line)
                    if m:
                        val = m.group(1)
                        # Skip Go template expressions
                        if "{{" in val or "}}" in val:
                            continue
                        if "/" in val or ":" in val:
                            images.append(val)
            except OSError:
                continue
        return list(dict.fromkeys(images))


# ---------------------------------------------------------------------------
# Kustomize Discoverer
# ---------------------------------------------------------------------------

class KustomizeDiscoverer:
    name = "Kustomize"

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []

        for name in ("kustomization.yaml", "kustomization.yml"):
            for path in _rglob_filtered(root, f"**/{name}"):
                data = self._load(path)
                if not data:
                    continue

                images_config = data.get("images", [])
                resource_images = self._scan_resources(path.parent, root)

                artifacts.append(DiscoveredArtifact(
                    kind="kustomize",
                    path=str(path.relative_to(root)),
                    details={
                        "images_transformer": images_config,
                        "resource_images": resource_images,
                        "image_refs": list(dict.fromkeys(
                            [f"{e.get('name', '')}:{e.get('newTag', e.get('newName', ''))}"
                             for e in images_config if isinstance(e, dict)]
                            + resource_images
                        )),
                        "resources": data.get("resources", []),
                    },
                ))
        return artifacts

    @staticmethod
    def _load(path: Path) -> dict | None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    @staticmethod
    def _scan_resources(kustomize_dir: Path, root: Path) -> list[str]:
        """Scan referenced resources for image refs."""
        images: list[str] = []
        image_re = re.compile(r'image:\s*["\']?([^"\'\s]+)')
        for pattern in ("*.yaml", "*.yml"):
            for f in kustomize_dir.glob(pattern):
                if f.name.startswith("kustomization"):
                    continue
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        m = image_re.search(line)
                        if m and ("/" in m.group(1) or ":" in m.group(1)):
                            images.append(m.group(1))
                except OSError:
                    continue
        return list(dict.fromkeys(images))


# ---------------------------------------------------------------------------
# Raw Kubernetes Manifest Discoverer
# ---------------------------------------------------------------------------

class KubernetesDiscoverer:
    name = "Kubernetes Manifests"

    def __init__(self) -> None:
        self._claimed_paths: set[Path] = set()

    def set_claimed_paths(self, paths: set[Path]) -> None:
        """Paths already claimed by Helm/Kustomize/Compose/Actions discoverers."""
        self._claimed_paths = paths

    def discover(self, root: Path) -> list[DiscoveredArtifact]:
        artifacts: list[DiscoveredArtifact] = []
        seen: set[Path] = set()

        for pattern in ("**/*.yaml", "**/*.yml"):
            for path in _rglob_filtered(root, pattern):
                resolved = path.resolve()
                if resolved in seen or resolved in self._claimed_paths:
                    continue
                seen.add(resolved)

                # Skip files that are clearly not k8s
                rel = str(path.relative_to(root))
                if rel.startswith(".github/"):
                    continue
                if any(p in path.name.lower() for p in ("docker-compose", "compose")):
                    continue
                if path.name in ("Chart.yaml", "kustomization.yaml", "kustomization.yml"):
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
        try:
            with open(path) as f:
                docs = list(yaml.safe_load_all(f))
            return [d for d in docs if isinstance(d, dict)]
        except Exception:
            return []

    @staticmethod
    def _is_k8s_manifest(doc: dict) -> bool:
        return "apiVersion" in doc and "kind" in doc

    @classmethod
    def _extract_images(cls, doc: dict) -> list[str]:
        images: list[str] = []
        cls._walk_containers(doc, images)
        return list(dict.fromkeys(images))

    @classmethod
    def _walk_containers(cls, obj: Any, images: list[str]) -> None:
        if isinstance(obj, dict):
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

# Instantiate discoverers — order matters: Helm and Kustomize run first
# so they can claim paths before the raw K8s discoverer runs.
_dockerfile_discoverer = DockerfileDiscoverer()
_actions_discoverer = ActionsDiscoverer()
_compose_discoverer = ComposeDiscoverer()
_helm_discoverer = HelmDiscoverer()
_kustomize_discoverer = KustomizeDiscoverer()
_k8s_discoverer = KubernetesDiscoverer()

ALL_DISCOVERERS: list[Discoverer] = [
    _dockerfile_discoverer,
    _actions_discoverer,
    _compose_discoverer,
    _helm_discoverer,
    _kustomize_discoverer,
    _k8s_discoverer,
]


def discover_all(root: Path) -> list[DiscoveredArtifact]:
    """Run all discoverers with path-claiming coordination."""
    all_artifacts: list[DiscoveredArtifact] = []
    claimed: set[Path] = set()

    # Run Helm, Kustomize, Compose first to claim their paths
    for discoverer in [_dockerfile_discoverer, _actions_discoverer,
                       _compose_discoverer, _helm_discoverer,
                       _kustomize_discoverer]:
        found = discoverer.discover(root)
        all_artifacts.extend(found)
        for a in found:
            # Claim all files under helm chart dirs and kustomize dirs
            artifact_path = root / a.path
            if artifact_path.is_dir():
                for f in artifact_path.rglob("*"):
                    claimed.add(f.resolve())
            else:
                claimed.add(artifact_path.resolve())
                # For kustomize, claim the whole directory
                if a.kind == "kustomize":
                    for f in artifact_path.parent.rglob("*"):
                        claimed.add(f.resolve())

    # Raw K8s gets the leftovers
    _k8s_discoverer.set_claimed_paths(claimed)
    all_artifacts.extend(_k8s_discoverer.discover(root))

    return all_artifacts
