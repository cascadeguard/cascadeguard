#!/usr/bin/env python3
"""
CascadeGuard — container image lifecycle tool.

Commands:
  images validate       Validate images.yaml configuration
  images enrol          Enrol a new image in images.yaml
  images check          Check image and base image states
  images status         Show status of all images
  pipeline run          Run full pipeline (validate -> check -> build -> deploy -> test)
  pipeline build        Trigger a build via GitHub Actions
  pipeline deploy       Deploy via ArgoCD
  pipeline test         Check build test results via GitHub Actions
  vuln report           Parse scanner output, write diffable vulnerability reports
  vuln issues           Create/update/reopen per-CVE GitHub issues
  actions pin           Pin GitHub Actions refs to full commit SHAs
  actions audit         Audit workflow files against an actions-policy.yaml
  actions policy init   Scaffold a starter actions-policy.yaml
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import yaml
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class CascadeGuardTool:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.images_yaml_path = root_dir / "images.yaml"
        self.state_images_dir = root_dir / "state" / "images"
        self.state_base_images_dir = root_dir / "state" / "base-images"
        
        # Ensure directories exist
        self.state_images_dir.mkdir(parents=True, exist_ok=True)
        self.state_base_images_dir.mkdir(parents=True, exist_ok=True)
    
    def _yaml_value(self, value):
        """Format a value for YAML output."""
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, str):
            return value
        else:
            return str(value)
    
    def load_images_yaml(self) -> List[Dict]:
        """Load and validate images.yaml."""
        if not self.images_yaml_path.exists():
            logger.warning(f"images.yaml not found at {self.images_yaml_path}")
            return []
        
        with open(self.images_yaml_path, 'r') as f:
            data = yaml.safe_load(f) or []
        
        logger.info(f"Loaded {len(data)} images from images.yaml")
        return data
    
    def parse_dockerfile_base_images(self, dockerfile_path: Path) -> List[str]:
        """Extract all base images from Dockerfile FROM statements (multi-stage support)."""
        if not dockerfile_path.exists():
            logger.warning(f"Dockerfile not found: {dockerfile_path}")
            return []
        
        base_images = []
        with open(dockerfile_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('FROM '):
                    # Extract image reference, handle AS alias
                    match = re.match(r'FROM\s+([^\s]+)', line)
                    if match:
                        image_ref = match.group(1)
                        # Skip scratch and stage references
                        if image_ref.lower() != 'scratch' and not self._is_stage_reference(image_ref, base_images):
                            base_images.append(image_ref)
        
        return base_images
    
    def _is_stage_reference(self, image_ref: str, previous_images: List[str]) -> bool:
        """Check if image reference is a stage name from previous FROM statements."""
        # Stage names are typically lowercase and don't contain registry/repository patterns
        if '/' in image_ref or ':' in image_ref or '.' in image_ref:
            return False
        
        # Check if it matches any previous stage names that might have been defined
        # This is a simple heuristic - stage names are usually simple identifiers
        return image_ref.islower() and len(image_ref) < 20
    
    def parse_dockerfile_base_image(self, dockerfile_path: Path) -> Optional[str]:
        """Extract base image from Dockerfile FROM statement (legacy method for compatibility)."""
        base_images = self.parse_dockerfile_base_images(dockerfile_path)
        return base_images[0] if base_images else None
    
    def normalize_base_image_name(self, image_ref: str) -> str:
        """Convert image reference to normalized name for filename."""
        # Remove registry prefix if present
        if '/' in image_ref:
            parts = image_ref.split('/')
            if len(parts) == 3:  # registry/repo/image:tag
                image_ref = '/'.join(parts[1:])
        
        # Replace special chars with hyphens
        name = re.sub(r'[:/]', '-', image_ref)
        return name
    
    def parse_image_reference(self, image_ref: str) -> Dict[str, str]:
        """Parse image reference into components."""
        result = {
            'fullImage': image_ref,
            'registry': 'docker.io',
            'repository': '',
            'tag': 'latest'
        }
        
        # Handle registry - only if it has a '.' (domain) and comes before any '/'
        parts = image_ref.split('/')
        if len(parts) > 1 and '.' in parts[0]:  # Has registry (e.g., ghcr.io/owner/image)
            result['registry'] = parts[0]
            parts = parts[1:]
        
        # Handle repository and tag
        if parts:
            repo_tag = '/'.join(parts)
            if ':' in repo_tag:
                repo, tag = repo_tag.rsplit(':', 1)
                result['repository'] = repo
                result['tag'] = tag
            else:
                result['repository'] = repo_tag
        
        # Add library/ prefix for official Docker images
        if result['registry'] == 'docker.io' and '/' not in result['repository']:
            result['repository'] = f"library/{result['repository']}"
        
        return result
    
    def generate_base_image_state(self, image_ref: str) -> Dict:
        """Generate state file content for a base image."""
        parsed = self.parse_image_reference(image_ref)
        name = self.normalize_base_image_name(image_ref)
        now = datetime.now(timezone.utc).isoformat()
        
        # Generate allowTags regex from tag
        tag = parsed['tag']
        # For simple tags (alphanumeric, hyphens, dots), no escaping needed
        # Only escape truly special regex chars: . * + ? ^ $ ( ) [ ] { } | \
        escaped_tag = tag.replace('.', r'\.').replace('*', r'\*').replace('+', r'\+').replace('?', r'\?')
        escaped_tag = escaped_tag.replace('(', r'\(').replace(')', r'\)').replace('[', r'\[').replace(']', r'\]')
        escaped_tag = escaped_tag.replace('{', r'\{').replace('}', r'\}').replace('|', r'\|').replace('\\', r'\\')
        allow_tags = f"^{escaped_tag}$"
        
        return {
            'name': name,
            'fullImage': image_ref,
            'registry': parsed['registry'],
            'repository': parsed['repository'],
            'tag': parsed['tag'],
            'allowTags': allow_tags,
            'imageSelectionStrategy': 'Lexical',
            'repoURL': f"{parsed['registry']}/{parsed['repository']}",
            'firstDiscovered': now,
            'lastChecked': now,
            'currentDigest': None,
            'lastUpdated': None,
            'previousDigest': None,
            'rebuildEligibleAt': {'default': None},
            'metadata': {},
            'updateHistory': [],
            'lastDiscovery': None
        }
    
    def write_base_image_state(self, state: Dict, file_path: Path):
        """Write base image state file with proper formatting and comments."""
        with open(file_path, 'w') as f:
            f.write(f"# Auto-generated by CascadeGuard\n")
            f.write(f"# This file tracks the upstream {state['fullImage']} base image\n\n")
            
            f.write("# Normalized identifier (used as filename and reference)\n")
            f.write(f"name: {state['name']}\n\n")
            
            f.write("# Original image reference\n")
            f.write(f"fullImage: {state['fullImage']}\n")
            f.write(f"registry: {state['registry']}\n")
            f.write(f"repository: {state['repository']}\n")
            f.write(f"tag: {state['tag']}\n\n")
            
            f.write("# Warehouse configuration (for CDK8s)\n")
            f.write(f"allowTags: {state['allowTags']}\n")
            f.write(f"imageSelectionStrategy: {state['imageSelectionStrategy']}\n")
            f.write(f"repoURL: {state['repoURL']}\n\n")
            
            f.write("# Discovery\n")
            f.write(f"firstDiscovered: {yaml.dump(state['firstDiscovered'], default_flow_style=True).strip()}\n")
            f.write(f"lastChecked: {yaml.dump(state['lastChecked'], default_flow_style=True).strip()}\n\n")
            
            f.write("# Current state\n")
            f.write(f"currentDigest: {self._yaml_value(state['currentDigest'])}\n")
            f.write(f"lastUpdated: {self._yaml_value(state['lastUpdated'])}  # Will be set when digest first changes\n")
            f.write(f"previousDigest: {self._yaml_value(state['previousDigest'])}\n\n")
            
            f.write("# Rebuild eligibility\n")
            f.write(f"rebuildEligibleAt:\n")
            f.write(f"  default: {self._yaml_value(state['rebuildEligibleAt']['default'])}  # Will be calculated as lastUpdated + rebuildDelay\n\n")
            
            f.write("# Metadata from registry\n")
            if state.get('metadata') and state['metadata']:
                f.write("metadata:\n")
                for key, value in state['metadata'].items():
                    f.write(f"  {key}: {yaml.dump(value, default_flow_style=True).strip()}\n")
            else:
                f.write("metadata: {}\n")
            f.write("\n")
            
            f.write("# Update history (last 10 digest changes)\n")
            if state.get('updateHistory'):
                f.write("updateHistory:\n")
                for entry in state['updateHistory']:
                    f.write(f"  - {yaml.dump(entry, default_flow_style=True).strip()}\n")
            else:
                f.write("updateHistory: []\n")
            
            if state.get('lastDiscovery') is not None:
                f.write(f"\nlastDiscovery: {self._yaml_value(state['lastDiscovery'])}\n")
    
    def write_image_state(self, state: Dict, file_path: Path):
        """Write image state file with proper formatting and comments."""
        is_external = state.get('discoveryStatus') == 'external'
        
        with open(file_path, 'w') as f:
            f.write(f"# Auto-generated by CascadeGuard\n")
            f.write(f"# This file tracks the state of the {state['name']} image\n")
            f.write(f"name: {state['name']}\n")
            f.write(f"enrolledAt: {yaml.dump(state['enrolledAt'], default_flow_style=True).strip()}\n")
            f.write(f"lastDiscovery: {yaml.dump(state['lastDiscovery'], default_flow_style=True).strip()}\n")
            f.write(f"discoveryStatus: {state['discoveryStatus']}\n\n")
            
            f.write("# Enrollment configuration (copied from images.yaml for reference)\n")
            f.write("enrollment:\n")
            enrollment = state['enrollment']
            f.write(f"  registry: {enrollment['registry']}\n")
            f.write(f"  repository: {enrollment['repository']}\n")
            if 'source' in enrollment:
                f.write("  source:\n")
                for key, value in enrollment['source'].items():
                    f.write(f"    {key}: {value}\n")
            f.write(f"  rebuildDelay: {enrollment['rebuildDelay']}\n")
            f.write(f"  autoRebuild: {str(enrollment['autoRebuild']).lower()}\n\n")
            
            if is_external:
                f.write("# Warehouse configuration (for CDK8s)\n")
                if 'allowTags' in state:
                    f.write(f"allowTags: {state['allowTags']}\n")
                if 'imageSelectionStrategy' in state:
                    f.write(f"imageSelectionStrategy: {state['imageSelectionStrategy']}\n")
                if 'repoURL' in state:
                    f.write(f"repoURL: {state['repoURL']}\n")
                f.write("\n")
            
            f.write("# Discovered from Dockerfile parsing\n")
            if not is_external:
                f.write("# References to base image state files (not inline data)\n")
            f.write("baseImages:")
            if state['baseImages']:
                f.write("\n")
                for base in state['baseImages']:
                    f.write(f"  - {base}\n")
            else:
                f.write(" []\n")
            f.write("\n")
            
            f.write("# Current published state (from registry/Kargo)\n")
            f.write(f"currentVersion: {self._yaml_value(state.get('currentVersion'))}\n")
            f.write(f"currentDigest: {self._yaml_value(state.get('currentDigest'))}\n")
            last_built = state.get('lastBuilt')
            if last_built:
                f.write(f"lastBuilt: {yaml.dump(last_built, default_flow_style=True).strip()}\n\n")
            else:
                f.write(f"lastBuilt: null\n")
    
    def generate_image_state(self, image_config: Dict, base_images: List[str]) -> Dict:
        """Generate state file content for a managed image."""
        name = image_config['name']
        now = datetime.now(timezone.utc).isoformat()
        
        # Check if this is an external image (no repo info)
        is_external = 'source' not in image_config or not image_config.get('source', {}).get('repo')
        
        state = {
            'name': name,
            'enrolledAt': now,
            'lastDiscovery': now,
            'discoveryStatus': 'pending' if not is_external else 'external',
            'enrollment': {
                'registry': image_config.get('registry', 'docker.io'),
                'repository': image_config.get('repository', ''),
                'rebuildDelay': image_config.get('rebuildDelay', '7d'),
                'autoRebuild': image_config.get('autoRebuild', True)
            }
        }
        
        # Add source info if present (managed image)
        if not is_external:
            state['enrollment']['source'] = image_config['source']
            state['baseImages'] = sorted(base_images)
        else:
            state['baseImages'] = []
        
        # Add warehouse fields for cdk8s
        if is_external:
            # External image - use registry/repository from enrollment
            parsed = self.parse_image_reference(
                f"{image_config.get('registry', 'docker.io')}/{image_config.get('repository', name)}"
            )
            state['allowTags'] = image_config.get('allowTags', '^.*$')
            state['imageSelectionStrategy'] = image_config.get('imageSelectionStrategy', 'Lexical')
            state['repoURL'] = f"{parsed['registry']}/{parsed['repository']}"
        
        state.update({
            'currentVersion': None,
            'currentDigest': None,
            'lastBuilt': None
        })
        
        return state
    
    def merge_state(self, existing: Dict, new: Dict, prefer_new: bool = True) -> Dict:
        """Merge existing state with new state, preserving runtime data."""
        # Start with new state to ensure all required fields are present
        merged = dict(new)
        
        # Preserve runtime data from existing state (not computed fields or rebuild orchestration data)
        runtime_fields = [
            'currentDigest', 'lastBuilt', 'previousDigest', 'lastUpdated',
            'updateHistory', 'metadata',
            'currentVersion', 'enrolledAt', 'firstDiscovered', 'rebuildEligibleAt'
        ]
        
        for key in runtime_fields:
            if key in existing and key not in merged:
                merged[key] = existing[key]
            elif key in existing and merged.get(key) is None:
                # Preserve existing value if new value is None
                merged[key] = existing[key]
        
        # For enrollment, prefer new but preserve if not in new
        if 'enrollment' not in merged and 'enrollment' in existing:
            merged['enrollment'] = existing['enrollment']
        
        return merged
    
    def process(self):
        """Main processing logic."""
        logger.info("Starting CascadeGuard processing...")
        
        # Load images.yaml
        images = self.load_images_yaml()
        if not images:
            logger.warning("No images to process")
            return
        
        # Track base images and their dependents
        base_image_dependents: Dict[str, Set[str]] = {}
        
        # Process each image
        for image_config in images:
            name = image_config.get('name')
            if not name:
                logger.warning(f"Skipping image without name: {image_config}")
                continue
            
            logger.info(f"Processing image: {name}")
            
            # Discover base images if this is a managed image
            base_images = []
            source = image_config.get('source', {})
            if source.get('repo') and source.get('dockerfile'):
                # Construct dockerfile path - dockerfile paths in images.yaml are relative to workspace root
                # The root_dir points to cascadeguard directory, so we need to go up one level to workspace root
                workspace_root = self.root_dir.resolve().parent
                dockerfile_path = workspace_root / source['dockerfile']
                discovered_base_images = self.parse_dockerfile_base_images(dockerfile_path)
                
                if discovered_base_images:
                    # Deduplicate base images while preserving order
                    seen = set()
                    for base_image_ref in discovered_base_images:
                        base_image_name = self.normalize_base_image_name(base_image_ref)
                        if base_image_name not in seen:
                            base_images.append(base_image_name)
                            seen.add(base_image_name)
                            
                            # Track dependency
                            if base_image_ref not in base_image_dependents:
                                base_image_dependents[base_image_ref] = set()
                            base_image_dependents[base_image_ref].add(name)
                    
                    logger.info(f"  Found {len(discovered_base_images)} base images, {len(base_images)} unique: {base_images}")
                else:
                    logger.info(f"  No base images found in Dockerfile")
            
            # Generate new state
            new_state = self.generate_image_state(image_config, base_images)
            
            # Load existing state if present
            state_file = self.state_images_dir / f"{name}.yaml"
            if state_file.exists():
                with open(state_file, 'r') as f:
                    existing_state = yaml.safe_load(f) or {}
                new_state = self.merge_state(existing_state, new_state, prefer_new=True)
                logger.info(f"  Updated existing state file")
            else:
                logger.info(f"  Created new state file")
            
            # Write state file with proper formatting
            self.write_image_state(new_state, state_file)
        
        # Process base images
        logger.info(f"Processing {len(base_image_dependents)} base images...")
        for base_image_ref in base_image_dependents.keys():
            base_image_name = self.normalize_base_image_name(base_image_ref)
            logger.info(f"Processing base image: {base_image_name}")
            
            # Generate new state
            new_state = self.generate_base_image_state(base_image_ref)
            
            # Load existing state if present
            state_file = self.state_base_images_dir / f"{base_image_name}.yaml"
            if state_file.exists():
                with open(state_file, 'r') as f:
                    existing_state = yaml.safe_load(f) or {}
                # Merge to preserve runtime data
                new_state = self.merge_state(existing_state, new_state, prefer_new=False)
                logger.info(f"  Updated existing base image state")
            else:
                logger.info(f"  Created new base image state")
            
            # Write state file with proper formatting
            self.write_base_image_state(new_state, state_file)
        
        logger.info("Processing complete!")


# ---------------------------------------------------------------------------
# Actions pinner
# ---------------------------------------------------------------------------

_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
# Matches a YAML `uses:` line (with or without leading `- `): captures (prefix, action, ref, trailing)
_USES_RE = re.compile(r'^(\s*(?:-\s+)?uses:\s+)([^@\n\s]+)@([^\s\n#]+)(.*?)$')
# Matches any `uses:` line (to detect local/unversioned actions with no `@`)
_USES_ANY_RE = re.compile(r'^\s*(?:-\s+)?uses:\s+\S')


class ActionsPinner:
    """Pins mutable GitHub Actions refs (tags/branches) to full commit SHAs."""

    def __init__(self, token: str, workflows_dir: Path):
        self.token = token
        self.workflows_dir = workflows_dir
        self._sha_cache: Dict[str, str] = {}

    def _resolve_sha(self, owner_repo: str, ref: str) -> Optional[str]:
        """Resolve a tag/branch ref to its commit SHA via the GitHub API."""
        cache_key = f"{owner_repo}@{ref}"
        if cache_key in self._sha_cache:
            return self._sha_cache[cache_key]

        url = f"https://api.github.com/repos/{owner_repo}/commits/{ref}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                sha = data["sha"]
                self._sha_cache[cache_key] = sha
                return sha
        except (urllib.error.HTTPError, urllib.error.URLError, KeyError):
            return None

    def pin(self, dry_run: bool = False, update: bool = False) -> Dict:
        """
        Pin all mutable action refs in workflow files to commit SHAs.

        Returns a summary dict with keys: pinned, already_pinned, skipped.
        """
        pinned = 0
        already_pinned = 0
        skipped = 0

        patterns = list(self.workflows_dir.glob("*.yml")) + list(self.workflows_dir.glob("*.yaml"))

        for wf_path in sorted(patterns):
            original = wf_path.read_text()
            lines = original.splitlines(keepends=True)
            new_lines = []
            changed = False

            for line in lines:
                m = _USES_RE.match(line)
                if not m:
                    # Count `uses:` lines without `@` (e.g. local actions) as skipped
                    if _USES_ANY_RE.match(line):
                        skipped += 1
                    new_lines.append(line)
                    continue

                prefix, action, ref, trailing = m.groups()

                # Skip local composite actions (relative paths)
                if action.startswith('./') or '/' not in action:
                    new_lines.append(line)
                    skipped += 1
                    continue

                eol = '\n' if line.endswith('\n') else ''

                if _SHA_RE.match(ref):
                    # Already pinned to a full SHA
                    if not update:
                        new_lines.append(line)
                        already_pinned += 1
                        continue

                    # --update: re-pin to latest SHA for the same tag (from trailing comment)
                    comment_match = re.search(r'#\s*(\S+)', trailing)
                    if not comment_match:
                        new_lines.append(line)
                        already_pinned += 1
                        continue

                    original_ref = comment_match.group(1)
                    sha = self._resolve_sha(action, original_ref)
                    if sha is None or sha == ref:
                        new_lines.append(line)
                        already_pinned += 1
                        continue

                    new_lines.append(f"{prefix}{action}@{sha} # {original_ref}{eol}")
                    changed = True
                    pinned += 1
                else:
                    # Mutable ref — resolve to SHA
                    sha = self._resolve_sha(action, ref)
                    if sha is None:
                        new_lines.append(line)
                        skipped += 1
                        continue

                    new_lines.append(f"{prefix}{action}@{sha} # {ref}{eol}")
                    changed = True
                    pinned += 1

            if changed and not dry_run:
                wf_path.write_text(''.join(new_lines))

        return {"pinned": pinned, "already_pinned": already_pinned, "skipped": skipped}


# ---------------------------------------------------------------------------
# Provider interfaces
# ---------------------------------------------------------------------------


class Provider(ABC):
    """Abstract base class for CI/CD providers."""

    @abstractmethod
    def trigger_build(self, image_name: str, tag: str = "latest") -> dict:
        """Trigger a build for an image."""

    @abstractmethod
    def get_build_status(self, image_name: str) -> dict:
        """Get the latest build status for an image."""


class GitHubActionsProvider(Provider):
    """GitHub Actions provider — triggers workflow_dispatch events."""

    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.api_base = "https://api.github.com"

    def _request(self, method: str, path: str, data: Optional[dict] = None) -> dict:
        url = f"{self.api_base}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                if resp.status == 204:
                    return {}
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"GitHub API error {exc.code}: {exc.read().decode()}"
            ) from exc

    def trigger_build(self, image_name: str, tag: str = "latest") -> dict:
        """Dispatch the build-<image_name>.yml workflow."""
        workflow_file = f"build-{image_name}.yml"
        path = f"/repos/{self.repo}/actions/workflows/{workflow_file}/dispatches"
        self._request("POST", path, {"ref": "main", "inputs": {"tag": tag}})
        return {"status": "triggered", "workflow": workflow_file, "tag": tag}

    def get_build_status(self, image_name: str) -> dict:
        """Return the most recent workflow run for build-<image_name>.yml."""
        workflow_file = f"build-{image_name}.yml"
        path = f"/repos/{self.repo}/actions/workflows/{workflow_file}/runs?per_page=1"
        result = self._request("GET", path)
        runs = result.get("workflow_runs", [])
        if not runs:
            return {"status": "no_runs", "workflow": workflow_file}
        run = runs[0]
        return {
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "workflow": workflow_file,
            "run_id": run.get("id"),
            "url": run.get("html_url"),
        }


class ArgoCDProvider(Provider):
    """ArgoCD provider — triggers application syncs."""

    def __init__(self, server: str, token: str, app_name: str):
        self.server = server.rstrip("/")
        self.token = token
        self.app_name = app_name

    def _request(self, method: str, path: str, data: Optional[dict] = None) -> dict:
        url = f"{self.server}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read()
                return json.loads(content) if content else {}
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"ArgoCD API error {exc.code}: {exc.read().decode()}"
            ) from exc

    def trigger_build(self, image_name: str, tag: str = "latest") -> dict:
        """Sync the ArgoCD application (deploy)."""
        return self.sync(image_name)

    def sync(self, image_name: str) -> dict:
        """POST /api/v1/applications/<app>/sync to trigger a deployment."""
        path = f"/api/v1/applications/{self.app_name}/sync"
        self._request("POST", path, {})
        return {"status": "syncing", "app": self.app_name, "image": image_name}

    def get_build_status(self, image_name: str) -> dict:
        """Return ArgoCD application health and sync status."""
        path = f"/api/v1/applications/{self.app_name}"
        result = self._request("GET", path)
        health = result.get("status", {}).get("health", {})
        sync = result.get("status", {}).get("sync", {})
        return {
            "health": health.get("status"),
            "sync": sync.get("status"),
            "app": self.app_name,
        }


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def load_config(repo_root: Path) -> dict:
    """Load .cascadeguard.yaml from repo_root. Returns {} if absent."""
    config_path = repo_root / ".cascadeguard.yaml"
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print(f"Error: malformed .cascadeguard.yaml: {exc}", file=sys.stderr)
        sys.exit(1)
    if data is None:
        return {}
    if not isinstance(data, dict):
        print("Error: .cascadeguard.yaml root must be a mapping", file=sys.stderr)
        sys.exit(1)
    return data


def merge_defaults(images: list, config: dict) -> list:
    """Apply repo-level defaults from .cascadeguard.yaml to each image.

    Per-image values always take precedence over config defaults.
    Only these keys are inherited: registry, repository, local.dir.
    Does NOT mutate the input list or its dicts.
    """
    defaults = config.get("defaults", {})
    if not defaults:
        return [dict(img) for img in images]

    default_registry = defaults.get("registry")
    default_repository = defaults.get("repository")
    default_local = defaults.get("local", {})
    default_local_dir = default_local.get("dir")

    result = []
    for img in images:
        merged = dict(img)

        if "registry" not in merged and default_registry:
            merged["registry"] = default_registry

        if "repository" not in merged and default_repository:
            merged["repository"] = default_repository

        if default_local_dir:
            img_local = merged.get("local", {})
            if "dir" not in img_local:
                merged_local = dict(img_local)
                merged_local["dir"] = default_local_dir
                merged["local"] = merged_local

        result.append(merged)

    return result


def cmd_validate(args) -> int:
    """Validate images.yaml structure and required fields."""
    images_yaml = Path(args.images_yaml)
    if not images_yaml.exists():
        print(f"Error: images.yaml not found: {images_yaml}", file=sys.stderr)
        return 1

    with open(images_yaml) as f:
        images = yaml.safe_load(f) or []

    if not isinstance(images, list):
        print("Error: images.yaml must be a list", file=sys.stderr)
        return 1

    # Load config and merge defaults BEFORE validation
    repo_root = images_yaml.parent
    config = load_config(repo_root)
    resolved_images = merge_defaults(images, config)

    errors = []
    for i, image in enumerate(resolved_images):
        name = image.get("name")
        if not name:
            errors.append(f"Image {i}: missing 'name' field")
            continue

        # Disabled images only need a name
        if not image.get("enabled", True):
            continue

        # Enabled images need registry and dockerfile
        if not image.get("registry"):
            errors.append(f"Image '{name}': missing 'registry' (set in image or .cascadeguard.yaml defaults)")
        if not image.get("dockerfile"):
            errors.append(f"Image '{name}': missing 'dockerfile' field")

    if errors:
        print("Validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"Validated {len(resolved_images)} images in {images_yaml}")
    return 0


def cmd_enrol(args) -> int:
    """Enrol a new image in images.yaml."""
    images_yaml = Path(args.images_yaml)

    if images_yaml.exists():
        with open(images_yaml) as f:
            images = yaml.safe_load(f) or []
    else:
        images = []

    if any(img.get("name") == args.name for img in images):
        print(f"Error: image '{args.name}' is already enrolled", file=sys.stderr)
        return 1

    new_image: dict = {
        "name": args.name,
        "registry": args.registry,
        "repository": args.repository,
    }

    if args.provider:
        source: dict = {"provider": args.provider, "repo": args.repo}
        if args.dockerfile:
            source["dockerfile"] = args.dockerfile
        if args.branch:
            source["branch"] = args.branch
        new_image["source"] = source

    if args.rebuild_delay:
        new_image["rebuildDelay"] = args.rebuild_delay

    if args.auto_rebuild:
        new_image["autoRebuild"] = True

    images.append(new_image)

    with open(images_yaml, "w") as f:
        yaml.dump(images, f, default_flow_style=False, allow_unicode=True)

    print(f"Enrolled '{args.name}' in {images_yaml}")
    return 0


def _fetch_manifest_digest(registry: str, repository: str, tag: str, token: Optional[str] = None) -> Optional[str]:
    """
    Fetch the current manifest digest for registry/repository:tag via the registry v2 API.

    Handles Docker Hub (docker.io) and GHCR (ghcr.io).  Returns the
    Docker-Content-Digest header value (e.g. 'sha256:abc…') or None when the
    registry is unreachable or the image/tag does not exist.
    """
    ACCEPT = (
        "application/vnd.docker.distribution.manifest.v2+json,"
        "application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.oci.image.index.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json"
    )

    def _get_token(auth_url: str, creds: Optional[str] = None) -> str:
        req = urllib.request.Request(auth_url)
        if creds:
            import base64
            req.add_header("Authorization", f"Basic {base64.b64encode(creds.encode()).decode()}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data.get("token") or data.get("access_token") or ""

    def _head_manifest(manifest_url: str, bearer: str) -> Optional[str]:
        req = urllib.request.Request(manifest_url, method="HEAD")
        req.add_header("Authorization", f"Bearer {bearer}")
        req.add_header("Accept", ACCEPT)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.headers.get("Docker-Content-Digest")

    try:
        if registry in ("docker.io", "registry-1.docker.io", "index.docker.io", ""):
            auth_url = (
                f"https://auth.docker.io/token"
                f"?service=registry.docker.io&scope=repository:{repository}:pull"
            )
            bearer = _get_token(auth_url)
            manifest_url = f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}"
            return _head_manifest(manifest_url, bearer)

        elif registry == "ghcr.io":
            ghcr_token = token or os.environ.get("GHCR_TOKEN") or os.environ.get("GITHUB_TOKEN")
            creds = f":{ghcr_token}" if ghcr_token else None
            auth_url = (
                f"https://ghcr.io/token"
                f"?service=ghcr.io&scope=repository:{repository}:pull"
            )
            bearer = _get_token(auth_url, creds)
            manifest_url = f"https://ghcr.io/v2/{repository}/manifests/{tag}"
            return _head_manifest(manifest_url, bearer)

        else:
            # Generic registry v2 — attempt anonymous
            auth_url = (
                f"https://{registry}/token"
                f"?service={registry}&scope=repository:{repository}:pull"
            )
            bearer = _get_token(auth_url)
            manifest_url = f"https://{registry}/v2/{repository}/manifests/{tag}"
            return _head_manifest(manifest_url, bearer)

    except Exception as exc:
        logger.warning(f"Could not query {registry}/{repository}:{tag}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Docker Hub upstream-tag helpers (used by cmd_check Phase 4)
# ---------------------------------------------------------------------------

_DOCKER_HUB_TAGS_URL = (
    "https://hub.docker.com/v2/repositories/{namespace}/{image}"
    "/tags?page_size=100&ordering=last_updated"
)


def _get_dockerhub_tags(namespace: str, image: str) -> List[str]:
    """Fetch all tags for a Docker Hub image, paginating up to 10 pages."""
    url: Optional[str] = _DOCKER_HUB_TAGS_URL.format(namespace=namespace, image=image)
    tags: List[str] = []
    page = 0
    try:
        while url and page < 10:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            tags.extend(t["name"] for t in data.get("results", []))
            url = data.get("next") or ""
            page += 1
    except Exception as exc:
        logger.warning(f"Could not fetch tags for {namespace}/{image}: {exc}")
    return tags


def _is_stable_tag(tag: str) -> bool:
    """Return True if *tag* looks like a stable release (not RC/nightly/etc.)."""
    skip = {"latest", "edge", "nightly", "testing"}
    if tag in skip:
        return False
    for suffix in ("-rc", "-alpha", "-beta", "-dev", "-test", ".rc", "-SNAPSHOT"):
        if suffix in tag.lower():
            return False
    if tag.startswith("sha256:") or len(tag) == 64:
        return False
    return True


def cmd_check(args) -> int:
    """Unified check: generate state, discover base images, query registries."""
    from generate_state import (
        parse_dockerfile_base_images,
        normalize_base_image_name,
        clone_repo_if_needed,
    )

    images_yaml = Path(args.images_yaml)
    if not images_yaml.exists():
        print(f"Error: images.yaml not found: {images_yaml}", file=sys.stderr)
        return 1

    with open(images_yaml) as f:
        images = yaml.safe_load(f) or []

    repo_root = images_yaml.parent
    config = load_config(repo_root)
    resolved_images = merge_defaults(images, config)

    state_dir = Path(args.state_dir)
    images_dir = state_dir / "images"
    base_images_dir = state_dir / "base-images"
    cache_dir = state_dir / ".cache"
    images_dir.mkdir(parents=True, exist_ok=True)
    base_images_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    image_filter: Optional[str] = getattr(args, "image", None)
    fmt: str = getattr(args, "format", "table")

    # ── Phase 1: Generate image state + discover base images ───────────────
    all_base_image_refs: Dict[str, str] = {}  # normalized_name -> full image ref

    for image in resolved_images:
        name = image.get("name")
        if not name:
            continue
        if not image.get("enabled", True):
            continue
        if image_filter and name != image_filter:
            continue

        # Find Dockerfile (local or remote)
        source = image.get("source", {})
        dockerfile_rel = image.get("dockerfile") or source.get("dockerfile")
        base_images = []

        if dockerfile_rel:
            try:
                if source.get("repo"):
                    repo_dir = clone_repo_if_needed(source, dockerfile_rel, cache_dir)
                    full_path = repo_dir / dockerfile_rel
                else:
                    full_path = repo_root / dockerfile_rel
                    if not full_path.exists():
                        full_path = state_dir / dockerfile_rel

                if full_path.exists():
                    discovered = parse_dockerfile_base_images(full_path)
                    seen = set()
                    for ref in discovered:
                        norm = normalize_base_image_name(ref)
                        if norm not in seen:
                            base_images.append(norm)
                            all_base_image_refs[norm] = ref
                            seen.add(norm)
                    if base_images:
                        print(f"  {name}: found {len(base_images)} base image(s): {', '.join(base_images)}", file=sys.stderr)
                else:
                    print(f"  {name}: Dockerfile not found at {full_path}", file=sys.stderr)
            except Exception as e:
                print(f"  {name}: error reading Dockerfile: {e}", file=sys.stderr)

        # Write/update image state file
        state_file = images_dir / f"{name}.yaml"
        existing = None
        if state_file.exists():
            with open(state_file) as f:
                existing = yaml.safe_load(f) or {}

        now = datetime.now(timezone.utc).isoformat()
        state = {
            "name": name,
            "enrolledAt": existing.get("enrolledAt", now) if existing else now,
            "lastChecked": now,
            "registry": image.get("registry", ""),
            "image": image.get("image", name),
            "tag": str(image.get("tag", "latest")),
            "dockerfile": dockerfile_rel or "",
            "baseImages": sorted(base_images),
            "currentDigest": existing.get("currentDigest") if existing else None,
        }

        with open(state_file, "w") as f:
            f.write(f"# Auto-generated by CascadeGuard\n")
            yaml.dump(state, f, default_flow_style=False, sort_keys=False)

    # ── Phase 2: Write base image state files ──────────────────────────────
    tool = CascadeGuardTool(repo_root)
    for norm_name, full_ref in all_base_image_refs.items():
        state_file = base_images_dir / f"{norm_name}.yaml"
        if state_file.exists():
            with open(state_file) as f:
                existing = yaml.safe_load(f) or {}
            # Update lastChecked but preserve runtime data
            existing["lastChecked"] = datetime.now(timezone.utc).isoformat()
            new_state = existing
        else:
            new_state = tool.generate_base_image_state(full_ref)
        tool.write_base_image_state(new_state, state_file)

    # ── Phase 3: Check registries for digest drift ─────────────────────────
    results: List[Dict] = []

    # Check base images
    if base_images_dir.exists():
        for state_file in sorted(base_images_dir.glob("*.yaml")):
            with open(state_file) as f:
                state = yaml.safe_load(f) or {}
            name = state.get("name", state_file.stem)
            if image_filter:
                continue  # skip base images when filtering by enrolled image

            registry = state.get("registry", "docker.io")
            repository = state.get("repository", "")
            tag = str(state.get("tag", "")) if state.get("tag") else ""
            recorded_digest = state.get("currentDigest") or None

            if not repository or not tag:
                results.append({"image": f"base:{name}", "status": "skipped", "reason": "no registry coordinates"})
                continue

            live_digest = _fetch_manifest_digest(registry, repository, tag)
            if live_digest is None:
                results.append({"image": f"base:{name}", "status": "error", "reason": "registry unreachable"})
            elif recorded_digest is None:
                results.append({"image": f"base:{name}", "status": "new", "live": live_digest})
                # Record the digest
                state["currentDigest"] = live_digest
                state["lastUpdated"] = datetime.now(timezone.utc).isoformat()
                tool.write_base_image_state(state, state_file)
            elif live_digest == recorded_digest:
                results.append({"image": f"base:{name}", "status": "ok", "digest": recorded_digest[:16]})
            else:
                results.append({"image": f"base:{name}", "status": "drift", "recorded": recorded_digest[:16], "live": live_digest[:16]})
                state["previousDigest"] = recorded_digest
                state["currentDigest"] = live_digest
                state["lastUpdated"] = datetime.now(timezone.utc).isoformat()
                tool.write_base_image_state(state, state_file)

    # ── Phase 4: Check upstream tags (absorbed from check-upstream) ────────
    for image in resolved_images:
        name = image.get("name")
        if not name or not image.get("enabled", True):
            continue
        if image_filter and name != image_filter:
            continue

        img_name = image.get("image", name)
        namespace = image.get("namespace", "library")
        current_tags: Set[str] = set(image.get("latest_stable_tags", []))

        upstream_tags = _get_dockerhub_tags(namespace, img_name)
        stable_upstream = {t for t in upstream_tags if _is_stable_tag(t)}

        new_tags = stable_upstream - current_tags
        surfaced = []
        for t in new_tags:
            base = t.split("-")[0].split(".")[0]
            if not current_tags or any(
                c.split("-")[0].split(".")[0] == base for c in current_tags
            ):
                surfaced.append(t)

        if surfaced:
            results.append({
                "image": name,
                "status": "new-tags",
                "new_tags": sorted(surfaced),
            })

    # ── Output ─────────────────────────────────────────────────────────────
    has_drift = any(r["status"] == "drift" for r in results)
    has_new_tags = any(r["status"] == "new-tags" for r in results)

    if fmt == "json":
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No base images to check (run with Dockerfiles to discover them).")
        else:
            for r in results:
                status = r["status"]
                img = r["image"]
                if status == "ok":
                    print(f"  ✓ {img} ({r['digest']}…)")
                elif status == "new":
                    print(f"  ● {img}: recorded digest ({r['live'][:16]}…)")
                elif status == "drift":
                    print(f"  ✗ {img}: DRIFT {r['recorded']}… → {r['live']}…")
                elif status == "new-tags":
                    print(f"  ↑ {img}: new upstream tags: {', '.join(r.get('new_tags', []))}")
                elif status == "error":
                    print(f"  ? {img}: {r['reason']}")
                elif status == "skipped":
                    print(f"  - {img}: skipped ({r['reason']})")

    return 1 if (has_drift or has_new_tags) else 0


def cmd_build(args) -> int:
    """Trigger a build via GitHub Actions."""
    token = args.github_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(
            "Error: GitHub token required (--github-token or GITHUB_TOKEN env var)",
            file=sys.stderr,
        )
        return 1

    if not args.repo:
        print("Error: GitHub repository required (--repo)", file=sys.stderr)
        return 1

    provider = GitHubActionsProvider(token=token, repo=args.repo)
    try:
        result = provider.trigger_build(args.image, tag=args.tag)
        print(f"Build triggered: {result}")
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_deploy(args) -> int:
    """Deploy via ArgoCD."""
    token = args.argocd_token or os.environ.get("ARGOCD_TOKEN", "")
    if not token:
        print(
            "Error: ArgoCD token required (--argocd-token or ARGOCD_TOKEN env var)",
            file=sys.stderr,
        )
        return 1

    if not args.argocd_server:
        print("Error: ArgoCD server required (--argocd-server)", file=sys.stderr)
        return 1

    if not args.app:
        print("Error: ArgoCD application name required (--app)", file=sys.stderr)
        return 1

    provider = ArgoCDProvider(
        server=args.argocd_server,
        token=token,
        app_name=args.app,
    )
    try:
        result = provider.sync(args.image)
        print(f"Deploy triggered: {result}")
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_test(args) -> int:
    """Check build results via GitHub Actions."""
    token = args.github_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(
            "Error: GitHub token required (--github-token or GITHUB_TOKEN env var)",
            file=sys.stderr,
        )
        return 1

    if not args.repo:
        print("Error: GitHub repository required (--repo)", file=sys.stderr)
        return 1

    provider = GitHubActionsProvider(token=token, repo=args.repo)
    try:
        result = provider.get_build_status(args.image)
        status = result.get("status")

        if status == "no_runs":
            print(f"No builds found for {args.image}")
            return 0

        print(f"Latest build for {args.image}:")
        print(f"  Status:     {status}")
        print(f"  Conclusion: {result.get('conclusion')}")
        if result.get("url"):
            print(f"  URL:        {result['url']}")

        return 1 if result.get("conclusion") == "failure" else 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_pipeline(args) -> int:
    """Run the full pipeline: validate -> check -> build -> deploy -> test."""
    print("Running pipeline...")

    print("\n[1/5] Validate")
    rc = cmd_validate(args)
    if rc != 0:
        print("Pipeline failed at validate step")
        return rc

    print("\n[2/5] Check")
    rc = cmd_check(args)
    if rc != 0:
        print("Pipeline failed at check step")
        return rc

    image = getattr(args, "image", None)
    if image:
        print("\n[3/5] Build")
        rc = cmd_build(args)
        if rc != 0:
            print("Pipeline failed at build step")
            return rc

        argocd_server = getattr(args, "argocd_server", None)
        if argocd_server:
            print("\n[4/5] Deploy")
            rc = cmd_deploy(args)
            if rc != 0:
                print("Pipeline failed at deploy step")
                return rc
        else:
            print("\n[4/5] Deploy (skipped — no ArgoCD server configured)")

        print("\n[5/5] Test")
        rc = cmd_test(args)
        if rc != 0:
            print("Pipeline: test step reported failure")
            return rc
    else:
        print("\n[3/5] Build  (skipped — no --image specified)")
        print("\n[4/5] Deploy (skipped)")
        print("\n[5/5] Test   (skipped)")

    print("\nPipeline complete")
    return 0


def _parse_grype_cves(grype_path: Path) -> List[Dict]:
    """Parse Grype JSON output into a list of CVE findings."""
    if not grype_path.exists():
        return []
    with open(grype_path) as f:
        data = json.load(f)
    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve_id = vuln.get("id", "UNKNOWN")
        findings.append({
            "cve": cve_id,
            "severity": vuln.get("severity", "Unknown"),
            "package": artifact.get("name", "unknown"),
            "version": artifact.get("version", "unknown"),
            "type": artifact.get("type", "unknown"),
            "fix_versions": [
                fv.get("version", "")
                for fv in vuln.get("fix", {}).get("versions", [])
            ],
            "description": vuln.get("description", ""),
            "url": vuln.get("dataSource", ""),
            "scanner": "grype",
        })
    return findings


def _parse_trivy_cves(trivy_path: Path) -> List[Dict]:
    """Parse Trivy JSON output into a list of CVE findings."""
    if not trivy_path.exists():
        return []
    with open(trivy_path) as f:
        data = json.load(f)
    findings = []
    for result in data.get("Results", []):
        for vuln in (result.get("Vulnerabilities") or []):
            findings.append({
                "cve": vuln.get("VulnerabilityID", "UNKNOWN"),
                "severity": vuln.get("Severity", "Unknown").capitalize(),
                "package": vuln.get("PkgName", "unknown"),
                "version": vuln.get("InstalledVersion", "unknown"),
                "type": result.get("Type", "unknown"),
                "fix_versions": [vuln["FixedVersion"]] if vuln.get("FixedVersion") else [],
                "description": vuln.get("Description", ""),
                "url": vuln.get("PrimaryURL", ""),
                "scanner": "trivy",
            })
    return findings


def _deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Deduplicate by CVE+package, preferring grype, keeping highest severity."""
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Negligible": 0, "Unknown": -1}
    seen: Dict[str, Dict] = {}
    for f in findings:
        key = f"{f['cve']}:{f['package']}"
        if key not in seen or severity_rank.get(f["severity"], -1) > severity_rank.get(seen[key]["severity"], -1):
            seen[key] = f
    return sorted(seen.values(), key=lambda x: (-severity_rank.get(x["severity"], -1), x["cve"]))


def cmd_scan_report(args) -> int:
    """Parse scanner output and write a diffable vulnerability report."""
    grype_path = Path(args.grype) if args.grype else None
    trivy_path = Path(args.trivy) if args.trivy else None

    if not grype_path and not trivy_path:
        print("Error: at least one of --grype or --trivy is required", file=sys.stderr)
        return 1

    findings = []
    if grype_path:
        findings.extend(_parse_grype_cves(grype_path))
    if trivy_path:
        findings.extend(_parse_trivy_cves(trivy_path))

    deduped = _deduplicate_findings(findings)

    # Write reports to the output directory
    report_dir = Path(args.dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Write JSON report (machine-readable, diffable)
    json_report = {
        "image": args.image,
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "summary": {
            "critical": sum(1 for f in deduped if f["severity"] == "Critical"),
            "high": sum(1 for f in deduped if f["severity"] == "High"),
            "medium": sum(1 for f in deduped if f["severity"] == "Medium"),
            "low": sum(1 for f in deduped if f["severity"] == "Low"),
            "total": len(deduped),
        },
        "findings": [
            {
                "cve": f["cve"],
                "severity": f["severity"],
                "package": f["package"],
                "version": f["version"],
                "fix_versions": f["fix_versions"],
            }
            for f in deduped
        ],
    }

    json_path = report_dir / "vulnerability-report.json"
    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2, sort_keys=False)
        f.write("\n")

    # Write markdown report (human-readable, diffable)
    md_path = report_dir / "vulnerability-report.md"
    with open(md_path, "w") as f:
        summary = json_report["summary"]
        f.write(f"# Vulnerability Report: {args.image}\n\n")
        f.write(f"| Severity | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| Critical | {summary['critical']} |\n")
        f.write(f"| High     | {summary['high']} |\n")
        f.write(f"| Medium   | {summary['medium']} |\n")
        f.write(f"| Low      | {summary['low']} |\n")
        f.write(f"| **Total**| **{summary['total']}** |\n\n")

        if deduped:
            f.write("## Findings\n\n")
            f.write("| CVE | Severity | Package | Version | Fix Available |\n")
            f.write("|-----|----------|---------|---------|---------------|\n")
            for finding in deduped:
                fix = ", ".join(finding["fix_versions"]) if finding["fix_versions"] else "No"
                f.write(f"| {finding['cve']} | {finding['severity']} | {finding['package']} | {finding['version']} | {fix} |\n")
        else:
            f.write("No vulnerabilities found.\n")

    print(f"Reports written to {report_dir}/")
    print(f"  {json_path}")
    print(f"  {md_path}")
    print(f"  Total findings: {len(deduped)} ({json_report['summary']['critical']} critical, {json_report['summary']['high']} high)")
    return 0


def cmd_scan_issues(args) -> int:
    """Create/update/reopen per-CVE GitHub issues from scanner output."""
    grype_path = Path(args.grype) if args.grype else None
    trivy_path = Path(args.trivy) if args.trivy else None

    if not grype_path and not trivy_path:
        print("Error: at least one of --grype or --trivy is required", file=sys.stderr)
        return 1

    token = args.github_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("Error: GitHub token required (--github-token or GITHUB_TOKEN env var)", file=sys.stderr)
        return 1

    if not args.repo:
        print("Error: GitHub repository required (--repo)", file=sys.stderr)
        return 1

    findings = []
    if grype_path:
        findings.extend(_parse_grype_cves(grype_path))
    if trivy_path:
        findings.extend(_parse_trivy_cves(trivy_path))

    deduped = _deduplicate_findings(findings)

    # Filter to critical and high only for issue creation
    actionable = [f for f in deduped if f["severity"] in ("Critical", "High")]

    if not actionable:
        print("No critical or high vulnerabilities found. No issues to create.")
        return 0

    gh = GitHubActionsProvider(token=token, repo=args.repo)

    # Fetch all open CVE issues in the repo
    existing_issues = _fetch_cve_issues(gh, args.repo)

    created = 0
    updated = 0
    reopened = 0

    for finding in actionable:
        cve = finding["cve"]
        pkg = finding["package"]
        severity = finding["severity"]
        issue_title = f"{cve}: {pkg} ({severity.lower()})"

        # Check for existing issue by CVE+package
        existing = _find_existing_issue(existing_issues, cve, pkg)

        fix_str = ", ".join(finding["fix_versions"]) if finding["fix_versions"] else "No fix available"
        image_label = f"image:{args.image}"
        severity_label = f"severity:{severity.lower()}"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        body = (
            f"## {cve}: {pkg}\n\n"
            f"- **Severity:** {severity}\n"
            f"- **Package:** {pkg} {finding['version']}\n"
            f"- **Fix:** {fix_str}\n"
            f"- **Affected image:** {args.image}"
            + (f":{args.tag}" if args.tag else "")
            + f"\n- **First detected:** {today}\n"
        )
        if finding.get("url"):
            body += f"- **Reference:** {finding['url']}\n"

        if existing and existing["state"] == "open":
            # Add a comment noting re-detection with image info
            comment_body = f"Re-detected on **{today}** in `{args.image}" + (f":{args.tag}" if args.tag else "") + f"`.\nPackage version: {finding['version']}. Fix: {fix_str}."
            _gh_request(gh, "POST", f"/repos/{args.repo}/issues/{existing['number']}/comments", {"body": comment_body})
            # Ensure image label exists
            _ensure_label(gh, args.repo, existing["number"], image_label)
            updated += 1
        elif existing and existing["state"] == "closed":
            # Reopen the issue
            _gh_request(gh, "PATCH", f"/repos/{args.repo}/issues/{existing['number']}", {"state": "open"})
            comment_body = f"Reopened on **{today}**: re-detected in `{args.image}" + (f":{args.tag}" if args.tag else "") + f"`.\nPackage version: {finding['version']}. Fix: {fix_str}."
            _gh_request(gh, "POST", f"/repos/{args.repo}/issues/{existing['number']}/comments", {"body": comment_body})
            _ensure_label(gh, args.repo, existing["number"], image_label)
            reopened += 1
        else:
            # Create new issue
            labels = ["cve", "automated", severity_label, image_label]
            new_issue = _gh_request(gh, "POST", f"/repos/{args.repo}/issues", {
                "title": issue_title,
                "body": body,
                "labels": labels,
            })
            if new_issue:
                print(f"  Created issue #{new_issue.get('number')}: {issue_title}")
            created += 1

    print(f"\nScan issues summary: {created} created, {updated} updated, {reopened} reopened")
    return 0


def _gh_request(provider: GitHubActionsProvider, method: str, path: str, data: Optional[dict] = None) -> Optional[dict]:
    """Make a GitHub API request using the provider's auth."""
    try:
        return provider._request(method, path, data)
    except RuntimeError as exc:
        print(f"  Warning: GitHub API error: {exc}", file=sys.stderr)
        return None


def _fetch_cve_issues(provider: GitHubActionsProvider, repo: str) -> List[Dict]:
    """Fetch all open and closed CVE-labelled issues."""
    issues = []
    for state in ("open", "closed"):
        page = 1
        while True:
            result = _gh_request(provider, "GET", f"/repos/{repo}/issues?labels=cve,automated&state={state}&per_page=100&page={page}")
            if not result:
                break
            issues.extend(result)
            if len(result) < 100:
                break
            page += 1
    return issues


def _find_existing_issue(issues: List[Dict], cve: str, package: str) -> Optional[Dict]:
    """Find an existing issue matching CVE and package."""
    for issue in issues:
        title = issue.get("title", "")
        if cve in title and package in title:
            return issue
    return None


def _ensure_label(provider: GitHubActionsProvider, repo: str, issue_number: int, label: str):
    """Add a label to an issue if it doesn't already have it."""
    _gh_request(provider, "POST", f"/repos/{repo}/issues/{issue_number}/labels", {"labels": [label]})


def cmd_actions_pin(args) -> int:
    """Pin mutable GitHub Actions refs to full commit SHAs."""
    token = getattr(args, 'github_token', None) or os.environ.get("GITHUB_TOKEN", "")
    workflows_dir = Path(args.workflows_dir)

    if not workflows_dir.exists():
        print(f"Error: workflows directory not found: {workflows_dir}", file=sys.stderr)
        return 1

    pinner = ActionsPinner(token=token, workflows_dir=workflows_dir)
    summary = pinner.pin(dry_run=args.dry_run, update=args.update)

    pinned = summary["pinned"]
    already_pinned = summary["already_pinned"]
    skipped = summary["skipped"]

    if args.dry_run:
        print(f"Dry run — no files written")

    print(f"Actions pinned: {pinned}, already pinned: {already_pinned}, skipped: {skipped}")
    return 0


def cmd_actions_audit(args) -> int:
    """Audit workflow files for pinning status and optionally against a policy."""
    import json as _json
    from actions_policy import (
        load_policy,
        PolicyAuditor,
        PolicyError,
        scan_pinning_status,
    )

    workflows_dir = Path(args.workflows_dir)
    fmt = getattr(args, "format", "text")
    policy_path_str: Optional[str] = getattr(args, "policy", None)

    if not workflows_dir.exists():
        print(f"Error: workflows directory not found: {workflows_dir}", file=sys.stderr)
        return 1

    # ── Mode A: pinning-only audit (no policy supplied) ────────────────────
    if not policy_path_str:
        refs = scan_pinning_status(workflows_dir)
        mutable = [r for r in refs if r.mutable]

        if fmt == "json":
            data: dict = {
                "passed": len(mutable) == 0,
                "summary": {
                    "pinned": sum(1 for r in refs if r.status == "pinned"),
                    "tag":    sum(1 for r in refs if r.status == "tag"),
                    "branch": sum(1 for r in refs if r.status == "branch"),
                    "local":  sum(1 for r in refs if r.status == "local"),
                },
                "refs": [r.as_dict() for r in refs],
            }
            print(_json.dumps(data, indent=2))
        else:
            _STATUS_LABEL = {
                "pinned": "✓ pinned",
                "tag":    "✗ tag   ",
                "branch": "✗ branch",
                "local":  "  local ",
            }
            for r in refs:
                label = _STATUS_LABEL.get(r.status, r.status)
                print(f"  {label}  {r.action}@{r.ref}  ({r.workflow_file}:{r.line_number})")
            if mutable:
                print(f"\nAudit FAILED — {len(mutable)} mutable reference(s) found.")
            else:
                n_pinned = sum(1 for r in refs if r.status == "pinned")
                n_local  = sum(1 for r in refs if r.status == "local")
                print(f"\nAudit PASSED — {n_pinned} pinned, {n_local} local.")

        return 1 if mutable else 0

    # ── Mode B: policy audit ────────────────────────────────────────────────
    policy_path = Path(policy_path_str)
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    auditor = PolicyAuditor(policy)
    result = auditor.audit(workflows_dir)

    if fmt == "json":
        data = {
            "passed": result.passed,
            "summary": {
                "violations": len(result.violations),
                "allowed":    result.allowed,
                "skipped":    result.skipped,
            },
            "violations": [
                {
                    "workflow_file": v.workflow_file,
                    "line_number":   v.line_number,
                    "action":        v.action,
                    "ref":           v.ref,
                    "reason":        v.reason,
                }
                for v in result.violations
            ],
        }
        print(_json.dumps(data, indent=2))
    else:
        if result.violations:
            print(f"Policy audit FAILED — {len(result.violations)} violation(s):\n")
            for v in result.violations:
                print(f"  {v}")
            print(
                f"\n{result.allowed} action(s) passed, "
                f"{result.skipped} skipped (local/composite)."
            )
        else:
            print(
                f"Policy audit PASSED — {result.allowed} action(s) checked, "
                f"{result.skipped} skipped."
            )

    return 0 if result.passed else 1


def cmd_actions_policy_init(args) -> int:
    """Scaffold a starter .cascadeguard/actions-policy.yaml."""
    from actions_policy import init_policy

    output_path = Path(args.output)
    written = init_policy(output_path, force=args.force)
    if written:
        print(f"Created {output_path}")
        print("Edit the file to customise allowed_owners, allowed_actions, and exceptions.")
    else:
        print(
            f"{output_path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_actions_policy(args) -> int:
    """Dispatch 'actions policy' subcommands."""
    return {"init": cmd_actions_policy_init}[args.policy_command](args)


def cmd_actions(args) -> int:
    """Dispatch 'actions' subcommands."""
    return {
        "pin":    cmd_actions_pin,
        "audit":  cmd_actions_audit,
        "policy": cmd_actions_policy,
    }[args.actions_command](args)








def cmd_images(args) -> int:
    """Dispatch 'images' subcommands."""
    return {
        "validate":       cmd_validate,
        "enrol":          cmd_enrol,
        "check":          cmd_check,
        "status":         cmd_status,
        "init":           cmd_init,
    }[args.images_command](args)


def cmd_pipeline_run(args) -> int:
    """Alias for the full pipeline runner (was cmd_pipeline)."""
    return cmd_pipeline(args)


def cmd_pipeline_dispatcher(args) -> int:
    """Dispatch 'pipeline' subcommands."""
    return {
        "run":    cmd_pipeline_run,
        "build":  cmd_build,
        "deploy": cmd_deploy,
        "test":   cmd_test,
    }[args.pipeline_command](args)


def cmd_vuln(args) -> int:
    """Dispatch 'vuln' subcommands."""
    return {
        "report": cmd_scan_report,
        "issues": cmd_scan_issues,
    }[args.vuln_command](args)


def cmd_status(args) -> int:
    """Show status of all images from state files."""
    state_dir = Path(args.state_dir)

    if not state_dir.exists():
        print(f"Error: state directory not found: {state_dir}", file=sys.stderr)
        return 1

    images_dir = state_dir / "images"
    base_images_dir = state_dir / "base-images"

    print(f"CascadeGuard Status ({state_dir})")
    print("=" * 60)

    if images_dir.exists():
        image_files = sorted(images_dir.glob("*.yaml"))
        print(f"\nApplication Images ({len(image_files)}):")
        for state_file in image_files:
            with open(state_file) as f:
                state = yaml.safe_load(f) or {}
            name = state.get("name", state_file.stem)
            version = state.get("currentVersion") or "-"
            digest = state.get("currentDigest") or "-"
            last_built = state.get("lastBuilt") or "-"
            status = state.get("discoveryStatus") or "-"
            base_images = state.get("baseImages") or []
            print(f"  {name}")
            print(f"    version:    {version}")
            print(f"    digest:     {digest}")
            print(f"    lastBuilt:  {last_built}")
            print(f"    status:     {status}")
            if base_images:
                print(f"    baseImages: {', '.join(base_images)}")
    else:
        print("\nNo application images found")

    if base_images_dir.exists():
        base_files = sorted(base_images_dir.glob("*.yaml"))
        print(f"\nBase Images ({len(base_files)}):")
        for state_file in base_files:
            with open(state_file) as f:
                state = yaml.safe_load(f) or {}
            name = state.get("name", state_file.stem)
            digest = state.get("currentDigest") or "-"
            last_updated = state.get("lastUpdated") or "-"
            last_checked = state.get("lastChecked") or "-"
            print(f"  {name}")
            print(f"    digest:      {digest}")
            print(f"    lastUpdated: {last_updated}")
            print(f"    lastChecked: {last_checked}")
    else:
        print("\nNo base images found")

    return 0


# ---------------------------------------------------------------------------
# Init command
# ---------------------------------------------------------------------------

SEED_REPO_URL = os.environ.get(
    "CASCADEGUARD_SEED_REPO",
    "https://github.com/cascadeguard/cascadeguard-seed.git",
)


def cmd_init(args) -> int:
    """Scaffold current directory from cascadeguard-seed."""
    target = Path(args.target_dir).resolve()

    tmp = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "main", SEED_REPO_URL, tmp + "/seed"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Error: failed to clone seed repo: {result.stderr.strip()}", file=sys.stderr)
            return 1

        seed_dir = Path(tmp) / "seed"

        skipped, copied = 0, 0
        for root, dirs, files in os.walk(seed_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                src = Path(root) / f
                rel = src.relative_to(seed_dir)
                dest = target / rel
                if dest.exists():
                    print(f"  skip (exists): {rel}", file=sys.stderr)
                    skipped += 1
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                copied += 1

        # Ensure .gitignore has cache entry
        gitignore = target / ".gitignore"
        cache_entry = ".cascadeguard/.cache/"
        if gitignore.exists():
            content = gitignore.read_text()
            if cache_entry not in content:
                with open(gitignore, "a") as gf:
                    gf.write(f"\n{cache_entry}\n")
        else:
            gitignore.write_text(f"{cache_entry}\n")

        print(f"Initialised: {copied} files copied, {skipped} skipped (already exist)")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CascadeGuard — container image lifecycle tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  images      Image lifecycle management
  pipeline    CI/CD orchestration
  vuln        Vulnerability management
  actions     GitHub Actions utilities
""",
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # ---------------------------------------------------------------------------
    # images — image lifecycle management
    # ---------------------------------------------------------------------------
    images = sub.add_parser("images", help="Image lifecycle management")
    images.add_argument(
        "--images-yaml",
        default="images.yaml",
        help="Path to images.yaml (default: images.yaml)",
    )
    images.add_argument(
        "--state-dir",
        default=".cascadeguard",
        help="Path to state directory (default: .cascadeguard)",
    )
    images_sub = images.add_subparsers(dest="images_command", metavar="subcommand")
    images_sub.required = True

    # images validate
    images_sub.add_parser("validate", help="Validate images.yaml configuration")

    # images enrol
    images_enrol = images_sub.add_parser("enrol", help="Enrol a new image")
    images_enrol.add_argument("--name", required=True, help="Image name")
    images_enrol.add_argument("--registry", required=True, help="Registry (e.g. ghcr.io)")
    images_enrol.add_argument(
        "--repository", required=True, help="Repository (e.g. org/image)"
    )
    images_enrol.add_argument("--provider", help="Source provider (github/gitlab)")
    images_enrol.add_argument("--repo", help="Source repository (e.g. org/repo)")
    images_enrol.add_argument("--dockerfile", help="Path to Dockerfile in source repo")
    images_enrol.add_argument("--branch", help="Source branch (default: main)")
    images_enrol.add_argument("--rebuild-delay", help="Rebuild delay (e.g. 7d)")
    images_enrol.add_argument(
        "--images-yaml",
        default="images.yaml",
        help="Path to images.yaml (default: images.yaml)",
    )
    images_enrol.add_argument(
        "--auto-rebuild",
        action="store_true",
        default=False,
        help="Set autoRebuild: true in the generated images.yaml entry",
    )

    # images check
    images_check = images_sub.add_parser(
        "check",
        help="Query the registry for digest drift on enrolled images",
    )
    images_check.add_argument(
        "--image",
        default=None,
        help="Scope check to a single image name (state file stem)",
    )
    images_check.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format: table (default) or json",
    )

    # images status
    images_sub.add_parser("status", help="Show status of all images")

    # images init
    images_init = images_sub.add_parser(
        "init", help="Scaffold a new state repository from cascadeguard-seed"
    )
    images_init.add_argument(
        "--target-dir",
        default=".",
        help="Target directory (default: current directory)",
    )

    # ---------------------------------------------------------------------------
    # pipeline — CI/CD orchestration
    # ---------------------------------------------------------------------------
    pipeline = sub.add_parser("pipeline", help="CI/CD orchestration")
    pipeline_sub = pipeline.add_subparsers(dest="pipeline_command", metavar="subcommand")
    pipeline_sub.required = True

    # pipeline run (full pipeline)
    pipeline_run = pipeline_sub.add_parser("run", help="Run full pipeline")
    pipeline_run.add_argument(
        "--images-yaml",
        default="images.yaml",
        help="Path to images.yaml (default: images.yaml)",
    )
    pipeline_run.add_argument(
        "--state-dir",
        default="state",
        help="Path to state directory (default: state)",
    )
    pipeline_run.add_argument("--image", help="Image name (optional)")
    pipeline_run.add_argument(
        "--tag", default="latest", help="Image tag (default: latest)"
    )
    pipeline_run.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    pipeline_run.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )
    pipeline_run.add_argument("--app", help="ArgoCD application name")
    pipeline_run.add_argument("--argocd-server", help="ArgoCD server URL")
    pipeline_run.add_argument(
        "--argocd-token", help="ArgoCD token (or ARGOCD_TOKEN env var)"
    )

    # pipeline build
    pipeline_build = pipeline_sub.add_parser(
        "build", help="Trigger a build via GitHub Actions"
    )
    pipeline_build.add_argument("--image", required=True, help="Image name to build")
    pipeline_build.add_argument(
        "--tag", default="latest", help="Image tag (default: latest)"
    )
    pipeline_build.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    pipeline_build.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )

    # pipeline deploy
    pipeline_deploy = pipeline_sub.add_parser("deploy", help="Deploy via ArgoCD")
    pipeline_deploy.add_argument("--image", required=True, help="Image name to deploy")
    pipeline_deploy.add_argument("--app", required=True, help="ArgoCD application name")
    pipeline_deploy.add_argument("--argocd-server", help="ArgoCD server URL")
    pipeline_deploy.add_argument(
        "--argocd-token", help="ArgoCD token (or ARGOCD_TOKEN env var)"
    )

    # pipeline test
    pipeline_test = pipeline_sub.add_parser(
        "test", help="Check build test results via GitHub Actions"
    )
    pipeline_test.add_argument("--image", required=True, help="Image name to check")
    pipeline_test.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    pipeline_test.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )

    # ---------------------------------------------------------------------------
    # vuln — vulnerability management
    # ---------------------------------------------------------------------------
    vuln = sub.add_parser("vuln", help="Vulnerability management")
    vuln_sub = vuln.add_subparsers(dest="vuln_command", metavar="subcommand")
    vuln_sub.required = True

    # vuln report (was scan-report)
    vuln_report = vuln_sub.add_parser(
        "report", help="Parse scanner output, write diffable vulnerability reports"
    )
    vuln_report.add_argument("--grype", help="Path to Grype JSON results file")
    vuln_report.add_argument("--trivy", help="Path to Trivy JSON results file")
    vuln_report.add_argument(
        "--image", required=True, help="Image name (for report metadata)"
    )
    vuln_report.add_argument(
        "--dir",
        required=True,
        help="Output directory for reports (e.g. images/alpine/reports)",
    )

    # vuln issues (was scan-issues)
    vuln_issues = vuln_sub.add_parser(
        "issues", help="Create/update/reopen per-CVE GitHub issues"
    )
    vuln_issues.add_argument("--grype", help="Path to Grype JSON results file")
    vuln_issues.add_argument("--trivy", help="Path to Trivy JSON results file")
    vuln_issues.add_argument("--image", required=True, help="Image name")
    vuln_issues.add_argument("--tag", default="", help="Image tag")
    vuln_issues.add_argument(
        "--repo", required=True, help="GitHub repository (e.g. org/repo)"
    )
    vuln_issues.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )

    # ---------------------------------------------------------------------------
    # actions — GitHub Actions utilities (unchanged structure)
    # ---------------------------------------------------------------------------
    actions = sub.add_parser("actions", help="GitHub Actions utilities")
    actions_sub = actions.add_subparsers(dest="actions_command", metavar="subcommand")
    actions_sub.required = True

    actions_pin = actions_sub.add_parser(
        "pin",
        help="Pin action refs to full commit SHAs",
    )
    actions_pin.add_argument(
        "--workflows-dir",
        default=".github/workflows",
        help="Path to workflows directory (default: .github/workflows)",
    )
    actions_pin.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without writing files",
    )
    actions_pin.add_argument(
        "--update",
        action="store_true",
        help="Re-pin already-pinned SHAs to the latest SHA for the same tag",
    )
    actions_pin.add_argument(
        "--github-token",
        help="GitHub token (or GITHUB_TOKEN env var)",
    )

    # actions audit
    actions_audit = actions_sub.add_parser(
        "audit",
        help="Audit workflow files for pinning status (and optionally against a policy)",
    )
    actions_audit.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help=(
            "Path to an actions-policy.yaml file. "
            "When supplied, validates each action against the policy allow-list. "
            "When omitted, reports the pinning status of every action "
            "(exit 1 if any mutable refs found)."
        ),
    )
    actions_audit.add_argument(
        "--workflows-dir",
        default=".github/workflows",
        help="Path to workflows directory (default: .github/workflows)",
    )
    actions_audit.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        metavar="FORMAT",
        help="Output format: text (default) or json",
    )

    # actions policy
    actions_policy = actions_sub.add_parser(
        "policy",
        help="Manage actions-policy.yaml",
    )
    policy_sub = actions_policy.add_subparsers(dest="policy_command", metavar="subcommand")
    policy_sub.required = True

    policy_init = policy_sub.add_parser(
        "init",
        help="Scaffold a starter .cascadeguard/actions-policy.yaml",
    )
    policy_init.add_argument(
        "--output",
        default=".cascadeguard/actions-policy.yaml",
        help="Output path (default: .cascadeguard/actions-policy.yaml)",
    )
    policy_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing policy file",
    )

    # scan
    scan = sub.add_parser("scan", help="Discover and analyse container artifacts in a repository")
    scan.add_argument(
        "--dir",
        default=".",
        help="Root directory to scan (default: current directory)",
    )
    scan.add_argument(
        "--non-interactive",
        action="store_true",
        help="Scan all discovered artifacts without prompting",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan.add_argument(
        "--output",
        default=None,
        help="Write results to file instead of stdout",
    )

    return parser


def cmd_scan(args) -> int:
    """Run repository scan for container artifacts."""
    from scan.engine import run_scan
    return run_scan(
        root=Path(args.dir),
        non_interactive=args.non_interactive,
        output_format=args.format,
        output_file=args.output,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "images":   cmd_images,
        "pipeline": cmd_pipeline_dispatcher,
        "vuln":     cmd_vuln,
        "actions":  cmd_actions,
        "scan":     cmd_scan,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
