#!/usr/bin/env python3
"""
CascadeGuard — container image lifecycle tool.

Commands:
  validate    Validate images.yaml configuration
  enrol       Enrol a new image in images.yaml
  check       Check image and base image states
  build       Trigger a build via GitHub Actions
  deploy      Deploy via ArgoCD
  test        Check build test results via GitHub Actions
  pipeline    Run full pipeline (validate -> check -> build -> deploy -> test)
  status      Show status of all images
"""
import argparse
import json
import os
import re
import sys
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


<<<<<<< HEAD
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

    errors = []
    for i, image in enumerate(images):
        name = image.get("name")
        if not name:
            errors.append(f"Image {i}: missing 'name' field")
            continue
        if not image.get("registry"):
            errors.append(f"Image '{name}': missing 'registry' field")
        if not image.get("repository"):
            errors.append(f"Image '{name}': missing 'repository' field")

        source = image.get("source", {})
        if source:
            if not source.get("repo"):
                errors.append(f"Image '{name}': source missing 'repo' field")
            if not source.get("provider"):
                errors.append(f"Image '{name}': source missing 'provider' field")

    if errors:
        print("Validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"Validated {len(images)} images in {images_yaml}")
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

    images.append(new_image)

    with open(images_yaml, "w") as f:
        yaml.dump(images, f, default_flow_style=False, allow_unicode=True)

    print(f"Enrolled '{args.name}' in {images_yaml}")
    return 0


def cmd_check(args) -> int:
    """Check image and base image states from state files."""
    state_dir = Path(args.state_dir)
    images_dir = state_dir / "images"
    base_images_dir = state_dir / "base-images"

    if images_dir.exists():
        print("Application images:")
        for state_file in sorted(images_dir.glob("*.yaml")):
            with open(state_file) as f:
                state = yaml.safe_load(f) or {}
            name = state.get("name", state_file.stem)
            digest = state.get("currentDigest") or "null"
            last_built = state.get("lastBuilt") or "never"
            status = state.get("discoveryStatus", "unknown")
            print(f"  {name}: digest={digest} lastBuilt={last_built} status={status}")
    else:
        print("No application images found")

    if base_images_dir.exists():
        print("Base images:")
        for state_file in sorted(base_images_dir.glob("*.yaml")):
            with open(state_file) as f:
                state = yaml.safe_load(f) or {}
            name = state.get("name", state_file.stem)
            digest = state.get("currentDigest") or "null"
            last_updated = state.get("lastUpdated") or "never"
            print(f"  {name}: digest={digest} lastUpdated={last_updated}")
    else:
        print("No base images found")

    return 0


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
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CascadeGuard — container image lifecycle tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  validate    Validate images.yaml configuration
  enrol       Enrol a new image in images.yaml
  check       Check image and base image states
  build       Trigger a build via GitHub Actions
  deploy      Deploy via ArgoCD
  test        Check build test results via GitHub Actions
  pipeline    Run full pipeline (validate -> check -> build -> deploy -> test)
  status      Show status of all images
""",
    )

    parser.add_argument(
        "--images-yaml",
        default="images.yaml",
        help="Path to images.yaml (default: images.yaml)",
    )
    parser.add_argument(
        "--state-dir",
        default="state",
        help="Path to state directory (default: state)",
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # validate
    sub.add_parser("validate", help="Validate images.yaml configuration")

    # enrol
    enrol = sub.add_parser("enrol", help="Enrol a new image")
    enrol.add_argument("--name", required=True, help="Image name")
    enrol.add_argument("--registry", required=True, help="Registry (e.g. ghcr.io)")
    enrol.add_argument(
        "--repository", required=True, help="Repository (e.g. org/image)"
    )
    enrol.add_argument("--provider", help="Source provider (github/gitlab)")
    enrol.add_argument("--repo", help="Source repository (e.g. org/repo)")
    enrol.add_argument("--dockerfile", help="Path to Dockerfile in source repo")
    enrol.add_argument("--branch", help="Source branch (default: main)")
    enrol.add_argument("--rebuild-delay", help="Rebuild delay (e.g. 7d)")

    # check
    sub.add_parser("check", help="Check image and base image states")

    # build
    build = sub.add_parser("build", help="Trigger a build via GitHub Actions")
    build.add_argument("--image", required=True, help="Image name to build")
    build.add_argument("--tag", default="latest", help="Image tag (default: latest)")
    build.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    build.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )

    # deploy
    deploy = sub.add_parser("deploy", help="Deploy via ArgoCD")
    deploy.add_argument("--image", required=True, help="Image name to deploy")
    deploy.add_argument("--app", required=True, help="ArgoCD application name")
    deploy.add_argument("--argocd-server", help="ArgoCD server URL")
    deploy.add_argument(
        "--argocd-token", help="ArgoCD token (or ARGOCD_TOKEN env var)"
    )

    # test
    test = sub.add_parser("test", help="Check build test results")
    test.add_argument("--image", required=True, help="Image name to check")
    test.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    test.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )

    # pipeline
    pipeline = sub.add_parser("pipeline", help="Run full pipeline")
    pipeline.add_argument("--image", help="Image name (optional)")
    pipeline.add_argument(
        "--tag", default="latest", help="Image tag (default: latest)"
    )
    pipeline.add_argument("--repo", help="GitHub repository (e.g. org/repo)")
    pipeline.add_argument(
        "--github-token", help="GitHub token (or GITHUB_TOKEN env var)"
    )
    pipeline.add_argument("--app", help="ArgoCD application name")
    pipeline.add_argument("--argocd-server", help="ArgoCD server URL")
    pipeline.add_argument(
        "--argocd-token", help="ArgoCD token (or ARGOCD_TOKEN env var)"
    )

    # status
    sub.add_parser("status", help="Show status of all images")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "validate": cmd_validate,
        "enrol": cmd_enrol,
        "check": cmd_check,
        "build": cmd_build,
        "deploy": cmd_deploy,
        "test": cmd_test,
        "pipeline": cmd_pipeline,
        "status": cmd_status,
    }

    return commands[args.command](args)
=======
def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='CascadeGuard Dockerfile Analysis Tool')
    parser.add_argument('--image', required=True, help='Image name')
    parser.add_argument('--tag', required=True, help='Image tag')
    parser.add_argument('--digest', required=True, help='Image digest')
    parser.add_argument('--dockerfile', required=True, help='Path to Dockerfile')
    parser.add_argument('--source-repo', required=True, help='Source repository')
    parser.add_argument('--source-provider', required=True, help='Source provider (github/gitlab)')
    parser.add_argument('--git-repo', required=True, help='Git repository URL')
    parser.add_argument('--git-branch', required=True, help='Git branch')
    parser.add_argument('--cascadeguard-dir', default='./cascadeguard', help='Path to cascadeguard directory')

    args = parser.parse_args()

    logger.info(f"Analyzing {args.image}:{args.tag}")
    logger.info(f"Dockerfile: {args.dockerfile}")
    logger.info(f"Source: {args.source_provider}/{args.source_repo}")

    # Determine root directory
    root_dir = Path(args.cascadeguard_dir)

    tool = CascadeGuardTool(root_dir)
    tool.process()
    
    logger.info("Analysis complete!")
>>>>>>> 8e21385 (feat: rename image-factory identifiers to cascadeguard)


if __name__ == "__main__":
    sys.exit(main())
