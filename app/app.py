#!/usr/bin/env python3
"""
Image Factory Tool - Manages state files for images and base images.

This tool:
- Reads image enrollment (from YAML or database via pluggable backend)
- Discovers base images from Dockerfiles
- Generates/updates state via the configured StorageBackend
- Ensures state has all fields needed by cdk8s

Backends:
- YamlBackend  (default) – original GitOps mode, reads/writes YAML files
- DatabaseBackend        – SaaS mode, reads/writes via SQLAlchemy
"""
import yaml
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import logging

from storage import StorageBackend, YamlBackend

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ImageFactoryTool:
    def __init__(self, root_dir: Path, backend: Optional[StorageBackend] = None):
        self.root_dir = root_dir
        self.backend = backend or YamlBackend(root_dir)

    # -- kept for backward compat; delegates to YamlBackend internally ------
    def _yaml_value(self, value):
        """Format a value for YAML output."""
        return YamlBackend._yaml_value(value)

    def load_images_yaml(self) -> List[Dict]:
        """Load and validate images.yaml (convenience wrapper)."""
        return self.backend.load_images()

    def write_image_state(self, state: Dict, file_path: Path):
        """Write image state file (backward-compat shim for direct callers)."""
        if isinstance(self.backend, YamlBackend):
            self.backend._write_image_state(state, file_path)
        else:
            self.backend.save_image_state(state)

    def write_base_image_state(self, state: Dict, file_path: Path):
        """Write base image state file (backward-compat shim for direct callers)."""
        if isinstance(self.backend, YamlBackend):
            self.backend._write_base_image_state(state, file_path)
        else:
            self.backend.save_base_image_state(state)

    # -- Dockerfile parsing (unchanged) ------------------------------------

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

    # -- Image reference utilities (unchanged) ------------------------------

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

    # -- State generation (unchanged) --------------------------------------

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

    # -- State merging (unchanged) -----------------------------------------

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

    # -- Main processing (refactored to use backend) -----------------------

    def process(self):
        """Main processing logic."""
        logger.info("Starting image factory processing...")

        # Load images from backend
        images = self.backend.load_images()
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
                # The root_dir points to image-factory directory, so we need to go up one level to workspace root
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

            # Load existing state from backend
            existing_state = self.backend.load_image_state(name)
            if existing_state is not None:
                new_state = self.merge_state(existing_state, new_state, prefer_new=True)
                logger.info(f"  Updated existing state")
            else:
                logger.info(f"  Created new state")

            # Save via backend
            self.backend.save_image_state(new_state)

        # Process base images
        logger.info(f"Processing {len(base_image_dependents)} base images...")
        for base_image_ref, dependent_names in base_image_dependents.items():
            base_image_name = self.normalize_base_image_name(base_image_ref)
            logger.info(f"Processing base image: {base_image_name}")

            # Generate new state
            new_state = self.generate_base_image_state(base_image_ref)

            # Load existing state from backend
            existing_state = self.backend.load_base_image_state(base_image_name)
            if existing_state is not None:
                new_state = self.merge_state(existing_state, new_state, prefer_new=False)
                logger.info(f"  Updated existing base image state")
            else:
                logger.info(f"  Created new base image state")

            # Save via backend
            self.backend.save_base_image_state(new_state)

            # Record dependencies
            for dep_name in dependent_names:
                self.backend.save_dependency(dep_name, base_image_name)

        logger.info("Processing complete!")


def main():
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Image Factory Dockerfile Analysis Tool')
    parser.add_argument('--image', required=True, help='Image name')
    parser.add_argument('--tag', required=True, help='Image tag')
    parser.add_argument('--digest', required=True, help='Image digest')
    parser.add_argument('--dockerfile', required=True, help='Path to Dockerfile')
    parser.add_argument('--source-repo', required=True, help='Source repository')
    parser.add_argument('--source-provider', required=True, help='Source provider (github/gitlab)')
    parser.add_argument('--git-repo', required=True, help='Git repository URL')
    parser.add_argument('--git-branch', required=True, help='Git branch')
    parser.add_argument('--image-factory-dir', default='./image-factory', help='Path to image-factory directory')

    args = parser.parse_args()

    logger.info(f"Analyzing {args.image}:{args.tag}")
    logger.info(f"Dockerfile: {args.dockerfile}")
    logger.info(f"Source: {args.source_provider}/{args.source_repo}")

    # Determine root directory
    root_dir = Path(args.image_factory_dir)

    tool = ImageFactoryTool(root_dir)
    tool.process()

    logger.info("Analysis complete!")


if __name__ == '__main__':
    main()
