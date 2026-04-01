#!/usr/bin/env python3
"""
Generate state files from images.yaml.

This script reads images.yaml and generates state files in base-images/ and images/
directories by analyzing Dockerfiles to discover base image dependencies.
"""

import yaml
import sys
import re
import os
from pathlib import Path
from datetime import datetime, timezone
import subprocess
import argparse


def load_images_yaml(images_yaml_path: Path) -> list:
    """Load and parse images.yaml."""
    with open(images_yaml_path) as f:
        return yaml.safe_load(f) or []


def parse_dockerfile_base_images(dockerfile_path: Path) -> list:
    """Extract all base images from Dockerfile FROM statements (multi-stage support)."""
    if not dockerfile_path.exists():
        print(f"Warning: Dockerfile not found: {dockerfile_path}", file=sys.stderr)
        return []

    base_images = []
    with open(dockerfile_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("FROM "):
                # Extract image reference, handle AS alias
                match = re.match(r"FROM\s+([^\s]+)", line)
                if match:
                    image_ref = match.group(1)
                    # Skip scratch and stage references
                    if image_ref.lower() != "scratch" and not is_stage_reference(
                        image_ref
                    ):
                        base_images.append(image_ref)

    return base_images


def is_stage_reference(image_ref: str) -> bool:
    """Check if image reference is a stage name (not a real image)."""
    # Stage names are typically lowercase and don't contain registry/repository patterns
    if "/" in image_ref or ":" in image_ref or "." in image_ref:
        return False
    # Stage names are usually simple identifiers
    return image_ref.islower() and len(image_ref) < 20


def normalize_base_image_name(image_ref: str) -> str:
    """Convert image reference to normalized name for filename."""
    # Replace special chars with hyphens
    name = re.sub(r"[:/]", "-", image_ref)
    return name


def clone_repo_if_needed(source: dict, dockerfile_path: str, cache_dir: Path) -> Path:
    """
    Clone a git repository (sparse checkout of just the Dockerfile) to cache directory.
    Returns the path to the cloned repo.

    If the repo is already cloned but the requested Dockerfile isn't in the sparse
    checkout, it is added and re-fetched (supports multiple Dockerfiles from one repo).
    """
    provider = source.get("provider", "github")
    repo = source.get("repo")
    branch = source.get("branch", "main")

    if not repo:
        raise ValueError("No repo specified in source")

    # Build git URL (inject token for authenticated access to private repos)
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if provider == "github":
        if github_token:
            git_url = f"https://x-access-token:{github_token}@github.com/{repo}.git"
        else:
            git_url = f"https://github.com/{repo}.git"
    elif provider == "gitlab":
        gitlab_token = os.environ.get("GITLAB_TOKEN", "")
        if gitlab_token:
            git_url = f"https://oauth2:{gitlab_token}@gitlab.com/{repo}.git"
        else:
            git_url = f"https://gitlab.com/{repo}.git"
    else:
        raise ValueError(f"Unknown provider: {provider}")

    # Create cache directory for this repo
    repo_cache_dir = cache_dir / repo.replace("/", "_")
    dockerfile_full_path = repo_cache_dir / dockerfile_path

    if dockerfile_full_path.exists():
        print(f"  Using cached Dockerfile: {dockerfile_full_path}")
        return repo_cache_dir

    # Log URL without token
    display_url = (
        re.sub(r"://[^@]+@", "://***@", git_url) if "@" in git_url else git_url
    )
    print(f"  Fetching {dockerfile_path} from {display_url} (branch: {branch})...")

    repo_cache_dir.mkdir(parents=True, exist_ok=True)
    git_dir = repo_cache_dir / ".git"
    already_initialised = git_dir.exists()

    try:
        if not already_initialised:
            # Fresh clone: init, add remote, enable sparse checkout
            subprocess.run(
                ["git", "init"], cwd=repo_cache_dir, check=True, capture_output=True
            )
            subprocess.run(
                ["git", "config", "core.sparseCheckout", "true"],
                cwd=repo_cache_dir,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "remote", "add", "origin", git_url],
                cwd=repo_cache_dir,
                check=True,
                capture_output=True,
            )

        # Append the requested path to the sparse-checkout list (deduplicates)
        sparse_checkout_file = git_dir / "info" / "sparse-checkout"
        sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)

        existing_paths = set()
        if sparse_checkout_file.exists():
            existing_paths = {
                line.strip()
                for line in sparse_checkout_file.read_text().splitlines()
                if line.strip()
            }

        if dockerfile_path not in existing_paths:
            with open(sparse_checkout_file, "a") as f:
                f.write(f"{dockerfile_path}\n")

        # Fetch and checkout (re-fetch is cheap with --depth 1)
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", branch],
            cwd=repo_cache_dir,
            check=True,
            capture_output=True,
        )

        # Use checkout for fresh clones, read-tree for updates
        if not already_initialised:
            subprocess.run(
                ["git", "checkout", branch],
                cwd=repo_cache_dir,
                check=True,
                capture_output=True,
            )
        else:
            subprocess.run(
                ["git", "read-tree", "-mu", "FETCH_HEAD"],
                cwd=repo_cache_dir,
                check=True,
                capture_output=True,
            )

        print(f"  Fetched to {repo_cache_dir}")

    except subprocess.CalledProcessError as e:
        print(f"  Error during git operations: {e}", file=sys.stderr)
        if not already_initialised:
            # Only clean up if we just created it
            import shutil

            shutil.rmtree(repo_cache_dir, ignore_errors=True)
        raise

    return repo_cache_dir


def _yaml_block(data: dict, indent: int = 0) -> str:
    """Render a dict as YAML with controlled key ordering (preserves insertion order)."""
    lines = []
    prefix = "  " * indent
    for key, value in data.items():
        if value is None:
            lines.append(f"{prefix}{key}: null")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{key}: {'true' if value else 'false'}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{prefix}{key}: []")
            else:
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        # Nested dict in list — use yaml.dump for simplicity
                        dumped = yaml.dump(item, default_flow_style=False).strip()
                        first, *rest = dumped.split("\n")
                        lines.append(f"{prefix}  - {first}")
                        for r in rest:
                            lines.append(f"{prefix}    {r}")
                    else:
                        lines.append(f"{prefix}  - {item}")
        elif isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_yaml_block(value, indent + 1))
        elif isinstance(value, str):
            # Quote strings that look like timestamps or contain special chars
            if (
                re.match(r"^\d{4}-\d{2}-\d{2}", value)
                or ":" in value
                and not value.startswith("^")
            ):
                lines.append(f"{prefix}{key}: '{value}'")
            else:
                lines.append(f"{prefix}{key}: {value}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)


def _write_app_image_state(
    state_file: Path,
    name: str,
    enrollment_data: dict,
    base_images: list,
    existing: dict | None,
) -> None:
    """Write an application image state file in the canonical format with comments."""
    now = datetime.now(timezone.utc).isoformat()

    # Preserve timestamps from existing file, or set new ones
    if existing:
        enrolled_at = existing.get("enrolledAt", now)
        last_discovery = existing.get("lastDiscovery", now)
        discovery_status = existing.get("discoveryStatus", "pending")
        current_version = existing.get("currentVersion")
        current_digest = existing.get("currentDigest")
        last_built = existing.get("lastBuilt")
    else:
        enrolled_at = now
        last_discovery = now
        discovery_status = "pending"
        current_version = None
        current_digest = None
        last_built = None

    # Build enrollment block with controlled key order
    enrollment_ordered = {}
    for key in [
        "registry",
        "repository",
        "source",
        "rebuildDelay",
        "autoRebuild",
        "updates",
    ]:
        if key in enrollment_data:
            enrollment_ordered[key] = enrollment_data[key]

    # Format base images list
    if base_images:
        base_images_block = "\n".join(f"  - {b}" for b in sorted(base_images))
    else:
        base_images_block = None

    # Build the file content with comments and controlled ordering
    lines = [
        "# Auto-generated by Image Factory",
        f"# This file tracks the state of the {name} image",
        f"name: {name}",
        f"enrolledAt: '{enrolled_at}'",
        f"lastDiscovery: '{last_discovery}'",
        f"discoveryStatus: {discovery_status}",
        "",
        "# Enrollment configuration (copied from images.yaml for reference)",
        _yaml_block({"enrollment": enrollment_ordered}),
        "",
        "# Discovered from Dockerfile parsing",
        "# References to base image state files (not inline data)",
    ]

    if base_images_block:
        lines.append("baseImages:")
        lines.append(base_images_block)
    else:
        lines.append("baseImages: []")

    lines += [
        "",
        "# Current published state (from registry/Kargo)",
        f"currentVersion: {'null' if current_version is None else current_version}",
        f"currentDigest: {'null' if current_digest is None else current_digest}",
        f"lastBuilt: {'null' if last_built is None else last_built}",
        "",  # trailing newline
    ]

    with open(state_file, "w") as f:
        f.write("\n".join(lines))


def generate_state_for_image(image: dict, output_dir: Path, cache_dir: Path) -> bool:
    """
    Generate or update state file for a single image by analyzing its Dockerfile.

    Idempotent: if a state file already exists, only enrollment and baseImages are
    updated (if changed). Timestamps and other runtime state are preserved.
    """
    name = image.get("name")
    if not name:
        print(f"Skipping image without name: {image}", file=sys.stderr)
        return False

    # Determine if this is a base image or application image
    source = image.get("source", {})
    if not source:
        enrollment = image.get("enrollment", {})
        source = enrollment.get("source", {})

    is_base_image = not source  # Base images don't have source

    # Determine state directory
    if is_base_image:
        state_dir = output_dir / "base-images"
    else:
        state_dir = output_dir / "images"

    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / f"{name}.yaml"

    # ── Base images: skip if file already exists (never overwrite) ──
    if is_base_image:
        if state_file.exists():
            print(f"  Skipping existing base image state: {state_file}")
        else:
            with open(state_file, "w") as f:
                yaml.dump(image, f, default_flow_style=False)
            print(f"✓ Generated state for base image: {name}")
        return True

    # ── Application images ──

    # Load existing state (if any) so we can preserve timestamps
    existing = None
    if state_file.exists():
        with open(state_file) as f:
            existing = yaml.safe_load(f)

    # Analyze Dockerfile to discover base images
    dockerfile_path = source.get("dockerfile")
    base_images = []
    discovery_failed = False

    if dockerfile_path:
        try:
            repo_dir = clone_repo_if_needed(source, dockerfile_path, cache_dir)
            full_dockerfile_path = repo_dir / dockerfile_path

            if full_dockerfile_path.exists():
                discovered = parse_dockerfile_base_images(full_dockerfile_path)
                seen = set()
                for base_image_ref in discovered:
                    base_image_name = normalize_base_image_name(base_image_ref)
                    if base_image_name not in seen:
                        base_images.append(base_image_name)
                        seen.add(base_image_name)

                if base_images:
                    print(f"  Discovered {len(base_images)} base images: {base_images}")
            else:
                discovery_failed = True
                print(
                    f"  Warning: Dockerfile not found at {full_dockerfile_path}",
                    file=sys.stderr,
                )
        except Exception as e:
            discovery_failed = True
            print(f"  Error fetching/analyzing Dockerfile: {e}", file=sys.stderr)

    # If discovery failed and we have existing baseImages, preserve them
    if discovery_failed and existing:
        existing_base = existing.get("baseImages") or []
        if existing_base:
            base_images = list(existing_base)
            print(f"  Preserving existing baseImages (discovery failed): {base_images}")

    # Build enrollment data from images.yaml input
    enrollment_data = {}
    for key in [
        "registry",
        "repository",
        "source",
        "rebuildDelay",
        "autoRebuild",
        "updates",
    ]:
        if key in image:
            enrollment_data[key] = image[key]

    # Check if anything actually changed vs existing file
    if existing:
        existing_enrollment = existing.get("enrollment", {})
        existing_base_images = sorted(existing.get("baseImages") or [])
        new_base_images = sorted(base_images)

        if (
            existing_enrollment == enrollment_data
            and existing_base_images == new_base_images
        ):
            print(f"  No changes for {name}, skipping write")
            return True

        print(f"  Updating state for {name} (enrollment or baseImages changed)")

    _write_app_image_state(state_file, name, enrollment_data, base_images, existing)

    verb = "Updated" if existing else "Generated"
    print(f"✓ {verb} state for application image: {name}")
    return True


def _generate_build_workflow(image: dict, output_dir: Path) -> bool:
    """
    Generate a GitHub Actions workflow for building and pushing a Docker image.

    Only generated for images that have a source (Dockerfile) but no existing
    workflow in the source repo. The workflow is placed in the state repo's
    .github/workflows/ directory and can be triggered manually or by Kargo.

    Supports a 'local' config block for state-repo-resident files:
      local:
        dir: local/image-name          # directory in state repo
        patchFiles: [Dockerfile.patch]  # patches applied before build
        versionFile: VERSION            # version file read as default tag
    """
    name = image.get("name")
    source = image.get("source", {})
    if not source:
        return False

    # Skip if the source repo already has a build workflow
    if source.get("workflow"):
        return False

    registry = image.get("registry", "ghcr.io")
    repository = image.get("repository", "")
    repo = source.get("repo", "")
    branch = source.get("branch", "main")
    dockerfile = source.get("dockerfile", "Dockerfile")

    # Local config block for state-repo-resident files
    local = image.get("local", {})
    local_dir = local.get("dir", "")
    local_dockerfile = local.get("dockerfile", "")
    patch_files = local.get("patchFiles", [])
    version_file = local.get("versionFile", "")

    workflows_dir = output_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    workflow_file = workflows_dir / f"build-{name}.yml"

    # --- Version file handling (shared by both modes) ---
    if version_file and local_dir:
        version_path = f"{local_dir}/{version_file}"
    elif version_file:
        version_path = version_file
    else:
        version_path = ""

    if version_path:
        version_inputs = """
      suffix:
        description: "Optional pre-release suffix (e.g. rc1, beta). Skips version bump."
        required: false
        type: string
      increment:
        description: "Version part to increment after build (major, minor, patch)"
        required: false
        default: "patch"
        type: choice
        options: [major, minor, patch]"""
        tag_expr = "${{ steps.tag.outputs.tag }}"
        contents_permission = "write"
        dispatch_inputs = f"""    inputs:{version_inputs}"""
    else:
        version_inputs = ""
        tag_expr = "${{ inputs.tag }}"
        contents_permission = "read"
        dispatch_inputs = """    inputs:
      tag:
        description: "Image tag to build"
        required: false
        default: "latest"
        type: string"""

    # --- Two modes: local dockerfile or upstream source ---
    if local_dockerfile:
        # Local mode: Dockerfile lives in the state repo, no upstream checkout
        if local_dir:
            dockerfile_path = f"{local_dir}/{local_dockerfile}"
            docker_context = local_dir
        else:
            dockerfile_path = local_dockerfile
            docker_context = "."

        version_steps = ""
        bump_step = ""
        if version_path:
            version_steps = f"""
      - name: Read version
        id: version
        run: echo "version=$(cat {version_path})" >> "$GITHUB_OUTPUT"

      - name: Resolve tag
        id: tag
        run: |
          version=$(cat {version_path})
          if [ -n "${{{{ inputs.suffix }}}}" ]; then
            echo "tag=$version-${{{{ inputs.suffix }}}}" >> "$GITHUB_OUTPUT"
          else
            echo "tag=$version" >> "$GITHUB_OUTPUT"
          fi
"""
            bump_step = f"""
      - name: Bump version
        if: inputs.suffix == ''
        run: |
          version=$(cat {version_path})
          IFS='.' read -r major minor patch <<< "$version"
          case "${{{{ inputs.increment }}}}" in
            major) major=$((major + 1)); minor=0; patch=0 ;;
            minor) minor=$((minor + 1)); patch=0 ;;
            *)     patch=$((patch + 1)) ;;
          esac
          new_version="$major.$minor.$patch"
          echo "$new_version" > {version_path}
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add {version_path}
          git commit -m "chore: Bump {name} version to $new_version"
          git push
"""

        source_label = repo if repo else repository

        workflow_content = f"""# Auto-generated by Image Factory
# Build and push {name} image
# Trigger manually or via Kargo automation
name: "Build {name}"

on:
  workflow_dispatch:
{dispatch_inputs}

env:
  REGISTRY: {registry}
  IMAGE_NAME: {repository}

jobs:
  build-and-push:
    name: "Build and push {name}"
    runs-on: ubuntu-latest
    permissions:
      contents: {contents_permission}
      packages: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4
{version_steps}
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to {registry}
        uses: docker/login-action@v3
        with:
          registry: {registry}
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: {docker_context}
          file: {dockerfile_path}
          push: true
          tags: |
            ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}:{tag_expr}
            ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}:latest
          labels: |
            org.opencontainers.image.source=https://github.com/{source_label}
            org.opencontainers.image.description={name} (built by image-factory)
          cache-from: type=gha
          cache-to: type=gha,mode=max
{bump_step}"""

    else:
        # Upstream mode: checkout upstream source, optionally apply patches
        docker_context = "."
        local_steps = ""
        has_local_files = patch_files or version_file

        if has_local_files:
            sparse_path = local_dir if local_dir else "."
            local_steps += f"""
      - name: Checkout local files
        uses: actions/checkout@v4
        with:
          path: _image-factory
          sparse-checkout: {sparse_path}
          sparse-checkout-cone-mode: false
"""

        for patch in patch_files:
            if "/" not in patch and local_dir:
                patch_path = f"{local_dir}/{patch}"
            else:
                patch_path = patch
            local_steps += f"""
      - name: Apply patch {patch}
        run: git apply _image-factory/{patch_path}
"""

        bump_step = ""
        if version_path:
            local_steps += f"""
      - name: Read version
        id: version
        run: echo "version=$(cat _image-factory/{version_path})" >> "$GITHUB_OUTPUT"

      - name: Resolve tag
        id: tag
        run: |
          version=$(cat _image-factory/{version_path})
          if [ -n "${{{{ inputs.suffix }}}}" ]; then
            echo "tag=$version-${{{{ inputs.suffix }}}}" >> "$GITHUB_OUTPUT"
          else
            echo "tag=$version" >> "$GITHUB_OUTPUT"
          fi
"""
            bump_step = f"""
      - name: Bump version
        if: inputs.suffix == ''
        run: |
          version=$(cat _image-factory/{version_path})
          IFS='.' read -r major minor patch <<< "$version"
          case "${{{{ inputs.increment }}}}" in
            major) major=$((major + 1)); minor=0; patch=0 ;;
            minor) minor=$((minor + 1)); patch=0 ;;
            *)     patch=$((patch + 1)) ;;
          esac
          new_version="$major.$minor.$patch"
          echo "$new_version" > _image-factory/{version_path}
          cd _image-factory
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add {version_path}
          git commit -m "chore: Bump {name} version to $new_version"
          git push
"""

        workflow_content = f"""# Auto-generated by Image Factory
# Build and push {name} image
# Trigger manually or via Kargo automation
name: "Build {name}"

on:
  workflow_dispatch:
{dispatch_inputs}

env:
  REGISTRY: {registry}
  IMAGE_NAME: {repository}

jobs:
  build-and-push:
    name: "Build and push {name}"
    runs-on: ubuntu-latest
    permissions:
      contents: {contents_permission}
      packages: write

    steps:
      - name: Checkout source
        uses: actions/checkout@v4
        with:
          repository: {repo}
          ref: {branch}
{local_steps}
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to {registry}
        uses: docker/login-action@v3
        with:
          registry: {registry}
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: {docker_context}
          file: {dockerfile}
          push: true
          tags: |
            ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}:{tag_expr}
            ${{{{ env.REGISTRY }}}}/${{{{ env.IMAGE_NAME }}}}:latest
          labels: |
            org.opencontainers.image.source=https://github.com/{repo}
            org.opencontainers.image.description={name} (built by image-factory)
          cache-from: type=gha
          cache-to: type=gha,mode=max
{bump_step}"""

    # Check if existing workflow matches
    if workflow_file.exists():
        existing = workflow_file.read_text()
        if existing == workflow_content:
            print(f"  No changes for workflow build-{name}.yml, skipping write")
            return False

    workflow_file.write_text(workflow_content)
    verb = "Updated" if workflow_file.exists() else "Generated"
    print(f"✓ {verb} build workflow: .github/workflows/build-{name}.yml")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate state files from images.yaml"
    )
    parser.add_argument(
        "--images-yaml", type=Path, required=True, help="Path to images.yaml"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for state files (will create base-images/ and images/ subdirs)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Cache directory for cloned repos (default: .image-factory-cache in output dir)",
    )

    args = parser.parse_args()

    if not args.images_yaml.exists():
        print(f"Error: images.yaml not found at {args.images_yaml}", file=sys.stderr)
        sys.exit(1)

    # Set up cache directory
    if args.cache_dir:
        cache_dir = args.cache_dir
    else:
        cache_dir = args.output_dir / ".image-factory-cache"

    cache_dir.mkdir(parents=True, exist_ok=True)

    # Load images
    images = load_images_yaml(args.images_yaml)
    print(f"Found {len(images)} images in {args.images_yaml}")

    # Generate state for each image
    success_count = 0
    workflow_count = 0
    for image in images:
        if generate_state_for_image(image, args.output_dir, cache_dir):
            success_count += 1
        if _generate_build_workflow(image, args.output_dir):
            workflow_count += 1

    print(f"\n✓ Generated state files for {success_count}/{len(images)} images")
    print(f"  Base images: {args.output_dir}/base-images/")
    print(f"  Application images: {args.output_dir}/images/")
    if workflow_count:
        print(f"  Build workflows: {workflow_count} generated in .github/workflows/")


if __name__ == "__main__":
    main()
