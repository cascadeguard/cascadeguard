#!/usr/bin/env python3
"""
CascadeGuard Task Mode CLI

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
import sys
import yaml
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error


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

    print(f"✓ Validated {len(images)} images in {images_yaml}")
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

    print(f"✓ Enrolled '{args.name}' in {images_yaml}")
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
        print(f"✓ Build triggered: {result}")
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
        print(f"✓ Deploy triggered: {result}")
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
    """Run the full pipeline: validate → check → build → deploy → test."""
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

    print("\n✓ Pipeline complete")
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
        description="CascadeGuard task mode CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  validate    Validate images.yaml configuration
  enrol       Enrol a new image in images.yaml
  check       Check image and base image states
  build       Trigger a build via GitHub Actions
  deploy      Deploy via ArgoCD
  test        Check build test results via GitHub Actions
  pipeline    Run full pipeline (validate → check → build → deploy → test)
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


if __name__ == "__main__":
    sys.exit(main())
