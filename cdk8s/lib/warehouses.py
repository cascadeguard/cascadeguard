"""
Warehouse creation functions for Kargo.
"""
from constructs import Construct
from imports.warehouse.io.akuity import kargo
import logging

logger = logging.getLogger(__name__)


def _build_git_repo_url(source: dict) -> str:
    """Build git repository URL from source configuration."""
    provider = source.get("provider", "github")
    repo = source.get("repo", "")
    
    if not repo:
        return ""
    
    if provider == "github":
        return f"https://github.com/{repo}.git"
    elif provider == "gitlab":
        return f"https://gitlab.com/{repo}.git"
    else:
        logger.warning("Unknown git provider: %s", provider)
        return ""


def _build_git_subscription_config(source: dict, image_name: str) -> dict:
    """Build git subscription configuration for a managed image."""
    provider = source.get("provider", "github")
    repo = source.get("repo", "")
    branch = source.get("branch", "")  # Don't default to "main", require explicit branch
    dockerfile = source.get("dockerfile", "")
    
    if not repo or not branch:
        return {}
    
    git_repo_url = _build_git_repo_url(source)
    if not git_repo_url:
        return {}
    
    # Build include paths based on dockerfile location and image factory directory
    include_paths = []
    
    # Add app-specific directory based on dockerfile path
    if dockerfile:
        # Extract app directory from dockerfile path
        # e.g., "apps/backstage/Dockerfile" -> "apps/backstage/"
        # e.g., "backstage/app/packages/backend/Dockerfile" -> "backstage/"
        dockerfile_parts = dockerfile.split("/")
        if len(dockerfile_parts) > 1:
            if dockerfile_parts[0] == "apps":
                # For apps/xxx/Dockerfile pattern, include apps/xxx/
                if len(dockerfile_parts) >= 2:
                    app_dir = f"apps/{dockerfile_parts[1]}/"
                    include_paths.append(app_dir)
            else:
                # For other patterns, include the first directory
                app_dir = f"{dockerfile_parts[0]}/"
                include_paths.append(app_dir)
    
    # Always include the image factory directory for configuration changes
    include_paths.append("image-factory/")
    
    return {
        "repoUrl": git_repo_url,
        "branch": branch,
        "commitSelectionStrategy": kargo.WarehouseSpecSubscriptionsGitCommitSelectionStrategy.NEWEST_FROM_BRANCH,
        "includePaths": include_paths,
        "discoveryLimit": 5,  # Limit to 5 most recent commits to reduce noise
        "strictSemvers": False
    }


def create_warehouse_for_managed_image(chart: Construct, image: dict):
    """Create a Warehouse for a managed image (monitors published versions and source code changes)."""
    name = image["name"]
    enrollment = image.get("enrollment", {})
    registry = enrollment.get("registry", "ghcr.io")
    repository = enrollment.get("repository", "")
    repo_url = f"{registry}/{repository}"
    
    # Check if image has a semver version, otherwise use latest tag
    current_version = image.get("currentVersion")
    
    if current_version:
        # Image has semver tags
        logger.warning("Creating warehouse for managed image %s (repo: %s) with semver", name, repo_url)
        image_config = {
            "repoUrl": repo_url,
            "semverConstraint": ">=0.1.0",
            "discoveryLimit": 10,
            "strictSemvers": False
        }
    else:
        # Image doesn't have semver tags yet, use latest
        logger.warning("Creating warehouse for managed image %s (repo: %s) with latest tag", name, repo_url)
        image_config = {
            "repoUrl": repo_url,
            "allowTags": "^latest$",
            "imageSelectionStrategy": kargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy.LEXICAL,
            "discoveryLimit": 10,
            "strictSemvers": False
        }
    
    # Build subscriptions list starting with image subscription
    subscriptions = [{"image": image_config}]
    
    # Add git subscription if source information is available
    source = enrollment.get("source", {})
    if source.get("repo") and source.get("branch"):
        git_repo_url = _build_git_repo_url(source)
        git_config = _build_git_subscription_config(source, name)
        
        if git_repo_url and git_config:
            subscriptions.append({"git": git_config})
            logger.warning("Adding git subscription for managed image %s (git repo: %s, branch: %s)", 
                         name, git_repo_url, source.get("branch"))
    
    kargo.Warehouse(
        chart,
        f"warehouse-{name}",
        metadata={"name": name},
        spec={
            "interval": "5m",
            "subscriptions": subscriptions
        }
    )


def create_warehouse_for_base_or_external_image(chart: Construct, image: dict):
    """Create a Warehouse for a base image or external image (monitors upstream updates)."""
    name = image["name"]
    repo_url = image.get("repoURL")
    allow_tags = image.get("allowTags")
    
    if not repo_url or not allow_tags:
        logger.warning("Skipping %s: missing repoURL or allowTags", name)
        return
    
    # Map strategy string to enum
    strategy_str = image.get("imageSelectionStrategy", "Lexical")
    strategy_map = {
        "Lexical": kargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy.LEXICAL,
        "NewestBuild": kargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy.NEWEST_BUILD,
        "SemVer": kargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy.SEM_VER,
    }
    strategy = strategy_map.get(strategy_str, kargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy.LEXICAL)
    
    logger.warning("Creating warehouse for base/external image %s (repo: %s, tags: %s)", name, repo_url, allow_tags)
    
    # Use 24h interval for base images to avoid Docker Hub rate limiting
    # Base images are unmanaged upstream images that should be checked infrequently
    kargo.Warehouse(
        chart,
        f"warehouse-{name}",
        metadata={"name": name},
        spec={
            "interval": "24h",
            "subscriptions": [
                {
                    "image": {
                        "repoUrl": repo_url,
                        "allowTags": allow_tags,
                        "imageSelectionStrategy": strategy,
                        "discoveryLimit": 10,
                        "strictSemvers": False
                    }
                }
            ]
        }
    )
