"""
Stage creation utilities for Kargo.
"""
from constructs import Construct
from cdk8s import ApiObject, JsonPatch
import logging

logger = logging.getLogger(__name__)


def setup_analysis_stage(chart: Construct, image: dict):
    """Create analysis Stage for a managed image."""
    from .steps import git_clone_step
    
    name = image["name"]
    enrollment = image.get("enrollment", {})
    registry = enrollment.get("registry", "ghcr.io")
    repository = enrollment.get("repository", "")
    repo_url = f"{registry}/{repository}"
    
    source = enrollment.get("source", {})
    git_repo = f"https://github.com/{source.get('repo', '')}.git"
    git_branch = source.get("branch", "main")
    dockerfile = source.get("dockerfile", "")
    source_repo = source.get("repo", "")
    source_provider = source.get("provider", "github")
    
    logger.warning("Creating analysis stage for managed image %s", name)
    
    # Build freight request
    requested_freight = [freight_from_warehouse(name, direct=True)]
    
    # Build promotion steps
    promotion_steps = [git_clone_step(git_repo, git_branch)]
    
    # Build verification config
    verification = {
        "analysisTemplates": [{"name": "analyze-dockerfile"}],
        "args": [
            {"name": "imageName", "value": name},
            {"name": "imageTag", "value": f"${{{{ imageFrom(\"{repo_url}\").Tag }}}}"},
            {"name": "imageDigest", "value": f"${{{{ imageFrom(\"{repo_url}\").Digest }}}}"},
            {"name": "dockerfile", "value": dockerfile},
            {"name": "sourceRepo", "value": source_repo},
            {"name": "sourceProvider", "value": source_provider},
            {"name": "gitRepo", "value": git_repo},
            {"name": "gitBranch", "value": git_branch}
        ]
    }
    
    create_kargo_stage(
        chart,
        name=f"analyze-dockerfile-{name}",
        requested_freight=requested_freight,
        promotion_steps=promotion_steps,
        verification=verification
    )


def setup_rebuild_trigger_stage(chart: Construct, base_image: dict, dependent_image: dict):
    """Create a rebuild-trigger stage for a dependent image."""
    from .steps import github_workflow_dispatch_step
    
    base_name = base_image.get("name")
    dep_name = dependent_image.get("name")
    
    source = dependent_image.get("enrollment", {}).get("source", {})
    workflow_file = source.get("workflow", f"{dep_name}.yml")
    repo = source.get("repo", "")
    branch = source.get("branch", "main")
    
    if not repo:
        logger.warning("Skipping rebuild-trigger for %s - no repo configured", dep_name)
        return
    
    # Create unique stage name that includes both base and dependent image names
    stage_name = f"rebuild-trigger-{dep_name}-from-{base_name}"
    logger.warning("Creating %s stage (watches %s)", stage_name, base_name)
    
    # Build freight request
    requested_freight = [freight_from_warehouse(base_name, direct=True)]
    
    # Build promotion steps
    promotion_steps = [
        github_workflow_dispatch_step(
            alias=f"trigger-{dep_name}",
            repo=repo,
            workflow_file=workflow_file,
            branch=branch,
            inputs={"version_bump": "patch"}
        )
    ]
    
    create_kargo_stage(
        chart,
        name=stage_name,
        requested_freight=requested_freight,
        promotion_steps=promotion_steps
    )


def freight_from_warehouse(warehouse_name: str, direct: bool = True, stages: list[str] | None = None) -> dict:
    """Build a freight request from a warehouse."""
    sources = {"direct": direct}
    if stages:
        sources["stages"] = stages
    
    return {
        "origin": {
            "kind": "Warehouse",
            "name": warehouse_name
        },
        "sources": sources
    }


def create_kargo_stage(
    chart: Construct,
    name: str,
    requested_freight: list[dict],
    promotion_steps: list[dict],
    verification: dict | None = None
) -> ApiObject:
    """
    Create a Kargo Stage resource with clean Python dicts.
    
    Args:
        chart: The CDK8s chart/construct
        name: Stage name
        requested_freight: List of freight request dicts
        promotion_steps: List of promotion step dicts
        verification: Optional verification config dict
    
    Returns:
        ApiObject representing the Stage
    """
    spec = {
        "requestedFreight": requested_freight,
        "promotionTemplate": {
            "spec": {
                "steps": promotion_steps
            }
        }
    }
    
    if verification:
        spec["verification"] = verification
    
    stage = ApiObject(
        chart,
        f"stage-{name}",
        api_version="kargo.akuity.io/v1alpha1",
        kind="Stage",
        metadata={"name": name}
    )
    stage.add_json_patch(JsonPatch.add("/spec", spec))
    return stage


def create_rebuild_trigger_stage(chart, base_image: dict, dependent_images: list, namespace: str):
    """
    Create a Kargo stage that triggers GitHub workflow rebuilds when a base image updates.
    
    Args:
        chart: CDK8s Chart
        base_image: Base image dict with name, repoURL
        dependent_images: List of dependent image dicts with enrollment.source info
        namespace: Kubernetes namespace
    """
    base_name = base_image.get("name")
    logger.warning(f"Creating rebuild-trigger stage for {base_name} with {len(dependent_images)} dependents")
    
    # Build HTTP steps to trigger each dependent workflow
    http_steps = []
    
    for dep_image in dependent_images:
        dep_name = dep_image.get("name")
        source = dep_image.get("enrollment", {}).get("source", {})
        workflow_file = source.get("workflow", f"{dep_name}.yml")
        repo = source.get("repo", "")
        branch = source.get("branch", "main")
        
        if not repo:
            logger.warning(f"Skipping {dep_name} - no repo configured")
            continue
        
        # GitHub workflow_dispatch API call
        http_steps.append({
            "uses": "http",
            "as": f"trigger-{dep_name}",
            "config": {
                "url": f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches",
                "method": "POST",
                "headers": [
                    {
                        "name": "Accept",
                        "value": "application/vnd.github.v3+json"
                    },
                    {
                        "name": "Authorization", 
                        "value": "Bearer ${secret.GITHUB_TOKEN}"
                    },
                    {
                        "name": "Content-Type",
                        "value": "application/json"
                    }
                ],
                "body": f'{{"ref":"{branch}","inputs":{{"version_bump":"patch","triggered_by":"kargo-base-image-update","base_image":"{base_name}"}}}}'
            }
        })
    
    if not http_steps:
        logger.warning(f"No valid dependents for {base_name}, skipping rebuild-trigger stage")
        return
    
    stage = ApiObject(
        chart,
        f"stage-rebuild-trigger-{base_name}",
        api_version="kargo.akuity.io/v1alpha1",
        kind="Stage",
        metadata={
            "name": f"rebuild-trigger-{base_name}",
            "namespace": namespace
        }
    )
    
    stage.add_json_patch(JsonPatch.add("/spec", {
        "requestedFreight": [
            {
                "origin": {
                    "kind": "Warehouse",
                    "name": base_name
                },
                "sources": {
                    "direct": True
                }
            }
        ],
        "promotionTemplate": {
            "spec": {
                "steps": http_steps
            }
        }
    }))
    
    return stage
