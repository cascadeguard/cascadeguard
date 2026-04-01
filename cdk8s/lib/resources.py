"""
DEPRECATED: This module has been split into focused modules.

This file is kept for reference only. Use the new modular structure:
- lib/data.py - YAML loading and merging
- lib/warehouses.py - Warehouse creation
- lib/stages.py - Stage creation
- lib/steps.py - Promotion steps
- lib/analysis.py - AnalysisTemplate
- lib/infrastructure.py - Infrastructure resources

Import from lib/__init__.py for the public API.
"""
from constructs import Construct
from cdk8s import ApiObject, JsonPatch
from imports import k8s
from imports.warehouse.io.akuity import kargo
import logging


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
    from cdk8s import JsonPatch
    
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


def create_analysis_template(
    chart: Construct,
    name: str,
    args: list[dict],
    job_spec: dict
) -> ApiObject:
    """
    Create an Argo Rollouts AnalysisTemplate.
    
    Args:
        chart: The CDK8s chart/construct
        name: Template name
        args: List of argument dicts
        job_spec: Kubernetes Job spec dict
    
    Returns:
        ApiObject representing the AnalysisTemplate
    """
    template = ApiObject(
        chart,
        f"analysis-template-{name}",
        api_version="argoproj.io/v1alpha1",
        kind="AnalysisTemplate",
        metadata={"name": name}
    )
    
    template.add_json_patch(JsonPatch.add("/spec", {
        "args": args,
        "metrics": [
            {
                "name": f"{name}-metric",
                "provider": {
                    "job": {
                        "spec": job_spec
                    }
                }
            }
        ]
    }))
    
    return template


def create_namespace_resource(chart: Construct, name: str, labels: dict) -> ApiObject:
    """
    Create a Namespace resource (cluster-scoped).
    
    Args:
        chart: The CDK8s chart/construct
        name: Namespace name
        labels: Labels dict
    
    Returns:
        ApiObject representing the Namespace
    """
    return ApiObject(
        chart,
        "namespace",
        api_version="v1",
        kind="Namespace",
        metadata={
            "name": name,
            "labels": labels
        }
    )


def create_project_resource(chart: Construct, name: str) -> ApiObject:
    """
    Create a Kargo Project resource (cluster-scoped).
    
    Args:
        chart: The CDK8s chart/construct
        name: Project name
    
    Returns:
        ApiObject representing the Project
    """
    return ApiObject(
        chart,
        "project",
        api_version="kargo.akuity.io/v1alpha1",
        kind="Project",
        metadata={"name": name}
    )


def create_project_config(
    chart: Construct,
    name: str,
    promotion_policies: list[dict]
) -> ApiObject:
    """
    Create a Kargo ProjectConfig resource.
    
    Args:
        chart: The CDK8s chart/construct
        name: ProjectConfig name
        promotion_policies: List of promotion policy dicts
    
    Returns:
        ApiObject representing the ProjectConfig
    """
    config = ApiObject(
        chart,
        "project-config",
        api_version="kargo.akuity.io/v1alpha1",
        kind="ProjectConfig",
        metadata={"name": name}
    )
    
    config.add_json_patch(JsonPatch.add("/spec", {"promotionPolicies": promotion_policies}))
    return config


def create_secret(
    chart: Construct,
    name: str,
    secret_type: str,
    data: dict | None = None,
    string_data: dict | None = None,
    labels: dict | None = None,
    annotations: dict | None = None
) -> ApiObject:
    """
    Create a Secret resource.
    
    Args:
        chart: The CDK8s chart/construct
        name: Secret name
        secret_type: Secret type (e.g., "Opaque", "kubernetes.io/dockerconfigjson")
        data: Optional base64-encoded data dict
        string_data: Optional plain-text string data dict
        labels: Optional labels dict
        annotations: Optional annotations dict
    
    Returns:
        ApiObject representing the Secret
    """
    metadata = {"name": name}
    if labels:
        metadata["labels"] = labels
    if annotations:
        metadata["annotations"] = annotations
    
    secret = ApiObject(
        chart,
        f"secret-{name}",
        api_version="v1",
        kind="Secret",
        metadata=metadata
    )
    
    secret.add_json_patch(JsonPatch.add("/type", secret_type))
    if data:
        secret.add_json_patch(JsonPatch.add("/data", data))
    if string_data:
        secret.add_json_patch(JsonPatch.add("/stringData", string_data))
    
    return secret


# Freight request builders
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


# Promotion step builders
def git_clone_step(repo_url: str, branch: str, path: str = "./repo") -> dict:
    """Build a git-clone promotion step."""
    return {
        "uses": "git-clone",
        "config": {
            "repoURL": repo_url,
            "checkout": [
                {
                    "branch": branch,
                    "path": path
                }
            ]
        }
    }


def http_step(
    alias: str,
    url: str,
    method: str,
    headers: list[dict],
    body: str | None = None
) -> dict:
    """Build an HTTP promotion step."""
    config = {
        "url": url,
        "method": method,
        "headers": headers
    }
    if body:
        config["body"] = body
    
    return {
        "uses": "http",
        "as": alias,
        "config": config
    }


def github_workflow_dispatch_step(
    alias: str,
    repo: str,
    workflow_file: str,
    branch: str,
    inputs: dict,
    token_secret: str = "github-workflow-token"
) -> dict:
    """Build a GitHub workflow_dispatch HTTP step."""
    import json
    
    return http_step(
        alias=alias,
        url=f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches",
        method="POST",
        headers=[
            {"name": "Accept", "value": "application/vnd.github.v3+json"},
            {"name": "Authorization", "value": f"Bearer ${{{{ secret('{token_secret}').token }}}}"},
            {"name": "Content-Type", "value": "application/json"}
        ],
        body=json.dumps({"ref": branch, "inputs": inputs})
    )
