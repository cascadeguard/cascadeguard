"""
Infrastructure resource creation (Namespace, Project, Secrets, etc.).
"""
from constructs import Construct
from cdk8s import ApiObject, JsonPatch
from imports import k8s
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def setup_infrastructure(chart: Construct, namespace: str, script_dir: Path):
    """Create infrastructure resources (namespace, project, secrets, etc.)."""
    logger.warning("Creating infrastructure resources")
    
    # Namespace
    create_namespace_resource(
        chart,
        name=namespace,
        labels={
            "kargo.akuity.io/project": "true",
            "kargo.deps/ghcr": "true",
            "secrets/gh-docker-registry": "true"
        }
    )
    
    # Project
    create_project_resource(chart, name=namespace)
    
    # ProjectConfig with auto-promotion policies
    create_project_config(
        chart,
        name=namespace,
        promotion_policies=[
            {"stageSelector": {"name": "analyze-dockerfile-backstage"}, "autoPromotionEnabled": True},
            {"stageSelector": {"name": "analyze-dockerfile-uv"}, "autoPromotionEnabled": True},
            {"stageSelector": {"name": "rebuild-trigger-backstage"}, "autoPromotionEnabled": True},
            {"stageSelector": {"name": "rebuild-trigger-uv"}, "autoPromotionEnabled": True}
        ]
    )
    
    # ServiceAccount
    create_service_account(chart, name="image-factory")
    
    # Docker pull secret (managed by ESO)
    # create_secret(
    #     chart,
    #     name="ghcr-pull-secret",
    #     secret_type="kubernetes.io/dockerconfigjson",
    #     data={".dockerconfigjson": "e30K"},  # Empty JSON - replaced by ESO
    #     annotations={"eso.io/source": "central-secret-store/github-docker-registry"}
    # )
    
    # Analysis ConfigMap
    app_py_path = script_dir / "../app/app.py"
    pyproject_path = script_dir / "../app/pyproject.toml"
    
    with open(app_py_path, "r") as f:
        app_py_content = f.read()
    
    with open(pyproject_path, "r") as f:
        pyproject_content = f.read()
    
    create_config_map(
        chart,
        name="image-factory-analysis",
        data={
            "app.py": app_py_content,
            "pyproject.toml": pyproject_content
        }
    )


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


def create_service_account(chart: Construct, name: str) -> k8s.KubeServiceAccount:
    """
    Create a ServiceAccount resource.
    
    Args:
        chart: The CDK8s chart/construct
        name: ServiceAccount name
    
    Returns:
        KubeServiceAccount object
    """
    return k8s.KubeServiceAccount(
        chart,
        "service-account",
        metadata={"name": name}
    )


def create_config_map(chart: Construct, name: str, data: dict) -> k8s.KubeConfigMap:
    """
    Create a ConfigMap resource.
    
    Args:
        chart: The CDK8s chart/construct
        name: ConfigMap name
        data: Data dict
    
    Returns:
        KubeConfigMap object
    """
    return k8s.KubeConfigMap(
        chart,
        f"configmap-{name}",
        metadata={"name": name},
        data=data
    )
