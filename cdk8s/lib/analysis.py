"""
AnalysisTemplate and job spec builders for Dockerfile analysis.
"""
from constructs import Construct
from cdk8s import ApiObject, JsonPatch
import yaml
import os
import logging

logger = logging.getLogger(__name__)


def load_image_config():
    """Load image configuration from images.yaml file."""
    try:
        images_yaml_path = os.path.join(os.path.dirname(__file__), '..', 'images.yaml')
        with open(images_yaml_path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('images', {})
    except Exception as e:
        logger.warning(f"Could not load images.yaml: {e}, using defaults")
        return {}


def get_uv_image_reference():
    """Get the UV image reference from configuration."""
    images = load_image_config()
    uv_config = images.get('uv', {})
    
    registry = uv_config.get('registry', 'ghcr.io')
    repository = uv_config.get('repository', 'craigedmunds/uv')
    tag = uv_config.get('tag')
    
    return f"{registry}/{repository}:{tag}"


def setup_analysis_template(chart: Construct):
    """Create the shared AnalysisTemplate for Dockerfile analysis."""
    import logging
    logging.warning("Creating shared AnalysisTemplate for Dockerfile analysis")
    
    args = [
        {"name": "imageName"},
        {"name": "imageTag"},
        {"name": "imageDigest"},
        {"name": "dockerfile"},
        {"name": "sourceRepo"},
        {"name": "sourceProvider"},
        {"name": "gitRepo"},
        {"name": "gitBranch"}
    ]
    
    create_analysis_template(
        chart,
        name="analyze-dockerfile",
        args=args,
        job_spec=build_analysis_job_spec()
    )


def build_analysis_job_spec() -> dict:
    """Build the Kubernetes Job spec for Dockerfile analysis."""
    return {
        "backoffLimit": 1,
        "template": {
            "spec": {
                "serviceAccountName": "image-factory",
                "restartPolicy": "Never",
                "imagePullSecrets": [{"name": "gh-docker-registry-creds"}],
                "containers": [
                    {
                        "name": "analyzer",
                        "image": get_uv_image_reference(),
                        "imagePullPolicy": "IfNotPresent",
                        "args": [
                            "/integration/app.py",
                            "--image", "{{args.imageName}}",
                            "--tag", "{{args.imageTag}}",
                            "--digest", "{{args.imageDigest}}",
                            "--dockerfile", "{{args.dockerfile}}",
                            "--source-repo", "{{args.sourceRepo}}",
                            "--source-provider", "{{args.sourceProvider}}",
                            "--git-repo", "{{args.gitRepo}}",
                            "--git-branch", "{{args.gitBranch}}",
                            "--image-factory-dir", "/workspace/repo/image-factory"
                        ],
                        "volumeMounts": [
                            {
                                "name": "analyzer-script",
                                "mountPath": "/integration"
                            },
                            {
                                "name": "workspace",
                                "mountPath": "/workspace"
                            }
                        ],
                        "env": [
                            {
                                "name": "GITHUB_TOKEN",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "github-credentials",
                                        "key": "password"
                                    }
                                }
                            }
                        ]
                    }
                ],
                "initContainers": [
                    {
                        "name": "git-clone",
                        "image": "alpine/git:latest",
                        "command": [
                            "sh",
                            "-c",
                            "git clone --depth 1 --branch {{args.gitBranch}} {{args.gitRepo}} /workspace/repo"
                        ],
                        "volumeMounts": [
                            {
                                "name": "workspace",
                                "mountPath": "/workspace"
                            }
                        ],
                        "env": [
                            {
                                "name": "GITHUB_TOKEN",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "github-credentials",
                                        "key": "password"
                                    }
                                }
                            }
                        ]
                    }
                ],
                "volumes": [
                    {
                        "name": "analyzer-script",
                        "configMap": {
                            "name": "image-factory-analysis"
                        }
                    },
                    {
                        "name": "workspace",
                        "emptyDir": {}
                    }
                ]
            }
        }
    }


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
                "name": "analysis",  # Shortened from "analyze-dockerfile-metric" to fit 63-char limit
                "provider": {
                    "job": {
                        "spec": job_spec
                    }
                }
            }
        ]
    }))
    
    return template
