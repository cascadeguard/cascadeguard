"""
Image Factory CDK8s library - clean resource builders for Kargo.
"""

# Data loading
from .data import load_yaml_dir, merge_images, is_managed_image

# Warehouses
from .warehouses import (
    create_warehouse_for_managed_image,
    create_warehouse_for_base_or_external_image
)

# Stages
from .stages import (
    create_kargo_stage,
    freight_from_warehouse,
    create_rebuild_trigger_stage,
    setup_analysis_stage,
    setup_rebuild_trigger_stage,
)

# Steps
from .steps import (
    git_clone_step,
    http_step,
    github_workflow_dispatch_step
)

# Analysis
from .analysis import (
    create_analysis_template,
    build_analysis_job_spec,
    setup_analysis_template,
)

# Infrastructure
from .infrastructure import (
    create_namespace_resource,
    create_project_resource,
    create_project_config,
    create_secret,
    create_service_account,
    create_config_map,
    setup_infrastructure,
)

__all__ = [
    # Data
    "load_yaml_dir",
    "merge_images",
    "is_managed_image",
    # Warehouses
    "create_warehouse_for_managed_image",
    "create_warehouse_for_base_or_external_image",
    # Stages
    "create_kargo_stage",
    "freight_from_warehouse",
    "create_rebuild_trigger_stage",
    "setup_analysis_stage",
    "setup_rebuild_trigger_stage",
    # Steps
    "git_clone_step",
    "http_step",
    "github_workflow_dispatch_step",
    # Analysis
    "create_analysis_template",
    "build_analysis_job_spec",
    "setup_analysis_template",
    # Infrastructure
    "create_namespace_resource",
    "create_project_resource",
    "create_project_config",
    "create_secret",
    "create_service_account",
    "create_config_map",
    "setup_infrastructure",
]
