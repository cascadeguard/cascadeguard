#!/usr/bin/env python
"""
CDK8s app for generating Kargo resources for the Image Factory.

This app reads images.yaml and state files, then generates:
- Warehouses for all images (managed, base, and external)
- AnalysisTemplate for running Dockerfile analysis
- Stages for orchestrating analysis and rebuild triggers
"""

from constructs import Construct
from cdk8s import App, Chart
from pathlib import Path
import logging

# Import from our clean module structure
from lib import (
    # Data
    merge_images,
    is_managed_image,
    # Warehouses
    create_warehouse_for_managed_image,
    create_warehouse_for_base_or_external_image,
    # Stages
    setup_analysis_stage,
    setup_rebuild_trigger_stage,
    # Analysis
    setup_analysis_template,
    # Infrastructure
    setup_infrastructure,
)

# Configure logging
logging.basicConfig(
    level=logging.WARN, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Paths
SCRIPT_DIR = Path(__file__).parent
IMAGE_FACTORY_DIR = SCRIPT_DIR.parent

# State directory can be overridden via environment variable
# Default to ../image-factory-state for local development
import os

STATE_DIR = Path(
    os.getenv("IMAGE_FACTORY_STATE_DIR", SCRIPT_DIR / "../../image-factory-state")
)
STATE_IMAGES_DIR = STATE_DIR / "images"
STATE_BASE_IMAGES_DIR = STATE_DIR / "base-images"

# images.yaml can be overridden via environment variable
IMAGES_YAML = Path(os.getenv("IMAGES_YAML", STATE_DIR / "images.yaml"))

NAMESPACE = "image-factory-kargo"


class ImageFactoryChart(Chart):
    """CDK8s Chart for Image Factory Kargo resources."""

    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id, namespace=NAMESPACE)

        logging.warning("Main script running in %s", SCRIPT_DIR)
        logging.warning("Looking for images.yaml file in %s", IMAGES_YAML.resolve())

        # Create infrastructure
        setup_infrastructure(self, NAMESPACE, SCRIPT_DIR)

        # Load and merge all images
        images_by_name = merge_images(
            IMAGES_YAML, STATE_IMAGES_DIR, STATE_BASE_IMAGES_DIR
        )

        # Separate managed images from base/external images
        managed_images = []

        for image in images_by_name.values():
            name = image.get("name")
            if not name:
                logging.warning("Skipping image without name: %s", image)
                continue

            if is_managed_image(image):
                managed_images.append(image)
                create_warehouse_for_managed_image(self, image)
            else:
                create_warehouse_for_base_or_external_image(self, image)

        # Generate AnalysisTemplate (shared by all managed images)
        if managed_images:
            setup_analysis_template(self)

        # Build dependency graph: base_image -> [dependent_images]
        base_to_dependents = {}
        for image in managed_images:
            base_images = image.get("baseImages", [])
            for base_name in base_images:
                if base_name not in base_to_dependents:
                    base_to_dependents[base_name] = []
                base_to_dependents[base_name].append(image)

        # Create rebuild-trigger stages for base images with dependents
        for base_name, dependents in base_to_dependents.items():
            base_image = images_by_name.get(base_name)
            if base_image:
                for dep_image in dependents:
                    setup_rebuild_trigger_stage(self, base_image, dep_image)

        # Generate analysis stages for each managed image
        for image in managed_images:
            setup_analysis_stage(self, image)


# Main entry point
if __name__ == "__main__":
    app = App(outdir=str(os.getenv("CDK8S_OUTDIR", STATE_DIR / "dist" / "cdk8s")))
    ImageFactoryChart(app, "cascadeguard")
    app.synth()
