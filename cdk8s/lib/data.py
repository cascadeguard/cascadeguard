"""
Data loading and merging utilities for image configurations.
"""
from pathlib import Path
import logging
import yaml

logger = logging.getLogger(__name__)


def load_yaml_dir(path: Path) -> list:
    """Load all YAML files in a directory, excluding example files."""
    if not path.exists():
        logger.warning("Directory %s does not exist; skipping", path)
        return []

    entries = []
    for file in sorted(path.glob("*.yaml")):
        if file.name.endswith(".example.yaml"):
            continue
        with open(file, "r") as fh:
            entries.append(yaml.safe_load(fh))
            logger.warning("Loaded %s", file)
    return entries


def merge_images(images_yaml_path: Path, state_images_dir: Path, state_base_images_dir: Path) -> dict:
    """
    Merge images from images.yaml and state files.
    
    Returns a dict of {name: image_data} where images.yaml takes precedence.
    """
    images_by_name = {}

    def merge_entry(existing: dict, incoming: dict, prefer_incoming: bool) -> dict:
        """Shallow merge dictionaries, optionally preferring incoming values."""
        merged = dict(existing or {})
        for key, value in (incoming or {}).items():
            if prefer_incoming or key not in merged:
                merged[key] = value
        return merged

    def add_images(entries, source: str, prefer_incoming: bool = False):
        for image in entries:
            if not image or "name" not in image:
                logger.warning("Skipping entry without name from %s: %s", source, image)
                continue
            name = image["name"]
            if name in images_by_name:
                logger.warning("Merging duplicate entry for %s from %s", name, source)
                images_by_name[name] = merge_entry(images_by_name[name], image, prefer_incoming)
            else:
                images_by_name[name] = image

    # Load and merge (images.yaml takes precedence)
    with open(images_yaml_path, "r") as f:
        registry_images = yaml.safe_load(f) or []
        add_images(registry_images, "images.yaml", prefer_incoming=True)
        logger.warning("Loaded %d entries from images.yaml", len(registry_images))

    add_images(load_yaml_dir(state_images_dir), "state/images", prefer_incoming=False)
    add_images(load_yaml_dir(state_base_images_dir), "state/base-images", prefer_incoming=False)

    logger.warning(
        "Total images after merge: %d -> %s",
        len(images_by_name),
        ", ".join(sorted(images_by_name.keys()))
    )

    return images_by_name


def is_managed_image(image: dict) -> bool:
    """Check if an image is managed (has source info)."""
    enrollment = image.get("enrollment", {})
    source = enrollment.get("source", {})
    return source.get("repo") is not None
