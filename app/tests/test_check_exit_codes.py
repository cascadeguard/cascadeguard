#!/usr/bin/env python3
"""Tests for cmd_check exit code contract.

Exit codes:
  0 — no updates found
  1 — genuine error (bad config, etc.)
  2 — updates available (new tags or digest drift detected)
"""

import os
import sys
import yaml
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import cmd_check


def _args(tmp_path, **kwargs):
    defaults = dict(
        images_yaml=str(tmp_path / "images.yaml"),
        state_dir=str(tmp_path / ".cascadeguard"),
        image=None,
        format="table",
        promote=None,
        no_commit=True,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _write_images_yaml(tmp_path, images):
    p = tmp_path / "images.yaml"
    p.write_text(yaml.dump(images))
    Path(tmp_path / ".cascadeguard").mkdir(exist_ok=True)


_HELLO_WORLD = {
    "name": "hello-world",
    "registry": "docker.io",
    "image": "hello-world",
    "namespace": "library",
    "tag": "latest",
}

_STABLE_TAGS = [
    {"name": "v1.0", "digest": "sha256:" + "a" * 64, "last_updated": "2025-01-01T00:00:00Z"},
    {"name": "v1.1", "digest": "sha256:" + "b" * 64, "last_updated": "2025-01-02T00:00:00Z"},
]


class TestCheckExitCodes:
    def test_exit_0_when_no_updates(self, tmp_path):
        """Exit 0 when all upstream tags are already known."""
        _write_images_yaml(tmp_path, [_HELLO_WORLD])
        # Pre-seed state with the tags that the mock will return
        img_state_dir = tmp_path / ".cascadeguard" / "images"
        img_state_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "upstreamTags": {
                "v1.0": {"digest": "sha256:" + "a" * 64, "firstSeen": "2025-01-01T00:00:00Z", "lastSeen": "2025-01-01T00:00:00Z", "lastUpdated": "2025-01-01T00:00:00Z"},
                "v1.1": {"digest": "sha256:" + "b" * 64, "firstSeen": "2025-01-02T00:00:00Z", "lastSeen": "2025-01-02T00:00:00Z", "lastUpdated": "2025-01-02T00:00:00Z"},
            }
        }
        (img_state_dir / "hello-world.yaml").write_text(yaml.dump(state))

        with patch("app._get_upstream_tags_rich", return_value={"tags": _STABLE_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path))

        assert rc == 0

    def test_exit_2_when_new_tags_found(self, tmp_path):
        """Exit 2 when upstream returns tags not yet in state."""
        _write_images_yaml(tmp_path, [_HELLO_WORLD])
        # No existing state — all tags are new

        with patch("app._get_upstream_tags_rich", return_value={"tags": _STABLE_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path))

        assert rc == 2

    def test_exit_1_when_images_yaml_missing(self, tmp_path):
        """Exit 1 when images.yaml does not exist."""
        rc = cmd_check(_args(tmp_path, images_yaml=str(tmp_path / "nonexistent.yaml")))
        assert rc == 1
