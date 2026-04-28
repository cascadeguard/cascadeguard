#!/usr/bin/env python3
"""Tests for --dry-run, --skip-state, and --images flags on cascadeguard images check."""

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
        images=None,
        format="table",
        promote=None,
        no_commit=False,
        dry_run=False,
        skip_state=False,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _write_images_yaml(tmp_path, images):
    (tmp_path / "images.yaml").write_text(yaml.dump(images))
    (tmp_path / ".cascadeguard").mkdir(exist_ok=True)


def _seed_state(tmp_path, name, upstream_tags):
    img_dir = tmp_path / ".cascadeguard" / "images"
    img_dir.mkdir(parents=True, exist_ok=True)
    state = {"upstreamTags": upstream_tags}
    (img_dir / f"{name}.yaml").write_text(yaml.dump(state))


_NGINX = {
    "name": "nginx",
    "registry": "docker.io",
    "image": "nginx",
    "namespace": "library",
    "tag": "latest",
}

_REDIS = {
    "name": "redis",
    "registry": "docker.io",
    "image": "redis",
    "namespace": "library",
    "tag": "latest",
}

_KNOWN_TAGS = {
    "v1.0": {"digest": "sha256:" + "a" * 64, "firstSeen": "2025-01-01T00:00:00Z",
              "lastSeen": "2025-01-01T00:00:00Z", "lastUpdated": "2025-01-01T00:00:00Z"},
}

_UPSTREAM_TAGS = [
    {"name": "v1.0", "digest": "sha256:" + "a" * 64, "last_updated": "2025-01-01T00:00:00Z"},
    {"name": "v2.0", "digest": "sha256:" + "b" * 64, "last_updated": "2025-02-01T00:00:00Z"},
]


class TestDryRunFlag:
    def test_dry_run_implies_no_commit(self, tmp_path):
        """--dry-run must not call git commit/push helpers."""
        _write_images_yaml(tmp_path, [_NGINX])

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                with patch("app._commit_state_changes") as mock_commit:
                    rc = cmd_check(_args(tmp_path, dry_run=True))

        mock_commit.assert_not_called()
        assert rc in (0, 2)

    def test_dry_run_still_detects_new_tags(self, tmp_path):
        """--dry-run still reports new tags (exit 2) even without committing."""
        _write_images_yaml(tmp_path, [_NGINX])

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path, dry_run=True))

        assert rc == 2

    def test_dry_run_does_not_modify_dockerfiles(self, tmp_path):
        """--dry-run must not call _update_dockerfile_digest."""
        _write_images_yaml(tmp_path, [_NGINX])

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                with patch("app._update_dockerfile_digest") as mock_update:
                    cmd_check(_args(tmp_path, dry_run=True, promote=True))

        mock_update.assert_not_called()


class TestSkipStateFlag:
    def test_skip_state_treats_all_tags_as_new(self, tmp_path):
        """--skip-state ignores existing state so all upstream tags appear new."""
        _write_images_yaml(tmp_path, [_NGINX])
        # Seed state with v1.0 as known; without --skip-state, only v2.0 would be new
        _seed_state(tmp_path, "nginx", _KNOWN_TAGS)

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path, no_commit=True, skip_state=True))

        # Both v1.0 and v2.0 are new from a blank-slate perspective → exit 2
        assert rc == 2

    def test_without_skip_state_known_tags_not_new(self, tmp_path):
        """Without --skip-state, pre-seeded tags are not reported as new."""
        _write_images_yaml(tmp_path, [_NGINX])
        # Seed state with both tags already known
        all_known = {
            "v1.0": {"digest": "sha256:" + "a" * 64, "firstSeen": "2025-01-01T00:00:00Z",
                     "lastSeen": "2025-01-01T00:00:00Z", "lastUpdated": "2025-01-01T00:00:00Z"},
            "v2.0": {"digest": "sha256:" + "b" * 64, "firstSeen": "2025-02-01T00:00:00Z",
                     "lastSeen": "2025-02-01T00:00:00Z", "lastUpdated": "2025-02-01T00:00:00Z"},
        }
        _seed_state(tmp_path, "nginx", all_known)

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path, no_commit=True))

        assert rc == 0

    def test_skip_state_combined_with_dry_run(self, tmp_path):
        """--dry-run --skip-state: no commits and all tags treated as new."""
        _write_images_yaml(tmp_path, [_NGINX])
        _seed_state(tmp_path, "nginx", _KNOWN_TAGS)

        with patch("app._get_upstream_tags_rich", return_value={"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                with patch("app._commit_state_changes") as mock_commit:
                    rc = cmd_check(_args(tmp_path, dry_run=True, skip_state=True))

        mock_commit.assert_not_called()
        assert rc == 2


class TestImagesFilter:
    def test_images_flag_single_name(self, tmp_path):
        """--images nginx filters to only that image."""
        _write_images_yaml(tmp_path, [_NGINX, _REDIS])

        upstream_calls = []

        def mock_upstream(registry, namespace, image):
            upstream_calls.append(image)
            return {"tags": _UPSTREAM_TAGS, "error": None, "http_status": None}

        with patch("app._get_upstream_tags_rich", side_effect=mock_upstream):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path, no_commit=True, images="nginx"))

        assert "nginx" in upstream_calls
        assert "redis" not in upstream_calls

    def test_images_flag_multiple_names(self, tmp_path):
        """--images nginx,redis checks both but not others."""
        extra = {"name": "alpine", "registry": "docker.io", "image": "alpine",
                 "namespace": "library", "tag": "latest"}
        _write_images_yaml(tmp_path, [_NGINX, _REDIS, extra])

        upstream_calls = []

        def mock_upstream(registry, namespace, image):
            upstream_calls.append(image)
            return {"tags": [], "error": None, "http_status": None}

        with patch("app._get_upstream_tags_rich", side_effect=mock_upstream):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path, no_commit=True, images="nginx,redis"))

        assert "nginx" in upstream_calls
        assert "redis" in upstream_calls
        assert "alpine" not in upstream_calls

    def test_image_single_flag_still_works(self, tmp_path):
        """Legacy --image (singular) flag is unaffected."""
        _write_images_yaml(tmp_path, [_NGINX, _REDIS])

        upstream_calls = []

        def mock_upstream(registry, namespace, image):
            upstream_calls.append(image)
            return {"tags": [], "error": None, "http_status": None}

        with patch("app._get_upstream_tags_rich", side_effect=mock_upstream):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path, no_commit=True, image="nginx"))

        assert "nginx" in upstream_calls
        assert "redis" not in upstream_calls
