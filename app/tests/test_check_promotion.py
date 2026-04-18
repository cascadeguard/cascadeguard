#!/usr/bin/env python3
"""Acceptance tests for the check → quarantine → promote → PR pipeline.

These tests exercise the full cmd_check flow end-to-end with mocked
registries and git operations.  Each test sets up a realistic repo
structure (images.yaml, Dockerfiles, state files, config) and verifies
the correct outcome across the quarantine/promotion matrix.
"""

import json
import os
import sys
import pytest
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import cmd_check, _DEFAULT_QUARANTINE_HOURS


# ── Constants ──────────────────────────────────────────────────────────────

DIGEST_OLD = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST_NEW = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DIGEST_NEW2 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"


# ── Helpers ────────────────────────────────────────────────────────────────


def _args(**kwargs):
    """Build a SimpleNamespace with sensible defaults for cmd_check."""
    defaults = dict(
        images_yaml="images.yaml",
        state_dir=".cascadeguard",
        image=None,
        format="table",
        promote=None,       # None = resolve from config (default: true)
        no_commit=True,     # Tests don't run git operations
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _mock_info(digest, published_at=None):
    """Return a _fetch_manifest_info-shaped dict."""
    return {"digest": digest, "publishedAt": published_at}


def _setup_repo(tmp_path, images, dockerfiles=None, config=None):
    """Create a minimal repo with images.yaml, optional Dockerfiles and config."""
    images_yaml = tmp_path / "images.yaml"
    images_yaml.write_text(yaml.dump(images))

    state_dir = tmp_path / ".cascadeguard"
    state_dir.mkdir(parents=True, exist_ok=True)

    if config:
        cfg_file = tmp_path / ".cascadeguard.yaml"
        cfg_file.write_text(yaml.dump(config))

    if dockerfiles:
        for path, content in dockerfiles.items():
            full = tmp_path / path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content)

    return str(images_yaml), str(state_dir)


def _seed_base_image_state(state_dir, name, digest=DIGEST_OLD,
                            published_at=None, observed_at=None,
                            promoted_digest=None, promoted_at=None,
                            registry="docker.io",
                            repository="library/node", tag="22"):
    """Pre-seed a base-images state file simulating a previous check run."""
    base_dir = Path(state_dir) / "base-images"
    base_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "name": name,
        "fullImage": f"{repository.split('/')[-1]}:{tag}",
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "currentDigest": digest,
        "publishedAt": published_at,
        "observedAt": observed_at,
        "previousDigest": None,
        "promotedDigest": promoted_digest,
        "promotedAt": promoted_at,
        "lastChecked": "2025-01-01T00:00:00+00:00",
        "allowTags": f"^{tag}$",
        "imageSelectionStrategy": "Lexical",
        "repoURL": f"{registry}/{repository}",
        "firstDiscovered": "2025-01-01T00:00:00+00:00",
        "rebuildEligibleAt": {"default": None},
        "metadata": {},
        "updateHistory": [],
        "lastDiscovery": None,
    }
    (base_dir / f"{name}.yaml").write_text(
        yaml.dump(state, default_flow_style=False)
    )


def _seed_image_state(state_dir, name, base_images, dockerfile=""):
    """Pre-seed an images state file."""
    images_dir = Path(state_dir) / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "name": name,
        "enrolledAt": "2025-01-01T00:00:00+00:00",
        "lastChecked": "2025-01-01T00:00:00+00:00",
        "registry": "ghcr.io",
        "image": name,
        "tag": "latest",
        "dockerfile": dockerfile,
        "baseImages": sorted(base_images),
        "currentDigest": None,
    }
    (images_dir / f"{name}.yaml").write_text(
        yaml.dump(state, default_flow_style=False)
    )


def _read_dockerfile(tmp_path, rel_path):
    return (tmp_path / rel_path).read_text()


# ── Acceptance Tests ───────────────────────────────────────────────────────

# Standard image config used by most tests
_MYAPP = {
    "name": "myapp",
    "dockerfile": "images/myapp/Dockerfile",
    "image": "myapp", "tag": "latest",
    "registry": "ghcr.io",
}
_MYAPP_DF = {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"}


class TestDriftWithQuarantineNotElapsed:
    """Upstream published 1h ago, quarantine is 48h → no promotion."""

    def test_dockerfile_unchanged(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=one_hour_ago,
                                observed_at=one_hour_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, one_hour_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert "@sha256:" not in content

    def test_stderr_shows_quarantine_remaining(self, tmp_path, capsys):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=one_hour_ago,
                                observed_at=one_hour_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, one_hour_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        err = capsys.readouterr().err
        assert "quarantine" in err.lower()
        assert "remaining" in err.lower()


class TestDriftWithQuarantineElapsed:
    """Upstream published 72h ago, quarantine is 48h → Dockerfile pinned."""

    def test_dockerfile_pinned_to_new_digest(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content

    def test_stderr_shows_promotion(self, tmp_path, capsys):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        err = capsys.readouterr().err
        assert "eligible for promotion" in err.lower() or "promoted" in err.lower()

    def test_state_records_promotion(self, tmp_path):
        """After promotion, promotedDigest should match currentDigest."""
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        bi_state = yaml.safe_load((Path(state_dir) / "base-images" / "node-22.yaml").read_text())
        assert bi_state["promotedDigest"] == DIGEST_NEW
        assert bi_state["promotedAt"] is not None

    def test_already_promoted_and_pinned_skipped(self, tmp_path):
        """If promotedDigest == currentDigest AND Dockerfile already pinned, no change."""
        images_yaml, state_dir = _setup_repo(tmp_path,
            images=[_MYAPP],
            dockerfiles={
                "images/myapp/Dockerfile": f"FROM node:22@{DIGEST_NEW}\nRUN echo hello\n",
            })
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago,
                                promoted_digest=DIGEST_NEW,
                                promoted_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        # Dockerfile should be unchanged — already pinned to the promoted digest
        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content


class TestQuarantineUsesPublishedAt:
    """Quarantine evaluates against publishedAt, not observedAt."""

    def test_published_long_ago_observed_recently(self, tmp_path):
        """Published 72h ago but we only saw it 1h ago → should promote."""
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        published = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        observed = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=published,
                                observed_at=observed)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, published)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content


class TestQuarantineDisabled:
    """quarantine: disabled → immediate promotion."""

    def test_immediate_promotion(self, tmp_path):
        myapp = dict(_MYAPP, quarantine="disabled")
        images_yaml, state_dir = _setup_repo(tmp_path, [myapp], _MYAPP_DF)
        just_now = datetime.now(timezone.utc).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=just_now,
                                observed_at=just_now)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, just_now)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content

    def test_zero_quarantine(self, tmp_path):
        myapp = dict(_MYAPP, quarantine="0")
        images_yaml, state_dir = _setup_repo(tmp_path, [myapp], _MYAPP_DF)
        just_now = datetime.now(timezone.utc).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=just_now,
                                observed_at=just_now)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, just_now)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content


class TestNoDrift:
    """No drift, digest already promoted and pinned → Dockerfile untouched."""

    def test_dockerfile_unchanged(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path,
            images=[_MYAPP],
            dockerfiles={
                "images/myapp/Dockerfile": f"FROM node:22@{DIGEST_OLD}\nRUN echo hello\n",
            })
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_OLD,
                                published_at=long_ago,
                                observed_at=long_ago,
                                promoted_digest=DIGEST_OLD,
                                promoted_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_OLD, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        assert rc == 0
        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_OLD}" in content


class TestPerImagePromoteFalse:
    def test_dockerfile_unchanged(self, tmp_path):
        myapp = dict(_MYAPP, promote=False)
        images_yaml, state_dir = _setup_repo(tmp_path, [myapp], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert "@sha256:" not in content


class TestRepoLevelPromoteFalse:
    def test_dockerfile_unchanged(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF,
            config={"check": {"promote": False}})
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert "@sha256:" not in content


class TestNoPromoteFlag:
    def test_overrides_config(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir,
                                promote=False))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert "@sha256:" not in content


class TestCustomQuarantinePeriod:
    def test_short_quarantine_promotes_early(self, tmp_path):
        myapp = dict(_MYAPP, quarantine="2h")
        images_yaml, state_dir = _setup_repo(tmp_path, [myapp], _MYAPP_DF)
        three_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=three_hours_ago,
                                observed_at=three_hours_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, three_hours_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content

    def test_long_quarantine_blocks(self, tmp_path):
        myapp = dict(_MYAPP, quarantine="7d")
        images_yaml, state_dir = _setup_repo(tmp_path, [myapp], _MYAPP_DF)
        three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=three_days_ago,
                                observed_at=three_days_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, three_days_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert "@sha256:" not in content


class TestRepoLevelQuarantine:
    def test_repo_config_overrides_default(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF,
            config={"quarantine": {"period": "1h"}})
        two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=two_hours_ago,
                                observed_at=two_hours_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, two_hours_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content


class TestUpdateHistory:
    """Drift detection populates updateHistory with both timestamps."""

    def test_history_entry_on_new_drift(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_OLD,
                                published_at=old_time,
                                observed_at=old_time,
                                promoted_digest=DIGEST_OLD,
                                promoted_at=old_time)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        new_published = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, new_published)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        bi_state = yaml.safe_load((Path(state_dir) / "base-images" / "node-22.yaml").read_text())
        assert bi_state["currentDigest"] == DIGEST_NEW
        assert bi_state["previousDigest"] == DIGEST_OLD
        history = bi_state.get("updateHistory", [])
        assert len(history) >= 1
        latest = history[-1]
        assert latest["digest"] == DIGEST_NEW
        assert latest["publishedAt"] is not None
        assert latest["observedAt"] is not None
        assert latest["promotedAt"] is None  # still in quarantine


class TestPromoteDestinationMain:
    """check.promote.destination: main → Dockerfile still gets modified."""

    def test_dockerfile_promoted(self, tmp_path):
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF,
            config={"check": {"promote": {"enabled": True, "destination": "main"}}})
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
        _seed_base_image_state(state_dir, "node-22",
                                digest=DIGEST_NEW,
                                published_at=long_ago,
                                observed_at=long_ago)
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        content = _read_dockerfile(tmp_path, "images/myapp/Dockerfile")
        assert f"FROM node:22@{DIGEST_NEW}" in content


class TestStateFileRoundtrip:
    """State files with platforms survive write → read → write."""

    def test_platforms_roundtrip_after_promotion(self, tmp_path):
        """Promotion writes state with platforms, then re-reading and
        writing again should not crash."""
        images_yaml, state_dir = _setup_repo(tmp_path, [_MYAPP], _MYAPP_DF)
        long_ago = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()

        # Pre-seed with platforms (as dicts, like the registry returns)
        base_dir = Path(state_dir) / "base-images"
        base_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "name": "node-22",
            "fullImage": "node:22",
            "registry": "docker.io",
            "repository": "library/node",
            "tag": "22",
            "currentDigest": DIGEST_NEW,
            "publishedAt": long_ago,
            "observedAt": long_ago,
            "previousDigest": None,
            "promotedDigest": None,
            "promotedAt": None,
            "lastChecked": "2025-01-01T00:00:00+00:00",
            "allowTags": "^22$",
            "imageSelectionStrategy": "Lexical",
            "repoURL": "docker.io/library/node",
            "firstDiscovered": "2025-01-01T00:00:00+00:00",
            "rebuildEligibleAt": {"default": None},
            "metadata": {},
            "platforms": [
                {"os": "linux", "architecture": "amd64"},
                {"os": "linux", "architecture": "arm64"},
                {"os": "linux", "architecture": "arm", "variant": "v7"},
            ],
            "updateHistory": [],
            "lastDiscovery": None,
        }
        (base_dir / "node-22.yaml").write_text(
            yaml.dump(state, default_flow_style=False)
        )
        _seed_image_state(state_dir, "myapp", ["node-22"],
                          dockerfile="images/myapp/Dockerfile")

        with patch("app._fetch_manifest_info", return_value=_mock_info(DIGEST_NEW, long_ago)):
            with patch("app._get_dockerhub_tags_rich", return_value=[]):
                cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        # Verify the state file was written successfully (no crash)
        bi_state = yaml.safe_load((base_dir / "node-22.yaml").read_text())
        assert bi_state["promotedDigest"] == DIGEST_NEW
        # Platforms should survive the roundtrip
        assert len(bi_state["platforms"]) == 3
        assert bi_state["platforms"][0]["os"] == "linux"
        assert bi_state["platforms"][0]["architecture"] == "amd64"
