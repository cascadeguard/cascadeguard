#!/usr/bin/env python3
"""Unit tests for CascadeGuard task mode CLI commands."""

import json
import os
import stat
import sys
import pytest
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import (
    ArgoCDProvider,
    GitHubActionsProvider,
    _fetch_manifest_digest,
    build_parser,
    cmd_check,
    cmd_deploy,
    cmd_enrol,
    cmd_status,
    cmd_test,
    cmd_validate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args(**kwargs):
    """Build a SimpleNamespace with sensible defaults for all common args."""
    defaults = dict(
        images_yaml="images.yaml",
        state_dir="state",
        github_token=None,
        argocd_token=None,
        repo=None,
        argocd_server=None,
        app=None,
        tag="latest",
        name=None,
        registry=None,
        repository=None,
        provider=None,
        dockerfile=None,
        branch=None,
        rebuild_delay=None,
        auto_rebuild=False,
        image=None,
        format="table",
        promote=False,
        no_commit=True,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# cmd_validate
# ---------------------------------------------------------------------------


class TestCmdValidate:
    def test_valid_images_yaml(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(
            yaml.dump(
                [
                    {
                        "name": "myapp",
                        "registry": "ghcr.io",
                        "dockerfile": "images/myapp/Dockerfile",
                    }
                ]
            )
        )
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 0

    def test_missing_name(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"registry": "ghcr.io", "dockerfile": "Dockerfile"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_missing_registry(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "dockerfile": "Dockerfile"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_missing_dockerfile(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "registry": "ghcr.io"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_disabled_image_only_needs_name(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "enabled": False}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 0

    def test_config_defaults_applied(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "dockerfile": "Dockerfile"}]))
        cfg = tmp_path / ".cascadeguard.yaml"
        cfg.write_text(yaml.dump({"defaults": {"registry": "ghcr.io/test"}}))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 0

    def test_file_not_found(self, tmp_path):
        rc = cmd_validate(_args(images_yaml=str(tmp_path / "missing.yaml")))
        assert rc == 1

    def test_empty_list_is_valid(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text("[]")
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 0

    def test_not_a_list(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text("name: foo\n")
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1


# ---------------------------------------------------------------------------
# cmd_enrol
# ---------------------------------------------------------------------------


class TestCmdEnrol:
    def test_enrol_new_image(self, tmp_path):
        f = tmp_path / "images.yaml"
        rc = cmd_enrol(
            _args(
                images_yaml=str(f),
                name="newapp",
                registry="ghcr.io",
                repository="org/newapp",
            )
        )
        assert rc == 0
        with open(f) as fh:
            images = yaml.safe_load(fh)
        assert len(images) == 1
        assert images[0]["name"] == "newapp"
        assert images[0]["registry"] == "ghcr.io"

    def test_enrol_with_source(self, tmp_path):
        f = tmp_path / "images.yaml"
        rc = cmd_enrol(
            _args(
                images_yaml=str(f),
                name="app",
                registry="ghcr.io",
                repository="org/app",
                provider="github",
                repo="org/app",
                dockerfile="Dockerfile",
                branch="main",
                rebuild_delay="7d",
            )
        )
        assert rc == 0
        with open(f) as fh:
            images = yaml.safe_load(fh)
        img = images[0]
        assert img["source"]["provider"] == "github"
        assert img["source"]["repo"] == "org/app"
        assert img["source"]["dockerfile"] == "Dockerfile"
        assert img["source"]["branch"] == "main"
        assert img["rebuildDelay"] == "7d"

    def test_enrol_duplicate_rejected(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(
            yaml.dump([{"name": "myapp", "registry": "ghcr.io", "repository": "x"}])
        )
        rc = cmd_enrol(
            _args(
                images_yaml=str(f),
                name="myapp",
                registry="ghcr.io",
                repository="org/myapp",
            )
        )
        assert rc == 1

    def test_enrol_appends_to_existing(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(
            yaml.dump([{"name": "first", "registry": "ghcr.io", "repository": "x"}])
        )
        cmd_enrol(
            _args(
                images_yaml=str(f),
                name="second",
                registry="ghcr.io",
                repository="org/second",
            )
        )
        with open(f) as fh:
            images = yaml.safe_load(fh)
        assert len(images) == 2
        assert images[1]["name"] == "second"

    def test_enrol_auto_rebuild_flag(self, tmp_path):
        f = tmp_path / "images.yaml"
        rc = cmd_enrol(
            _args(
                images_yaml=str(f),
                name="app",
                registry="ghcr.io",
                repository="org/app",
                auto_rebuild=True,
            )
        )
        assert rc == 0
        with open(f) as fh:
            images = yaml.safe_load(fh)
        assert images[0]["autoRebuild"] is True

    def test_enrol_auto_rebuild_false_by_default(self, tmp_path):
        f = tmp_path / "images.yaml"
        cmd_enrol(
            _args(
                images_yaml=str(f),
                name="app",
                registry="ghcr.io",
                repository="org/app",
            )
        )
        with open(f) as fh:
            images = yaml.safe_load(fh)
        assert "autoRebuild" not in images[0]


# ---------------------------------------------------------------------------
# cmd_check
# ---------------------------------------------------------------------------


DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIGEST_B = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class TestFetchManifestDigest:
    """Unit tests for _fetch_manifest_digest (network isolated)."""

    def _mock_urlopen(self, token_digest_pairs):
        """Return a side-effect list: first call returns token JSON, second returns digest header."""
        calls = iter(token_digest_pairs)

        def _urlopen(req, timeout=10):
            token_json, digest = next(calls)
            resp = MagicMock()
            resp.read.return_value = json.dumps({"token": token_json}).encode()
            resp.headers = {"Docker-Content-Digest": digest} if digest else {}
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        return _urlopen

    def test_dockerhub_returns_digest(self):
        responses = [("tok", None), (None, DIGEST_A)]
        with patch("urllib.request.urlopen", side_effect=self._mock_urlopen(responses)):
            result = _fetch_manifest_digest("docker.io", "library/node", "22")
        assert result == DIGEST_A

    def test_ghcr_returns_digest(self):
        responses = [("tok", None), (None, DIGEST_A)]
        with patch("urllib.request.urlopen", side_effect=self._mock_urlopen(responses)):
            result = _fetch_manifest_digest("ghcr.io", "myorg/myapp", "1.0.0")
        assert result == DIGEST_A

    def test_network_error_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = _fetch_manifest_digest("docker.io", "library/node", "22")
        assert result is None

    def test_missing_digest_header_returns_none(self):
        responses = [("tok", None), (None, None)]
        with patch("urllib.request.urlopen", side_effect=self._mock_urlopen(responses)):
            result = _fetch_manifest_digest("docker.io", "library/node", "22")
        assert result is None


class TestCmdCheck:
    def _setup_repo(self, tmp_path, images_yaml_content, dockerfiles=None):
        """Set up a minimal repo with images.yaml, .cascadeguard.yaml, and optional Dockerfiles."""
        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump(images_yaml_content))
        state_dir = tmp_path / ".cascadeguard"
        state_dir.mkdir(parents=True, exist_ok=True)
        if dockerfiles:
            for path, content in dockerfiles.items():
                full = tmp_path / path
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text(content)
        return str(images_yaml), str(state_dir)

    def _pre_seed_base_image(self, state_dir, name, registry="docker.io",
                              repository="library/node", tag="22", digest=DIGEST_A):
        """Pre-seed a base-images state file (simulates a previous check run)."""
        base_dir = Path(state_dir) / "base-images"
        base_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "name": name,
            "fullImage": f"{repository}:{tag}",
            "registry": registry,
            "repository": repository,
            "tag": tag,
            "currentDigest": digest,
            "lastChecked": "2025-01-01T00:00:00+00:00",
            "allowTags": f"^{tag}$",
            "imageSelectionStrategy": "Lexical",
            "repoURL": f"{registry}/{repository}",
            "firstDiscovered": "2025-01-01T00:00:00+00:00",
            "lastUpdated": None,
            "previousDigest": None,
            "rebuildEligibleAt": {"default": None},
            "metadata": {},
            "updateHistory": [],
            "lastDiscovery": None,
        }
        (base_dir / f"{name}.yaml").write_text(yaml.dump(state, default_flow_style=False))

    # ── discovers base images from Dockerfile ────────────────────────────────

    def test_discovers_base_images_from_dockerfile(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22-slim\nRUN echo hello\n"})

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_A, "publishedAt": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        assert rc == 0
        # Should have created base-images/node-22-slim.yaml
        assert (Path(state_dir) / "base-images" / "node-22-slim.yaml").exists()
        # Should have created images/myapp.yaml
        assert (Path(state_dir) / "images" / "myapp.yaml").exists()

    # ── clean match on pre-seeded base image ─────────────────────────────────

    def test_clean_base_image_returns_0(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_A, "publishedAt": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        assert rc == 0

    # ── drift detected ───────────────────────────────────────────────────────

    def test_drift_base_image_returns_2(self, tmp_path):
        # Drift = "updates available" → exit 2 (not a genuine error).
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_B, "publishedAt": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        assert rc == 2

    def test_drift_table_output(self, tmp_path, capsys):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_B, "publishedAt": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        out = capsys.readouterr().out
        assert "DRIFT" in out

    def test_clean_table_output(self, tmp_path, capsys):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_A, "publishedAt": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        out = capsys.readouterr().out
        assert "node-22" in out

    # ── json output ──────────────────────────────────────────────────────────

    def test_drift_json_output(self, tmp_path, capsys):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_B, "publishedAt": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir, format="json"))
        data = json.loads(capsys.readouterr().out)
        assert any(d["status"] == "drift" for d in data)

    def test_clean_json_output(self, tmp_path, capsys):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22", digest=DIGEST_A)

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_A, "publishedAt": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir, format="json"))
        data = json.loads(capsys.readouterr().out)
        assert data[0]["status"] == "ok"

    # ── network error non-fatal ──────────────────────────────────────────────

    def test_registry_error_is_non_fatal(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22")

        with patch("app._fetch_manifest_info", return_value=None):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        assert rc == 0

    def test_registry_error_shown_in_output(self, tmp_path, capsys):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"}],
            {"images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n"})
        self._pre_seed_base_image(state_dir, "node-22")

        with patch("app._fetch_manifest_info", return_value=None):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        out = capsys.readouterr().out
        assert "error" in out or "unreachable" in out

    # ── --image scoping ──────────────────────────────────────────────────────

    def test_image_filter_scopes_to_named_image(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path, [
            {"name": "myapp", "dockerfile": "images/myapp/Dockerfile", "image": "myapp", "tag": "latest", "registry": "ghcr.io"},
            {"name": "other", "dockerfile": "images/other/Dockerfile", "image": "other", "tag": "latest", "registry": "ghcr.io"},
        ], {
            "images/myapp/Dockerfile": "FROM node:22\nRUN echo hello\n",
            "images/other/Dockerfile": "FROM alpine:3.20\nRUN echo hello\n",
        })

        with patch("app._fetch_manifest_info", return_value={"digest": DIGEST_A, "publishedAt": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir, image="myapp"))
        assert rc == 0
        # Only myapp's base image should be discovered, not other's
        assert (Path(state_dir) / "images" / "myapp.yaml").exists()

    # ── skipped when disabled ────────────────────────────────────────────────

    def test_disabled_image_is_skipped(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "memcached", "enabled": False}])

        with patch("app._fetch_manifest_info") as mock_fetch:
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        mock_fetch.assert_not_called()
        assert rc == 0

    # ── empty images.yaml ────────────────────────────────────────────────────

    def test_empty_images_returns_0(self, tmp_path):
        images_yaml, state_dir = self._setup_repo(tmp_path, [])
        rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))
        assert rc == 0

    # ── parser ───────────────────────────────────────────────────────────────

    def test_parser_check_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["images", "check"])
        assert args.image is None
        assert args.format == "table"

    def test_parser_check_with_flags(self):
        parser = build_parser()
        args = parser.parse_args(["images", "check", "--image", "node-22", "--format", "json"])
        assert args.image == "node-22"
        assert args.format == "json"

    # ── lastChecked only updated on successful registry query ────────────────

    def test_lastchecked_updated_on_404_to_prevent_queue_hogging(self, tmp_path):
        """lastChecked MUST be updated even on 404 so the image doesn't stay at the front of the queue."""
        original_ts = "2026-04-15T10:00:00+00:00"
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "seaweedfs", "image": "seaweedfs", "tag": "3.65", "namespace": "library",
              "full_name": "chrislusf/seaweedfs"}])

        # Pre-seed the image state with an existing lastChecked
        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "seaweedfs.yaml").write_text(yaml.dump({
            "name": "seaweedfs",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": original_ts,
            "registry": "",
            "image": "seaweedfs",
            "tag": "3.65",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {},
        }))

        # 404 response
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [], "error": "not_found", "http_status": 404}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "seaweedfs.yaml") as f:
            state = yaml.safe_load(f)
        # lastChecked should be updated so this image rotates to the back of the queue
        assert state["lastChecked"] != original_ts
        assert state["checkStatus"] == "error"
        assert "404" in state["checkError"]

    def test_lastchecked_not_updated_on_rate_limit(self, tmp_path):
        """lastChecked must NOT be updated when rate limited (empty response but known tags exist)."""
        original_ts = "2026-04-15T10:00:00+00:00"
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "nginx", "image": "nginx", "tag": "1.27", "namespace": "library",
              "full_name": "library/nginx"}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "nginx.yaml").write_text(yaml.dump({
            "name": "nginx",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": original_ts,
            "registry": "",
            "image": "nginx",
            "tag": "1.27",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {"1.26": {"digest": "sha256:aaa"}, "1.27": {"digest": "sha256:bbb"}},
        }))

        # Empty response but we have known tags → rate limited
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [], "error": "rate_limited", "http_status": 429}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "nginx.yaml") as f:
            state = yaml.safe_load(f)
        assert state["lastChecked"] == original_ts

    def test_lastchecked_updated_on_successful_tag_fetch(self, tmp_path):
        """lastChecked MUST be updated when upstream tags are successfully fetched."""
        original_ts = "2026-04-15T10:00:00+00:00"
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "alpine", "image": "alpine", "tag": "3.23", "namespace": "library",
              "full_name": "library/alpine"}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "alpine.yaml").write_text(yaml.dump({
            "name": "alpine",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": original_ts,
            "registry": "",
            "image": "alpine",
            "tag": "3.23",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": [],
        }))

        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [
                 {"name": "3.20", "digest": "sha256:aaa", "last_updated": "2026-04-01T00:00:00Z"},
                 {"name": "3.21", "digest": "sha256:bbb", "last_updated": "2026-04-02T00:00:00Z"},
                 {"name": "3.22", "digest": "sha256:ccc", "last_updated": "2026-04-03T00:00:00Z"},
                 {"name": "3.23", "digest": "sha256:ddd", "last_updated": "2026-04-04T00:00:00Z"},
             ], "error": None, "http_status": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "alpine.yaml") as f:
            state = yaml.safe_load(f)
        # lastChecked should have been updated (different from original)
        assert state["lastChecked"] != original_ts

    # ── upstream tags persisted to state file ────────────────────────────────

    def test_upstream_tags_persisted_to_state_file(self, tmp_path):
        """Discovered upstream tags must be written to the image state YAML."""
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "fluent-bit", "image": "fluent-bit", "tag": "3.3",
              "namespace": "fluent", "full_name": "fluent/fluent-bit"}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        # Pre-seed with some known tags — these should NOT be reported as new
        (images_dir / "fluent-bit.yaml").write_text(yaml.dump({
            "name": "fluent-bit",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": "2026-04-15T10:00:00+00:00",
            "registry": "",
            "image": "fluent-bit",
            "tag": "3.3",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {
                "3.0": {"digest": "sha256:old0", "firstSeen": "2026-04-15T00:00:00+00:00", "lastSeen": "2026-04-15T00:00:00+00:00"},
                "3.1": {"digest": "sha256:old1", "firstSeen": "2026-04-15T00:00:00+00:00", "lastSeen": "2026-04-15T00:00:00+00:00"},
                "3.2": {"digest": "sha256:old2", "firstSeen": "2026-04-15T00:00:00+00:00", "lastSeen": "2026-04-15T00:00:00+00:00"},
                "3.3": {"digest": "sha256:old3", "firstSeen": "2026-04-15T00:00:00+00:00", "lastSeen": "2026-04-15T00:00:00+00:00"},
            },
        }))

        fake_tags = [
            {"name": "3.0", "digest": "sha256:old0", "last_updated": "2026-04-01T00:00:00Z"},
            {"name": "3.1", "digest": "sha256:old1", "last_updated": "2026-04-02T00:00:00Z"},
            {"name": "3.2", "digest": "sha256:old2", "last_updated": "2026-04-03T00:00:00Z"},
            {"name": "3.3", "digest": "sha256:old3", "last_updated": "2026-04-04T00:00:00Z"},
            {"name": "3.3.1", "digest": "sha256:new1", "last_updated": "2026-04-05T00:00:00Z"},
            {"name": "latest", "digest": "sha256:lat", "last_updated": "2026-04-04T00:00:00Z"},
        ]
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": fake_tags, "error": None, "http_status": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "fluent-bit.yaml") as f:
            state = yaml.safe_load(f)
        assert isinstance(state["upstreamTags"], dict)
        # Known tags preserved, new tag added
        assert "3.3" in state["upstreamTags"]
        assert "3.3.1" in state["upstreamTags"]
        assert "latest" not in state["upstreamTags"]
        assert state["upstreamTags"]["3.3.1"]["digest"] == "sha256:new1"

    def test_known_tags_not_reported_as_new(self, tmp_path, capsys):
        """Tags already in the state file must NOT appear in new-tags output."""
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "alpine", "image": "alpine", "tag": "3.23",
              "namespace": "library", "full_name": "library/alpine"}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "alpine.yaml").write_text(yaml.dump({
            "name": "alpine",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": "2026-04-15T10:00:00+00:00",
            "registry": "",
            "image": "alpine",
            "tag": "3.23",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {
                "3.20": {"digest": "sha256:aaa"},
                "3.21": {"digest": "sha256:bbb"},
                "3.22": {"digest": "sha256:ccc"},
                "3.23": {"digest": "sha256:ddd"},
            },
        }))

        # Return the same tags — nothing new
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [
                 {"name": "3.20", "digest": "sha256:aaa", "last_updated": None},
                 {"name": "3.21", "digest": "sha256:bbb", "last_updated": None},
                 {"name": "3.22", "digest": "sha256:ccc", "last_updated": None},
                 {"name": "3.23", "digest": "sha256:ddd", "last_updated": None},
             ], "error": None, "http_status": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        out = capsys.readouterr().out
        assert "new-tags" not in out
        assert "new upstream tags" not in out

    def test_tag_repoint_detected_and_previous_digest_stored(self, tmp_path):
        """When a tag's digest changes, previousDigest must be recorded."""
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "alpine", "image": "alpine", "tag": "3.23",
              "namespace": "library", "full_name": "library/alpine"}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "alpine.yaml").write_text(yaml.dump({
            "name": "alpine",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": "2026-04-15T10:00:00+00:00",
            "registry": "",
            "image": "alpine",
            "tag": "3.23",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {
                "3.23": {
                    "digest": "sha256:old_digest_aaa",
                    "firstSeen": "2026-04-15T10:00:00+00:00",
                    "lastSeen": "2026-04-15T10:00:00+00:00",
                    "lastUpdated": "2026-04-14T00:00:00Z",
                },
            },
        }))

        # Same tag, different digest — repoint
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [
                 {"name": "3.23", "digest": "sha256:new_digest_bbb", "last_updated": "2026-04-18T00:00:00Z"},
             ], "error": None, "http_status": None}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "alpine.yaml") as f:
            state = yaml.safe_load(f)
        tag_state = state["upstreamTags"]["3.23"]
        assert tag_state["digest"] == "sha256:new_digest_bbb"
        assert tag_state["previousDigest"] == "sha256:old_digest_aaa"
        # firstSeen should be preserved from original observation
        assert tag_state["firstSeen"] == "2026-04-15T10:00:00+00:00"

    def test_upstream_tags_not_written_on_empty_response(self, tmp_path):
        """When registry returns no tags (error/rate-limit), upstreamTags must not be cleared."""
        images_yaml, state_dir = self._setup_repo(tmp_path,
            [{"name": "nginx", "image": "nginx", "tag": "1.27", "namespace": "library",
              "full_name": "library/nginx", "latest_stable_tags": ["1.26", "1.27"]}])

        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        existing_tags = ["1.25", "1.26", "1.27"]
        (images_dir / "nginx.yaml").write_text(yaml.dump({
            "name": "nginx",
            "enrolledAt": "2026-04-14T19:11:49+00:00",
            "lastChecked": "2026-04-15T10:00:00+00:00",
            "registry": "",
            "image": "nginx",
            "tag": "1.27",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": existing_tags,
        }))

        # Empty response with current_tags set → rate limited, should not touch state
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", return_value={"tags": [], "error": "rate_limited", "http_status": 429}):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        with open(images_dir / "nginx.yaml") as f:
            state = yaml.safe_load(f)
        # Existing tags should be preserved (not cleared)
        assert state["upstreamTags"] == existing_tags

    # ── ordering: recently checked images should be at the back ──────────────

    def test_recently_checked_image_processed_after_stale_one(self, tmp_path):
        """An image checked recently must sort AFTER one checked long ago.

        Reproduces the bug where fluent-bit was always first despite having
        a recent lastChecked — Phase 4 was stamping each image with
        datetime.now() as it was processed, so the first image always got
        the earliest timestamp and sorted first on the next run.
        """
        images_yaml, state_dir = self._setup_repo(tmp_path, [
            {"name": "fluent-bit", "image": "fluent-bit", "tag": "3.3",
             "namespace": "fluent", "full_name": "fluent/fluent-bit"},
            {"name": "zookeeper", "image": "zookeeper", "tag": "3.9",
             "namespace": "library", "full_name": "library/zookeeper"},
        ])

        # Pre-seed state: fluent-bit was checked recently, zookeeper long ago
        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "fluent-bit.yaml").write_text(yaml.dump({
            "name": "fluent-bit",
            "enrolledAt": "2026-04-14T00:00:00+00:00",
            "lastChecked": "2026-04-20T06:00:00+00:00",  # checked today
            "registry": "",
            "image": "fluent-bit",
            "tag": "3.3",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {"3.3": {"digest": "sha256:aaa"}},
        }))
        (images_dir / "zookeeper.yaml").write_text(yaml.dump({
            "name": "zookeeper",
            "enrolledAt": "2026-04-14T00:00:00+00:00",
            "lastChecked": "2026-04-15T06:00:00+00:00",  # checked 5 days ago
            "registry": "",
            "image": "zookeeper",
            "tag": "3.9",
            "dockerfile": "",
            "baseImages": [],
            "currentDigest": None,
            "upstreamTags": {"3.9": {"digest": "sha256:bbb"}},
        }))

        call_order = []

        def mock_get_tags(namespace, image):
            call_order.append(image)
            return {"tags": [{"name": "1.0", "digest": "sha256:xxx", "last_updated": None}], "error": None, "http_status": None}

        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
            cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        # zookeeper (older lastChecked) must be processed BEFORE fluent-bit
        assert len(call_order) == 2
        assert call_order[0] == "zookeeper", f"Expected zookeeper first, got {call_order}"
        assert call_order[1] == "fluent-bit", f"Expected fluent-bit second, got {call_order}"

    def test_post_image_check_hook_fires_and_state_is_persisted(self, tmp_path):
        """End-to-end: cg images check with a hook configured in .cascadeguard.yaml.

        Verifies that the hook executes as part of the check flow and that its
        output is shallow-merged into the image state file on disk.
        """
        # Arrange — repo layout
        images_yaml, state_dir = self._setup_repo(tmp_path, [
            {
                "name": "nginx",
                "image": "nginx",
                "namespace": "library",
                "full_name": "library/nginx",
                "registry": "docker.io",
                "tag": "1.27",
            }
        ])

        # Hook script: emit a JSON patch with weeklyDownloads
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        hook = hooks_dir / "weekly-stats.sh"
        hook.write_text("#!/bin/sh\necho '{\"weeklyDownloads\": 999}'\n")
        hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        # .cascadeguard.yaml wires the hook
        (tmp_path / ".cascadeguard.yaml").write_text(yaml.dump({
            "hooks": {
                "post-image-check": [{"path": "hooks/weekly-stats.sh"}]
            }
        }))

        # Pre-seed state so tag 1.27 is already known (avoids "new-tags" exit code)
        images_dir = Path(state_dir) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "nginx.yaml").write_text(yaml.dump({
            "name": "nginx",
            "lastChecked": "2026-04-01T00:00:00+00:00",
            "upstreamTags": {
                "1.27": {"digest": "sha256:aaa", "firstSeen": "2026-04-01T00:00:00+00:00",
                         "lastSeen": "2026-04-01T00:00:00+00:00", "lastUpdated": None},
            },
        }))

        fake_tags = [
            {"name": "1.27", "digest": "sha256:aaa", "last_updated": "2026-04-01T00:00:00Z"},
        ]

        # Act
        with patch("app._fetch_manifest_info", return_value=None), \
             patch("app._get_dockerhub_tags_rich",
                   return_value={"tags": fake_tags, "error": None, "http_status": None}):
            rc = cmd_check(_args(images_yaml=images_yaml, state_dir=state_dir))

        assert rc == 0, f"cmd_check exited {rc} — unexpected error"

        # Assert — hook output merged into the state file
        state_file = Path(state_dir) / "images" / "nginx.yaml"
        assert state_file.exists(), "State file not created after check"
        with open(state_file) as f:
            persisted = yaml.safe_load(f)
        assert persisted.get("weeklyDownloads") == 999, (
            f"Hook output not persisted. State: {persisted}"
        )


# ---------------------------------------------------------------------------
# cmd_status
# ---------------------------------------------------------------------------


class TestCmdStatus:
    def test_status_with_images(self, tmp_path):
        images_dir = tmp_path / "images"
        images_dir.mkdir(parents=True)
        base_dir = tmp_path / "base-images"
        base_dir.mkdir(parents=True)

        (images_dir / "myapp.yaml").write_text(
            yaml.dump(
                {
                    "name": "myapp",
                    "currentVersion": "1.0.0",
                    "currentDigest": "sha256:abc",
                    "lastBuilt": "2025-01-01T00:00:00Z",
                    "discoveryStatus": "pending",
                    "baseImages": ["node-22"],
                }
            )
        )
        (base_dir / "node-22.yaml").write_text(
            yaml.dump(
                {
                    "name": "node-22",
                    "currentDigest": "sha256:def",
                    "lastUpdated": "2025-01-01T00:00:00Z",
                    "lastChecked": "2025-01-02T00:00:00Z",
                }
            )
        )

        rc = cmd_status(_args(state_dir=str(tmp_path)))
        assert rc == 0

    def test_status_missing_state_dir(self, tmp_path):
        rc = cmd_status(_args(state_dir=str(tmp_path / "nonexistent")))
        assert rc == 1

    def test_status_empty_dir(self, tmp_path):
        rc = cmd_status(_args(state_dir=str(tmp_path)))
        assert rc == 0


# ---------------------------------------------------------------------------
# GitHubActionsProvider
# ---------------------------------------------------------------------------


class TestGitHubActionsProvider:
    def _mock_response(self, body: dict, status: int = 200):
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.status = status
        resp.read.return_value = json.dumps(body).encode()
        return resp

    def test_trigger_build_success(self):
        provider = GitHubActionsProvider(token="tok", repo="org/repo")
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.status = 204
        resp.read.return_value = b""

        with patch("urllib.request.urlopen", return_value=resp):
            result = provider.trigger_build("myapp", tag="v1.0")

        assert result["status"] == "triggered"
        assert result["workflow"] == "build-myapp.yml"
        assert result["tag"] == "v1.0"

    def test_get_build_status_with_run(self):
        provider = GitHubActionsProvider(token="tok", repo="org/repo")
        payload = {
            "workflow_runs": [
                {
                    "status": "completed",
                    "conclusion": "success",
                    "id": 123,
                    "html_url": "https://github.com/org/repo/actions/runs/123",
                }
            ]
        }
        resp = self._mock_response(payload)

        with patch("urllib.request.urlopen", return_value=resp):
            result = provider.get_build_status("myapp")

        assert result["status"] == "completed"
        assert result["conclusion"] == "success"
        assert result["run_id"] == 123

    def test_get_build_status_no_runs(self):
        provider = GitHubActionsProvider(token="tok", repo="org/repo")
        resp = self._mock_response({"workflow_runs": []})

        with patch("urllib.request.urlopen", return_value=resp):
            result = provider.get_build_status("myapp")

        assert result["status"] == "no_runs"

    def test_trigger_build_http_error(self):
        import urllib.error

        provider = GitHubActionsProvider(token="tok", repo="org/repo")
        err = urllib.error.HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=MagicMock()
        )
        err.read = lambda: b"Not Found"

        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError, match="GitHub API error 404"):
                provider.trigger_build("missing")


# ---------------------------------------------------------------------------
# ArgoCDProvider
# ---------------------------------------------------------------------------


class TestArgoCDProvider:
    def _mock_response(self, body: dict, status: int = 200):
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.status = status
        resp.read.return_value = json.dumps(body).encode()
        return resp

    def test_sync_success(self):
        provider = ArgoCDProvider(
            server="https://argocd.example.com", token="tok", app_name="myapp"
        )
        resp = self._mock_response({})

        with patch("urllib.request.urlopen", return_value=resp):
            result = provider.sync("myapp")

        assert result["status"] == "syncing"
        assert result["app"] == "myapp"

    def test_get_build_status(self):
        provider = ArgoCDProvider(
            server="https://argocd.example.com", token="tok", app_name="myapp"
        )
        payload = {
            "status": {
                "health": {"status": "Healthy"},
                "sync": {"status": "Synced"},
            }
        }
        resp = self._mock_response(payload)

        with patch("urllib.request.urlopen", return_value=resp):
            result = provider.get_build_status("myapp")

        assert result["health"] == "Healthy"
        assert result["sync"] == "Synced"

    def test_sync_http_error(self):
        import urllib.error

        provider = ArgoCDProvider(
            server="https://argocd.example.com", token="tok", app_name="myapp"
        )
        err = urllib.error.HTTPError(
            url="", code=401, msg="Unauthorized", hdrs=None, fp=MagicMock()
        )
        err.read = lambda: b"Unauthorized"

        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError, match="ArgoCD API error 401"):
                provider.sync("myapp")

    def test_server_trailing_slash_stripped(self):
        provider = ArgoCDProvider(
            server="https://argocd.example.com/",
            token="tok",
            app_name="myapp",
        )
        assert provider.server == "https://argocd.example.com"


# ---------------------------------------------------------------------------
# cmd_build / cmd_deploy / cmd_test — missing credentials
# ---------------------------------------------------------------------------


class TestCmdBuildDeployTest:
    def test_build_no_token(self, tmp_path):
        from app import cmd_build

        with patch.dict(os.environ, {}, clear=True):
            rc = cmd_build(
                _args(image="myapp", github_token=None, repo="org/repo")
            )
        assert rc == 1

    def test_build_no_repo(self, tmp_path):
        from app import cmd_build

        rc = cmd_build(_args(image="myapp", github_token="tok", repo=None))
        assert rc == 1

    def test_deploy_no_token(self):
        from app import cmd_deploy

        with patch.dict(os.environ, {}, clear=True):
            rc = cmd_deploy(
                _args(
                    image="myapp",
                    argocd_token=None,
                    argocd_server="https://argocd.example.com",
                    app="myapp",
                )
            )
        assert rc == 1

    def test_deploy_no_server(self):
        from app import cmd_deploy

        rc = cmd_deploy(
            _args(image="myapp", argocd_token="tok", argocd_server=None, app="myapp")
        )
        assert rc == 1

    def test_deploy_no_app(self):
        from app import cmd_deploy

        rc = cmd_deploy(
            _args(
                image="myapp",
                argocd_token="tok",
                argocd_server="https://argocd.example.com",
                app=None,
            )
        )
        assert rc == 1

    def test_test_no_token(self):
        with patch.dict(os.environ, {}, clear=True):
            rc = cmd_test(_args(image="myapp", github_token=None, repo="org/repo"))
        assert rc == 1

    def test_test_no_repo(self):
        rc = cmd_test(_args(image="myapp", github_token="tok", repo=None))
        assert rc == 1


# ---------------------------------------------------------------------------
# Parser smoke test
# ---------------------------------------------------------------------------


class TestParser:
    def test_images_validate_command(self):
        parser = build_parser()
        args = parser.parse_args(["images", "validate"])
        assert args.command == "images"
        assert args.images_command == "validate"

    def test_images_enrol_command(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "images",
                "enrol",
                "--name",
                "myapp",
                "--registry",
                "ghcr.io",
                "--repository",
                "org/myapp",
            ]
        )
        assert args.command == "images"
        assert args.images_command == "enrol"
        assert args.name == "myapp"

    def test_pipeline_build_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["pipeline", "build", "--image", "myapp"])
        assert args.command == "pipeline"
        assert args.pipeline_command == "build"
        assert args.image == "myapp"
        assert args.tag == "latest"

    def test_images_status_command(self):
        parser = build_parser()
        args = parser.parse_args(["images", "status"])
        assert args.command == "images"
        assert args.images_command == "status"

    def test_images_yaml_override(self):
        parser = build_parser()
        args = parser.parse_args(["images", "--images-yaml", "/tmp/custom.yaml", "validate"])
        assert args.images_yaml == "/tmp/custom.yaml"

    def test_images_enrol_images_yaml_after_subcommand(self):
        """CAS-267: --images-yaml must be usable after `enrol` subcommand."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "images",
                "enrol",
                "--images-yaml", "/tmp/custom.yaml",
                "--name", "myapp",
                "--registry", "ghcr.io",
                "--repository", "org/myapp",
            ]
        )
        assert args.images_yaml == "/tmp/custom.yaml"

    def test_images_enrol_auto_rebuild_flag(self):
        """CAS-268: --auto-rebuild flag must be accepted by `images enrol`."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "images",
                "enrol",
                "--name", "myapp",
                "--registry", "ghcr.io",
                "--repository", "org/myapp",
                "--auto-rebuild",
            ]
        )
        assert args.auto_rebuild is True

    def test_images_enrol_auto_rebuild_default_false(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "images",
                "enrol",
                "--name", "myapp",
                "--registry", "ghcr.io",
                "--repository", "org/myapp",
            ]
        )
        assert args.auto_rebuild is False

    def test_state_dir_override(self):
        parser = build_parser()
        args = parser.parse_args(["images", "--state-dir", "/tmp/state", "check"])
        assert args.state_dir == "/tmp/state"

    def test_vuln_report_command(self):
        parser = build_parser()
        args = parser.parse_args(
            ["vuln", "report", "--image", "myapp", "--dir", "/tmp/reports"]
        )
        assert args.command == "vuln"
        assert args.vuln_command == "report"

    def test_vuln_issues_command(self):
        parser = build_parser()
        args = parser.parse_args(
            ["vuln", "issues", "--image", "myapp", "--repo", "org/repo"]
        )
        assert args.command == "vuln"
        assert args.vuln_command == "issues"

    def test_pipeline_run_command(self):
        parser = build_parser()
        args = parser.parse_args(["pipeline", "run"])
        assert args.command == "pipeline"
        assert args.pipeline_command == "run"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
