"""Tests for quarantine resolution, Dockerfile digest pinning, and promotion flow."""

import pytest
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app import (
    _parse_duration,
    _resolve_quarantine_hours,
    _update_dockerfile_digest,
    _DEFAULT_QUARANTINE_HOURS,
)


# ── _parse_duration ────────────────────────────────────────────────────────


class TestParseDuration:
    def test_none_returns_none(self):
        assert _parse_duration(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_duration("") is None
        assert _parse_duration("  ") is None

    def test_hours(self):
        assert _parse_duration("48h") == 48
        assert _parse_duration("0h") == 0
        assert _parse_duration("1h") == 1

    def test_days(self):
        assert _parse_duration("7d") == 168
        assert _parse_duration("1d") == 24
        assert _parse_duration("0d") == 0

    def test_bare_integer_treated_as_hours(self):
        assert _parse_duration("24") == 24
        assert _parse_duration("0") == 0

    def test_disabled_values(self):
        assert _parse_duration("none") == 0
        assert _parse_duration("false") == 0
        assert _parse_duration("disabled") == 0

    def test_case_insensitive(self):
        assert _parse_duration("48H") == 48
        assert _parse_duration("7D") == 168
        assert _parse_duration("None") == 0
        assert _parse_duration("DISABLED") == 0

    def test_invalid_returns_none(self):
        assert _parse_duration("abc") is None
        assert _parse_duration("48x") is None


# ── _resolve_quarantine_hours ──────────────────────────────────────────────


class TestResolveQuarantineHours:
    def test_default_when_no_config(self):
        assert _resolve_quarantine_hours({}, {}) == _DEFAULT_QUARANTINE_HOURS

    def test_repo_level_override(self):
        config = {"quarantine": {"period": "24h"}}
        assert _resolve_quarantine_hours({}, config) == 24

    def test_repo_level_shorthand(self):
        """quarantine: 72h  (not nested under .period)"""
        config = {"quarantine": "72h"}
        assert _resolve_quarantine_hours({}, config) == 72

    def test_per_image_override(self):
        image = {"quarantine": "12h"}
        config = {"quarantine": {"period": "24h"}}
        assert _resolve_quarantine_hours(image, config) == 12

    def test_per_image_zero_disables(self):
        image = {"quarantine": "0"}
        assert _resolve_quarantine_hours(image, {}) == 0

    def test_per_image_disabled(self):
        image = {"quarantine": "disabled"}
        assert _resolve_quarantine_hours(image, {}) == 0

    def test_hierarchy_fallthrough(self):
        """Per-image None → repo-level None → built-in default."""
        image = {"quarantine": None}
        config = {"quarantine": {"period": None}}
        assert _resolve_quarantine_hours(image, config) == _DEFAULT_QUARANTINE_HOURS


# ── _update_dockerfile_digest ──────────────────────────────────────────────


class TestUpdateDockerfileDigest:
    def test_pins_tag_only_from(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM nginx:stable-alpine-slim AS build\nRUN echo hello\n")

        modified = _update_dockerfile_digest(
            df, "nginx:stable-alpine-slim", "sha256:abc123"
        )
        assert modified is True
        content = df.read_text()
        assert "FROM nginx:stable-alpine-slim@sha256:abc123 AS build" in content

    def test_updates_existing_digest(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM nginx:stable-alpine-slim@sha256:old123 AS build\n")

        modified = _update_dockerfile_digest(
            df, "nginx:stable-alpine-slim@sha256:old123", "sha256:new456"
        )
        assert modified is True
        content = df.read_text()
        assert "FROM nginx:stable-alpine-slim@sha256:new456 AS build" in content
        assert "old123" not in content

    def test_no_change_when_already_pinned(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM nginx:stable-alpine-slim@sha256:abc123 AS build\n")

        modified = _update_dockerfile_digest(
            df, "nginx:stable-alpine-slim", "sha256:abc123"
        )
        assert modified is False

    def test_no_match_returns_false(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.12-slim AS build\n")

        modified = _update_dockerfile_digest(
            df, "nginx:stable-alpine-slim", "sha256:abc123"
        )
        assert modified is False
        # File unchanged
        assert "python:3.12-slim" in df.read_text()

    def test_missing_file_returns_false(self, tmp_path):
        df = tmp_path / "nonexistent" / "Dockerfile"
        assert _update_dockerfile_digest(df, "nginx:tag", "sha256:abc") is False

    def test_multistage_only_matches_correct_from(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text(textwrap.dedent("""\
            FROM golang:1.22 AS builder
            RUN go build -o app .

            FROM alpine:3.20 AS runtime
            COPY --from=builder /app /app
        """))

        modified = _update_dockerfile_digest(
            df, "alpine:3.20", "sha256:alpine_digest"
        )
        assert modified is True
        content = df.read_text()
        assert "FROM golang:1.22 AS builder" in content  # unchanged
        assert "FROM alpine:3.20@sha256:alpine_digest AS runtime" in content

    def test_preserves_comments_and_whitespace(self, tmp_path):
        df = tmp_path / "Dockerfile"
        original = textwrap.dedent("""\
            # CascadeGuard Hardened Image
            # https://github.com/cascadeguard

            FROM nginx:stable-alpine-slim AS build

            RUN echo hello
        """)
        df.write_text(original)

        _update_dockerfile_digest(df, "nginx:stable-alpine-slim", "sha256:abc")
        content = df.read_text()
        assert content.startswith("# CascadeGuard Hardened Image")
        assert "RUN echo hello" in content


# ── _resolve_bool_setting ──────────────────────────────────────────────────

from app import _resolve_bool_setting


class TestResolveBoolSetting:
    def test_default_true(self):
        assert _resolve_bool_setting("promote", {}, {}) is True

    def test_default_false(self):
        assert _resolve_bool_setting("promote", {}, {}, default=False) is False

    def test_per_image_override_true(self):
        assert _resolve_bool_setting("promote", {"promote": True}, {}, default=False) is True

    def test_per_image_override_false(self):
        assert _resolve_bool_setting("promote", {"promote": False}, {}) is False

    def test_repo_level_under_check_section(self):
        config = {"check": {"promote": False}}
        assert _resolve_bool_setting("promote", {}, config) is False

    def test_repo_level_top_level(self):
        config = {"createPr": False}
        assert _resolve_bool_setting("createPr", {}, config) is False
        config2 = {"check": {"createPr": False}}
        assert _resolve_bool_setting("createPr", {}, config2) is False

    def test_per_image_beats_repo_level(self):
        image = {"promote": True}
        config = {"check": {"promote": False}}
        assert _resolve_bool_setting("promote", image, config) is True

    def test_per_image_false_beats_repo_level_true(self):
        image = {"promote": False}
        config = {"check": {"promote": True}}
        assert _resolve_bool_setting("promote", image, config) is False


class TestCliPromoteDefaults:
    """Verify --promote and --create-pr default to None (resolved from config)."""

    def test_promote_default_none(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check"])
        assert args.promote is None

    def test_no_promote_flag(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check", "--no-promote"])
        assert args.promote is False

    def test_promote_flag(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check", "--promote"])
        assert args.promote is True

    def test_no_commit_default_false(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check"])
        assert args.no_commit is False

    def test_no_commit_flag(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check", "--no-commit"])
        assert args.no_commit is True


# ── _resolve_check_config ──────────────────────────────────────────────────

from app import _resolve_check_config


class TestResolveCheckConfig:
    def test_defaults(self):
        result = _resolve_check_config({})
        assert result["state"]["destination"] == "main"
        assert result["promote"]["enabled"] is True
        assert result["promote"]["destination"] == "pr"

    def test_state_destination_pr(self):
        config = {"check": {"state": {"destination": "pr"}}}
        result = _resolve_check_config(config)
        assert result["state"]["destination"] == "pr"

    def test_promote_disabled(self):
        config = {"check": {"promote": {"enabled": False}}}
        result = _resolve_check_config(config)
        assert result["promote"]["enabled"] is False
        assert result["promote"]["destination"] == "pr"

    def test_promote_destination_main(self):
        config = {"check": {"promote": {"destination": "main"}}}
        result = _resolve_check_config(config)
        assert result["promote"]["enabled"] is True
        assert result["promote"]["destination"] == "main"

    def test_backwards_compat_promote_bool(self):
        config = {"check": {"promote": False}}
        result = _resolve_check_config(config)
        assert result["promote"]["enabled"] is False

    def test_full_config(self):
        config = {"check": {
            "state": {"destination": "pr"},
            "promote": {"enabled": True, "destination": "main"},
        }}
        result = _resolve_check_config(config)
        assert result["state"]["destination"] == "pr"
        assert result["promote"]["enabled"] is True
        assert result["promote"]["destination"] == "main"


# ── _fetch_manifest_info (manifest list handling) ──────────────────────────

from unittest.mock import patch, MagicMock
from app import _fetch_manifest_info, _fetch_blob_json
import json
import urllib.error


def _mock_urlopen_sequence(responses):
    """Build a side_effect for urllib.request.urlopen.

    Each entry is (body_dict, headers_dict, status).
    Only covers token, HEAD manifest, and GET manifest calls.
    Blob fetches go through _fetch_blob_json (mocked separately).
    """
    calls = iter(responses)

    def _urlopen(req_or_url, timeout=10):
        body, headers, status = next(calls)
        resp = MagicMock()
        resp.read.return_value = json.dumps(body).encode() if body else b""
        resp.headers = headers or {}
        resp.status = status
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return _urlopen


class TestFetchManifestInfoManifestList:
    """_fetch_manifest_info follows manifest lists to get publishedAt."""

    def test_single_manifest_returns_created(self):
        responses = [
            # Token
            ({"token": "tok"}, {}, 200),
            # HEAD manifest
            (None, {"Docker-Content-Digest": "sha256:abc"}, 200),
            # GET manifest → single manifest with config
            ({"config": {"digest": "sha256:cfg"}}, {}, 200),
        ]
        with patch("urllib.request.urlopen", side_effect=_mock_urlopen_sequence(responses)):
            with patch("app._fetch_blob_json", return_value={"created": "2026-03-20T10:00:00Z"}):
                result = _fetch_manifest_info("docker.io", "library/test", "latest")

        assert result["digest"] == "sha256:abc"
        assert result["publishedAt"] == "2026-03-20T10:00:00Z"

    def test_manifest_list_follows_amd64(self):
        responses = [
            ({"token": "tok"}, {}, 200),
            (None, {"Docker-Content-Digest": "sha256:idx"}, 200),
            # GET manifest → manifest list
            ({"manifests": [
                {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
            ]}, {}, 200),
            # GET amd64 manifest
            ({"config": {"digest": "sha256:cfg"}}, {}, 200),
        ]
        with patch("urllib.request.urlopen", side_effect=_mock_urlopen_sequence(responses)):
            with patch("app._fetch_blob_json", return_value={"created": "2026-03-24T23:11:15Z"}):
                result = _fetch_manifest_info("docker.io", "library/nginx", "stable")

        assert result["digest"] == "sha256:idx"
        assert result["publishedAt"] == "2026-03-24T23:11:15Z"

    def test_manifest_list_no_amd64_uses_first(self):
        responses = [
            ({"token": "tok"}, {}, 200),
            (None, {"Docker-Content-Digest": "sha256:idx"}, 200),
            ({"manifests": [
                {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
            ]}, {}, 200),
            ({"config": {"digest": "sha256:cfg"}}, {}, 200),
        ]
        with patch("urllib.request.urlopen", side_effect=_mock_urlopen_sequence(responses)):
            with patch("app._fetch_blob_json", return_value={"created": "2026-03-25T00:00:00Z"}):
                result = _fetch_manifest_info("docker.io", "library/test", "latest")

        assert result["publishedAt"] == "2026-03-25T00:00:00Z"

    def test_network_error_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = _fetch_manifest_info("docker.io", "library/test", "latest")
        assert result is None

    def test_no_digest_returns_none(self):
        responses = [
            ({"token": "tok"}, {}, 200),
            (None, {}, 200),
        ]
        with patch("urllib.request.urlopen", side_effect=_mock_urlopen_sequence(responses)):
            result = _fetch_manifest_info("docker.io", "library/test", "latest")
        assert result is None

    def test_blob_failure_returns_digest_without_publishedat(self):
        responses = [
            ({"token": "tok"}, {}, 200),
            (None, {"Docker-Content-Digest": "sha256:abc"}, 200),
            ({"config": {"digest": "sha256:cfg"}}, {}, 200),
        ]
        with patch("urllib.request.urlopen", side_effect=_mock_urlopen_sequence(responses)):
            with patch("app._fetch_blob_json", return_value=None):
                result = _fetch_manifest_info("docker.io", "library/test", "latest")

        assert result["digest"] == "sha256:abc"
        assert result["publishedAt"] is None


class TestFetchBlobJson:
    """_fetch_blob_json handles CDN redirects."""

    def test_direct_response(self):
        resp = MagicMock()
        resp.read.return_value = json.dumps({"created": "2026-01-01"}).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)

        opener = MagicMock()
        opener.open.return_value = resp

        with patch("urllib.request.build_opener", return_value=opener):
            result = _fetch_blob_json("https://reg/v2/lib/test/blobs/sha256:abc", "tok")

        assert result == {"created": "2026-01-01"}

    def test_redirect_followed_without_auth(self):
        err = urllib.error.HTTPError(
            url="", code=302, msg="Found", hdrs=MagicMock(), fp=MagicMock()
        )
        err.headers = {"Location": "https://cdn.example.com/blob"}

        opener = MagicMock()
        opener.open.side_effect = err

        cdn_resp = MagicMock()
        cdn_resp.read.return_value = json.dumps({"created": "2026-03-24"}).encode()
        cdn_resp.__enter__ = lambda s: s
        cdn_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.build_opener", return_value=opener):
            with patch("urllib.request.urlopen", return_value=cdn_resp):
                result = _fetch_blob_json("https://reg/v2/lib/test/blobs/sha256:abc", "tok")

        assert result == {"created": "2026-03-24"}

    def test_error_returns_none(self):
        opener = MagicMock()
        opener.open.side_effect = Exception("fail")

        with patch("urllib.request.build_opener", return_value=opener):
            result = _fetch_blob_json("https://reg/v2/lib/test/blobs/sha256:abc", "tok")

        assert result is None


# ── Docker Hub auth + namespace resolution ─────────────────────────────────

from app import _get_dockerhub_token, _get_dockerhub_tags
import base64
import os
import yaml
from types import SimpleNamespace


class TestGetDockerHubToken:
    def setup_method(self):
        import app
        app._dockerhub_auth_cache = None
        app._dockerhub_auth_checked = False

    def test_returns_none_without_env_vars(self):
        with patch.dict("os.environ", {}, clear=True):
            assert _get_dockerhub_token() is None

    def test_returns_none_with_partial_env(self):
        with patch.dict("os.environ", {"DOCKERHUB_USERNAME": "user"}, clear=True):
            assert _get_dockerhub_token() is None

    def test_returns_basic_auth_with_credentials(self):
        def mock_urlopen(req, timeout=10):
            resp = MagicMock()
            resp.read.return_value = json.dumps({"results": []}).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch.dict("os.environ", {
            "DOCKERHUB_USERNAME": "myuser",
            "DOCKERHUB_TOKEN": "mytoken",
        }, clear=True):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                result = _get_dockerhub_token()
                assert result is not None
                assert result.startswith("Basic ")
                decoded = base64.b64decode(result.split(" ")[1]).decode()
                assert decoded == "myuser:mytoken"


class TestGetDockerHubTagsAuth:
    def setup_method(self):
        import app
        app._dockerhub_auth_cache = None
        app._dockerhub_auth_checked = False
    def test_unauthenticated_request(self):
        """Without credentials, no Authorization header is sent."""
        calls = []

        def mock_urlopen(req, timeout=10):
            calls.append(req)
            resp = MagicMock()
            resp.read.return_value = json.dumps({"results": [], "next": ""}).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                _get_dockerhub_tags("library", "nginx")

        assert len(calls) == 1
        assert calls[0].get_header("Authorization") is None

    def test_authenticated_request(self):
        """With credentials, Authorization header is sent."""
        calls = []

        def mock_urlopen(req, timeout=10):
            calls.append(req)
            resp = MagicMock()
            resp.read.return_value = json.dumps({"results": [], "next": ""}).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch.dict("os.environ", {
            "DOCKERHUB_USERNAME": "user",
            "DOCKERHUB_TOKEN": "tok",
        }):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                _get_dockerhub_tags("library", "nginx")

        # First call is auth verification, second is the actual tag fetch
        tag_calls = [c for c in calls if "tags" in c.full_url and "library/nginx" in c.full_url]
        assert len(tag_calls) == 1
        assert tag_calls[0].get_header("Authorization") is not None
        assert tag_calls[0].get_header("Authorization").startswith("Basic ")


class TestNamespaceResolution:
    """Phase 4 uses full_name when available."""

    def test_full_name_used_over_namespace_image(self, tmp_path):
        """full_name: bitnami/postgresql should query bitnami/postgresql,
        not bitnami/bitnami-postgresql."""
        from app import cmd_check

        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump([{
            "name": "bitnami-postgresql",
            "image": "bitnami-postgresql",
            "tag": "16",
            "namespace": "bitnami",
            "full_name": "bitnami/postgresql",
        }]))
        state_dir = tmp_path / ".cascadeguard"
        state_dir.mkdir()

        tag_calls = []
        original_get_tags = _get_dockerhub_tags.__wrapped__ if hasattr(_get_dockerhub_tags, '__wrapped__') else None

        def mock_get_tags(namespace, image):
            tag_calls.append((namespace, image))
            return {"tags": [], "error": None, "http_status": None}

        args = SimpleNamespace(
            images_yaml=str(images_yaml),
            state_dir=str(state_dir),
            image=None, format="table",
            promote=False, no_commit=True,
        )

        with patch("app._fetch_manifest_info", return_value=None):
            with patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
                cmd_check(args)

        assert len(tag_calls) == 1
        assert tag_calls[0] == ("bitnami", "postgresql")

    def test_falls_back_to_namespace_image(self, tmp_path):
        """Without full_name, uses namespace/image."""
        from app import cmd_check

        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump([{
            "name": "nginx",
            "image": "nginx",
            "tag": "stable",
            "namespace": "library",
        }]))
        state_dir = tmp_path / ".cascadeguard"
        state_dir.mkdir()

        tag_calls = []

        def mock_get_tags(namespace, image):
            tag_calls.append((namespace, image))
            return {"tags": [], "error": None, "http_status": None}

        args = SimpleNamespace(
            images_yaml=str(images_yaml),
            state_dir=str(state_dir),
            image=None, format="table",
            promote=False, no_commit=True,
        )

        with patch("app._fetch_manifest_info", return_value=None):
            with patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
                cmd_check(args)

        assert len(tag_calls) == 1
        assert tag_calls[0] == ("library", "nginx")

    def test_skips_non_dockerhub_registry(self, tmp_path):
        """Images with ghcr.io registry skip tag checking."""
        from app import cmd_check

        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump([{
            "name": "myapp",
            "image": "myapp",
            "tag": "latest",
            "registry": "ghcr.io/cascadeguard",
            "source": {"dockerfile": "images/myapp/Dockerfile"},
        }]))
        state_dir = tmp_path / ".cascadeguard"
        state_dir.mkdir()

        tag_calls = []

        def mock_get_tags(namespace, image):
            tag_calls.append((namespace, image))
            return {"tags": [], "error": None, "http_status": None}

        args = SimpleNamespace(
            images_yaml=str(images_yaml),
            state_dir=str(state_dir),
            image=None, format="table",
            promote=False, no_commit=True,
        )

        with patch("app._fetch_manifest_info", return_value=None):
            with patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
                cmd_check(args)

        assert len(tag_calls) == 0


class TestRateLimitedIncrementalProgress:
    """Phase 4 processes oldest-first and stops on rate limit."""

    def setup_method(self):
        import app
        app._dockerhub_auth_cache = None
        app._dockerhub_auth_checked = False

    def test_processes_oldest_first_stops_on_rate_limit(self, tmp_path):
        """Three images, tag fetch fails on the third. Only first two get checked."""
        from app import cmd_check

        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump([
            {"name": "img-old", "image": "old", "tag": "1", "namespace": "library",
             "latest_stable_tags": ["1.0"]},
            {"name": "img-mid", "image": "mid", "tag": "1", "namespace": "library",
             "latest_stable_tags": ["1.0"]},
            {"name": "img-new", "image": "new", "tag": "1", "namespace": "library",
             "latest_stable_tags": ["1.0"]},
        ]))
        state_dir = tmp_path / ".cascadeguard"
        images_dir = state_dir / "images"
        images_dir.mkdir(parents=True)

        # Seed image state with different lastChecked times
        for name, checked in [("img-old", "2026-01-01"), ("img-mid", "2026-02-01"), ("img-new", "2026-03-01")]:
            (images_dir / f"{name}.yaml").write_text(yaml.dump({
                "name": name, "lastChecked": checked,
                "baseImages": [], "dockerfile": "",
            }))

        call_order = []

        def mock_get_tags(namespace, image):
            call_order.append(image)
            if len(call_order) >= 3:
                return {"tags": [], "error": "rate_limited", "http_status": 429}  # simulate rate limit
            return {"tags": [{"name": "1.0", "digest": "sha256:aaa", "last_updated": None},
                    {"name": "1.1", "digest": "sha256:bbb", "last_updated": None}], "error": None, "http_status": None}

        args = SimpleNamespace(
            images_yaml=str(images_yaml), state_dir=str(state_dir),
            image=None, format="table", promote=False, no_commit=True,
        )

        with patch("app._fetch_manifest_info", return_value=None):
            with patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
                cmd_check(args)

        # Should process oldest first
        assert call_order[0] == "old"
        assert call_order[1] == "mid"
        # Third call returns empty → rate_limited flag set → stops
        assert len(call_order) == 3  # called but got empty result

    def test_images_without_latest_stable_tags_not_rate_limited(self, tmp_path):
        """Images with no latest_stable_tags don't trigger rate limit detection."""
        from app import cmd_check

        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump([
            {"name": "img-a", "image": "a", "tag": "1", "namespace": "library"},
            {"name": "img-b", "image": "b", "tag": "1", "namespace": "library"},
        ]))
        state_dir = tmp_path / ".cascadeguard"
        state_dir.mkdir(parents=True)

        call_order = []

        def mock_get_tags(namespace, image):
            call_order.append(image)
            return {"tags": [], "error": None, "http_status": None}  # empty but no current_tags → not rate limited

        args = SimpleNamespace(
            images_yaml=str(images_yaml), state_dir=str(state_dir),
            image=None, format="table", promote=False, no_commit=True,
        )

        with patch("app._fetch_manifest_info", return_value=None):
            with patch("app._get_dockerhub_tags_rich", side_effect=mock_get_tags):
                cmd_check(args)

        # Both should be called — empty result with no current_tags isn't rate limiting
        assert len(call_order) == 2
