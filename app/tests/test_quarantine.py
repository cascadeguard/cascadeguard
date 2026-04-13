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

    def test_create_pr_default_none(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check"])
        assert args.create_pr is None

    def test_no_create_pr_flag(self):
        from app import build_parser
        parser = build_parser()
        args = parser.parse_args(["images", "check", "--no-create-pr"])
        assert args.create_pr is False
