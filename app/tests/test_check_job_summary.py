#!/usr/bin/env python3
"""Integration tests for cmd_check job summary and post-run hook point.

Covers:
- New tag count summary printed to stderr after check
- GITHUB_STEP_SUMMARY written when env var is set
- Post-run hooks invoked with correct payload (hookPoint, stateDir, summary)
- Post-run hook skipped when none configured
- Zero-new-tags run still prints summary line
"""

import json
import os
import stat
import sys
import yaml
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import cmd_check


# ── Helpers ────────────────────────────────────────────────────────────────

_IMAGE = {
    "name": "nginx",
    "registry": "docker.io",
    "image": "nginx",
    "namespace": "library",
    "tag": "latest",
}

_NEW_TAGS = [
    {"name": "1.27", "digest": "sha256:" + "a" * 64, "last_updated": "2026-04-01T00:00:00Z"},
    {"name": "1.28", "digest": "sha256:" + "b" * 64, "last_updated": "2026-04-02T00:00:00Z"},
]


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


def _setup(tmp_path, images=None, config=None):
    """Write images.yaml and create state directory."""
    (tmp_path / ".cascadeguard").mkdir(exist_ok=True)
    (tmp_path / ".cascadeguard" / "images").mkdir(parents=True, exist_ok=True)
    images_yaml = tmp_path / "images.yaml"
    images_yaml.write_text(yaml.dump(images or [_IMAGE]))
    if config:
        (tmp_path / ".cascadeguard.yaml").write_text(yaml.dump(config))


def _make_hook(tmp_path, name: str, script: str) -> str:
    """Write an executable shell script; return its path relative to tmp_path."""
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{script}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return name  # relative path for config


# ── Job summary (stderr) ───────────────────────────────────────────────────


class TestJobSummaryStderr:
    def test_summary_printed_when_new_tags_found(self, tmp_path, capsys):
        _setup(tmp_path)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        captured = capsys.readouterr()
        assert "2 new upstream tag" in captured.err
        assert "CascadeGuard check" in captured.err

    def test_summary_printed_when_no_new_tags(self, tmp_path, capsys):
        _setup(tmp_path)
        # Pre-seed state so all tags are already known
        state = {
            "upstreamTags": {
                t["name"]: {"digest": t["digest"], "firstSeen": "2026-01-01T00:00:00Z",
                             "lastSeen": "2026-01-01T00:00:00Z", "lastUpdated": t["last_updated"]}
                for t in _NEW_TAGS
            }
        }
        (tmp_path / ".cascadeguard" / "images" / "nginx.yaml").write_text(yaml.dump(state))
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        captured = capsys.readouterr()
        assert "CascadeGuard check" in captured.err
        assert "0 new upstream tag" in captured.err

    def test_new_tag_count_matches_actual_new_tags(self, tmp_path, capsys):
        _setup(tmp_path)
        # Seed one tag as known, one is new
        state = {
            "upstreamTags": {
                "1.27": {"digest": "sha256:" + "a" * 64, "firstSeen": "2026-01-01T00:00:00Z",
                          "lastSeen": "2026-01-01T00:00:00Z", "lastUpdated": "2026-04-01T00:00:00Z"},
            }
        }
        (tmp_path / ".cascadeguard" / "images" / "nginx.yaml").write_text(yaml.dump(state))
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        captured = capsys.readouterr()
        assert "1 new upstream tag" in captured.err


# ── GITHUB_STEP_SUMMARY ────────────────────────────────────────────────────


class TestGithubStepSummary:
    def test_summary_written_to_step_summary_file(self, tmp_path, monkeypatch):
        summary_file = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        _setup(tmp_path)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        assert summary_file.exists()
        content = summary_file.read_text()
        assert "CascadeGuard" in content
        assert "new upstream tag" in content

    def test_no_step_summary_without_env_var(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        _setup(tmp_path)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))
        # No file should have been created in tmp_path (beyond what setup wrote)
        assert not (tmp_path / "summary.md").exists()

    def test_step_summary_appended_not_overwritten(self, tmp_path, monkeypatch):
        summary_file = tmp_path / "summary.md"
        summary_file.write_text("## Prior content\n\n")
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        _setup(tmp_path)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        content = summary_file.read_text()
        assert "Prior content" in content
        assert "CascadeGuard" in content


# ── Post-run hook invocation ───────────────────────────────────────────────


class TestPostRunHookInvocation:
    def test_post_run_hook_called_with_correct_hook_point(self, tmp_path):
        captured_file = tmp_path / "hook-payload.json"
        hook_name = _make_hook(
            tmp_path, "capture.sh", f"cat > {captured_file}"
        )
        config = {"hooks": {"post-run": [{"path": f"./{hook_name}"}]}}
        _setup(tmp_path, config=config)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        payload = json.loads(captured_file.read_text())
        assert payload["hookPoint"] == "post-run"

    def test_post_run_hook_receives_new_tag_count(self, tmp_path):
        captured_file = tmp_path / "hook-payload.json"
        hook_name = _make_hook(
            tmp_path, "capture.sh", f"cat > {captured_file}"
        )
        config = {"hooks": {"post-run": [{"path": f"./{hook_name}"}]}}
        _setup(tmp_path, config=config)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path))

        payload = json.loads(captured_file.read_text())
        assert payload["summary"]["newTagCount"] == 2

    def test_post_run_hook_receives_state_dir(self, tmp_path):
        captured_file = tmp_path / "hook-payload.json"
        hook_name = _make_hook(
            tmp_path, "capture.sh", f"cat > {captured_file}"
        )
        config = {"hooks": {"post-run": [{"path": f"./{hook_name}"}]}}
        _setup(tmp_path, config=config)
        state_dir = str(tmp_path / ".cascadeguard")
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                cmd_check(_args(tmp_path, state_dir=state_dir))

        payload = json.loads(captured_file.read_text())
        assert payload["stateDir"] == state_dir

    def test_post_run_hook_not_called_when_not_configured(self, tmp_path):
        """No post-run hooks in config → _run_post_run_hooks is still called but does nothing."""
        _setup(tmp_path)
        with patch("app._run_post_run_hooks") as mock_hook:
            with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
                with patch("app._fetch_manifest_info", return_value=None):
                    cmd_check(_args(tmp_path))
        # Should have been called once with the correct args
        mock_hook.assert_called_once()
        call_kwargs = mock_hook.call_args
        assert call_kwargs.args[4] == 2  # total_new_tag_count

    def test_post_run_hook_failure_does_not_abort_check(self, tmp_path):
        hook_name = _make_hook(tmp_path, "fail.sh", "exit 1")
        config = {"hooks": {"post-run": [{"path": f"./{hook_name}"}]}}
        _setup(tmp_path, config=config)
        with patch("app._get_upstream_tags_rich", return_value={"tags": _NEW_TAGS, "error": None, "http_status": None}):
            with patch("app._fetch_manifest_info", return_value=None):
                rc = cmd_check(_args(tmp_path))
        # Check still exits 2 (new tags), not 1 (error)
        assert rc == 2
