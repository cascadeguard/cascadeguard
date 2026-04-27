#!/usr/bin/env python3
"""Unit tests for the _run_hooks hook infrastructure."""

import json
import os
import stat
import subprocess
import sys
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import _run_hooks


def _make_hook(tmpdir: Path, name: str, script: str) -> Path:
    """Write an executable shell script and return its path."""
    path = tmpdir / name
    path.write_text(f"#!/bin/sh\n{script}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TestRunHooks:

    def test_no_hooks_returns_state_unchanged(self, tmp_path):
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", {}, tmp_path, {}, state, {})
        assert result == state

    def test_hook_output_merged_into_state(self, tmp_path):
        _make_hook(tmp_path, "hook.sh", "echo '{\"weeklyDownloads\": 42}'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "hook.sh"}]
            }
        }
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result["weeklyDownloads"] == 42
        assert result["lastChecked"] == "2026-01-01"  # original field preserved

    def test_hook_receives_image_state_and_registry_response(self, tmp_path):
        # Write a Node.js hook that echoes back fields from each input sections
        hook = tmp_path / "echo-hook.js"
        hook.write_text(
            "#!/usr/bin/env node\n"
            "let buf = '';\n"
            "process.stdin.on('data', c => buf += c);\n"
            "process.stdin.on('end', () => {\n"
            "  const d = JSON.parse(buf);\n"
            "  process.stdout.write(JSON.stringify({\n"
            "    receivedName: d.image.name,\n"
            "    receivedLastChecked: d.state.lastChecked,\n"
            "    receivedTagCount: d.registryResponse.tags.length,\n"
            "  }));\n"
            "});\n"
        )
        hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        config = {
            "hooks": {
                "post-image-check": [{"path": "echo-hook.js"}]
            }
        }
        image = {"name": "nginx", "registry": "docker.io"}
        state = {"lastChecked": "2026-04-01"}
        registry_response = {"tags": [{"name": "1.27"}]}
        result = _run_hooks("post-image-check", config, tmp_path, image, state, registry_response)
        assert result["receivedName"] == "nginx"
        assert result["receivedLastChecked"] == "2026-04-01"
        assert result["receivedTagCount"] == 1

    def test_hook_failure_is_warning_not_error(self, tmp_path):
        _make_hook(tmp_path, "fail.sh", "exit 1")
        config = {
            "hooks": {
                "post-image-check": [{"path": "fail.sh"}]
            }
        }
        state = {"lastChecked": "2026-01-01"}
        # Should not raise; state unchanged
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

    def test_invalid_json_output_skipped(self, tmp_path):
        _make_hook(tmp_path, "bad.sh", "echo 'not json'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "bad.sh"}]
            }
        }
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

    def test_non_object_json_output_skipped(self, tmp_path):
        _make_hook(tmp_path, "array.sh", "echo '[1, 2, 3]'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "array.sh"}]
            }
        }
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

    def test_registries_filter_skips_non_matching(self, tmp_path):
        _make_hook(tmp_path, "dockerhub.sh", "echo '{\"pulled\": true}'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "dockerhub.sh", "registries": ["docker.io"]}]
            }
        }
        image = {"name": "nginx", "registry": "ghcr.io"}  # not docker.io
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", config, tmp_path, image, state, {})
        assert "pulled" not in result

    def test_registries_filter_fires_for_matching(self, tmp_path):
        _make_hook(tmp_path, "dockerhub.sh", "echo '{\"pulled\": true}'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "dockerhub.sh", "registries": ["docker.io"]}]
            }
        }
        image = {"name": "nginx", "registry": "docker.io"}
        state = {"lastChecked": "2026-01-01"}
        result = _run_hooks("post-image-check", config, tmp_path, image, state, {})
        assert result["pulled"] is True

    def test_multiple_hooks_chain_state(self, tmp_path):
        _make_hook(tmp_path, "first.sh", "echo '{\"a\": 1}'")
        _make_hook(tmp_path, "second.sh", "echo '{\"b\": 2}'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "first.sh"}, {"path": "second.sh"}]
            }
        }
        state = {}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result["a"] == 1
        assert result["b"] == 2

    def test_missing_hook_executable_skipped(self, tmp_path):
        config = {
            "hooks": {
                "post-image-check": [{"path": "nonexistent.sh"}]
            }
        }
        state = {"x": 1}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

    def test_empty_stdout_leaves_state_unchanged(self, tmp_path):
        _make_hook(tmp_path, "empty.sh", "true")  # exits 0, prints nothing
        config = {
            "hooks": {
                "post-image-check": [{"path": "empty.sh"}]
            }
        }
        state = {"y": 2}
        result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

    def test_path_traversal_rejected(self, tmp_path):
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        _make_hook(outside, "evil.sh", "echo '{\"pwned\": true}'")
        config = {
            "hooks": {
                "post-image-check": [{"path": "../outside/evil.sh"}]
            }
        }
        state = {"x": 1}
        result = _run_hooks("post-image-check", config, repo_root, {}, state, {})
        assert "pwned" not in result
        assert result == state

    def test_hook_timeout_is_warning_not_error(self, tmp_path):
        _make_hook(tmp_path, "slow.sh", "sleep 999")
        config = {
            "hooks": {
                "post-image-check": [{"path": "slow.sh"}]
            }
        }
        state = {"y": 2}
        with unittest.mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="slow.sh", timeout=30),
        ):
            result = _run_hooks("post-image-check", config, tmp_path, {}, state, {})
        assert result == state

from app import _run_post_run_hooks


class TestRunPostRunHooks:

    def test_no_hooks_returns_without_error(self, tmp_path):
        # Should silently do nothing when no post-run hooks configured
        _run_post_run_hooks({}, tmp_path, tmp_path, [], 0)

    def test_hook_receives_correct_payload(self, tmp_path):
        # Hook dumps the received hookPoint and newTagCount back to a file
        out_file = tmp_path / "received.json"
        hook = tmp_path / "capture.sh"
        hook.write_text(
            f"#!/bin/sh\n"
            f"cat > {out_file}\n"
        )
        hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        config = {"hooks": {"post-run": [{"path": "capture.sh"}]}}
        results = [{"image": "nginx", "status": "new-tags", "new_tags": ["1.28", "1.29"]}]
        _run_post_run_hooks(config, tmp_path, tmp_path / "state", results, 2)

        received = json.loads(out_file.read_text())
        assert received["hookPoint"] == "post-run"
        assert received["summary"]["newTagCount"] == 2
        assert received["summary"]["totalImages"] == 1
        assert received["stateDir"] == str(tmp_path / "state")

    def test_hook_failure_does_not_raise(self, tmp_path):
        _make_hook(tmp_path, "fail.sh", "exit 1")
        config = {"hooks": {"post-run": [{"path": "fail.sh"}]}}
        # Should not raise even on hook failure
        _run_post_run_hooks(config, tmp_path, tmp_path, [], 0)

    def test_hook_timeout_does_not_raise(self, tmp_path):
        _make_hook(tmp_path, "slow.sh", "sleep 999")
        config = {"hooks": {"post-run": [{"path": "slow.sh"}]}}
        with unittest.mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="slow.sh", timeout=60),
        ):
            _run_post_run_hooks(config, tmp_path, tmp_path, [], 0)

    def test_path_traversal_rejected(self, tmp_path):
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        _make_hook(outside, "evil.sh", "echo malicious")
        config = {"hooks": {"post-run": [{"path": "../outside/evil.sh"}]}}
        # Should not raise — hook is silently skipped
        _run_post_run_hooks(config, repo_root, repo_root / "state", [], 0)

    def test_missing_hook_file_skipped(self, tmp_path):
        config = {"hooks": {"post-run": [{"path": "nonexistent.sh"}]}}
        _run_post_run_hooks(config, tmp_path, tmp_path / "state", [], 0)

    def test_zero_new_tags_reported(self, tmp_path):
        out_file = tmp_path / "received.json"
        hook = tmp_path / "capture.sh"
        hook.write_text(f"#!/bin/sh\ncat > {out_file}\n")
        hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        config = {"hooks": {"post-run": [{"path": "capture.sh"}]}}
        _run_post_run_hooks(config, tmp_path, tmp_path / "state", [], 0)
        received = json.loads(out_file.read_text())
        assert received["summary"]["newTagCount"] == 0
        assert received["summary"]["totalImages"] == 0
