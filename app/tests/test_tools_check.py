#!/usr/bin/env python3
"""Unit tests for tools_check.py."""

import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools_check import (
    VALID_TOOL_TYPES,
    cmd_tools_check,
    detect_drift,
    generate_tool_state,
    normalize_tool_name,
    output_results,
    parse_tools_yaml,
    validate_tool_entry,
    write_tool_state,
)


# ---------------------------------------------------------------------------
# Schema / parsing tests
# ---------------------------------------------------------------------------


class TestParseToolsYaml(unittest.TestCase):
    def test_valid_yaml(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "tools.yaml"
            p.write_text(
                "- name: actions/checkout\n"
                "  type: github-action\n"
                "  version: '4.2.2'\n"
            )
            tools = parse_tools_yaml(p)
            assert len(tools) == 1
            assert tools[0]["name"] == "actions/checkout"

    def test_empty_yaml_returns_empty_list(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "tools.yaml"
            p.write_text("")
            tools = parse_tools_yaml(p)
            assert tools == []

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_tools_yaml(Path("/nonexistent/tools.yaml"))

    def test_non_list_raises(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "tools.yaml"
            p.write_text("key: value\n")
            with self.assertRaises(ValueError):
                parse_tools_yaml(p)

    def test_multiple_tools(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "tools.yaml"
            data = [
                {"name": "actions/checkout", "type": "github-action", "version": "4"},
                {"name": "cosign", "type": "cli-tool", "version": "2.0.0"},
            ]
            p.write_text(yaml.dump(data))
            tools = parse_tools_yaml(p)
            assert len(tools) == 2


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestValidateToolEntry(unittest.TestCase):
    def test_valid_entry(self):
        tool = {"name": "actions/checkout", "type": "github-action"}
        assert validate_tool_entry(tool) == []

    def test_missing_name(self):
        tool = {"type": "github-action"}
        errors = validate_tool_entry(tool)
        assert any("name" in e for e in errors)

    def test_missing_type(self):
        tool = {"name": "actions/checkout"}
        errors = validate_tool_entry(tool)
        assert any("type" in e for e in errors)

    def test_invalid_type(self):
        tool = {"name": "foo", "type": "unknown-type"}
        errors = validate_tool_entry(tool)
        assert any("unknown type" in e for e in errors)

    def test_all_valid_types(self):
        for t in VALID_TOOL_TYPES:
            tool = {"name": "foo", "type": t}
            assert validate_tool_entry(tool) == [], f"type {t} should be valid"


# ---------------------------------------------------------------------------
# Name normalization tests
# ---------------------------------------------------------------------------


class TestNormalizeToolName(unittest.TestCase):
    def test_slash_becomes_hyphen(self):
        assert normalize_tool_name("actions/checkout") == "actions-checkout"

    def test_multiple_special_chars(self):
        assert normalize_tool_name("docker/build-push-action") == "docker-build-push-action"

    def test_simple_name(self):
        assert normalize_tool_name("cosign") == "cosign"

    def test_monorepo_path(self):
        assert normalize_tool_name("github/codeql-action/upload-sarif") == "github-codeql-action-upload-sarif"


# ---------------------------------------------------------------------------
# State generation tests
# ---------------------------------------------------------------------------


class TestGenerateToolState(unittest.TestCase):
    def _make_tool(self):
        return {
            "name": "actions/checkout",
            "type": "github-action",
            "version": "4.2.2",
            "repository": "actions/checkout",
            "pinDigest": "abc123",
        }

    def test_creates_new_state(self):
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "tools"
            state_file, state = generate_tool_state(self._make_tool(), state_dir, "2026-01-01T00:00:00+00:00")
            assert state["currentVersion"] == "4.2.2"
            assert state["checkStatus"] == "new"
            assert state["enrolledAt"] == "2026-01-01T00:00:00+00:00"

    def test_preserves_existing_timestamps(self):
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "tools"
            state_dir.mkdir()
            state_file = state_dir / "actions-checkout.yaml"
            existing = {
                "name": "actions-checkout",
                "type": "github-action",
                "enrolledAt": "2025-01-01T00:00:00+00:00",
                "lastChecked": "2025-06-01T00:00:00+00:00",
                "currentVersion": "4.2.1",
                "checkStatus": "ok",
                "upstreamVersions": {},
            }
            state_file.write_text(yaml.dump(existing))

            _, state = generate_tool_state(self._make_tool(), state_dir, "2026-01-01T00:00:00+00:00")
            assert state["enrolledAt"] == "2025-01-01T00:00:00+00:00"
            assert state["lastChecked"] == "2025-06-01T00:00:00+00:00"
            # Version updated from tools.yaml
            assert state["currentVersion"] == "4.2.2"

    def test_write_and_reload(self):
        with TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "tools"
            state_file, state = generate_tool_state(self._make_tool(), state_dir, "2026-01-01T00:00:00+00:00")
            write_tool_state(state_file, state)
            assert state_file.exists()
            loaded = yaml.safe_load(state_file.read_text())
            assert loaded["currentVersion"] == "4.2.2"


# ---------------------------------------------------------------------------
# Drift detection tests
# ---------------------------------------------------------------------------


class TestDetectDrift(unittest.TestCase):
    def _state(self, current="4.2.2"):
        return {
            "currentVersion": current,
            "upstreamVersions": {},
        }

    def test_no_drift(self):
        state = self._state("4.2.2")
        upstream = {"latestVersion": "v4.2.2", "latestDigest": "abc", "versions": {}}
        result = detect_drift({}, state, upstream)
        assert result["checkStatus"] == "ok"
        assert result["updateAvailable"] is False

    def test_drift_detected(self):
        state = self._state("4.2.1")
        upstream = {"latestVersion": "v4.2.2", "latestDigest": "abc", "versions": {}}
        result = detect_drift({}, state, upstream)
        assert result["checkStatus"] == "update-available"
        assert result["updateAvailable"] is True

    def test_no_current_version(self):
        state = {"currentVersion": None, "upstreamVersions": {}}
        upstream = {"latestVersion": "v4.2.2", "latestDigest": "abc", "versions": {}}
        result = detect_drift({}, state, upstream)
        assert result["checkStatus"] == "new"
        assert result["updateAvailable"] is False

    def test_no_upstream(self):
        state = self._state("4.2.2")
        upstream = {"latestVersion": None, "latestDigest": None, "versions": {}}
        result = detect_drift({}, state, upstream)
        assert result["checkStatus"] == "ok"
        assert result["updateAvailable"] is False

    def test_upstream_versions_merged(self):
        state = {"currentVersion": "4.2.1", "upstreamVersions": {}}
        upstream = {
            "latestVersion": "v4.2.2",
            "latestDigest": "sha-new",
            "versions": {
                "v4.2.2": {"digest": "sha-new", "firstSeen": "2026-01-01T00:00:00+00:00", "lastSeen": "2026-01-02T00:00:00+00:00"},
                "v4.2.1": {"digest": "sha-old", "firstSeen": "2025-12-01T00:00:00+00:00", "lastSeen": "2025-12-31T00:00:00+00:00"},
            },
        }
        result = detect_drift({}, state, upstream)
        assert "v4.2.2" in result["upstreamVersions"]
        assert "v4.2.1" in result["upstreamVersions"]

    def test_existing_firstseen_preserved(self):
        state = {
            "currentVersion": "4.2.1",
            "upstreamVersions": {
                "v4.2.2": {"digest": "sha", "firstSeen": "2026-01-01T00:00:00+00:00", "lastSeen": "2026-01-01T00:00:00+00:00"},
            },
        }
        upstream = {
            "latestVersion": "v4.2.2",
            "latestDigest": "sha",
            "versions": {
                "v4.2.2": {"digest": "sha", "firstSeen": "2099-01-01T00:00:00+00:00", "lastSeen": "2099-01-01T00:00:00+00:00"},
            },
        }
        result = detect_drift({}, state, upstream)
        assert result["upstreamVersions"]["v4.2.2"]["firstSeen"] == "2026-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# cmd_tools_check integration tests (no network)
# ---------------------------------------------------------------------------


class TestCmdToolsCheck(unittest.TestCase):
    def _make_args(self, tmp, tools_yaml="tools.yaml", tool=None, fmt="table", no_commit=True):
        args = MagicMock()
        args.tools_yaml = str(Path(tmp) / tools_yaml)
        args.state_dir = str(Path(tmp) / ".cascadeguard")
        args.tool = tool
        args.format = fmt
        args.no_commit = no_commit
        return args

    def _write_tools_yaml(self, tmp, data):
        p = Path(tmp) / "tools.yaml"
        p.write_text(yaml.dump(data))
        return p

    def test_missing_tools_yaml_returns_1(self):
        with TemporaryDirectory() as tmp:
            args = self._make_args(tmp)
            rc = cmd_tools_check(args)
            assert rc == 1

    def test_valid_cli_tool_returns_0(self):
        """cli-tool type has no upstream query — should return 0 when up to date."""
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {"name": "cosign", "type": "cli-tool", "version": "2.0.0"}
            ])
            args = self._make_args(tmp)
            rc = cmd_tools_check(args)
            assert rc == 0

    def test_state_file_created(self):
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {"name": "cosign", "type": "cli-tool", "version": "2.0.0"}
            ])
            args = self._make_args(tmp)
            cmd_tools_check(args)
            state_file = Path(tmp) / ".cascadeguard" / "tools" / "cosign.yaml"
            assert state_file.exists()
            state = yaml.safe_load(state_file.read_text())
            assert state["currentVersion"] == "2.0.0"

    def test_invalid_tool_returns_1(self):
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {"name": "bad-tool", "type": "invalid-type"}
            ])
            args = self._make_args(tmp)
            rc = cmd_tools_check(args)
            assert rc == 1

    def test_tool_filter(self):
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {"name": "cosign", "type": "cli-tool", "version": "2.0.0"},
                {"name": "trivy", "type": "cli-tool", "version": "0.50.0"},
            ])
            args = self._make_args(tmp, tool="cosign")
            rc = cmd_tools_check(args)
            state_dir = Path(tmp) / ".cascadeguard" / "tools"
            assert (state_dir / "cosign.yaml").exists()
            assert not (state_dir / "trivy.yaml").exists()

    def test_github_action_with_mocked_upstream(self):
        """GitHub Action check with mocked upstream returns 2 when update available."""
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {
                    "name": "actions/checkout",
                    "type": "github-action",
                    "version": "4.2.1",
                    "repository": "actions/checkout",
                }
            ])
            args = self._make_args(tmp)

            fake_upstream = {
                "latestVersion": "v4.2.2",
                "latestDigest": "abc123",
                "versions": {
                    "v4.2.2": {"digest": "abc123", "firstSeen": "2026-01-01T00:00:00+00:00", "lastSeen": "2026-01-01T00:00:00+00:00"},
                },
            }

            with patch("tools_check.query_upstream", return_value=fake_upstream):
                rc = cmd_tools_check(args)

            assert rc == 2

    def test_github_action_up_to_date(self):
        """GitHub Action check with mocked upstream returns 0 when current."""
        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {
                    "name": "actions/checkout",
                    "type": "github-action",
                    "version": "v4.2.2",
                    "repository": "actions/checkout",
                }
            ])
            args = self._make_args(tmp)

            fake_upstream = {
                "latestVersion": "v4.2.2",
                "latestDigest": "abc123",
                "versions": {},
            }

            with patch("tools_check.query_upstream", return_value=fake_upstream):
                rc = cmd_tools_check(args)

            assert rc == 0

    def test_json_output_format(self, capsys=None):
        """JSON output format writes valid JSON."""
        import io
        from contextlib import redirect_stdout

        with TemporaryDirectory() as tmp:
            self._write_tools_yaml(tmp, [
                {"name": "cosign", "type": "cli-tool", "version": "2.0.0"}
            ])
            args = self._make_args(tmp, fmt="json")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cmd_tools_check(args)

            output = buf.getvalue()
            parsed = json.loads(output)
            assert isinstance(parsed, list)
            assert parsed[0]["name"] == "cosign"


# ---------------------------------------------------------------------------
# Output formatting tests
# ---------------------------------------------------------------------------


class TestOutputResults(unittest.TestCase):
    def test_table_no_results(self, capsys=None):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            output_results([], "table")
        assert "No tools" in buf.getvalue()

    def test_json_output(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        results = [{"name": "cosign", "status": "ok", "currentVersion": "2.0.0", "latestVersion": "2.0.0"}]
        with redirect_stdout(buf):
            output_results(results, "json")
        data = json.loads(buf.getvalue())
        assert data[0]["name"] == "cosign"

    def test_table_with_update(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        results = [{"name": "cosign", "status": "update-available", "currentVersion": "2.0.0", "latestVersion": "2.1.0"}]
        with redirect_stdout(buf):
            output_results(results, "table")
        out = buf.getvalue()
        assert "UPDATE" in out
        assert "cosign" in out


if __name__ == "__main__":
    unittest.main()
