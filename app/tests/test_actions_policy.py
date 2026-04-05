#!/usr/bin/env python3
"""Unit tests for actions_policy.py — PolicyAuditor, load_policy, init_policy."""

import sys
import os
from datetime import date, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from actions_policy import (
    ActionRef,
    AuditResult,
    PolicyAuditor,
    PolicyError,
    PolicyViolation,
    init_policy,
    load_policy,
    scan_pinning_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_policy(path: Path, content: dict) -> Path:
    policy_file = path / "actions-policy.yaml"
    policy_file.write_text(yaml.dump(content))
    return policy_file


def _write_workflow(workflows_dir: Path, name: str, uses_lines: list[str]) -> Path:
    wf = workflows_dir / name
    lines = ["on: [push]", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:"]
    for uses in uses_lines:
        lines.append(f"      - uses: {uses}")
    wf.write_text("\n".join(lines))
    return wf


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------

class TestLoadPolicy:

    def test_minimal_valid_policy(self, tmp_path):
        p = _write_policy(tmp_path, {"version": "1"})
        policy = load_policy(p)
        assert policy["version"] == "1"

    def test_full_valid_policy(self, tmp_path):
        content = {
            "version": "1",
            "default": "deny",
            "allowed_owners": ["actions", "docker"],
            "allowed_actions": ["hashicorp/setup-terraform"],
            "denied_actions": ["bad-org/bad-action"],
            "exceptions": [
                {"action": "old-org/legacy-action", "reason": "legacy pipeline"},
            ],
        }
        p = _write_policy(tmp_path, content)
        policy = load_policy(p)
        assert policy["allowed_owners"] == ["actions", "docker"]

    def test_missing_version_raises(self, tmp_path):
        p = _write_policy(tmp_path, {"default": "deny"})
        with pytest.raises(PolicyError, match="missing required field 'version'"):
            load_policy(p)

    def test_wrong_version_raises(self, tmp_path):
        p = _write_policy(tmp_path, {"version": "2"})
        with pytest.raises(PolicyError, match="unsupported version '2'"):
            load_policy(p)

    def test_invalid_default_raises(self, tmp_path):
        p = _write_policy(tmp_path, {"version": "1", "default": "maybe"})
        with pytest.raises(PolicyError, match="'default' must be one of"):
            load_policy(p)

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(PolicyError, match="Policy file not found"):
            load_policy(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("version: 1\nkey: [unclosed")
        with pytest.raises(PolicyError, match="YAML parse error"):
            load_policy(p)

    def test_non_mapping_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(PolicyError, match="expected a YAML mapping"):
            load_policy(p)

    def test_allowed_actions_not_list_raises(self, tmp_path):
        p = _write_policy(tmp_path, {"version": "1", "allowed_actions": "actions/checkout"})
        with pytest.raises(PolicyError, match="'allowed_actions' must be a list"):
            load_policy(p)

    def test_exception_missing_action_raises(self, tmp_path):
        content = {
            "version": "1",
            "exceptions": [{"reason": "no action field"}],
        }
        p = _write_policy(tmp_path, content)
        with pytest.raises(PolicyError, match="exceptions\\[0\\] missing required field 'action'"):
            load_policy(p)

    def test_exception_missing_reason_raises(self, tmp_path):
        content = {
            "version": "1",
            "exceptions": [{"action": "some-org/some-action"}],
        }
        p = _write_policy(tmp_path, content)
        with pytest.raises(PolicyError, match="exceptions\\[0\\] missing required field 'reason'"):
            load_policy(p)


# ---------------------------------------------------------------------------
# PolicyAuditor._evaluate
# ---------------------------------------------------------------------------

class TestPolicyAuditorEvaluate:
    """Tests for the _evaluate method via audit_file."""

    def _auditor(self, **kwargs) -> PolicyAuditor:
        policy = {"version": "1", **kwargs}
        return PolicyAuditor(policy)

    def test_denied_action_is_violation(self):
        auditor = self._auditor(denied_actions=["bad-org/bad-action"])
        assert auditor._evaluate("bad-org/bad-action") is not None

    def test_allowed_action_is_not_violation(self):
        auditor = self._auditor(
            default="deny",
            allowed_actions=["actions/checkout"],
        )
        assert auditor._evaluate("actions/checkout") is None

    def test_denied_takes_precedence_over_allowed(self):
        auditor = self._auditor(
            allowed_actions=["bad-org/bad-action"],
            denied_actions=["bad-org/bad-action"],
        )
        assert auditor._evaluate("bad-org/bad-action") is not None

    def test_allowed_owner_permits_action(self):
        auditor = self._auditor(default="deny", allowed_owners=["actions"])
        assert auditor._evaluate("actions/checkout") is None

    def test_default_deny_blocks_unknown(self):
        auditor = self._auditor(default="deny")
        assert auditor._evaluate("unknown-org/some-action") is not None

    def test_default_allow_permits_unknown(self):
        auditor = self._auditor(default="allow")
        assert auditor._evaluate("unknown-org/some-action") is None

    def test_active_exception_permits_action(self):
        future = (date.today() + timedelta(days=30)).isoformat()
        auditor = self._auditor(
            default="deny",
            exceptions=[{"action": "legacy/tool", "reason": "migrating", "expires": future}],
        )
        assert auditor._evaluate("legacy/tool") is None

    def test_expired_exception_is_violation(self):
        past = "2020-01-01"
        auditor = self._auditor(
            default="deny",
            exceptions=[{"action": "legacy/tool", "reason": "migrating", "expires": past}],
        )
        result = auditor._evaluate("legacy/tool")
        assert result is not None
        assert "expired" in result

    def test_exception_without_expiry_is_active(self):
        auditor = self._auditor(
            default="deny",
            exceptions=[{"action": "legacy/tool", "reason": "migrating"}],
        )
        assert auditor._evaluate("legacy/tool") is None

    def test_malformed_expiry_treated_as_active(self):
        auditor = self._auditor(
            default="deny",
            exceptions=[{"action": "legacy/tool", "reason": "migrating", "expires": "not-a-date"}],
        )
        assert auditor._evaluate("legacy/tool") is None


# ---------------------------------------------------------------------------
# PolicyAuditor.audit / audit_file
# ---------------------------------------------------------------------------

class TestPolicyAuditorAuditFile:

    def test_allowed_action_passes(self, tmp_path):
        policy = {"version": "1", "default": "deny", "allowed_actions": ["actions/checkout"]}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", ["actions/checkout@v4"])
        result = auditor.audit_file(wf)
        assert result.passed
        assert result.allowed == 1
        assert result.skipped == 0

    def test_denied_action_is_violation(self, tmp_path):
        policy = {"version": "1", "default": "allow", "denied_actions": ["bad/action"]}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", ["bad/action@v1"])
        result = auditor.audit_file(wf)
        assert not result.passed
        assert len(result.violations) == 1
        assert result.violations[0].action == "bad/action"

    def test_local_action_without_ref_not_matched(self, tmp_path):
        # Local composite actions without an @ref don't match _USES_RE at all — not a violation.
        policy = {"version": "1", "default": "deny"}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", ["./local-action"])
        result = auditor.audit_file(wf)
        assert result.passed
        assert result.skipped == 0
        assert result.allowed == 0

    def test_local_action_with_ref_is_skipped(self, tmp_path):
        # Local composite actions referenced as ./path@sha are skipped (not evaluated).
        policy = {"version": "1", "default": "deny"}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", ["./.github/actions/my-action@abc123"])
        result = auditor.audit_file(wf)
        assert result.passed
        assert result.skipped == 1

    def test_multiple_violations_reported(self, tmp_path):
        policy = {"version": "1", "default": "deny"}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", [
            "unknown-org/action-a@v1",
            "unknown-org/action-b@v1",
        ])
        result = auditor.audit_file(wf)
        assert len(result.violations) == 2

    def test_violation_contains_correct_metadata(self, tmp_path):
        policy = {"version": "1", "default": "deny"}
        auditor = PolicyAuditor(policy)
        wf = _write_workflow(tmp_path, "ci.yml", ["unknown-org/risky@abc123"])
        result = auditor.audit_file(wf)
        v = result.violations[0]
        assert v.action == "unknown-org/risky"
        assert v.ref == "abc123"
        assert v.workflow_file == str(wf)
        assert v.line_number > 0

    def test_audit_directory_scans_all_yaml(self, tmp_path):
        workflows_dir = tmp_path / "workflows"
        workflows_dir.mkdir()
        policy = {"version": "1", "default": "deny", "allowed_owners": ["actions"]}
        auditor = PolicyAuditor(policy)
        _write_workflow(workflows_dir, "ci.yml", ["actions/checkout@v4"])
        _write_workflow(workflows_dir, "deploy.yaml", ["actions/setup-node@v4"])
        result = auditor.audit(workflows_dir)
        assert result.passed
        assert result.allowed == 2

    def test_audit_directory_collects_violations_across_files(self, tmp_path):
        workflows_dir = tmp_path / "workflows"
        workflows_dir.mkdir()
        policy = {"version": "1", "default": "deny"}
        auditor = PolicyAuditor(policy)
        _write_workflow(workflows_dir, "a.yml", ["bad-org/action-a@v1"])
        _write_workflow(workflows_dir, "b.yml", ["bad-org/action-b@v1"])
        result = auditor.audit(workflows_dir)
        assert len(result.violations) == 2


# ---------------------------------------------------------------------------
# init_policy
# ---------------------------------------------------------------------------

class TestInitPolicy:

    def test_creates_file(self, tmp_path):
        out = tmp_path / ".cascadeguard" / "actions-policy.yaml"
        result = init_policy(out)
        assert result is True
        assert out.exists()

    def test_does_not_overwrite_by_default(self, tmp_path):
        out = tmp_path / "actions-policy.yaml"
        out.write_text("existing content")
        result = init_policy(out)
        assert result is False
        assert out.read_text() == "existing content"

    def test_force_overwrites(self, tmp_path):
        out = tmp_path / "actions-policy.yaml"
        out.write_text("existing content")
        result = init_policy(out, force=True)
        assert result is True
        assert out.read_text() != "existing content"

    def test_created_file_is_valid_policy(self, tmp_path):
        out = tmp_path / ".cascadeguard" / "actions-policy.yaml"
        init_policy(out)
        policy = load_policy(out)
        assert policy["version"] == "1"

    def test_creates_parent_directories(self, tmp_path):
        out = tmp_path / "a" / "b" / "c" / "actions-policy.yaml"
        init_policy(out)
        assert out.exists()


# ---------------------------------------------------------------------------
# PolicyViolation.__str__
# ---------------------------------------------------------------------------

class TestPolicyViolationStr:

    def test_str_format(self):
        v = PolicyViolation(
            workflow_file="ci.yml",
            line_number=12,
            action="bad/action",
            ref="v1",
            reason="denied",
        )
        s = str(v)
        assert "ci.yml:12" in s
        assert "bad/action@v1" in s
        assert "denied" in s


# ---------------------------------------------------------------------------
# scan_pinning_status / ActionRef
# ---------------------------------------------------------------------------

class TestScanPinningStatus:

    SHA = "a" * 40

    def _write_workflow(self, workflows_dir: Path, name: str, uses_lines: list) -> Path:
        wf = workflows_dir / name
        lines = ["on: [push]", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:"]
        for uses in uses_lines:
            lines.append(f"      - uses: {uses}")
        wf.write_text("\n".join(lines))
        return wf

    def test_sha_pinned_classified_as_pinned(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", [f"actions/checkout@{self.SHA}"])
        refs = scan_pinning_status(wf_dir)
        assert len(refs) == 1
        assert refs[0].status == "pinned"
        assert refs[0].mutable is False

    def test_version_tag_classified_as_tag(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["actions/checkout@v4"])
        refs = scan_pinning_status(wf_dir)
        assert refs[0].status == "tag"
        assert refs[0].mutable is True

    def test_numeric_version_classified_as_tag(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["actions/checkout@4.1.0"])
        refs = scan_pinning_status(wf_dir)
        assert refs[0].status == "tag"

    def test_branch_ref_classified_as_branch(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["actions/checkout@main"])
        refs = scan_pinning_status(wf_dir)
        assert refs[0].status == "branch"
        assert refs[0].mutable is True

    def test_local_action_classified_as_local(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["./actions/my-action@v1"])
        refs = scan_pinning_status(wf_dir)
        assert refs[0].status == "local"
        assert refs[0].mutable is False

    def test_mixed_workflow_classified_correctly(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", [
            f"actions/checkout@{self.SHA}",
            "actions/setup-python@v5",
            "org/action@main",
        ])
        refs = scan_pinning_status(wf_dir)
        statuses = [r.status for r in refs]
        assert statuses == ["pinned", "tag", "branch"]

    def test_action_ref_as_dict(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["actions/checkout@v4"])
        refs = scan_pinning_status(wf_dir)
        d = refs[0].as_dict()
        assert d["action"] == "actions/checkout"
        assert d["ref"] == "v4"
        assert d["status"] == "tag"
        assert "line_number" in d
        assert "workflow_file" in d

    def test_scans_multiple_files(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        self._write_workflow(wf_dir, "ci.yml", ["actions/checkout@v4"])
        self._write_workflow(wf_dir, "deploy.yml", ["actions/setup-python@v5"])
        refs = scan_pinning_status(wf_dir)
        assert len(refs) == 2

    def test_empty_directory_returns_empty(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        refs = scan_pinning_status(wf_dir)
        assert refs == []
