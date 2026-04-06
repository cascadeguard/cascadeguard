#!/usr/bin/env python3
"""Mocked unit tests for cmd_scan_issues GitHub API integration."""

import json
import sys
import os
from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import cmd_scan_issues, GitHubActionsProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_GRYPE = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2026-1234",
                "severity": "Critical",
                "description": "Buffer overflow in libfoo",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                "fix": {"versions": [{"version": "1.2.4"}]},
            },
            "artifact": {"name": "libfoo", "version": "1.2.3", "type": "deb"},
        },
        {
            "vulnerability": {
                "id": "CVE-2026-5678",
                "severity": "High",
                "description": "Use-after-free in libbar",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-5678",
                "fix": {"versions": []},
            },
            "artifact": {"name": "libbar", "version": "2.0.0", "type": "deb"},
        },
    ]
}


def _make_args(tmp_path, grype_data=None, image="myimage", tag="v1", repo="org/repo", github_token="ghp_fake"):
    """Build a minimal args namespace for cmd_scan_issues."""
    grype_file = None
    if grype_data is not None:
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(grype_data))

    class Args:
        pass

    a = Args()
    a.grype = str(grype_file) if grype_file else None
    a.trivy = None
    a.image = image
    a.tag = tag
    a.repo = repo
    a.github_token = github_token
    return a


# ---------------------------------------------------------------------------
# Tests: create new issue when none exists
# ---------------------------------------------------------------------------

class TestCreateNewIssue:
    def test_creates_issue_for_critical_and_high_findings(self, tmp_path):
        """When no existing issue matches, a new issue is created per critical/high finding."""
        args = _make_args(tmp_path, grype_data=SAMPLE_GRYPE)

        mock_request = MagicMock(side_effect=[
            # _fetch_cve_issues: open page 1 (empty), closed page 1 (empty)
            [],
            [],
            # create issue for CVE-2026-1234
            {"number": 42, "title": "CVE-2026-1234: libfoo (critical)"},
            # create issue for CVE-2026-5678
            {"number": 43, "title": "CVE-2026-5678: libbar (high)"},
        ])

        with patch.object(GitHubActionsProvider, "_request", mock_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        # MagicMock replaces the class attribute without binding, so no self in args
        create_calls = [
            c for c in mock_request.call_args_list
            if c.args[0] == "POST" and "/issues" in c.args[1]
            and "/comments" not in c.args[1] and "/labels" not in c.args[1]
        ]
        assert len(create_calls) == 2

    def test_new_issue_has_correct_labels(self, tmp_path):
        """Created issue carries cve, automated, severity and image labels."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]  # Critical only
        })

        created_payloads = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return []
            if method == "POST" and "/issues" in path and "/comments" not in path and "/labels" not in path:
                created_payloads.append(data)
                return {"number": 1, "title": data["title"]}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        assert len(created_payloads) == 1
        labels = created_payloads[0]["labels"]
        assert "cve" in labels
        assert "automated" in labels
        assert "severity:critical" in labels
        assert "image:myimage" in labels

    def test_no_issues_created_for_medium_severity(self, tmp_path):
        """Medium and lower findings are not turned into GitHub issues."""
        medium_only = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2026-9999",
                        "severity": "Medium",
                        "description": "Low-risk issue",
                        "dataSource": "",
                        "fix": {"versions": []},
                    },
                    "artifact": {"name": "liblow", "version": "1.0", "type": "deb"},
                }
            ]
        }
        args = _make_args(tmp_path, grype_data=medium_only)

        mock_request = MagicMock(return_value=[])

        with patch.object(GitHubActionsProvider, "_request", mock_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        mock_request.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: update existing open issue (deduplication path)
# ---------------------------------------------------------------------------

class TestUpdateExistingOpenIssue:
    def test_adds_comment_to_open_issue(self, tmp_path):
        """Re-detection of an open issue appends a comment instead of creating."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]  # CVE-2026-1234/libfoo Critical
        })

        existing_open = [
            {"number": 10, "title": "CVE-2026-1234: libfoo (critical)", "state": "open"},
        ]

        comment_calls = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return existing_open if "open" in path else []
            if method == "POST" and "/comments" in path:
                comment_calls.append((path, data))
                return {"id": 99}
            if method == "POST" and "/labels" in path:
                return {}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        assert len(comment_calls) == 1
        path, body = comment_calls[0]
        assert "/issues/10/comments" in path
        assert "Re-detected" in body["body"]

    def test_no_new_issue_created_for_existing_open(self, tmp_path):
        """When a matching open issue exists, no new issue is created via POST /issues."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        })

        existing_open = [
            {"number": 10, "title": "CVE-2026-1234: libfoo (critical)", "state": "open"},
        ]

        create_calls = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return existing_open if "open" in path else []
            if method == "POST" and "/comments" in path:
                return {"id": 1}
            if method == "POST" and "/labels" in path:
                return {}
            if method == "POST" and "/issues" in path and "/comments" not in path and "/labels" not in path:
                create_calls.append(path)
                return {"number": 99}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            cmd_scan_issues(args)

        assert create_calls == [], "Should not create a new issue when one already exists open"


# ---------------------------------------------------------------------------
# Tests: reopen closed issue
# ---------------------------------------------------------------------------

class TestReopenClosedIssue:
    def test_reopens_closed_issue(self, tmp_path):
        """A matching closed issue is reopened via PATCH and a comment is added."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        })

        closed_issue = {"number": 7, "title": "CVE-2026-1234: libfoo (critical)", "state": "closed"}

        patch_calls = []
        comment_calls = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return [] if "open" in path else [closed_issue]
            if method == "PATCH" and "/issues/7" in path:
                patch_calls.append(data)
                return {}
            if method == "POST" and "/comments" in path:
                comment_calls.append(data)
                return {"id": 1}
            if method == "POST" and "/labels" in path:
                return {}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        assert any(p.get("state") == "open" for p in patch_calls), "Should reopen issue"
        assert len(comment_calls) == 1
        assert "Reopened" in comment_calls[0]["body"]

    def test_reopen_comment_includes_image_info(self, tmp_path):
        """Reopen comment mentions the image and tag."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        }, image="nginx", tag="1.25")

        closed_issue = {"number": 7, "title": "CVE-2026-1234: libfoo (critical)", "state": "closed"}

        comments = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return [] if "open" in path else [closed_issue]
            if method == "POST" and "/comments" in path:
                comments.append(data["body"])
                return {"id": 1}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            cmd_scan_issues(args)

        assert comments
        assert "nginx" in comments[0]
        assert "1.25" in comments[0]


# ---------------------------------------------------------------------------
# Tests: label assignment
# ---------------------------------------------------------------------------

class TestLabelAssignment:
    def test_high_severity_label_on_new_issue(self, tmp_path):
        """High-severity finding gets severity:high label."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][1]]  # High severity
        })

        created_payloads = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return []
            if method == "POST" and "/issues" in path and "/comments" not in path and "/labels" not in path:
                created_payloads.append(data)
                return {"number": 5}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            cmd_scan_issues(args)

        assert len(created_payloads) == 1
        labels = created_payloads[0]["labels"]
        assert "severity:high" in labels
        assert "image:myimage" in labels

    def test_image_label_added_when_updating_open_issue(self, tmp_path):
        """When updating an open issue, the image label is applied via POST /labels."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        }, image="redis", tag="7")

        existing_open = [
            {"number": 10, "title": "CVE-2026-1234: libfoo (critical)", "state": "open"},
        ]

        label_calls = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return existing_open if "open" in path else []
            if method == "POST" and "/labels" in path:
                label_calls.append((path, data))
                return {}
            if method == "POST" and "/comments" in path:
                return {"id": 1}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            cmd_scan_issues(args)

        assert any("image:redis" in str(d) for _, d in label_calls), "image label should be applied"


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_github_api_error_on_create_does_not_crash(self, tmp_path):
        """RuntimeError from _request is caught and logged; command still exits 0."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        })

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                return []
            raise RuntimeError("GitHub API error 403: rate limit exceeded")

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            rc = cmd_scan_issues(args)

        assert rc == 0  # Should not raise or crash

    def test_github_404_on_fetch_issues_continues(self, tmp_path):
        """If fetching existing issues fails, the command creates new issues anyway."""
        args = _make_args(tmp_path, grype_data={
            "matches": [SAMPLE_GRYPE["matches"][0]]
        })

        create_calls = []

        def fake_request(self_obj, method, path, data=None):
            if method == "GET":
                raise RuntimeError("GitHub API error 404: not found")
            if method == "POST" and "/issues" in path and "/comments" not in path and "/labels" not in path:
                create_calls.append(data)
                return {"number": 1}
            return {}

        with patch.object(GitHubActionsProvider, "_request", fake_request):
            rc = cmd_scan_issues(args)

        assert rc == 0
        assert len(create_calls) == 1

    def test_missing_github_token_returns_error(self, tmp_path):
        """Missing token causes early exit with return code 1."""
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE))

        class Args:
            grype = str(grype_file)
            trivy = None
            image = "test"
            tag = ""
            repo = "org/repo"
            github_token = ""

        saved = os.environ.pop("GITHUB_TOKEN", None)
        try:
            rc = cmd_scan_issues(Args())
        finally:
            if saved is not None:
                os.environ["GITHUB_TOKEN"] = saved

        assert rc == 1

    def test_missing_repo_returns_error(self, tmp_path):
        """Missing --repo causes early exit with return code 1."""
        grype_file = tmp_path / "grype.json"
        grype_file.write_text(json.dumps(SAMPLE_GRYPE))

        class Args:
            grype = str(grype_file)
            trivy = None
            image = "test"
            tag = ""
            repo = ""
            github_token = "ghp_fake"

        rc = cmd_scan_issues(Args())
        assert rc == 1
