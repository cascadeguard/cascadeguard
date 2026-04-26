#!/usr/bin/env python3
"""Unit tests for platform-aware promotion PR/MR creation.

Covers:
  - _github_repo  — env var and git remote URL parsing
  - _github_api   — correct auth headers, JSON parse, HTTP error handling
  - _gitlab_api   — correct auth headers, JSON parse, HTTP error handling
  - _create_promotion_pr(ci_platform="github") — no token skip, create PR, update PR
  - _create_promotion_pr(ci_platform="gitlab") — no token skip, create MR, update MR
  - _commit_state_changes(ci_platform="github") — no changes, commit to main, create PR
  - _commit_state_changes(ci_platform="gitlab") — create MR, no token skip
"""

import json
import os
import sys
import urllib.error
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import (
    _commit_state_changes,
    _create_promotion_pr,
    _github_api,
    _github_repo,
    _gitlab_api,
)


# ── Helpers ────────────────────────────────────────────────────────────────


def _fake_response(data, status=200):
    """Build a urllib context-manager-compatible mock response."""
    body = json.dumps(data).encode()
    m = MagicMock()
    m.read.return_value = body
    m.status = status
    m.__enter__ = lambda s: s
    m.__exit__ = MagicMock(return_value=False)
    return m


def _http_error(code, message="error"):
    exc = urllib.error.HTTPError(
        url="https://example.com", code=code, msg=message,
        hdrs=None, fp=BytesIO(message.encode()),
    )
    return exc


def _promoted_entry(base_image="node:22", image="myapp", dockerfile="Dockerfile"):
    return {
        "image": image,
        "base_image": base_image,
        "dockerfile": dockerfile,
        "new_digest": "sha256:" + "b" * 64,
        "quarantine_hours": 48,
        "full_ref": base_image,
        "published_at": "2025-01-01T00:00:00+00:00",
        "observed_at": "2025-01-01T01:00:00+00:00",
        "promoted_at": "2025-01-03T00:00:00+00:00",
    }


# ── _github_repo ───────────────────────────────────────────────────────────


class TestGithubRepo:
    def test_uses_github_repository_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
        assert _github_repo(tmp_path) == "myorg/myrepo"

    def test_parses_https_remote(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(
                stdout="https://github.com/myorg/myrepo.git\n",
                returncode=0,
            )
            result = _github_repo(tmp_path)
        assert result == "myorg/myrepo"

    def test_parses_ssh_remote(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(
                stdout="git@github.com:myorg/myrepo.git\n",
                returncode=0,
            )
            result = _github_repo(tmp_path)
        assert result == "myorg/myrepo"

    def test_returns_none_for_non_github_remote(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(
                stdout="https://gitlab.com/myorg/myrepo.git\n",
                returncode=0,
            )
            result = _github_repo(tmp_path)
        assert result is None

    def test_returns_none_on_subprocess_failure(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with patch("subprocess.run", side_effect=Exception("no git")):
            result = _github_repo(tmp_path)
        assert result is None


# ── _github_api ────────────────────────────────────────────────────────────


class TestGithubApi:
    def test_sends_correct_auth_headers(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _fake_response({"number": 1})
            _github_api("GET", "https://api.github.com/repos/o/r/pulls", "mytoken")

        req = mock_open.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer mytoken"
        assert "github" in req.get_header("Accept").lower()

    def test_returns_parsed_json(self):
        payload = {"number": 42, "html_url": "https://github.com/o/r/pull/42"}
        with patch("urllib.request.urlopen", return_value=_fake_response(payload)):
            result, err = _github_api("POST", "https://api.github.com/repos/o/r/pulls", "tok", {"title": "x"})
        assert result == payload
        assert err is None

    def test_returns_error_on_http_error(self):
        with patch("urllib.request.urlopen", side_effect=_http_error(422, "Unprocessable")):
            result, err = _github_api("POST", "https://api.github.com/repos/o/r/pulls", "tok")
        assert result is None
        assert "422" in err

    def test_returns_error_on_exception(self):
        with patch("urllib.request.urlopen", side_effect=Exception("network down")):
            result, err = _github_api("GET", "https://api.github.com/repos/o/r/pulls", "tok")
        assert result is None
        assert "network down" in err


# ── _gitlab_api ────────────────────────────────────────────────────────────


class TestGitlabApi:
    def test_sends_bearer_auth(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _fake_response([])
            _gitlab_api("GET", "https://gitlab.com/api/v4/projects/1/merge_requests", "gltoken", "https://gitlab.com")

        req = mock_open.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer gltoken"

    def test_constructs_full_url_from_path(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value = _fake_response({"iid": 1})
            _gitlab_api("POST", "projects/42/merge_requests", "tok", "https://gitlab.example.com")

        req = mock_open.call_args[0][0]
        assert req.full_url.startswith("https://gitlab.example.com/api/v4/projects/42")

    def test_returns_parsed_json(self):
        payload = {"iid": 7, "web_url": "https://gitlab.com/o/r/-/merge_requests/7"}
        with patch("urllib.request.urlopen", return_value=_fake_response(payload)):
            result, err = _gitlab_api("POST", "projects/1/merge_requests", "tok", "https://gitlab.com", {"title": "x"})
        assert result == payload
        assert err is None

    def test_returns_error_on_http_error(self):
        with patch("urllib.request.urlopen", side_effect=_http_error(403, "Forbidden")):
            result, err = _gitlab_api("POST", "projects/1/merge_requests", "tok", "https://gitlab.com")
        assert result is None
        assert "403" in err


# ── _create_promotion_pr — GitHub platform ─────────────────────────────────


class TestCreatePromotionPrGitHub:
    def test_skips_when_no_github_token(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with patch("subprocess.run", side_effect=Exception("no git")):
            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="github"
            )
        assert pr_urls == []
        assert pr_errors == []
        assert "GITHUB_TOKEN" in capsys.readouterr().err

    def test_creates_pr_via_github_api(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")

        new_pr = {"number": 10, "html_url": "https://github.com/myorg/myrepo/pull/10"}
        empty_list = []

        with patch("app._run_git"), \
             patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_open:

            # First urlopen call: GET pulls (no existing PR) → []
            # Second urlopen call: POST pulls (create PR) → new_pr
            # Third urlopen call: POST labels (best-effort) → {}
            mock_open.side_effect = [
                _fake_response(empty_list),
                _fake_response(new_pr),
                _fake_response({}),
            ]
            # subprocess.run for git diff --cached
            mock_subproc.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="github"
            )

        assert pr_errors == []
        assert "https://github.com/myorg/myrepo/pull/10" in pr_urls

    def test_updates_existing_pr_with_comment(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")

        existing_prs = [{"number": 5, "title": "old promotion"}]

        with patch("app._run_git"), \
             patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_open:

            # First call: GET pulls → existing PR found
            # Second call: POST comment → {}
            mock_open.side_effect = [
                _fake_response(existing_prs),
                _fake_response({}),
            ]
            mock_subproc.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="github"
            )

        assert pr_errors == []
        assert any("5" in u for u in pr_urls)
        assert any("updated" in u for u in pr_urls)


# ── _create_promotion_pr — GitLab platform ─────────────────────────────────


class TestCreatePromotionPrGitLab:
    def test_skips_when_no_token(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("CI_JOB_TOKEN", raising=False)
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        monkeypatch.setenv("CI_PROJECT_ID", "123")
        pr_urls, pr_errors = _create_promotion_pr(
            tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="gitlab"
        )
        assert pr_urls == []
        assert pr_errors == []
        assert "CI_JOB_TOKEN" in capsys.readouterr().err

    def test_skips_when_no_project_id(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
        monkeypatch.delenv("CI_PROJECT_ID", raising=False)
        monkeypatch.delenv("CI_PROJECT_PATH", raising=False)
        pr_urls, pr_errors = _create_promotion_pr(
            tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="gitlab"
        )
        assert pr_urls == []
        assert pr_errors == []

    def test_creates_mr_via_gitlab_api(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
        monkeypatch.setenv("CI_PROJECT_ID", "99")
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")

        new_mr = {"iid": 3, "web_url": "https://gitlab.example.com/o/r/-/merge_requests/3"}
        empty_list = []

        with patch("app._run_git"), \
             patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_open:

            mock_open.side_effect = [
                _fake_response(empty_list),   # GET MRs — none existing
                _fake_response(new_mr),        # POST MR — created
            ]
            mock_subproc.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="gitlab"
            )

        assert pr_errors == []
        assert "https://gitlab.example.com/o/r/-/merge_requests/3" in pr_urls

    def test_updates_existing_mr_with_note(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
        monkeypatch.setenv("CI_PROJECT_ID", "99")
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")

        existing_mrs = [{"iid": 2, "title": "old promotion"}]

        with patch("app._run_git"), \
             patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_open:

            mock_open.side_effect = [
                _fake_response(existing_mrs),  # GET MRs — existing found
                _fake_response({}),            # POST note
            ]
            mock_subproc.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="gitlab"
            )

        assert pr_errors == []
        assert any("!2" in u for u in pr_urls)
        assert any("updated" in u for u in pr_urls)

    def test_records_error_on_api_failure(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
        monkeypatch.setenv("CI_PROJECT_ID", "99")
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")

        with patch("app._run_git"), \
             patch("subprocess.run") as mock_subproc, \
             patch("urllib.request.urlopen") as mock_open:

            mock_open.side_effect = [
                _fake_response([]),                         # GET MRs — none existing
                _http_error(403, "Forbidden"),              # POST MR — fails
            ]
            mock_subproc.return_value = SimpleNamespace(returncode=1, stdout="", stderr="")

            pr_urls, pr_errors = _create_promotion_pr(
                tmp_path, [_promoted_entry()], {"node:22": 48}, ci_platform="gitlab"
            )

        assert pr_urls == []
        assert len(pr_errors) == 1
        assert "node:22" in pr_errors[0]


# ── _commit_state_changes ───────────────────────────────────────────────────


def _make_state_dir(tmp_path):
    state_dir = tmp_path / ".cascadeguard"
    state_dir.mkdir()
    (state_dir / "state.yaml").write_text("images: {}")
    return state_dir


def _git_no_changes():
    """subprocess.run mock: git diff --cached --quiet returns 0 (nothing staged)."""
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def _git_has_changes():
    """subprocess.run mock: git diff --cached --quiet returns 1 (changes staged)."""
    return SimpleNamespace(returncode=1, stdout="diff", stderr="")


class TestCommitStateChangesNoChanges:
    def test_returns_false_when_nothing_staged(self, tmp_path):
        state_dir = _make_state_dir(tmp_path)
        with patch("app._run_git"), \
             patch("subprocess.run", return_value=_git_no_changes()):
            result = _commit_state_changes(tmp_path, state_dir, "main")
        assert result is False


class TestCommitStateChangesMainDestination:
    def test_commits_and_pushes_to_main(self, tmp_path):
        state_dir = _make_state_dir(tmp_path)
        with patch("app._run_git") as mock_git, \
             patch("subprocess.run", return_value=_git_has_changes()):
            result = _commit_state_changes(tmp_path, state_dir, "main")

        assert result is True
        calls = [str(c) for c in mock_git.call_args_list]
        assert any("push" in c and "main" in c for c in calls)


class TestCommitStateChangesPrGitHub:
    def test_creates_pr_via_github_api(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("GITHUB_REPOSITORY", "myorg/myrepo")
        state_dir = _make_state_dir(tmp_path)
        new_pr = {"number": 99, "html_url": "https://github.com/myorg/myrepo/pull/99"}

        with patch("app._run_git"), \
             patch("subprocess.run", return_value=_git_has_changes()), \
             patch("urllib.request.urlopen", return_value=_fake_response(new_pr)):
            result = _commit_state_changes(tmp_path, state_dir, "pr", ci_platform="github")

        assert result is True

    def test_skips_pr_when_no_github_token(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        state_dir = _make_state_dir(tmp_path)

        with patch("app._run_git"), \
             patch("subprocess.run", side_effect=[
                 _git_has_changes(),            # diff --cached
                 SimpleNamespace(returncode=0, stdout="", stderr=""),  # git remote get-url
             ]):
            result = _commit_state_changes(tmp_path, state_dir, "pr", ci_platform="github")

        assert result is True  # branch pushed; PR creation just skipped
        assert "GITHUB_TOKEN" in capsys.readouterr().err


class TestCommitStateChangesPrGitLab:
    def test_creates_mr_via_gitlab_api(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
        monkeypatch.setenv("CI_PROJECT_ID", "42")
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")
        state_dir = _make_state_dir(tmp_path)
        new_mr = {"iid": 5, "web_url": "https://gitlab.example.com/o/r/-/merge_requests/5"}

        with patch("app._run_git"), \
             patch("subprocess.run", return_value=_git_has_changes()), \
             patch("urllib.request.urlopen", return_value=_fake_response(new_mr)):
            result = _commit_state_changes(tmp_path, state_dir, "pr", ci_platform="gitlab")

        assert result is True

    def test_skips_mr_when_no_token(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("CI_JOB_TOKEN", raising=False)
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)
        monkeypatch.setenv("CI_PROJECT_ID", "42")
        state_dir = _make_state_dir(tmp_path)

        with patch("app._run_git"), \
             patch("subprocess.run", return_value=_git_has_changes()):
            result = _commit_state_changes(tmp_path, state_dir, "pr", ci_platform="gitlab")

        assert result is True  # branch pushed; MR creation just skipped
        assert "CI_JOB_TOKEN" in capsys.readouterr().err
