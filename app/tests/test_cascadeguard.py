#!/usr/bin/env python3
"""Unit tests for CascadeGuard task mode CLI commands."""

import json
import os
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
                        "repository": "org/myapp",
                        "source": {"provider": "github", "repo": "org/myapp"},
                    }
                ]
            )
        )
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 0

    def test_missing_name(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"registry": "ghcr.io", "repository": "org/x"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_missing_registry(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "repository": "org/x"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_missing_repository(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump([{"name": "x", "registry": "ghcr.io"}]))
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_source_missing_provider(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(
            yaml.dump(
                [
                    {
                        "name": "x",
                        "registry": "ghcr.io",
                        "repository": "org/x",
                        "source": {"repo": "org/x"},
                    }
                ]
            )
        )
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

    def test_source_missing_repo(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(
            yaml.dump(
                [
                    {
                        "name": "x",
                        "registry": "ghcr.io",
                        "repository": "org/x",
                        "source": {"provider": "github"},
                    }
                ]
            )
        )
        rc = cmd_validate(_args(images_yaml=str(f)))
        assert rc == 1

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


class TestCmdCheck:
    def _make_state(self, tmp_path):
        images_dir = tmp_path / "images"
        images_dir.mkdir(parents=True)
        base_dir = tmp_path / "base-images"
        base_dir.mkdir(parents=True)
        return tmp_path, images_dir, base_dir

    def test_check_with_state_files(self, tmp_path):
        state_dir, images_dir, base_dir = self._make_state(tmp_path)

        (images_dir / "myapp.yaml").write_text(
            yaml.dump(
                {
                    "name": "myapp",
                    "currentDigest": "sha256:abc",
                    "lastBuilt": "2025-01-01T00:00:00Z",
                    "discoveryStatus": "pending",
                }
            )
        )
        (base_dir / "node-22.yaml").write_text(
            yaml.dump(
                {
                    "name": "node-22",
                    "currentDigest": "sha256:def",
                    "lastUpdated": "2025-01-01T00:00:00Z",
                }
            )
        )

        rc = cmd_check(_args(state_dir=str(state_dir)))
        assert rc == 0

    def test_check_empty_state_dir(self, tmp_path):
        rc = cmd_check(_args(state_dir=str(tmp_path)))
        assert rc == 0


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
