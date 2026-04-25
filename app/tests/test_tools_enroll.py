#!/usr/bin/env python3
"""Unit tests for tools_enroll.py."""

import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools_enroll import (
    deduplicate_discovered,
    detect_github_actions,
    detect_gitlab_ci,
    detect_platforms,
    merge_with_existing,
    cmd_tools_enroll,
)


# ---------------------------------------------------------------------------
# GitHub Actions detector tests
# ---------------------------------------------------------------------------


class TestDetectGithubActions(unittest.TestCase):
    def _make_root(self, tmp: str, workflows: dict) -> Path:
        root = Path(tmp)
        wf_dir = root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        for name, content in workflows.items():
            (wf_dir / name).write_text(content)
        return root

    def test_detects_action_uses(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf})
            tools = detect_github_actions(root)
        names = [t["name"] for t in tools]
        assert "actions/checkout" in names
        assert "docker/build-push-action" in names

    def test_skips_local_actions(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/my-local-action
      - uses: actions/checkout@v4
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf})
            tools = detect_github_actions(root)
        names = [t["name"] for t in tools]
        assert "actions/checkout" in names
        assert not any(".github" in n for n in names)

    def test_detects_reusable_workflow(self):
        wf = """
on: [push]
jobs:
  call:
    uses: org/repo/.github/workflows/shared.yml@main
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf})
            tools = detect_github_actions(root)
        assert len(tools) == 1
        assert tools[0]["type"] == "github-reusable-workflow"
        assert tools[0]["name"] == "org/repo/.github/workflows/shared.yml"

    def test_extracts_version_ref(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf})
            tools = detect_github_actions(root)
        assert tools[0]["version"] == "11bd71901bbe5b1630ceea73d27597364c9af683"

    def test_no_workflows_dir(self):
        with TemporaryDirectory() as tmp:
            tools = detect_github_actions(Path(tmp))
        assert tools == []

    def test_source_location_recorded(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf})
            tools = detect_github_actions(root)
        assert tools[0]["sources"][0]["platform"] == "github-actions"
        assert tools[0]["sources"][0]["file"] == ".github/workflows/ci.yml"
        assert tools[0]["sources"][0]["ref"] == "actions/checkout@v4"

    def test_multiple_workflow_files(self):
        wf1 = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf2 = """
on: [push]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"ci.yml": wf1, "lint.yml": wf2})
            tools = detect_github_actions(root)
        names = [t["name"] for t in tools]
        assert "actions/checkout" in names
        assert "actions/setup-python" in names

    def test_malformed_yaml_skipped(self):
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, {"bad.yml": ": : invalid: yaml: ["})
            tools = detect_github_actions(root)
        assert tools == []


# ---------------------------------------------------------------------------
# GitLab CI detector tests
# ---------------------------------------------------------------------------


class TestDetectGitlabCI(unittest.TestCase):
    def _make_root(self, tmp: str, gitlab_ci: str, extra_files: dict = None) -> Path:
        root = Path(tmp)
        (root / ".gitlab-ci.yml").write_text(gitlab_ci)
        if extra_files:
            for path, content in extra_files.items():
                p = root / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
        return root

    def test_detects_top_level_image(self):
        ci = "image: python:3.12-slim\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        assert any(t["name"] == "python" and t["type"] == "gitlab-ci-image" for t in tools)

    def test_image_version_extracted(self):
        ci = "image: python:3.12-slim\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        img = next(t for t in tools if t["name"] == "python")
        assert img["version"] == "3.12-slim"

    def test_image_dict_form(self):
        ci = "image:\n  name: python:3.12-slim\n  entrypoint: ['']\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        assert any(t["name"] == "python" for t in tools)

    def test_detects_job_image(self):
        ci = """
stages: [build]
build:
  image: node:20
  script: ["npm ci"]
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        assert any(t["name"] == "node" and t["type"] == "gitlab-ci-image" for t in tools)

    def test_detects_component(self):
        ci = """
include:
  - component: gitlab.com/org/project/scan@1.0.0
stages: [test]
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        assert any(t["type"] == "gitlab-ci-component" and "scan" in t["name"] for t in tools)

    def test_component_version_extracted(self):
        ci = """
include:
  - component: gitlab.com/org/project/scan@1.0.0
stages: [test]
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        comp = next(t for t in tools if t["type"] == "gitlab-ci-component")
        assert comp["version"] == "1.0.0"

    def test_detects_pip_install(self):
        ci = """
stages: [test]
test:
  image: python:3.12
  script:
    - pip install trivy
    - trivy --version
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        assert any(t["name"] == "trivy" and t["type"] == "cli-tool" for t in tools)

    def test_follows_local_include(self):
        ci = """
include:
  - local: /ci/security.yml
stages: [test]
"""
        included = """
security:
  image: aquasec/trivy:latest
  script: ["trivy image myimage"]
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci, {"ci/security.yml": included})
            tools = detect_gitlab_ci(root)
        assert any(t["name"] == "aquasec/trivy" for t in tools)

    def test_no_gitlab_ci_file(self):
        with TemporaryDirectory() as tmp:
            tools = detect_gitlab_ci(Path(tmp))
        assert tools == []

    def test_skips_template_jobs(self):
        """Jobs starting with '.' are GitLab CI templates and should be skipped."""
        ci = """
stages: [test]
.template:
  image: hidden:image
test:
  image: python:3.12
  script: ["pytest"]
"""
        with TemporaryDirectory() as tmp:
            root = self._make_root(tmp, ci)
            tools = detect_gitlab_ci(root)
        names = [t["name"] for t in tools if t["type"] == "gitlab-ci-image"]
        assert "python" in names
        assert "hidden" not in names


# ---------------------------------------------------------------------------
# Platform detection tests
# ---------------------------------------------------------------------------


class TestDetectPlatforms(unittest.TestCase):
    def test_detects_github_actions(self):
        with TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            platforms = detect_platforms(Path(tmp))
        assert "github-actions" in platforms

    def test_detects_gitlab_ci(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / ".gitlab-ci.yml").write_text("stages: [test]\n")
            platforms = detect_platforms(Path(tmp))
        assert "gitlab-ci" in platforms

    def test_detects_both(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".gitlab-ci.yml").write_text("stages: [test]\n")
            platforms = detect_platforms(root)
        assert "github-actions" in platforms
        assert "gitlab-ci" in platforms

    def test_detects_none(self):
        with TemporaryDirectory() as tmp:
            assert detect_platforms(Path(tmp)) == []


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------


class TestDeduplicateDiscovered(unittest.TestCase):
    def test_same_tool_different_files_merged(self):
        tools = [
            {"name": "actions/checkout", "type": "github-action", "version": "v4",
             "sources": [{"platform": "github-actions", "file": "ci.yml", "ref": "actions/checkout@v4"}]},
            {"name": "actions/checkout", "type": "github-action", "version": "v4",
             "sources": [{"platform": "github-actions", "file": "release.yml", "ref": "actions/checkout@v4"}]},
        ]
        result = deduplicate_discovered(tools)
        assert len(result) == 1
        assert len(result[0]["sources"]) == 2

    def test_different_types_not_merged(self):
        tools = [
            {"name": "python", "type": "gitlab-ci-image", "sources": []},
            {"name": "python", "type": "cli-tool", "sources": []},
        ]
        result = deduplicate_discovered(tools)
        assert len(result) == 2

    def test_identical_sources_not_duplicated(self):
        src = {"platform": "github-actions", "file": "ci.yml", "ref": "actions/checkout@v4"}
        tools = [
            {"name": "actions/checkout", "type": "github-action", "sources": [src]},
            {"name": "actions/checkout", "type": "github-action", "sources": [src]},
        ]
        result = deduplicate_discovered(tools)
        assert len(result[0]["sources"]) == 1


# ---------------------------------------------------------------------------
# Merge with existing tests
# ---------------------------------------------------------------------------


class TestMergeWithExisting(unittest.TestCase):
    def test_new_tool_appended(self):
        existing = [{"name": "cosign", "type": "cli-tool", "sources": []}]
        discovered = [{"name": "trivy", "type": "cli-tool", "sources": []}]
        result = merge_with_existing(existing, discovered)
        assert len(result) == 2
        assert result[-1]["name"] == "trivy"

    def test_existing_source_appended(self):
        existing = [
            {"name": "actions/checkout", "type": "github-action",
             "sources": [{"platform": "github-actions", "file": "ci.yml", "ref": "actions/checkout@v4"}]}
        ]
        discovered = [
            {"name": "actions/checkout", "type": "github-action",
             "sources": [{"platform": "github-actions", "file": "release.yml", "ref": "actions/checkout@v4"}]}
        ]
        result = merge_with_existing(existing, discovered)
        assert len(result) == 1
        assert len(result[0]["sources"]) == 2

    def test_manually_set_fields_preserved(self):
        existing = [
            {"name": "actions/checkout", "type": "github-action",
             "versionConstraint": "^4", "category": "scm", "sources": []}
        ]
        discovered = [
            {"name": "actions/checkout", "type": "github-action",
             "sources": [{"platform": "github-actions", "file": "ci.yml", "ref": "actions/checkout@v4"}]}
        ]
        result = merge_with_existing(existing, discovered)
        assert result[0].get("versionConstraint") == "^4"
        assert result[0].get("category") == "scm"

    def test_duplicate_source_not_added(self):
        src = {"platform": "github-actions", "file": "ci.yml", "ref": "actions/checkout@v4"}
        existing = [{"name": "actions/checkout", "type": "github-action", "sources": [src]}]
        discovered = [{"name": "actions/checkout", "type": "github-action", "sources": [src]}]
        result = merge_with_existing(existing, discovered)
        assert len(result[0]["sources"]) == 1


# ---------------------------------------------------------------------------
# cmd_tools_enroll integration tests
# ---------------------------------------------------------------------------


class TestCmdToolsEnroll(unittest.TestCase):
    def _make_args(self, tmp, path=None, platform="auto", dry_run=False, tools_yaml=None):
        args = MagicMock()
        args.path = path or tmp
        args.platform = platform
        args.dry_run = dry_run
        args.tools_yaml = tools_yaml or str(Path(tmp) / "tools.yaml")
        return args

    def test_no_platforms_detected_returns_0(self):
        with TemporaryDirectory() as tmp:
            args = self._make_args(tmp)
            rc = cmd_tools_enroll(args)
        assert rc == 0

    def test_dry_run_does_not_write(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            args = self._make_args(tmp, dry_run=True)
            rc = cmd_tools_enroll(args)
            assert rc == 0
            assert not (root / "tools.yaml").exists()

    def test_writes_tools_yaml(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            args = self._make_args(tmp)
            rc = cmd_tools_enroll(args)
            assert rc == 0
            tools_yaml = root / "tools.yaml"
            assert tools_yaml.exists()
            data = yaml.safe_load(tools_yaml.read_text())
            assert isinstance(data, list)
            assert any(t["name"] == "actions/checkout" for t in data)

    def test_merges_with_existing_tools_yaml(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        existing = [{"name": "cosign", "type": "cli-tool", "version": "2.0.0", "sources": []}]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            tools_yaml = root / "tools.yaml"
            tools_yaml.write_text(yaml.dump(existing))
            args = self._make_args(tmp)
            rc = cmd_tools_enroll(args)
            assert rc == 0
            data = yaml.safe_load(tools_yaml.read_text())
            names = [t["name"] for t in data]
            assert "cosign" in names
            assert "actions/checkout" in names

    def test_platform_github_actions_only(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        gitlab_ci = "image: python:3.12\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            (root / ".gitlab-ci.yml").write_text(gitlab_ci)
            args = self._make_args(tmp, platform="github-actions")
            rc = cmd_tools_enroll(args)
            assert rc == 0
            data = yaml.safe_load((root / "tools.yaml").read_text())
            types = [t["type"] for t in data]
            assert "github-action" in types
            assert "gitlab-ci-image" not in types

    def test_platform_gitlab_ci_only(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        gitlab_ci = "image: python:3.12\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            (root / ".gitlab-ci.yml").write_text(gitlab_ci)
            args = self._make_args(tmp, platform="gitlab-ci")
            rc = cmd_tools_enroll(args)
            assert rc == 0
            data = yaml.safe_load((root / "tools.yaml").read_text())
            types = [t["type"] for t in data]
            assert "gitlab-ci-image" in types
            assert "github-action" not in types

    def test_invalid_path_returns_1(self):
        with TemporaryDirectory() as tmp:
            args = self._make_args(tmp, path="/nonexistent/path/does/not/exist")
            rc = cmd_tools_enroll(args)
        assert rc == 1

    def test_unknown_platform_returns_1(self):
        with TemporaryDirectory() as tmp:
            args = self._make_args(tmp, platform="circle-ci")
            rc = cmd_tools_enroll(args)
        assert rc == 1

    def test_auto_detects_both_platforms(self):
        wf = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        gitlab_ci = "image: python:3.12\nstages: [test]\n"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(wf)
            (root / ".gitlab-ci.yml").write_text(gitlab_ci)
            args = self._make_args(tmp)
            rc = cmd_tools_enroll(args)
            assert rc == 0
            data = yaml.safe_load((root / "tools.yaml").read_text())
            types = {t["type"] for t in data}
            assert "github-action" in types
            assert "gitlab-ci-image" in types


if __name__ == "__main__":
    unittest.main()
