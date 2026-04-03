#!/usr/bin/env python3
"""Unit tests for the generate_ci module."""

import sys
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from generate_ci import (
    load_images,
    build_image_workflow,
    ci_workflow,
    scheduled_scan_workflow,
    release_workflow,
    generate_ci,
)

SAMPLE_IMAGES = [
    {
        "name": "python-3.12-slim",
        "dockerfile": "images/python/3.12/Dockerfile",
        "registry": "ghcr.io/cascadeguard",
        "image": "python",
        "tag": "3.12-slim",
    },
    {
        "name": "node-20-slim",
        "dockerfile": "images/node/20/Dockerfile",
        "registry": "ghcr.io/cascadeguard",
        "image": "node",
        "tag": "20-slim",
    },
]


class TestLoadImages:
    def test_loads_valid_file(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text(yaml.dump(SAMPLE_IMAGES))
        result = load_images(f)
        assert len(result) == 2
        assert result[0]["name"] == "python-3.12-slim"

    def test_exits_on_missing_file(self, tmp_path):
        with pytest.raises(SystemExit):
            load_images(tmp_path / "missing.yaml")

    def test_returns_empty_list_for_empty_file(self, tmp_path):
        f = tmp_path / "images.yaml"
        f.write_text("")
        # load_images returns [] for empty file (yaml.safe_load returns None → [])
        # but exits because file does exist — need to handle the empty case
        result = load_images(f)
        assert result == []


class TestBuildImageWorkflow:
    def test_produces_valid_yaml(self):
        content = build_image_workflow(SAMPLE_IMAGES)
        # Should not raise
        parsed = yaml.safe_load(content)
        assert parsed["name"] == "build-image"

    def test_workflow_call_trigger(self):
        content = build_image_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "workflow_call" in parsed["on"]

    def test_has_required_inputs(self):
        content = build_image_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        inputs = parsed["on"]["workflow_call"]["inputs"]
        for field in ("name", "dockerfile", "registry", "image", "tag", "push", "sign"):
            assert field in inputs, f"Missing input: {field}"

    def test_has_build_scan_sign_steps(self):
        content = build_image_workflow(SAMPLE_IMAGES)
        step_names = [
            s.get("name", "") or s.get("uses", "")
            for s in content.split("\n")
            if "- name:" in s or "uses:" in s
        ]
        assert any("Grype" in n for n in content.split("\n"))
        assert any("Trivy" in n for n in content.split("\n"))
        assert any("Cosign" in n for n in content.split("\n"))
        assert any("SBOM" in n for n in content.split("\n"))


class TestCIWorkflow:
    def test_produces_valid_yaml(self):
        content = ci_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert parsed["name"] == "CI"

    def test_has_push_and_pr_triggers(self):
        content = ci_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "push" in parsed["on"]
        assert "pull_request" in parsed["on"]

    def test_matrix_contains_all_images(self):
        content = ci_workflow(SAMPLE_IMAGES)
        for img in SAMPLE_IMAGES:
            assert img["name"] in content

    def test_uses_build_image_workflow(self):
        content = ci_workflow(SAMPLE_IMAGES)
        assert "./.github/workflows/build-image.yaml" in content

    def test_single_image(self):
        content = ci_workflow([SAMPLE_IMAGES[0]])
        parsed = yaml.safe_load(content)
        assert parsed is not None  # valid YAML
        assert "python-3.12-slim" in content


class TestScheduledScanWorkflow:
    def test_produces_valid_yaml(self):
        content = scheduled_scan_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "Scheduled" in parsed["name"]

    def test_has_cron_trigger(self):
        content = scheduled_scan_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "schedule" in parsed["on"]

    def test_has_workflow_dispatch(self):
        content = scheduled_scan_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "workflow_dispatch" in parsed["on"]

    def test_matrix_contains_all_images(self):
        content = scheduled_scan_workflow(SAMPLE_IMAGES)
        for img in SAMPLE_IMAGES:
            assert img["name"] in content

    def test_opens_issue_on_failure(self):
        content = scheduled_scan_workflow(SAMPLE_IMAGES)
        assert "issues.create" in content


class TestReleaseWorkflow:
    def test_produces_valid_yaml(self):
        content = release_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert parsed["name"] == "Release"

    def test_triggered_on_tags(self):
        content = release_workflow(SAMPLE_IMAGES)
        parsed = yaml.safe_load(content)
        assert "tags" in parsed["on"]["push"]

    def test_matrix_contains_all_images(self):
        content = release_workflow(SAMPLE_IMAGES)
        for img in SAMPLE_IMAGES:
            assert img["name"] in content

    def test_creates_github_release(self):
        content = release_workflow(SAMPLE_IMAGES)
        assert "createRelease" in content


class TestGenerateCi:
    def test_creates_four_workflow_files(self, tmp_path):
        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump(SAMPLE_IMAGES))

        generate_ci(images_yaml_path=images_yaml, output_dir=tmp_path)

        workflows_dir = tmp_path / ".github" / "workflows"
        expected = {"ci.yaml", "build-image.yaml", "scheduled-scan.yaml", "release.yaml"}
        actual = {f.name for f in workflows_dir.iterdir()}
        assert expected == actual

    def test_dry_run_does_not_write_files(self, tmp_path):
        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump(SAMPLE_IMAGES))

        generate_ci(images_yaml_path=images_yaml, output_dir=tmp_path, dry_run=True)

        assert not (tmp_path / ".github").exists()

    def test_generated_workflows_are_valid_yaml(self, tmp_path):
        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump(SAMPLE_IMAGES))

        generate_ci(images_yaml_path=images_yaml, output_dir=tmp_path)

        workflows_dir = tmp_path / ".github" / "workflows"
        for wf_file in workflows_dir.iterdir():
            parsed = yaml.safe_load(wf_file.read_text())
            assert parsed is not None, f"{wf_file.name} is not valid YAML"
            assert "name" in parsed, f"{wf_file.name} missing 'name' field"

    def test_adding_image_updates_matrix(self, tmp_path):
        """Re-running generate-ci after adding a new image should include it in all workflows."""
        images_v1 = list(SAMPLE_IMAGES)
        images_yaml = tmp_path / "images.yaml"
        images_yaml.write_text(yaml.dump(images_v1))
        generate_ci(images_yaml_path=images_yaml, output_dir=tmp_path)

        # Add a new image and regenerate
        images_v2 = images_v1 + [
            {
                "name": "alpine-3.20",
                "dockerfile": "images/alpine/Dockerfile",
                "registry": "ghcr.io/cascadeguard",
                "image": "alpine",
                "tag": "3.20",
            }
        ]
        images_yaml.write_text(yaml.dump(images_v2))
        generate_ci(images_yaml_path=images_yaml, output_dir=tmp_path)

        workflows_dir = tmp_path / ".github" / "workflows"
        for wf_file in workflows_dir.iterdir():
            content = wf_file.read_text()
            assert "alpine-3.20" in content, (
                f"{wf_file.name} does not contain newly added image 'alpine-3.20'"
            )
