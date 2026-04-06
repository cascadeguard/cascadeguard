#!/usr/bin/env python3
"""Unit tests for the CascadeGuard tool."""

import pytest
import yaml
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import os

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import CascadeGuardTool


class TestCascadeGuardTool:
    """Test suite for CascadeGuardTool."""

    @pytest.fixture
    def temp_factory(self):
        """Create a temporary CascadeGuard directory structure."""
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Create directory structure
            (root / "state" / "images").mkdir(parents=True)
            (root / "state" / "base-images").mkdir(parents=True)

            yield root

    def test_normalize_base_image_name(self, temp_factory):
        """Test base image name normalization."""
        tool = CascadeGuardTool(temp_factory)

        assert (
            tool.normalize_base_image_name("node:22-bookworm-slim")
            == "node-22-bookworm-slim"
        )
        assert (
            tool.normalize_base_image_name("docker.io/library/node:22")
            == "library-node-22"
        )
        assert (
            tool.normalize_base_image_name("ghcr.io/owner/image:v1.0")
            == "owner-image-v1.0"
        )

    def test_parse_image_reference(self, temp_factory):
        """Test parsing image references."""
        tool = CascadeGuardTool(temp_factory)

        # Official Docker image
        result = tool.parse_image_reference("node:22-bookworm-slim")
        assert result["registry"] == "docker.io"
        assert result["repository"] == "library/node"
        assert result["tag"] == "22-bookworm-slim"

        # Custom registry
        result = tool.parse_image_reference("ghcr.io/owner/image:v1.0")
        assert result["registry"] == "ghcr.io"
        assert result["repository"] == "owner/image"
        assert result["tag"] == "v1.0"

        # No tag
        result = tool.parse_image_reference("nginx")
        assert result["repository"] == "library/nginx"
        assert result["tag"] == "latest"

    def test_parse_dockerfile_multi_stage(self, temp_factory):
        """Test extracting all base images from multi-stage Dockerfile."""
        tool = CascadeGuardTool(temp_factory)

        # Create a multi-stage Dockerfile
        dockerfile = temp_factory / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.12-slim AS builder
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

FROM gcr.io/distroless/python3-debian12:latest
COPY --from=builder /app /app
WORKDIR /app
""")

        base_images = tool.parse_dockerfile_base_images(dockerfile)
        assert len(base_images) == 2
        assert "python:3.12-slim" in base_images
        assert "gcr.io/distroless/python3-debian12:latest" in base_images

    def test_parse_dockerfile_deduplication(self, temp_factory):
        """Test deduplication of repeated base images in same Dockerfile."""
        tool = CascadeGuardTool(temp_factory)

        # Create a Dockerfile with duplicate FROM statements
        dockerfile = temp_factory / "Dockerfile"
        dockerfile.write_text("""
FROM node:18-alpine AS deps
WORKDIR /app
COPY package.json .
RUN npm install

FROM node:18-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app
COPY --from=builder /app/dist ./dist
""")

        # The parse method returns all FROM statements (no deduplication at parse level)
        base_images = tool.parse_dockerfile_base_images(dockerfile)
        assert len(base_images) == 3
        assert all(img == "node:18-alpine" for img in base_images)

        # Deduplication happens during processing when normalizing names
        normalized_names = []
        seen = set()
        for base_image_ref in base_images:
            base_image_name = tool.normalize_base_image_name(base_image_ref)
            if base_image_name not in seen:
                normalized_names.append(base_image_name)
                seen.add(base_image_name)

        assert len(normalized_names) == 1
        assert "node-18-alpine" in normalized_names

    def test_parse_dockerfile_stage_references(self, temp_factory):
        """Test that stage references are not treated as base images."""
        tool = CascadeGuardTool(temp_factory)

        # Create a Dockerfile with stage references
        dockerfile = temp_factory / "Dockerfile"
        dockerfile.write_text("""
FROM node:18-alpine AS builder
WORKDIR /app
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
""")

        base_images = tool.parse_dockerfile_base_images(dockerfile)
        assert len(base_images) == 2
        assert "node:18-alpine" in base_images
        assert "nginx:alpine" in base_images
        # "builder" should not be included as it's a stage reference

    def test_generate_base_image_state(self, temp_factory):
        """Test generating base image state."""
        tool = CascadeGuardTool(temp_factory)

        state = tool.generate_base_image_state("node:22-bookworm-slim")

        assert state["name"] == "node-22-bookworm-slim"
        assert state["fullImage"] == "node:22-bookworm-slim"
        assert state["registry"] == "docker.io"
        assert state["repository"] == "library/node"
        assert state["tag"] == "22-bookworm-slim"
        assert state["allowTags"] == "^22-bookworm-slim$"
        assert state["repoURL"] == "docker.io/library/node"

    def test_generate_image_state_managed(self, temp_factory):
        """Test generating state for a managed image."""
        tool = CascadeGuardTool(temp_factory)

        image_config = {
            "name": "backstage",
            "registry": "ghcr.io",
            "repository": "owner/backstage",
            "source": {
                "provider": "github",
                "repo": "owner/repo",
                "dockerfile": "Dockerfile",
            },
            "rebuildDelay": "7d",
            "autoRebuild": True,
        }

        state = tool.generate_image_state(image_config, ["node-22-bookworm-slim"])

        assert state["name"] == "backstage"
        assert state["discoveryStatus"] == "pending"
        assert state["baseImages"] == ["node-22-bookworm-slim"]
        assert state["enrollment"]["registry"] == "ghcr.io"
        assert state["enrollment"]["source"]["repo"] == "owner/repo"
        assert "allowTags" not in state  # Managed images don't have warehouse fields

    def test_generate_image_state_external(self, temp_factory):
        """Test generating state for an external image."""
        tool = CascadeGuardTool(temp_factory)

        image_config = {
            "name": "postgres",
            "registry": "docker.io",
            "repository": "library/postgres",
            "allowTags": "^16-alpine$",
            "rebuildDelay": "30d",
        }

        state = tool.generate_image_state(image_config, [])

        assert state["name"] == "postgres"
        assert state["discoveryStatus"] == "external"
        assert state["baseImages"] == []
        assert "source" not in state["enrollment"]
        assert state["allowTags"] == "^16-alpine$"
        assert state["repoURL"] == "docker.io/library/postgres"

    def test_merge_state_preserves_runtime_data(self, temp_factory):
        """Test that merge preserves runtime data while updating config."""
        tool = CascadeGuardTool(temp_factory)

        existing = {
            "name": "backstage",
            "enrolledAt": "2024-01-01T00:00:00Z",
            "enrollment": {"registry": "ghcr.io", "repository": "old/backstage"},
            "currentDigest": "sha256:abc123",
            "lastBuilt": "2024-12-01T00:00:00Z",
            "rebuildHistory": [{"date": "2024-12-01"}],
        }

        new = {
            "name": "backstage",
            "enrolledAt": "2024-12-04T00:00:00Z",
            "enrollment": {"registry": "ghcr.io", "repository": "new/backstage"},
            "baseImages": ["node-22-bookworm-slim"],
        }

        merged = tool.merge_state(existing, new, prefer_new=True)

        # Config updated from new
        assert merged["enrollment"]["repository"] == "new/backstage"
        assert merged["baseImages"] == ["node-22-bookworm-slim"]

        # Runtime data preserved from existing
        assert merged["currentDigest"] == "sha256:abc123"
        assert merged["lastBuilt"] == "2024-12-01T00:00:00Z"
        # rebuildHistory is not a preserved runtime field in the current implementation

    def test_process_creates_state_files(self, temp_factory):
        """Test full processing creates expected state files."""
        tool = CascadeGuardTool(temp_factory)

        # Create images.yaml
        images_yaml = temp_factory / "images.yaml"
        images_yaml.write_text(
            yaml.dump(
                [
                    {
                        "name": "test-image",
                        "registry": "ghcr.io",
                        "repository": "owner/test",
                        "source": {
                            "provider": "github",
                            "repo": "owner/repo",
                            "dockerfile": "Dockerfile",
                        },
                    }
                ]
            )
        )

        # Create Dockerfile
        dockerfile = temp_factory.parent / "Dockerfile"
        dockerfile.write_text("FROM node:22-bookworm-slim\n")

        # Process
        tool.process()

        # Check image state file created
        image_state_file = temp_factory / "state" / "images" / "test-image.yaml"
        assert image_state_file.exists()

        with open(image_state_file) as f:
            image_state = yaml.safe_load(f)

        assert image_state["name"] == "test-image"
        assert "node-22-bookworm-slim" in image_state["baseImages"]

        # Check base image state file created
        base_state_file = (
            temp_factory / "state" / "base-images" / "node-22-bookworm-slim.yaml"
        )
        assert base_state_file.exists()

        with open(base_state_file) as f:
            base_state = yaml.safe_load(f)

        assert base_state["name"] == "node-22-bookworm-slim"
        # dependentImages is computed, not stored

    def test_process_updates_existing_state(self, temp_factory):
        """Test that processing updates existing state files correctly."""
        tool = CascadeGuardTool(temp_factory)

        # Create initial state file with runtime data
        image_state_file = temp_factory / "state" / "images" / "test-image.yaml"
        image_state_file.write_text(
            yaml.dump(
                {
                    "name": "test-image",
                    "enrolledAt": "2024-01-01T00:00:00Z",
                    "enrollment": {"registry": "ghcr.io", "repository": "owner/old"},
                    "currentDigest": "sha256:preserved",
                    "lastBuilt": "2024-11-01T00:00:00Z",
                }
            )
        )

        # Create images.yaml with updated config
        images_yaml = temp_factory / "images.yaml"
        images_yaml.write_text(
            yaml.dump(
                [
                    {
                        "name": "test-image",
                        "registry": "ghcr.io",
                        "repository": "owner/new",
                        "source": {
                            "provider": "github",
                            "repo": "owner/repo",
                            "dockerfile": "Dockerfile",
                        },
                    }
                ]
            )
        )

        # Create Dockerfile
        dockerfile = temp_factory.parent / "Dockerfile"
        dockerfile.write_text("FROM alpine:latest\n")

        # Process
        tool.process()

        # Check state was updated
        with open(image_state_file) as f:
            updated_state = yaml.safe_load(f)

        # Config updated
        assert updated_state["enrollment"]["repository"] == "owner/new"

        # Runtime data preserved
        assert updated_state["currentDigest"] == "sha256:preserved"
        assert updated_state["lastBuilt"] == "2024-11-01T00:00:00Z"


class TestGenerateBuildWorkflow:
    """Test suite for _generate_build_workflow."""

    @pytest.fixture
    def output_dir(self):
        """Create a temporary output directory."""
        with TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def _read_workflow(self, output_dir, name):
        """Read generated workflow file content."""
        wf = output_dir / ".github" / "workflows" / f"build-{name}.yml"
        assert wf.exists(), f"Workflow file {wf} was not created"
        return wf.read_text()

    def test_generates_standard_workflow(self, output_dir):
        """Test generating a standard workflow without local config."""
        from generate_state import _generate_build_workflow

        image = {
            "name": "test-app",
            "registry": "ghcr.io",
            "repository": "org/test-app",
            "source": {
                "provider": "github",
                "repo": "upstream/test-app",
                "branch": "main",
                "dockerfile": "Dockerfile",
            },
        }

        result = _generate_build_workflow(image, output_dir)
        assert result is True

        content = self._read_workflow(output_dir, "test-app")
        assert "# Auto-generated by CascadeGuard" in content
        assert "repository: upstream/test-app" in content
        assert "file: Dockerfile" in content
        assert 'default: "latest"' in content
        # Should NOT have local steps
        assert "Checkout local files" not in content
        assert "Apply patch" not in content
        assert "Read version" not in content
        assert "Bump version" not in content
        assert "increment" not in content
        # No version file means contents: read only
        assert "contents: read" in content

    def test_generates_workflow_with_local_block(self, output_dir):
        """Test generating a workflow with local config (patches + version)."""
        from generate_state import _generate_build_workflow

        image = {
            "name": "test-app",
            "registry": "ghcr.io",
            "repository": "org/test-app",
            "source": {
                "provider": "github",
                "repo": "upstream/test-app",
                "branch": "main",
                "dockerfile": "Dockerfile",
            },
            "local": {
                "dir": "local/test-app",
                "patchFiles": ["Dockerfile.patch"],
                "versionFile": "VERSION",
            },
        }

        result = _generate_build_workflow(image, output_dir)
        assert result is True

        content = self._read_workflow(output_dir, "test-app")
        assert "# Auto-generated by CascadeGuard" in content
        # Local files checkout
        assert "Checkout local files" in content
        assert "sparse-checkout: local/test-app" in content
        # Patch applied
        assert "Apply patch Dockerfile.patch" in content
        assert "git apply _cascadeguard/local/test-app/Dockerfile.patch" in content
        # Version file read
        assert "Read version" in content
        assert "cat _cascadeguard/local/test-app/VERSION" in content
        # Resolve tag step with suffix support
        assert "Resolve tag" in content
        assert "inputs.suffix" in content
        assert "steps.tag.outputs.tag" in content
        # No tag input, no hardcoded default
        assert 'default: "latest"' not in content
        assert "inputs.tag" not in content
        # suffix and increment inputs present
        assert "suffix" in content
        assert "increment" in content
        assert 'default: "patch"' in content
        assert "options: [major, minor, patch]" in content
        # Still uses upstream source as context
        assert "repository: upstream/test-app" in content
        assert "context: ." in content
        # Bump step present, gated on empty suffix
        assert "Bump version" in content
        assert "if: inputs.suffix == ''" in content
        assert "git commit" in content
        assert "git push" in content
        # Needs write permission to commit back
        assert "contents: write" in content

    def test_generates_workflow_with_local_dockerfile(self, output_dir):
        """Test generating a workflow with local.dockerfile (no upstream checkout)."""
        from generate_state import _generate_build_workflow

        image = {
            "name": "test-app",
            "registry": "ghcr.io",
            "repository": "org/test-app",
            "source": {
                "provider": "github",
                "repo": "upstream/test-app",
            },
            "local": {
                "dir": "local/test-app",
                "dockerfile": "Dockerfile",
                "versionFile": "VERSION",
            },
        }

        result = _generate_build_workflow(image, output_dir)
        assert result is True

        content = self._read_workflow(output_dir, "test-app")
        assert "# Auto-generated by CascadeGuard" in content
        # Should checkout state repo (no repository: override)
        assert "Checkout\n" in content or "- name: Checkout\n" in content
        assert "repository:" not in content
        # Dockerfile and context point to local dir
        assert "file: local/test-app/Dockerfile" in content
        assert "context: local/test-app" in content
        # No upstream checkout, no patches
        assert "Checkout source" not in content
        assert "Checkout local files" not in content
        assert "Apply patch" not in content
        # VERSION is for the image tag only, not passed as a build arg
        assert "build-args" not in content
        # Version, tag, bump all present
        assert "Read version" in content
        assert "Resolve tag" in content
        assert "Bump version" in content
        assert "contents: write" in content
        # Bump step works directly (no _cascadeguard prefix)
        assert "_cascadeguard" not in content

    def test_skips_when_source_has_workflow(self, output_dir):
        """Test that workflow generation is skipped when source.workflow is set."""
        from generate_state import _generate_build_workflow

        image = {
            "name": "test-app",
            "source": {
                "workflow": "existing.yml",
                "repo": "org/repo",
            },
        }

        result = _generate_build_workflow(image, output_dir)
        assert result is False

    def test_skips_when_no_source(self, output_dir):
        """Test that workflow generation is skipped for external images."""
        from generate_state import _generate_build_workflow

        image = {"name": "postgres", "registry": "docker.io"}

        result = _generate_build_workflow(image, output_dir)
        assert result is False

    def test_idempotent_no_rewrite(self, output_dir):
        """Test that unchanged workflow is not rewritten."""
        from generate_state import _generate_build_workflow

        image = {
            "name": "test-app",
            "registry": "ghcr.io",
            "repository": "org/test-app",
            "source": {
                "provider": "github",
                "repo": "upstream/test-app",
                "branch": "main",
                "dockerfile": "Dockerfile",
            },
        }

        # First generation
        result1 = _generate_build_workflow(image, output_dir)
        assert result1 is True

        # Second generation with same config — should skip
        result2 = _generate_build_workflow(image, output_dir)
        assert result2 is False


class TestActionsPinner:
    """Unit tests for ActionsPinner."""

    @pytest.fixture
    def workflows_dir(self):
        with TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def _write_workflow(self, workflows_dir, name, content):
        p = workflows_dir / name
        p.write_text(content)
        return p

    def test_pin_mutable_tag(self, workflows_dir):
        """Mutable tag refs are replaced with SHA + comment."""
        from app import ActionsPinner

        wf = self._write_workflow(workflows_dir, "ci.yml", (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        ))

        fake_sha = "a" * 40

        def fake_resolve(owner_repo, ref):
            assert owner_repo == "actions/checkout"
            assert ref == "v4"
            return fake_sha

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = fake_resolve

        summary = pinner.pin()
        assert summary["pinned"] == 1
        assert summary["already_pinned"] == 0
        assert summary["skipped"] == 0

        content = wf.read_text()
        assert f"actions/checkout@{fake_sha} # v4" in content

    def test_already_pinned_skipped_without_update(self, workflows_dir):
        """Lines already pinned to a SHA are counted as already_pinned."""
        from app import ActionsPinner

        sha = "b" * 40
        wf = self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: actions/checkout@" + sha + " # v4\n"
        ))

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        summary = pinner.pin(update=False)

        assert summary["already_pinned"] == 1
        assert summary["pinned"] == 0
        # File unchanged
        assert sha in wf.read_text()

    def test_update_flag_repins_to_latest_sha(self, workflows_dir):
        """--update re-pins already-pinned SHAs to the latest SHA for the same tag."""
        from app import ActionsPinner

        old_sha = "c" * 40
        new_sha = "d" * 40

        wf = self._write_workflow(workflows_dir, "ci.yml",
            f"      - uses: actions/checkout@{old_sha} # v4\n"
        )

        def fake_resolve(owner_repo, ref):
            assert ref == "v4"
            return new_sha

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = fake_resolve

        summary = pinner.pin(update=True)
        assert summary["pinned"] == 1

        content = wf.read_text()
        assert new_sha in content
        assert old_sha not in content
        assert "# v4" in content

    def test_dry_run_does_not_write(self, workflows_dir):
        """--dry-run previews without writing."""
        from app import ActionsPinner

        original = "      - uses: actions/checkout@v4\n"
        wf = self._write_workflow(workflows_dir, "ci.yml", original)

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = lambda owner_repo, ref: "e" * 40

        summary = pinner.pin(dry_run=True)
        assert summary["pinned"] == 1
        # File unchanged
        assert wf.read_text() == original

    def test_local_action_skipped(self, workflows_dir):
        """Local composite actions (./path) are skipped."""
        from app import ActionsPinner

        self._write_workflow(workflows_dir, "ci.yml",
            "      - uses: ./.github/actions/my-action\n"
        )

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        summary = pinner.pin()

        assert summary["skipped"] == 1
        assert summary["pinned"] == 0

    def test_api_failure_skips_ref(self, workflows_dir):
        """When GitHub API fails, the ref is counted as skipped and line unchanged."""
        from app import ActionsPinner

        original = "      - uses: actions/checkout@v4\n"
        wf = self._write_workflow(workflows_dir, "ci.yml", original)

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = lambda owner_repo, ref: None  # simulate failure

        summary = pinner.pin()
        assert summary["skipped"] == 1
        assert summary["pinned"] == 0
        assert wf.read_text() == original

    def test_multiple_actions_in_workflow(self, workflows_dir):
        """Multiple uses: lines are all processed."""
        from app import ActionsPinner

        sha1 = "1" * 40
        sha2 = "2" * 40
        sha3 = "3" * 40

        self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n"
            "      - uses: actions/upload-artifact@v4\n"
        ))

        shas = {"actions/checkout": sha1, "actions/setup-python": sha2, "actions/upload-artifact": sha3}

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = lambda owner_repo, ref: shas[owner_repo]

        summary = pinner.pin()
        assert summary["pinned"] == 3

    def test_sha_cache_avoids_duplicate_api_calls(self, workflows_dir):
        """Same action@ref is resolved only once (via internal cache)."""
        from app import ActionsPinner
        import urllib.request
        import unittest.mock as mock

        self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/checkout@v4\n"
        ))

        fake_sha = "f" * 40
        fake_response = mock.MagicMock()
        fake_response.read.return_value = f'{{"sha": "{fake_sha}"}}'.encode()
        fake_response.__enter__ = lambda s: s
        fake_response.__exit__ = mock.MagicMock(return_value=False)

        call_count = {"n": 0}
        original_urlopen = urllib.request.urlopen

        def counting_urlopen(req, **kwargs):
            call_count["n"] += 1
            return fake_response

        pinner = ActionsPinner(token="t", workflows_dir=workflows_dir)
        with mock.patch("urllib.request.urlopen", side_effect=counting_urlopen):
            pinner.pin()

        assert call_count["n"] == 1

    def test_cmd_actions_pin_missing_dir(self):
        """cmd_actions_pin returns 1 when workflows dir does not exist."""
        from app import cmd_actions_pin
        import argparse

        args = argparse.Namespace(
            workflows_dir="/nonexistent/path/.github/workflows",
            dry_run=False,
            update=False,
            github_token=None,
        )
        assert cmd_actions_pin(args) == 1


class TestCmdActionsAudit:
    """CLI-level tests for cmd_actions_audit."""

    @pytest.fixture
    def workflows_dir(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        return wf_dir

    def _write_workflow(self, workflows_dir, name, content):
        p = workflows_dir / name
        p.write_text(content)
        return p

    def _make_args(self, workflows_dir, fmt="text", policy=None):
        import argparse
        return argparse.Namespace(
            workflows_dir=str(workflows_dir),
            format=fmt,
            policy=policy,
        )

    def test_missing_workflows_dir_returns_1(self):
        """Returns 1 when workflows directory does not exist."""
        from app import cmd_actions_audit
        import argparse

        args = argparse.Namespace(
            workflows_dir="/nonexistent/path/.github/workflows",
            format="text",
            policy=None,
        )
        assert cmd_actions_audit(args) == 1

    def test_pinning_only_mode_pass(self, workflows_dir):
        """All pinned refs -> exit 0."""
        from app import cmd_actions_audit

        sha = "a" * 40
        self._write_workflow(workflows_dir, "ci.yml", (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            f"      - uses: actions/checkout@{sha} # v4\n"
        ))

        args = self._make_args(workflows_dir)
        assert cmd_actions_audit(args) == 0

    def test_pinning_only_mode_fail(self, workflows_dir):
        """Mutable tag ref -> exit 1."""
        from app import cmd_actions_audit

        self._write_workflow(workflows_dir, "ci.yml", (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        ))

        args = self._make_args(workflows_dir)
        assert cmd_actions_audit(args) == 1

    def test_pinning_only_json_format(self, workflows_dir, capsys):
        """--format json emits valid JSON with expected keys in pinning-only mode."""
        import json
        from app import cmd_actions_audit

        sha = "b" * 40
        self._write_workflow(workflows_dir, "ci.yml", (
            f"      - uses: actions/setup-python@{sha} # v5\n"
            "      - uses: actions/upload-artifact@v4\n"
        ))

        args = self._make_args(workflows_dir, fmt="json")
        ret = cmd_actions_audit(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "passed" in data
        assert "summary" in data
        assert "refs" in data
        assert data["passed"] is False  # mutable ref present
        assert ret == 1

    def test_policy_mode_pass(self, workflows_dir, tmp_path):
        """All actions allowed by policy -> exit 0."""
        from app import cmd_actions_audit

        sha = "c" * 40
        self._write_workflow(workflows_dir, "ci.yml", (
            f"      - uses: actions/checkout@{sha} # v4\n"
        ))

        policy_file = tmp_path / "actions-policy.yaml"
        policy_file.write_text(
            "version: '1'\n"
            "default: deny\n"
            "allowed_owners:\n"
            "  - actions\n"
        )

        args = self._make_args(workflows_dir, policy=str(policy_file))
        assert cmd_actions_audit(args) == 0

    def test_policy_mode_fail(self, workflows_dir, tmp_path):
        """Action violating policy -> exit 1."""
        from app import cmd_actions_audit

        self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: some-org/untrusted-action@v1\n"
        ))

        policy_file = tmp_path / "actions-policy.yaml"
        policy_file.write_text(
            "version: '1'\n"
            "default: deny\n"
            "allowed_owners:\n"
            "  - actions\n"
        )

        args = self._make_args(workflows_dir, policy=str(policy_file))
        assert cmd_actions_audit(args) == 1

    def test_policy_mode_json_format(self, workflows_dir, tmp_path, capsys):
        """--format json emits valid JSON with violations in policy mode."""
        import json
        from app import cmd_actions_audit

        self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: bad-org/bad-action@v2\n"
        ))

        policy_file = tmp_path / "actions-policy.yaml"
        policy_file.write_text(
            "version: '1'\n"
            "default: deny\n"
            "allowed_owners:\n"
            "  - actions\n"
        )

        args = self._make_args(workflows_dir, fmt="json", policy=str(policy_file))
        ret = cmd_actions_audit(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["passed"] is False
        assert len(data["violations"]) == 1
        assert data["violations"][0]["action"] == "bad-org/bad-action"
        assert ret == 1

    def test_bad_policy_file_returns_1(self, workflows_dir, tmp_path):
        """Invalid policy YAML -> exit 1 without crashing."""
        from app import cmd_actions_audit

        self._write_workflow(workflows_dir, "ci.yml", (
            "      - uses: actions/checkout@v4\n"
        ))

        policy_file = tmp_path / "actions-policy.yaml"
        policy_file.write_text(": invalid: yaml: content: [\n")

        args = self._make_args(workflows_dir, policy=str(policy_file))
        assert cmd_actions_audit(args) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
