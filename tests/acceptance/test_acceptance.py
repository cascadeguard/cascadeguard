#!/usr/bin/env python3
"""
Acceptance tests for CascadeGuard CLI tools.

These tests exercise the tools end-to-end as a user would:
1. generate_state.py CLI — reads images.yaml, generates state files and workflows
2. cdk8s synth — reads state files, produces Kargo Kubernetes manifests
3. generate_ci.py CLI — reads images.yaml, emits GitHub Actions workflow files
"""
import pytest
import yaml
import subprocess
import sys
import os
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).parent.parent.parent


class TestGenerateStateCLI:
    """Acceptance tests for the generate_state.py CLI tool."""

    @pytest.fixture
    def workspace(self):
        """Create a temporary workspace with sample images.yaml and Dockerfiles."""
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output_dir = root / "state"
            output_dir.mkdir()

            # Create images.yaml with a mix of managed and external images
            images_yaml = root / "images.yaml"
            images_yaml.write_text(yaml.dump([
                {
                    'name': 'backstage',
                    'registry': 'ghcr.io',
                    'repository': 'cascadeguard/backstage',
                    'source': {
                        'provider': 'github',
                        'repo': 'cascadeguard/cascadeguard',
                        'branch': 'main',
                        'dockerfile': 'Dockerfile',
                    },
                    'rebuildDelay': '7d',
                    'autoRebuild': True,
                },
                {
                    'name': 'postgres',
                    'registry': 'docker.io',
                    'repository': 'library/postgres',
                    'allowTags': '^16-alpine$',
                    'imageSelectionStrategy': 'Lexical',
                    'rebuildDelay': '30d',
                    'autoRebuild': False,
                },
            ]))

            # Create a Dockerfile for the managed image in the cache
            # (skip git clone by placing it directly)
            cache_dir = root / "cache" / "cascadeguard_cascadeguard"
            cache_dir.mkdir(parents=True)
            (cache_dir / "Dockerfile").write_text(
                "FROM node:22-bookworm-slim AS builder\n"
                "WORKDIR /app\n"
                "COPY . .\n"
                "RUN npm install\n"
                "\n"
                "FROM gcr.io/distroless/nodejs22-debian12:latest\n"
                "COPY --from=builder /app /app\n"
            )

            yield {
                'root': root,
                'images_yaml': images_yaml,
                'output_dir': output_dir,
                'cache_dir': root / "cache",
            }

    def test_cli_generates_state_files(self, workspace):
        """Run generate_state.py CLI and verify it creates state files."""
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "app" / "generate_state.py"),
                "--images-yaml", str(workspace['images_yaml']),
                "--output-dir", str(workspace['output_dir']),
                "--cache-dir", str(workspace['cache_dir']),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # Verify managed image state files were created
        images_dir = workspace['output_dir'] / "images"
        assert (images_dir / "backstage.yaml").exists(), "backstage state file not created"

        # Verify base image state files were created for images.yaml entries without source
        base_dir = workspace['output_dir'] / "base-images"
        assert (base_dir / "postgres.yaml").exists(), "postgres state file not created"

        # Discovered base images from Dockerfile parsing are referenced by name
        # in the app image's baseImages field, not as separate state files

        # Verify backstage state content
        with open(images_dir / "backstage.yaml") as f:
            content = f.read()
        assert "name: backstage" in content
        assert "node-22-bookworm-slim" in content
        assert "CascadeGuard" in content

        # Verify postgres (external, no source) state content
        with open(base_dir / "postgres.yaml") as f:
            data = yaml.safe_load(f)
        assert data['name'] == 'postgres'

    def test_cli_generates_build_workflows(self, workspace):
        """Run generate_state.py CLI and verify workflow generation."""
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "app" / "generate_state.py"),
                "--images-yaml", str(workspace['images_yaml']),
                "--output-dir", str(workspace['output_dir']),
                "--cache-dir", str(workspace['cache_dir']),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed:\nstderr: {result.stderr}"

        # Only managed images with source (no workflow key) get build workflows
        workflow = workspace['output_dir'] / ".github" / "workflows" / "build-backstage.yml"
        assert workflow.exists(), "Build workflow for backstage not generated"

        content = workflow.read_text()
        assert "# Auto-generated by CascadeGuard" in content
        assert "Build backstage" in content
        assert "ghcr.io" in content

        # External images should NOT get workflows
        postgres_wf = workspace['output_dir'] / ".github" / "workflows" / "build-postgres.yml"
        assert not postgres_wf.exists(), "External image should not get a build workflow"

    def test_cli_idempotent(self, workspace):
        """Running the CLI twice produces the same output."""
        cmd = [
            sys.executable,
            str(REPO_ROOT / "app" / "generate_state.py"),
            "--images-yaml", str(workspace['images_yaml']),
            "--output-dir", str(workspace['output_dir']),
            "--cache-dir", str(workspace['cache_dir']),
        ]

        # First run
        r1 = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert r1.returncode == 0

        state_file = workspace['output_dir'] / "images" / "backstage.yaml"
        with open(state_file) as f:
            content1 = f.read()

        # Second run — should not change files
        r2 = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert r2.returncode == 0
        assert "No changes" in r2.stdout or "skipping" in r2.stdout.lower()

    def test_cli_missing_images_yaml(self):
        """CLI exits with error when images.yaml doesn't exist."""
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "app" / "generate_state.py"),
                "--images-yaml", "/nonexistent/images.yaml",
                "--output-dir", "/tmp/out",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0


class TestCdk8sSynth:
    """Acceptance tests for CDK8s synthesis of Kargo manifests."""

    @pytest.fixture
    def state_workspace(self):
        """Create a temporary state directory with sample state files."""
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)

            # Create images.yaml
            images_yaml = root / "images.yaml"
            images_yaml.write_text(yaml.dump([
                {
                    'name': 'backstage',
                    'registry': 'ghcr.io',
                    'repository': 'cascadeguard/backstage',
                    'source': {
                        'provider': 'github',
                        'repo': 'cascadeguard/cascadeguard',
                        'branch': 'main',
                        'dockerfile': 'apps/backstage/Dockerfile',
                    },
                },
                {
                    'name': 'postgres',
                    'registry': 'docker.io',
                    'repository': 'library/postgres',
                    'allowTags': '^16-alpine$',
                    'repoURL': 'docker.io/library/postgres',
                    'imageSelectionStrategy': 'Lexical',
                },
            ]))

            # Create state/images
            images_dir = root / "images"
            images_dir.mkdir()
            (images_dir / "backstage.yaml").write_text(yaml.dump({
                'name': 'backstage',
                'enrollment': {
                    'registry': 'ghcr.io',
                    'repository': 'cascadeguard/backstage',
                    'source': {
                        'provider': 'github',
                        'repo': 'cascadeguard/cascadeguard',
                        'branch': 'main',
                        'dockerfile': 'apps/backstage/Dockerfile',
                    },
                },
                'baseImages': ['node-22-bookworm-slim'],
                'discoveryStatus': 'pending',
            }))

            # Create state/base-images
            base_dir = root / "base-images"
            base_dir.mkdir()
            (base_dir / "node-22-bookworm-slim.yaml").write_text(yaml.dump({
                'name': 'node-22-bookworm-slim',
                'repoURL': 'docker.io/library/node',
                'allowTags': '^22-bookworm-slim$',
                'imageSelectionStrategy': 'Lexical',
            }))

            # Output directory
            output_dir = root / "dist" / "cdk8s"
            output_dir.mkdir(parents=True)

            yield {
                'root': root,
                'images_yaml': images_yaml,
                'images_dir': images_dir,
                'base_dir': base_dir,
                'output_dir': output_dir,
            }

    def test_cdk8s_synth_produces_valid_yaml(self, state_workspace):
        """Run CDK8s synth and verify it produces valid Kubernetes YAML."""
        cdk8s_dir = REPO_ROOT / "cdk8s"

        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(cdk8s_dir),
            env={
                **os.environ,
                'CASCADEGUARD_STATE_DIR': str(state_workspace['root']),
                'IMAGES_YAML': str(state_workspace['images_yaml']),
                'CDK8S_OUTDIR': str(state_workspace['output_dir']),
            },
        )

        assert result.returncode == 0, f"CDK8s synth failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # Find generated YAML files
        yaml_files = list(state_workspace['output_dir'].glob("*.k8s.yaml"))
        assert len(yaml_files) > 0, "No .k8s.yaml files generated"

        # Parse all generated manifests and verify they are valid YAML
        all_manifests = []
        for yaml_file in yaml_files:
            with open(yaml_file) as f:
                docs = list(yaml.safe_load_all(f))
                all_manifests.extend([d for d in docs if d is not None])

        assert len(all_manifests) > 0, "No Kubernetes manifests in generated YAML"

        # Verify we get expected resource types
        kinds = {m.get('kind') for m in all_manifests if m}
        assert 'Warehouse' in kinds, f"No Warehouse resources found. Got kinds: {kinds}"

        # Verify all resources have required metadata
        for manifest in all_manifests:
            assert 'apiVersion' in manifest, f"Missing apiVersion in {manifest.get('kind', 'unknown')}"
            assert 'kind' in manifest
            assert 'metadata' in manifest
            assert 'name' in manifest['metadata']

    def test_cdk8s_synth_creates_warehouse_for_base_image(self, state_workspace):
        """Verify CDK8s creates a Warehouse for base images."""
        cdk8s_dir = REPO_ROOT / "cdk8s"

        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(cdk8s_dir),
            env={
                **os.environ,
                'CASCADEGUARD_STATE_DIR': str(state_workspace['root']),
                'IMAGES_YAML': str(state_workspace['images_yaml']),
                'CDK8S_OUTDIR': str(state_workspace['output_dir']),
            },
        )

        assert result.returncode == 0

        yaml_files = list(state_workspace['output_dir'].glob("*.k8s.yaml"))
        all_manifests = []
        for yaml_file in yaml_files:
            with open(yaml_file) as f:
                all_manifests.extend([d for d in yaml.safe_load_all(f) if d])

        # Find node warehouse
        warehouses = [m for m in all_manifests if m.get('kind') == 'Warehouse']
        warehouse_names = {w['metadata']['name'] for w in warehouses}

        assert 'node-22-bookworm-slim' in warehouse_names, \
            f"Base image warehouse not found. Warehouses: {warehouse_names}"

        # Verify warehouse spec
        node_wh = next(w for w in warehouses if w['metadata']['name'] == 'node-22-bookworm-slim')
        subs = node_wh['spec']['subscriptions']
        assert len(subs) > 0
        image_sub = subs[0].get('image', {})
        assert image_sub.get('repoURL') == 'docker.io/library/node'


class TestGenerateCICLI:
    """
    Acceptance tests for the generate_ci.py CLI tool.

    How users invoke generate-ci
    =============================
    Users run the command explicitly when they want to (re-)generate their
    GitHub Actions workflows — typically after enrolling a new image or during
    initial repo setup:

      # Via Taskfile (recommended — wraps the Docker image):
      task generate-ci

      # Via Docker directly:
      docker run --rm -v $(pwd):/workspace \\
          ghcr.io/cascadeguard/cascadeguard:v1.0.0 generate-ci

      # In CI (e.g. to verify workflows are up-to-date):
      python app/generate_ci.py --images-yaml images.yaml --output-dir . --dry-run

    There is no automatic trigger today; adding an image to images.yaml and
    re-running generate-ci is the recommended workflow.
    """

    FIXTURE_DIR = Path(__file__).parent / "fixtures" / "generate-ci"
    EXPECTED_WORKFLOWS = {
        "ci.yaml",
        "build-image.yaml",
        "scheduled-scan.yaml",
        "release.yaml",
    }

    @pytest.fixture
    def workspace(self, tmp_path):
        """Copy the fixture images.yaml into a temp workspace directory."""
        import shutil
        shutil.copy(self.FIXTURE_DIR / "images.yaml", tmp_path / "images.yaml")
        return tmp_path

    def _run_generate_ci(self, workspace: Path, extra_args=None):
        """Invoke generate_ci.py as a subprocess (mirrors how Docker entrypoint calls it)."""
        cmd = [
            sys.executable,
            str(REPO_ROOT / "app" / "generate_ci.py"),
            "--images-yaml", str(workspace / "images.yaml"),
            "--output-dir", str(workspace),
        ]
        if extra_args:
            cmd.extend(extra_args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_cli_exits_zero(self, workspace):
        """generate_ci.py exits 0 on a valid images.yaml."""
        result = self._run_generate_ci(workspace)
        assert result.returncode == 0, (
            f"generate_ci.py failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_creates_all_four_workflow_files(self, workspace):
        """Running generate-ci produces exactly the four expected workflow files."""
        result = self._run_generate_ci(workspace)
        assert result.returncode == 0, result.stderr

        workflows_dir = workspace / ".github" / "workflows"
        assert workflows_dir.is_dir(), ".github/workflows/ directory was not created"

        actual = {f.name for f in workflows_dir.iterdir()}
        assert actual == self.EXPECTED_WORKFLOWS, (
            f"Expected {self.EXPECTED_WORKFLOWS}, got {actual}"
        )

    def test_all_generated_files_are_valid_yaml(self, workspace):
        """Every generated workflow file must be parseable as valid YAML."""
        self._run_generate_ci(workspace)
        workflows_dir = workspace / ".github" / "workflows"

        for wf_file in workflows_dir.iterdir():
            content = wf_file.read_text()
            try:
                parsed = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                pytest.fail(f"{wf_file.name} is not valid YAML: {exc}")
            assert parsed is not None, f"{wf_file.name} parsed to None"
            assert "name" in parsed, f"{wf_file.name} missing 'name' field"
            assert "on" in parsed, f"{wf_file.name} missing 'on' (trigger) field"
            assert "jobs" in parsed, f"{wf_file.name} missing 'jobs' field"

    def test_ci_workflow_matrix_includes_all_fixture_images(self, workspace):
        """ci.yaml matrix must contain every image defined in the fixture images.yaml."""
        self._run_generate_ci(workspace)
        ci_file = workspace / ".github" / "workflows" / "ci.yaml"
        content = ci_file.read_text()

        fixture_images = yaml.safe_load((workspace / "images.yaml").read_text())
        for img in fixture_images:
            assert img["name"] in content, (
                f"Image '{img['name']}' not found in ci.yaml matrix"
            )

    def test_build_image_workflow_is_workflow_call(self, workspace):
        """build-image.yaml must be a reusable workflow (workflow_call trigger)."""
        self._run_generate_ci(workspace)
        wf = yaml.safe_load(
            (workspace / ".github" / "workflows" / "build-image.yaml").read_text()
        )
        assert "workflow_call" in wf["on"], (
            "build-image.yaml must use the workflow_call trigger"
        )

    def test_ci_workflow_calls_build_image(self, workspace):
        """ci.yaml must delegate to build-image.yaml via uses:."""
        self._run_generate_ci(workspace)
        content = (workspace / ".github" / "workflows" / "ci.yaml").read_text()
        assert "./.github/workflows/build-image.yaml" in content

    def test_scheduled_scan_has_cron_trigger(self, workspace):
        """scheduled-scan.yaml must include a schedule/cron trigger."""
        self._run_generate_ci(workspace)
        wf = yaml.safe_load(
            (workspace / ".github" / "workflows" / "scheduled-scan.yaml").read_text()
        )
        assert "schedule" in wf["on"], "scheduled-scan.yaml missing schedule trigger"
        crons = [entry.get("cron") for entry in wf["on"]["schedule"]]
        assert any(crons), "scheduled-scan.yaml has no cron expression"

    def test_release_workflow_triggered_on_version_tags(self, workspace):
        """release.yaml must trigger on version tag pushes (v*)."""
        self._run_generate_ci(workspace)
        wf = yaml.safe_load(
            (workspace / ".github" / "workflows" / "release.yaml").read_text()
        )
        tags = wf["on"]["push"].get("tags", [])
        assert any("v*" in t for t in tags), (
            f"release.yaml push trigger lacks 'v*' tag pattern; got: {tags}"
        )

    def test_adding_image_updates_all_workflows(self, workspace):
        """Re-running generate-ci after adding an image must include it in all four workflows."""
        # First generation with 2 images
        self._run_generate_ci(workspace)

        # Add a third image to the fixture
        images = yaml.safe_load((workspace / "images.yaml").read_text())
        images.append({
            "name": "alpine-3.20",
            "dockerfile": "images/alpine/Dockerfile",
            "registry": "ghcr.io/acme",
            "image": "alpine",
            "tag": "3.20",
        })
        (workspace / "images.yaml").write_text(yaml.dump(images))

        # Re-generate
        result = self._run_generate_ci(workspace)
        assert result.returncode == 0, result.stderr

        workflows_dir = workspace / ".github" / "workflows"
        for wf_file in workflows_dir.iterdir():
            content = wf_file.read_text()
            assert "alpine-3.20" in content, (
                f"Newly added image 'alpine-3.20' not found in {wf_file.name} after re-generation"
            )

    def test_dry_run_does_not_write_files(self, workspace):
        """--dry-run flag must not create any files."""
        result = self._run_generate_ci(workspace, extra_args=["--dry-run"])
        assert result.returncode == 0, result.stderr
        assert not (workspace / ".github").exists(), (
            "--dry-run should not create .github/workflows/"
        )

    def test_stdout_reports_written_files(self, workspace):
        """generate_ci.py must print the paths of files it writes."""
        result = self._run_generate_ci(workspace)
        assert result.returncode == 0, result.stderr
        for wf_name in self.EXPECTED_WORKFLOWS:
            assert wf_name in result.stdout, (
                f"Expected '{wf_name}' to appear in stdout; got:\n{result.stdout}"
            )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
