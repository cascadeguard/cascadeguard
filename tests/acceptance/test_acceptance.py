#!/usr/bin/env python3
"""
Acceptance tests for CascadeGuard CLI tools.

These tests exercise the tools end-to-end as a user would:
1. generate_state.py CLI — reads images.yaml, generates state files and workflows
2. cdk8s synth — reads state files, produces Kargo Kubernetes manifests
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

        # Since PR#78, all enrolled images (including registry-tracked ones without
        # a dockerfile) go to images/. The base-images/ dir is now reserved exclusively
        # for images discovered from Dockerfile FROM statements during check runs.
        assert (images_dir / "postgres.yaml").exists(), "postgres state file not created"

        # Discovered base images from Dockerfile parsing are referenced by name
        # in the app image's baseImages field, not as separate state files

        # Verify backstage state content
        with open(images_dir / "backstage.yaml") as f:
            content = f.read()
        assert "name: backstage" in content
        assert "node-22-bookworm-slim" in content
        assert "CascadeGuard" in content

        # Verify postgres (external, no dockerfile) state content
        with open(images_dir / "postgres.yaml") as f:
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



ACTIONS_PIN_FIXTURE = Path(__file__).parent / "fixtures" / "actions-pin"


class TestActionsPinCLI:
    """Acceptance tests for `cascadeguard actions pin` using a fixture repo."""

    @pytest.fixture
    def repo(self):
        """Copy the actions-pin fixture into a temp dir so tests can mutate it."""
        import shutil

        with TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "repo"
            shutil.copytree(ACTIONS_PIN_FIXTURE, dest)
            yield dest

    @staticmethod
    def _run_actions_pin(repo, extra_args=None):
        workflows_dir = repo / ".github" / "workflows"
        cmd = [
            sys.executable,
            str(REPO_ROOT / "app" / "app.py"),
            "actions", "pin",
            "--workflows-dir", str(workflows_dir),
        ]
        if extra_args:
            cmd.extend(extra_args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={**os.environ, "GITHUB_TOKEN": ""},
            cwd=str(repo),
        )

    def test_dry_run_reports_counts_without_modifying(self, repo):
        """--dry-run prints summary but leaves files untouched."""
        wf = repo / ".github" / "workflows" / "ci.yml"
        original = wf.read_text()

        result = self._run_actions_pin(repo, ["--dry-run"])
        assert result.returncode == 0, f"Unexpected failure:\n{result.stderr}"
        assert "Dry run" in result.stdout
        assert "Actions pinned:" in result.stdout

        # Files must be unchanged
        assert wf.read_text() == original

    def test_pin_with_mock_resolver(self, repo):
        """End-to-end pin using ActionsPinner directly on the fixture repo."""
        sys.path.insert(0, str(REPO_ROOT / "app"))
        from app import ActionsPinner

        workflows_dir = repo / ".github" / "workflows"
        sha_map = {
            "actions/checkout@v4": "a" * 40,
            "actions/setup-python@v5": "b" * 40,
            "actions/upload-artifact@v4": "c" * 40,
            "github/super-linter@v6": "d" * 40,
            "actions/setup-node@v4": "e" * 40,
            "softprops/action-gh-release@v2": "f" * 40,
        }

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = lambda owner_repo, ref: sha_map.get(f"{owner_repo}@{ref}")

        summary = pinner.pin()

        # ci.yml: checkout(x2), setup-python, upload-artifact, super-linter = 5 mutable
        # release.yml: setup-node, action-gh-release = 2 mutable
        # Total mutable pinned: 7
        assert summary["pinned"] == 7
        # release.yml checkout is already pinned to a SHA
        assert summary["already_pinned"] == 1
        # ci.yml has one local action (./.github/actions/local-lint)
        assert summary["skipped"] == 1

        # Verify ci.yml content
        ci_content = (workflows_dir / "ci.yml").read_text()
        assert f"actions/checkout@{'a' * 40} # v4" in ci_content
        assert f"actions/setup-python@{'b' * 40} # v5" in ci_content
        assert f"actions/upload-artifact@{'c' * 40} # v4" in ci_content
        assert f"github/super-linter@{'d' * 40} # v6" in ci_content
        # Local action untouched
        assert "./.github/actions/local-lint" in ci_content

        # Verify release.yml content
        release_content = (workflows_dir / "release.yml").read_text()
        assert f"actions/setup-node@{'e' * 40} # v4" in release_content
        assert f"softprops/action-gh-release@{'f' * 40} # v2" in release_content
        # Already-pinned checkout SHA preserved (no update flag)
        assert "b4ffde65f46336ab88eb53be808477a3936bae11" in release_content

    def test_update_repins_existing_sha(self, repo):
        """--update re-resolves already-pinned SHAs to the latest for their tag."""
        sys.path.insert(0, str(REPO_ROOT / "app"))
        from app import ActionsPinner

        workflows_dir = repo / ".github" / "workflows"
        new_checkout_sha = "1" * 40

        def resolve(owner_repo, ref):
            if owner_repo == "actions/checkout" and ref == "v4":
                return new_checkout_sha
            return None

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = resolve

        summary = pinner.pin(update=True)

        # The already-pinned checkout in release.yml should be re-pinned
        release_content = (workflows_dir / "release.yml").read_text()
        assert f"actions/checkout@{new_checkout_sha} # v4" in release_content
        assert "b4ffde65f46336ab88eb53be808477a3936bae11" not in release_content

    def test_idempotent_second_pin(self, repo):
        """Pinning twice without --update reports all as already_pinned."""
        sys.path.insert(0, str(REPO_ROOT / "app"))
        from app import ActionsPinner

        workflows_dir = repo / ".github" / "workflows"

        pinner = ActionsPinner(token="", workflows_dir=workflows_dir)
        pinner._resolve_sha = lambda owner_repo, ref: "a" * 40

        # First pass — pin everything
        pinner.pin()

        # Second pass — all should be already_pinned
        pinner2 = ActionsPinner(token="", workflows_dir=workflows_dir)
        summary = pinner2.pin(update=False)

        assert summary["pinned"] == 0
        assert summary["already_pinned"] >= 7
        assert summary["skipped"] >= 1

    def test_missing_workflows_dir_exits_nonzero(self):
        """CLI exits non-zero when the workflows directory does not exist."""
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "app" / "app.py"),
                "actions", "pin",
                "--workflows-dir", "/nonexistent/.github/workflows",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
