"""Fixture-based tests for scan discovery modules."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scan.discoverers import (
    ActionsDiscoverer,
    ComposeDiscoverer,
    DockerfileDiscoverer,
    HelmDiscoverer,
    KubernetesDiscoverer,
    KustomizeDiscoverer,
    _is_excluded,
    _rglob_filtered,
    discover_all,
)
from scan.models import DiscoveredArtifact


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write(path: Path, content: str) -> Path:
    """Write text to *path*, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))
    return path


# ---------------------------------------------------------------------------
# _is_excluded / _rglob_filtered
# ---------------------------------------------------------------------------

class TestIsExcluded:
    def test_excluded_dirs(self):
        assert _is_excluded(Path(".git/config"))
        assert _is_excluded(Path("node_modules/foo/bar"))
        assert _is_excluded(Path("vendor/pkg"))
        assert _is_excluded(Path("__pycache__/mod.pyc"))

    def test_not_excluded(self):
        assert not _is_excluded(Path("app/Dockerfile"))
        assert not _is_excluded(Path("docker/Dockerfile"))
        assert not _is_excluded(Path("src/config.yaml"))


class TestRglobFiltered:
    def test_skips_excluded(self, tmp_path):
        write(tmp_path / ".git" / "config", "gitfile")
        write(tmp_path / "node_modules" / "pkg" / "Dockerfile", "FROM node")
        write(tmp_path / "app" / "Dockerfile", "FROM python")

        results = _rglob_filtered(tmp_path, "**/Dockerfile")
        paths = [str(r.relative_to(tmp_path)) for r in results]
        assert any("app/Dockerfile" in p for p in paths)
        assert not any("node_modules" in p for p in paths)
        assert not any(".git" in p for p in paths)


# ---------------------------------------------------------------------------
# DockerfileDiscoverer
# ---------------------------------------------------------------------------

class TestDockerfileDiscoverer:
    def setup_method(self):
        self.d = DockerfileDiscoverer()

    def test_discovers_dockerfile(self, tmp_path):
        write(tmp_path / "Dockerfile", "FROM python:3.12-slim\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert results[0].kind == "dockerfile"
        assert results[0].path == "Dockerfile"

    def test_discovers_nested_dockerfile(self, tmp_path):
        write(tmp_path / "services" / "api" / "Dockerfile", "FROM node:20-alpine\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert "services/api/Dockerfile" in results[0].path

    def test_discovers_dockerfile_dot_extension(self, tmp_path):
        write(tmp_path / "prod.dockerfile", "FROM alpine:3.20\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 1

    def test_extracts_base_images(self, tmp_path):
        write(tmp_path / "Dockerfile", "FROM python:3.12-slim\nRUN apt-get update\n")
        results = self.d.discover(tmp_path)
        assert "python:3.12-slim" in results[0].details["base_images"]

    def test_extracts_pinned_digest(self, tmp_path):
        write(
            tmp_path / "Dockerfile",
            "FROM python@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1\n",
        )
        results = self.d.discover(tmp_path)
        bases = results[0].details["base_images"]
        assert any("sha256:" in b for b in bases)

    def test_multistage_dockerfile(self, tmp_path):
        write(
            tmp_path / "Dockerfile",
            """\
            FROM golang:1.22 AS builder
            RUN go build ./...
            FROM gcr.io/distroless/base
            COPY --from=builder /app /app
            """,
        )
        results = self.d.discover(tmp_path)
        details = results[0].details
        assert "builder" in details["stages"]
        # scratch and stage aliases should not appear as base images
        assert "builder" not in details["base_images"]
        assert "golang:1.22" in details["base_images"]
        assert "gcr.io/distroless/base" in details["base_images"]

    def test_skips_scratch(self, tmp_path):
        write(tmp_path / "Dockerfile", "FROM scratch\nCOPY binary /binary\n")
        results = self.d.discover(tmp_path)
        assert "scratch" not in results[0].details.get("base_images", [])

    def test_no_dockerfiles(self, tmp_path):
        assert self.d.discover(tmp_path) == []

    def test_deduplicates_same_file(self, tmp_path):
        write(tmp_path / "Dockerfile", "FROM alpine\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 1

    def test_skips_excluded_dirs(self, tmp_path):
        write(tmp_path / "node_modules" / "app" / "Dockerfile", "FROM node\n")
        write(tmp_path / "app" / "Dockerfile", "FROM python\n")
        results = self.d.discover(tmp_path)
        paths = [r.path for r in results]
        assert not any("node_modules" in p for p in paths)

    def test_containerfile(self, tmp_path):
        write(tmp_path / "Containerfile", "FROM fedora:39\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# ActionsDiscoverer
# ---------------------------------------------------------------------------

class TestActionsDiscoverer:
    def setup_method(self):
        self.d = ActionsDiscoverer()

    def _workflow(self, tmp_path: Path, name: str, content: str) -> Path:
        return write(tmp_path / ".github" / "workflows" / name, content)

    def test_no_workflows_dir(self, tmp_path):
        assert self.d.discover(tmp_path) == []

    def test_skips_file_with_no_uses(self, tmp_path):
        self._workflow(tmp_path, "ci.yml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        assert self.d.discover(tmp_path) == []

    def test_detects_unpinned_action(self, tmp_path):
        self._workflow(
            tmp_path, "ci.yml",
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        refs = results[0].details["action_refs"]
        assert len(refs) == 1
        assert refs[0]["action"] == "actions/checkout"
        assert refs[0]["pinned"] is False

    def test_detects_pinned_action(self, tmp_path):
        sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
        self._workflow(
            tmp_path, "ci.yml",
            f"name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"
        )
        results = self.d.discover(tmp_path)
        refs = results[0].details["action_refs"]
        assert refs[0]["pinned"] is True

    def test_skips_local_actions(self, tmp_path):
        self._workflow(
            tmp_path, "ci.yml",
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local-action\n"
        )
        # Local actions are skipped; if no other refs, artifact is excluded
        assert self.d.discover(tmp_path) == []

    def test_multiple_workflows(self, tmp_path):
        self._workflow(tmp_path, "ci.yml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        self._workflow(tmp_path, "release.yml", "name: Release\non: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 2

    def test_workflow_name_extracted(self, tmp_path):
        self._workflow(
            tmp_path, "ci.yml",
            "name: My CI Workflow\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        )
        results = self.d.discover(tmp_path)
        assert results[0].details["workflow_name"] == "My CI Workflow"

    def test_path_relative_to_root(self, tmp_path):
        self._workflow(tmp_path, "ci.yml", "name: CI\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        results = self.d.discover(tmp_path)
        assert results[0].path == ".github/workflows/ci.yml"


# ---------------------------------------------------------------------------
# ComposeDiscoverer
# ---------------------------------------------------------------------------

class TestComposeDiscoverer:
    def setup_method(self):
        self.d = ComposeDiscoverer()

    def test_discovers_compose(self, tmp_path):
        write(
            tmp_path / "docker-compose.yml",
            """\
            services:
              web:
                image: nginx:stable
              db:
                image: postgres:16-alpine
            """,
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        details = results[0].details
        assert "web" in details["services"]
        assert "db" in details["services"]
        assert "nginx:stable" in details["image_refs"]
        assert "postgres:16-alpine" in details["image_refs"]

    def test_skips_no_services(self, tmp_path):
        write(tmp_path / "docker-compose.yml", "version: '3'\n")
        assert self.d.discover(tmp_path) == []

    def test_compose_override_file(self, tmp_path):
        write(
            tmp_path / "docker-compose.override.yml",
            "services:\n  web:\n    image: nginx:latest\n",
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1

    def test_nested_compose(self, tmp_path):
        write(
            tmp_path / "infra" / "docker-compose.yml",
            "services:\n  proxy:\n    image: traefik:v3\n",
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert "infra/docker-compose.yml" in results[0].path

    def test_no_image_refs(self, tmp_path):
        write(
            tmp_path / "docker-compose.yml",
            "services:\n  web:\n    build: .\n",
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert results[0].details["image_refs"] == []


# ---------------------------------------------------------------------------
# HelmDiscoverer
# ---------------------------------------------------------------------------

class TestHelmDiscoverer:
    def setup_method(self):
        self.d = HelmDiscoverer()

    def _chart(self, tmp_path: Path, name="myapp", version="1.0.0", values: str = "") -> Path:
        chart_dir = tmp_path / "charts" / name
        write(chart_dir / "Chart.yaml", f"name: {name}\nversion: {version}\n")
        if values:
            write(chart_dir / "values.yaml", values)
        return chart_dir

    def test_discovers_chart(self, tmp_path):
        self._chart(tmp_path)
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert results[0].kind == "helm"
        assert results[0].details["chart_name"] == "myapp"

    def test_extracts_values_images(self, tmp_path):
        self._chart(
            tmp_path,
            values="image:\n  repository: docker.io/library/nginx\n  tag: stable\n",
        )
        results = self.d.discover(tmp_path)
        assert any("nginx" in img for img in results[0].details["values_images"])

    def test_extracts_template_images(self, tmp_path):
        chart_dir = self._chart(tmp_path)
        write(
            chart_dir / "templates" / "deployment.yaml",
            "spec:\n  containers:\n  - image: redis:7-alpine\n",
        )
        results = self.d.discover(tmp_path)
        assert "redis:7-alpine" in results[0].details["template_images"]

    def test_skips_go_template_expressions(self, tmp_path):
        chart_dir = self._chart(tmp_path)
        write(
            chart_dir / "templates" / "deployment.yaml",
            "spec:\n  containers:\n  - image: {{ .Values.image }}\n",
        )
        results = self.d.discover(tmp_path)
        assert results[0].details["template_images"] == []

    def test_no_charts(self, tmp_path):
        assert self.d.discover(tmp_path) == []


# ---------------------------------------------------------------------------
# KustomizeDiscoverer
# ---------------------------------------------------------------------------

class TestKustomizeDiscoverer:
    def setup_method(self):
        self.d = KustomizeDiscoverer()

    def test_discovers_kustomization(self, tmp_path):
        write(
            tmp_path / "kustomization.yaml",
            "resources:\n  - deployment.yaml\n",
        )
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert results[0].kind == "kustomize"

    def test_extracts_images_transformer(self, tmp_path):
        write(
            tmp_path / "kustomization.yaml",
            """\
            resources:
              - deployment.yaml
            images:
              - name: nginx
                newTag: "1.25"
            """,
        )
        results = self.d.discover(tmp_path)
        transformer = results[0].details["images_transformer"]
        assert len(transformer) == 1
        assert transformer[0]["name"] == "nginx"

    def test_extracts_resource_images(self, tmp_path):
        write(tmp_path / "kustomization.yaml", "resources:\n  - deployment.yaml\n")
        write(
            tmp_path / "deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: myapp:1.0.0\n",
        )
        results = self.d.discover(tmp_path)
        assert "myapp:1.0.0" in results[0].details["resource_images"]

    def test_nested_overlays(self, tmp_path):
        write(tmp_path / "base" / "kustomization.yaml", "resources:\n  - deployment.yaml\n")
        write(tmp_path / "overlays" / "prod" / "kustomization.yaml", "resources:\n  - ../../base\n")
        results = self.d.discover(tmp_path)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# KubernetesDiscoverer
# ---------------------------------------------------------------------------

class TestKubernetesDiscoverer:
    def setup_method(self):
        self.d = KubernetesDiscoverer()

    def _deployment(self, image: str = "nginx:1.25") -> str:
        return textwrap.dedent(f"""\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: app
            spec:
              template:
                spec:
                  containers:
                  - name: app
                    image: {image}
        """)

    def test_discovers_k8s_manifest(self, tmp_path):
        write(tmp_path / "deploy.yaml", self._deployment())
        results = self.d.discover(tmp_path)
        assert len(results) == 1
        assert results[0].kind == "k8s"
        assert results[0].details["resource_kind"] == "Deployment"

    def test_extracts_images(self, tmp_path):
        write(tmp_path / "deploy.yaml", self._deployment("myapp:1.0.0"))
        results = self.d.discover(tmp_path)
        assert "myapp:1.0.0" in results[0].details["image_refs"]

    def test_skips_non_k8s_yaml(self, tmp_path):
        write(tmp_path / "config.yaml", "key: value\nanother: thing\n")
        assert self.d.discover(tmp_path) == []

    def test_skips_github_workflows(self, tmp_path):
        write(
            tmp_path / ".github" / "workflows" / "ci.yml",
            "name: CI\non: push\n",
        )
        results = self.d.discover(tmp_path)
        assert results == []

    def test_claimed_paths_excluded(self, tmp_path):
        p = write(tmp_path / "deploy.yaml", self._deployment())
        self.d.set_claimed_paths({p.resolve()})
        results = self.d.discover(tmp_path)
        assert results == []

    def test_multidoc_yaml(self, tmp_path):
        write(
            tmp_path / "resources.yaml",
            textwrap.dedent("""\
                apiVersion: apps/v1
                kind: Deployment
                metadata:
                  name: app
                spec:
                  template:
                    spec:
                      containers:
                      - name: app
                        image: nginx:1.25
                ---
                apiVersion: v1
                kind: Service
                metadata:
                  name: app-svc
                spec:
                  selector:
                    app: app
            """),
        )
        results = self.d.discover(tmp_path)
        # Only the Deployment has images
        kinds = [r.details["resource_kind"] for r in results]
        assert "Deployment" in kinds


# ---------------------------------------------------------------------------
# discover_all integration
# ---------------------------------------------------------------------------

class TestDiscoverAll:
    def test_mixed_repo(self, tmp_path):
        # Dockerfile
        write(tmp_path / "Dockerfile", "FROM python:3.12-slim\n")
        # Actions workflow
        write(
            tmp_path / ".github" / "workflows" / "ci.yml",
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        # Compose
        write(tmp_path / "docker-compose.yml", "services:\n  web:\n    image: nginx:stable\n")

        results = discover_all(tmp_path)
        kinds = {a.kind for a in results}
        assert "dockerfile" in kinds
        assert "actions" in kinds
        assert "compose" in kinds

    def test_empty_dir(self, tmp_path):
        assert discover_all(tmp_path) == []

    def test_k8s_files_not_double_counted(self, tmp_path):
        # A chart directory should be claimed by HelmDiscoverer, not re-discovered by K8sDiscoverer
        chart_dir = tmp_path / "charts" / "app"
        write(chart_dir / "Chart.yaml", "name: app\nversion: 1.0.0\n")
        write(
            chart_dir / "templates" / "deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n      - image: nginx\n",
        )

        results = discover_all(tmp_path)
        helm_results = [r for r in results if r.kind == "helm"]
        k8s_results = [r for r in results if r.kind == "k8s"]
        assert len(helm_results) == 1
        assert len(k8s_results) == 0
