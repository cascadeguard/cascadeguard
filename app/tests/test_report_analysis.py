"""Tests for the _analyse_* analysis rules in scan/report.py."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scan.models import DiscoveredArtifact
from scan.report import (
    _analyse_actions,
    _analyse_compose,
    _analyse_dockerfile,
    _analyse_helm,
    _analyse_k8s,
    _analyse_kustomize,
    analyse,
    build_summary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _artifact(kind: str, path: str = "test/path", **details) -> DiscoveredArtifact:
    return DiscoveredArtifact(kind=kind, path=path, details=dict(details))


# ---------------------------------------------------------------------------
# _analyse_dockerfile
# ---------------------------------------------------------------------------

class TestAnalyseDockerfile:
    def test_pinned_digest_is_info(self):
        a = _artifact(
            "dockerfile",
            base_images=["python@sha256:abc123"],
            stages=[],
        )
        result = _analyse_dockerfile(a)
        assert result.risk_level == "info"
        assert any("pinned" in f for f in result.findings)

    def test_latest_tag_is_high(self):
        a = _artifact("dockerfile", base_images=["nginx:latest"], stages=[])
        result = _analyse_dockerfile(a)
        assert result.risk_level == "high"
        assert any("latest" in f for f in result.findings)

    def test_no_tag_is_high(self):
        a = _artifact("dockerfile", base_images=["nginx"], stages=[])
        result = _analyse_dockerfile(a)
        assert result.risk_level == "high"

    def test_mutable_tag_is_medium(self):
        a = _artifact("dockerfile", base_images=["python:3.12-slim"], stages=[])
        result = _analyse_dockerfile(a)
        assert result.risk_level == "medium"
        assert any("mutable" in f or "tag" in f for f in result.findings)

    def test_high_overrides_medium(self):
        a = _artifact(
            "dockerfile",
            base_images=["python:3.12-slim", "alpine:latest"],
            stages=[],
        )
        result = _analyse_dockerfile(a)
        assert result.risk_level == "high"

    def test_no_base_images_is_info(self):
        a = _artifact("dockerfile", base_images=[], stages=[])
        result = _analyse_dockerfile(a)
        assert result.risk_level == "info"

    def test_multistage_stages_noted(self):
        a = _artifact(
            "dockerfile",
            base_images=["golang:1.22", "gcr.io/distroless/base"],
            stages=["builder"],
        )
        result = _analyse_dockerfile(a)
        assert any("stage" in f.lower() for f in result.findings)

    def test_unpinned_produces_recommendation(self):
        a = _artifact("dockerfile", base_images=["nginx:1.25"], stages=[])
        result = _analyse_dockerfile(a)
        assert len(result.recommendations) > 0

    def test_all_pinned_no_recommendation(self):
        a = _artifact(
            "dockerfile",
            base_images=["python@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"],
            stages=[],
        )
        result = _analyse_dockerfile(a)
        assert result.recommendations == []


# ---------------------------------------------------------------------------
# _analyse_actions
# ---------------------------------------------------------------------------

class TestAnalyseActions:
    def _ref(self, action: str, ref: str, pinned: bool) -> dict:
        return {"action": action, "ref": ref, "pinned": pinned}

    def test_all_pinned_is_info(self):
        sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
        a = _artifact("actions", action_refs=[self._ref("actions/checkout", sha, True)])
        result = _analyse_actions(a)
        assert result.risk_level == "info"

    def test_unpinned_tag_is_medium(self):
        a = _artifact("actions", action_refs=[self._ref("actions/checkout", "v4", False)])
        result = _analyse_actions(a)
        assert result.risk_level == "medium"

    def test_branch_ref_is_high(self):
        a = _artifact("actions", action_refs=[self._ref("actions/checkout", "main", False)])
        result = _analyse_actions(a)
        assert result.risk_level == "high"
        assert any("branch" in f.lower() or "main" in f for f in result.findings)

    def test_master_ref_is_high(self):
        a = _artifact("actions", action_refs=[self._ref("actions/checkout", "master", False)])
        result = _analyse_actions(a)
        assert result.risk_level == "high"

    def test_high_overrides_medium(self):
        a = _artifact(
            "actions",
            action_refs=[
                self._ref("actions/checkout", "v4", False),
                self._ref("actions/upload-artifact", "main", False),
            ],
        )
        result = _analyse_actions(a)
        assert result.risk_level == "high"

    def test_no_action_refs(self):
        a = _artifact("actions", action_refs=[])
        result = _analyse_actions(a)
        assert result.risk_level == "info"

    def test_unpinned_produces_recommendation(self):
        a = _artifact("actions", action_refs=[self._ref("actions/checkout", "v4", False)])
        result = _analyse_actions(a)
        assert len(result.recommendations) > 0

    def test_count_in_findings(self):
        a = _artifact(
            "actions",
            action_refs=[
                self._ref("actions/checkout", "v4", False),
                self._ref("actions/setup-python", "11bd71901bbe5b1630ceea73d27597364c9af683", True),
            ],
        )
        result = _analyse_actions(a)
        assert any("2" in f and "1" in f for f in result.findings)


# ---------------------------------------------------------------------------
# _analyse_compose
# ---------------------------------------------------------------------------

class TestAnalyseCompose:
    def test_no_images_is_info(self):
        a = _artifact("compose", services=["web"], image_refs=[])
        result = _analyse_compose(a)
        assert result.risk_level == "info"

    def test_latest_tag_is_medium(self):
        a = _artifact("compose", services=["web"], image_refs=["nginx:latest"])
        result = _analyse_compose(a)
        assert result.risk_level == "medium"
        assert any("latest" in f for f in result.findings)

    def test_no_tag_is_medium(self):
        a = _artifact("compose", services=["web"], image_refs=["nginx"])
        result = _analyse_compose(a)
        assert result.risk_level == "medium"

    def test_pinned_digest_is_info(self):
        a = _artifact(
            "compose",
            services=["web"],
            image_refs=["nginx@sha256:abc123"],
        )
        result = _analyse_compose(a)
        assert result.risk_level == "info"

    def test_service_count_in_findings(self):
        a = _artifact("compose", services=["web", "db"], image_refs=["nginx:1", "postgres:16"])
        result = _analyse_compose(a)
        assert any("2" in f for f in result.findings)


# ---------------------------------------------------------------------------
# _analyse_helm
# ---------------------------------------------------------------------------

class TestAnalyseHelm:
    def test_no_images_is_info(self):
        a = _artifact(
            "helm",
            chart_name="myapp",
            chart_version="1.0.0",
            values_images=[],
            template_images=[],
            image_refs=[],
        )
        result = _analyse_helm(a)
        assert result.risk_level == "info"

    def test_values_images_noted(self):
        a = _artifact(
            "helm",
            chart_name="myapp",
            chart_version="1.0.0",
            values_images=["nginx:stable"],
            template_images=[],
            image_refs=["nginx:stable"],
        )
        result = _analyse_helm(a)
        assert any("values.yaml" in f for f in result.findings)

    def test_template_images_are_medium(self):
        a = _artifact(
            "helm",
            chart_name="myapp",
            chart_version="1.0.0",
            values_images=[],
            template_images=["nginx:1.25"],
            image_refs=["nginx:1.25"],
        )
        result = _analyse_helm(a)
        assert result.risk_level == "medium"
        assert any("hardcoded" in f.lower() or "templates" in f for f in result.findings)

    def test_latest_in_values_is_medium(self):
        a = _artifact(
            "helm",
            chart_name="myapp",
            chart_version="1.0.0",
            values_images=["nginx:latest"],
            template_images=[],
            image_refs=["nginx:latest"],
        )
        result = _analyse_helm(a)
        assert result.risk_level == "medium"


# ---------------------------------------------------------------------------
# _analyse_kustomize
# ---------------------------------------------------------------------------

class TestAnalyseKustomize:
    def test_no_images_is_info(self):
        a = _artifact("kustomize", images_transformer=[], resource_images=[], image_refs=[])
        result = _analyse_kustomize(a)
        assert result.risk_level == "info"

    def test_unpinned_resources_without_transformer_is_medium(self):
        a = _artifact(
            "kustomize",
            images_transformer=[],
            resource_images=["nginx:1.25"],
            image_refs=["nginx:1.25"],
        )
        result = _analyse_kustomize(a)
        assert result.risk_level == "medium"
        assert any("transformer" in f.lower() for f in result.findings)

    def test_transformer_present_covers_resources(self):
        a = _artifact(
            "kustomize",
            images_transformer=[{"name": "nginx", "newTag": "1.25"}],
            resource_images=["nginx:1.25"],
            image_refs=["nginx:1.25"],
        )
        result = _analyse_kustomize(a)
        # Transformer is present — risk stays info
        assert result.risk_level == "info"

    def test_transformer_noted_in_findings(self):
        a = _artifact(
            "kustomize",
            images_transformer=[{"name": "nginx", "newTag": "1.25"}],
            resource_images=[],
            image_refs=[],
        )
        result = _analyse_kustomize(a)
        assert any("override" in f.lower() or "transformer" in f.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# _analyse_k8s
# ---------------------------------------------------------------------------

class TestAnalyseK8s:
    def test_pinned_digest_is_info(self):
        a = _artifact("k8s", image_refs=["nginx@sha256:abc123"], resource_kind="Deployment")
        result = _analyse_k8s(a)
        assert result.risk_level == "info"

    def test_latest_tag_is_high(self):
        a = _artifact("k8s", image_refs=["nginx:latest"], resource_kind="Deployment")
        result = _analyse_k8s(a)
        assert result.risk_level == "high"

    def test_no_tag_is_high(self):
        a = _artifact("k8s", image_refs=["nginx"], resource_kind="Pod")
        result = _analyse_k8s(a)
        assert result.risk_level == "high"

    def test_mutable_tag_is_low(self):
        a = _artifact("k8s", image_refs=["nginx:1.25"], resource_kind="StatefulSet")
        result = _analyse_k8s(a)
        assert result.risk_level == "low"

    def test_high_overrides_low(self):
        a = _artifact(
            "k8s",
            image_refs=["nginx:1.25", "alpine:latest"],
            resource_kind="Deployment",
        )
        result = _analyse_k8s(a)
        assert result.risk_level == "high"

    def test_resource_kind_in_findings(self):
        a = _artifact("k8s", image_refs=["nginx:1.25"], resource_kind="DaemonSet")
        result = _analyse_k8s(a)
        assert any("DaemonSet" in f for f in result.findings)

    def test_unpinned_produces_recommendation(self):
        a = _artifact("k8s", image_refs=["nginx:1.25"], resource_kind="Deployment")
        result = _analyse_k8s(a)
        assert len(result.recommendations) > 0


# ---------------------------------------------------------------------------
# analyse() dispatcher
# ---------------------------------------------------------------------------

class TestAnalyseDispatcher:
    def test_dispatches_all_known_kinds(self):
        artifacts = [
            _artifact("dockerfile", base_images=[], stages=[]),
            _artifact("actions", action_refs=[]),
            _artifact("compose", services=[], image_refs=[]),
            _artifact(
                "helm",
                chart_name="x",
                chart_version="",
                values_images=[],
                template_images=[],
                image_refs=[],
            ),
            _artifact("kustomize", images_transformer=[], resource_images=[], image_refs=[]),
            _artifact("k8s", image_refs=[], resource_kind="Deployment"),
        ]
        results = analyse(artifacts)
        assert len(results) == 6
        for r in results:
            assert r.artifact is not None

    def test_unknown_kind_returns_empty_analysis(self):
        artifacts = [_artifact("unknown_kind")]
        results = analyse(artifacts)
        assert len(results) == 1
        assert results[0].findings == []
        assert results[0].risk_level == "info"


# ---------------------------------------------------------------------------
# build_summary
# ---------------------------------------------------------------------------

class TestBuildSummary:
    def test_counts_by_kind(self):
        discovered = [
            _artifact("dockerfile"),
            _artifact("actions"),
            _artifact("actions"),
        ]
        selected = discovered[:]
        analysis = analyse(selected)
        summary = build_summary(discovered, selected, analysis)
        assert summary.total_discovered == 3
        assert summary.total_selected == 3

    def test_counts_by_risk(self):
        artifacts = [
            _artifact("k8s", image_refs=["nginx:latest"], resource_kind="Deployment"),  # high
            _artifact("k8s", image_refs=["nginx:1.25"], resource_kind="Pod"),            # low
            _artifact("k8s", image_refs=[], resource_kind="Service"),                   # info
        ]
        analysis = analyse(artifacts)
        summary = build_summary(artifacts, artifacts, analysis)
        assert summary.by_risk.get("high", 0) >= 1
        assert summary.by_risk.get("low", 0) >= 1
