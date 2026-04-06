"""Analysis engine and output formatting for scan results."""

from __future__ import annotations
import json
from datetime import datetime, timezone

from .models import DiscoveredArtifact, ArtifactAnalysis, ScanResult, ScanSummary


# ---------------------------------------------------------------------------
# Analysis rules per artifact kind
# ---------------------------------------------------------------------------

def _analyse_dockerfile(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    bases = a.details.get("base_images", [])
    stages = a.details.get("stages", [])

    if stages:
        findings.append(f"Multi-stage build with {len(stages)} stages")

    unpinned = [img for img in bases if "@sha256:" not in img]
    for img in bases:
        if "@sha256:" in img:
            findings.append(f"{img} is pinned to digest")
        elif ":latest" in img or ":" not in img:
            findings.append(f"{img} uses 'latest' tag (mutable)")
            risk = "high"
        else:
            findings.append(f"{img} uses a tag (mutable)")
            if risk != "high":
                risk = "medium"

    if unpinned:
        recommendations.append(f"Run: cascadeguard images pin --file {a.path}")

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


def _analyse_actions(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    refs = a.details.get("action_refs", [])
    unpinned = [r for r in refs if not r.get("pinned")]

    findings.append(f"{len(refs)} action references, {len(unpinned)} unpinned")

    for r in unpinned:
        ref_str = r.get("ref", "")
        if ref_str in ("main", "master"):
            findings.append(f"{r['action']}@{ref_str} tracks a branch (high risk)")
            risk = "high"
        else:
            if risk != "high":
                risk = "medium"

    if unpinned:
        recommendations.append("Run: cascadeguard actions pin")

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


def _analyse_compose(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    imgs = a.details.get("image_refs", [])
    svcs = a.details.get("services", [])
    findings.append(f"{len(svcs)} services, {len(imgs)} image references")

    for img in imgs:
        if "@sha256:" in img:
            continue
        if ":latest" in img or ":" not in img:
            findings.append(f"{img} uses 'latest' tag")
            risk = "medium"
    if imgs:
        recommendations.append(f"Run: cascadeguard images pin --file {a.path}")

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


def _analyse_helm(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    chart_name = a.details.get("chart_name", "")
    values_imgs = a.details.get("values_images", [])
    template_imgs = a.details.get("template_images", [])

    findings.append(f"Chart: {chart_name}")

    if values_imgs:
        findings.append(f"{len(values_imgs)} image(s) configured in values.yaml")
    if template_imgs:
        findings.append(f"{len(template_imgs)} hardcoded image(s) in templates")
        risk = "medium"

    for img in values_imgs + template_imgs:
        if "@sha256:" in img:
            continue
        if ":latest" in img or ":" not in img:
            findings.append(f"{img} uses 'latest' tag")
            if risk != "high":
                risk = "medium"

    if values_imgs:
        recommendations.append(f"Pin image tags in {a.path}/values.yaml")
    if template_imgs:
        recommendations.append(
            f"Move hardcoded images to values.yaml and override at deploy time"
        )

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


def _analyse_kustomize(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    transformer = a.details.get("images_transformer", [])
    resource_imgs = a.details.get("resource_images", [])

    if transformer:
        findings.append(f"{len(transformer)} image override(s) in kustomization.yaml")
    if resource_imgs:
        findings.append(f"{len(resource_imgs)} image(s) in resources")

    unpinned_resources = [i for i in resource_imgs if "@sha256:" not in i]
    if unpinned_resources and not transformer:
        findings.append("No images transformer configured — images are not overridden")
        risk = "medium"
        recommendations.append(
            f"Add an images transformer to {a.path} to pin digests"
        )
    elif unpinned_resources:
        recommendations.append(
            f"Pin digests via the images transformer in {a.path}"
        )

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


def _analyse_k8s(a: DiscoveredArtifact) -> ArtifactAnalysis:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "info"

    imgs = a.details.get("image_refs", [])
    kind = a.details.get("resource_kind", "")
    findings.append(f"{kind} with {len(imgs)} container image(s)")

    unpinned = [img for img in imgs if "@sha256:" not in img]
    for img in imgs:
        if "@sha256:" in img:
            continue
        if ":latest" in img or ":" not in img:
            findings.append(f"{img} uses 'latest' tag")
            risk = "high"
        else:
            if risk == "info":
                risk = "low"

    if unpinned:
        recommendations.append(f"Run: cascadeguard images pin --file {a.path}")

    return ArtifactAnalysis(artifact=a, findings=findings,
                            recommendations=recommendations, risk_level=risk)


_ANALYSERS = {
    "dockerfile": _analyse_dockerfile,
    "actions": _analyse_actions,
    "compose": _analyse_compose,
    "helm": _analyse_helm,
    "kustomize": _analyse_kustomize,
    "k8s": _analyse_k8s,
}


def analyse(artifacts: list[DiscoveredArtifact]) -> list[ArtifactAnalysis]:
    """Run analysis rules on a list of artifacts."""
    results = []
    for a in artifacts:
        analyser = _ANALYSERS.get(a.kind)
        if analyser:
            results.append(analyser(a))
        else:
            results.append(ArtifactAnalysis(artifact=a))
    return results


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def build_summary(
    discovered: list[DiscoveredArtifact],
    selected: list[DiscoveredArtifact],
    analysis: list[ArtifactAnalysis],
) -> ScanSummary:
    """Build aggregate summary from analysis results."""
    by_kind: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    all_images: set[str] = set()
    all_actions: set[str] = set()

    for a in selected:
        by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
        for img in a.details.get("base_images", []):
            all_images.add(img)
        for img in a.details.get("image_refs", []):
            all_images.add(img)
        for ref in a.details.get("action_refs", []):
            all_actions.add(ref.get("action", ""))

    for r in analysis:
        by_risk[r.risk_level] = by_risk.get(r.risk_level, 0) + 1

    return ScanSummary(
        total_discovered=len(discovered),
        total_selected=len(selected),
        total_images=len(all_images),
        total_actions=len(all_actions),
        by_kind=by_kind,
        by_risk=by_risk,
    )


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

_KIND_LABELS = {
    "dockerfile": "Dockerfiles",
    "actions": "GitHub Actions",
    "compose": "Docker Compose",
    "helm": "Helm Charts",
    "kustomize": "Kustomize",
    "k8s": "Kubernetes Manifests",
}

_RISK_ICONS = {
    "high": "✖",
    "medium": "⚠",
    "low": "△",
    "info": "ℹ",
}


def format_text(result: ScanResult) -> str:
    """Format scan result as human-readable text."""
    lines: list[str] = []
    lines.append("")
    lines.append("CascadeGuard Scan Report")
    lines.append("=" * 50)
    lines.append(f"Scanned:   {result.root_dir}")
    lines.append(
        f"Artifacts: {result.summary.total_discovered} discovered, "
        f"{result.summary.total_selected} selected"
    )
    lines.append("")

    # Group by kind
    by_kind: dict[str, list[ArtifactAnalysis]] = {}
    for a in result.analysis:
        by_kind.setdefault(a.artifact.kind, []).append(a)

    for kind in ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        label = _KIND_LABELS.get(kind, kind)
        lines.append(f"{label} ({len(group)})")

        # Split into actionable vs info-only
        actionable = [a for a in group if a.risk_level != "info"]
        info_only = [a for a in group if a.risk_level == "info"]

        # Show up to MAX_DETAIL items with full detail, then summarise the rest
        MAX_DETAIL = 5
        for a in actionable[:MAX_DETAIL]:
            icon = _RISK_ICONS.get(a.risk_level, " ")
            lines.append(f"  {icon} {a.artifact.path}")
            for f in a.findings:
                lines.append(f"    · {f}")
            for r in a.recommendations:
                lines.append(f"    → {r}")

        remaining = actionable[MAX_DETAIL:]
        if remaining:
            lines.append(f"  ⚠ ... and {len(remaining)} more with findings:")
            for a in remaining:
                lines.append(f"    {a.artifact.path}")

        if info_only:
            lines.append(f"  ℹ {len(info_only)} with no findings")

        lines.append("")

    # Summary
    s = result.summary
    risk_parts = []
    for level in ("high", "medium", "low", "info"):
        count = s.by_risk.get(level, 0)
        if count:
            risk_parts.append(f"{count} {level}")
    if risk_parts:
        lines.append(f"Summary: {', '.join(risk_parts)}")
    lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format scan result as JSON."""
    data = {
        "scan": {
            "directory": result.root_dir,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_discovered": result.summary.total_discovered,
                "total_selected": result.summary.total_selected,
                "total_images": result.summary.total_images,
                "total_actions": result.summary.total_actions,
                "by_kind": result.summary.by_kind,
                "by_risk": result.summary.by_risk,
            },
            "artifacts": [
                {
                    "kind": a.artifact.kind,
                    "path": a.artifact.path,
                    "details": a.artifact.details,
                    "risk_level": a.risk_level,
                    "findings": a.findings,
                    "recommendations": a.recommendations,
                }
                for a in result.analysis
            ],
        }
    }
    return json.dumps(data, indent=2)
