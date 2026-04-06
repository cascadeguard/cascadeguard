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


# ---------------------------------------------------------------------------
# Kind-level action summaries (for the summary table)
# ---------------------------------------------------------------------------

_KIND_ACTIONS = {
    "dockerfile": "cascadeguard images pin",
    "actions": "cascadeguard actions pin",
    "compose": "cascadeguard images pin",
    "helm": "cascadeguard images pin",
    "kustomize": "cascadeguard images pin",
    "k8s": "cascadeguard images pin",
}


def format_text(result: ScanResult) -> str:
    """Format scan result as a compact Rich summary table for the terminal."""
    from io import StringIO
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100)

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold]CascadeGuard Scan[/bold]  [dim]{result.root_dir}[/dim]",
        border_style="cyan",
    ))
    console.print()

    # Summary table — no Action column, deduplicated actions at the bottom
    table = Table(show_edge=False, pad_edge=False, expand=True)
    table.add_column("Kind", style="bold", min_width=20)
    table.add_column("Found", justify="right", min_width=6)
    table.add_column("Issues", justify="right", min_width=7)

    by_kind: dict[str, list[ArtifactAnalysis]] = {}
    for a in result.analysis:
        by_kind.setdefault(a.artifact.kind, []).append(a)

    total_found = 0
    total_issues = 0
    # Collect actions: action_text -> list of kind labels
    action_counts: dict[str, dict] = {}

    for kind in ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        label = _KIND_LABELS.get(kind, kind)
        issues = sum(1 for a in group if a.risk_level != "info")
        action = _KIND_ACTIONS.get(kind, "")

        issue_style = "bold red" if issues > 0 else "green"
        issue_text = str(issues) if issues > 0 else "✓"

        table.add_row(
            label,
            str(len(group)),
            f"[{issue_style}]{issue_text}[/{issue_style}]",
        )
        total_found += len(group)
        total_issues += issues

        if issues > 0 and action:
            if action not in action_counts:
                action_counts[action] = {"count": 0, "kinds": []}
            action_counts[action]["count"] += issues
            action_counts[action]["kinds"].append(label)

    table.add_section()
    issue_style = "bold red" if total_issues > 0 else "green"
    table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{total_found}[/bold]",
        f"[{issue_style}][bold]{total_issues}[/bold][/{issue_style}]",
    )

    console.print(table)
    console.print()

    # Deduplicated recommended actions
    if action_counts:
        console.print("[bold]Recommended actions:[/bold]")
        for action, info in action_counts.items():
            kinds_str = ", ".join(info["kinds"])
            console.print(f"  [green]→[/green] {action}  [dim]— {info['count']} issues across {kinds_str}[/dim]")
    console.print()

    return buf.getvalue()


def format_markdown(result: ScanResult) -> str:
    """Format scan result as a detailed markdown report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append(f"# CascadeGuard Scan Report")
    lines.append(f"")
    lines.append(f"- **Directory:** `{result.root_dir}`")
    lines.append(f"- **Date:** {ts}")
    lines.append(f"- **Artifacts:** {result.summary.total_discovered} discovered, "
                 f"{result.summary.total_selected} selected")
    lines.append(f"")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Kind | Found | Issues | Action |")
    lines.append("|------|------:|-------:|--------|")

    by_kind: dict[str, list[ArtifactAnalysis]] = {}
    for a in result.analysis:
        by_kind.setdefault(a.artifact.kind, []).append(a)

    for kind in ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        label = _KIND_LABELS.get(kind, kind)
        issues = sum(1 for a in group if a.risk_level != "info")
        action = _KIND_ACTIONS.get(kind, "")
        lines.append(f"| {label} | {len(group)} | {issues} | {action if issues else '✓'} |")

    lines.append("")

    # Detail sections per kind
    for kind in ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        label = _KIND_LABELS.get(kind, kind)
        lines.append(f"## {label}")
        lines.append("")

        actionable = [a for a in group if a.risk_level != "info"]
        info_only = [a for a in group if a.risk_level == "info"]

        if actionable:
            lines.append("| | Component | Findings | Recommendation |")
            lines.append("|---|-----------|----------|----------------|")
            for a in actionable:
                icon = _RISK_ICONS.get(a.risk_level, "ℹ")
                name = a.artifact.component_name

                # Compact findings: just the headline, not every image
                headline = a.findings[0] if a.findings else ""
                unpinned_count = sum(1 for f in a.findings if "latest" in f or "mutable" in f)
                if unpinned_count > 1:
                    headline = f"{unpinned_count} unpinned images"
                elif unpinned_count == 1:
                    # Use the specific image finding
                    headline = next((f for f in a.findings if "latest" in f or "mutable" in f), headline)

                rec_str = a.recommendations[0] if a.recommendations else ""
                lines.append(f"| {icon} | {name} | {headline} | {rec_str} |")
            lines.append("")

            # Detail: full findings + paths (collapsed)
            lines.append("<details><summary>Details</summary>")
            lines.append("")
            lines.append("| Component | Path | Finding |")
            lines.append("|-----------|------|---------|")
            for a in actionable:
                name = a.artifact.component_name
                path = a.artifact.path
                if a.findings:
                    # First finding gets the component name and path
                    lines.append(f"| {name} | `{path}` | {a.findings[0]} |")
                    # Subsequent findings: empty component/path columns
                    for f in a.findings[1:]:
                        lines.append(f"| | | {f} |")
                else:
                    lines.append(f"| {name} | `{path}` | |")
            lines.append("")
            lines.append("</details>")
            lines.append("")

        if info_only:
            lines.append(f"<details><summary>{len(info_only)} with no findings</summary>")
            lines.append("")
            lines.append("| Component | Path |")
            lines.append("|-----------|------|")
            for a in info_only:
                lines.append(f"| {a.artifact.component_name} | `{a.artifact.path}` |")
            lines.append("")
            lines.append("</details>")
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
