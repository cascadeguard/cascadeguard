"""Scan engine — orchestrates discovery, analysis, and output."""

from __future__ import annotations
import sys
from pathlib import Path

from .discoverers import discover_all, _EXCLUDED_DIRS
from .models import DiscoveredArtifact, ScanResult
from .report import analyse, build_summary, format_text, format_markdown, format_json

_KIND_LABELS = {
    "dockerfile": "Dockerfiles",
    "actions": "GitHub Actions",
    "compose": "Docker Compose",
    "helm": "Helm Charts",
    "kustomize": "Kustomize",
    "k8s": "Kubernetes Manifests",
}


def run_scan(
    root: Path,
    *,
    non_interactive: bool = False,
    output_format: str = "text",
    output_file: str | None = None,
) -> int:
    """Run the full scan pipeline. Returns exit code."""
    root = root.resolve()

    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 1

    # --- Discovery ---
    all_artifacts = discover_all(root)

    if not all_artifacts:
        print(f"No container artifacts found in {root}")
        return 0

    # --- Selection ---
    if non_interactive:
        selected = list(all_artifacts)
    else:
        selected = _interactive_select(all_artifacts)

    if not selected:
        print("No artifacts selected.")
        return 0

    # --- Analysis ---
    analysis = analyse(selected)
    summary = build_summary(all_artifacts, selected, analysis)

    result = ScanResult(
        root_dir=str(root),
        discovered=all_artifacts,
        selected=selected,
        analysis=analysis,
        summary=summary,
    )

    # --- Output ---
    if output_format == "json":
        output = format_json(result)
        if output_file:
            Path(output_file).write_text(output)
            print(f"Report written to {output_file}")
        else:
            print(output)
    else:
        # Always write detailed markdown report
        report_dir = root / ".cascadeguard"
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / "scan-report.md"
        report_path.write_text(format_markdown(result))

        # Print compact summary to terminal
        print(format_text(result))
        print(f"  Full report: {report_path.relative_to(root)}")
        print()

    # Exit 1 if any high-risk findings
    if summary.by_risk.get("high", 0) > 0:
        return 1
    return 0


def _interactive_select(artifacts: list[DiscoveredArtifact]) -> list[DiscoveredArtifact]:
    """Interactive selection — show summary, let user exclude by kind."""
    # If stdin is not a TTY, select all
    if not sys.stdin.isatty():
        return list(artifacts)

    # Group by kind, preserving display order
    _KIND_ORDER = ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s")
    by_kind: dict[str, list[DiscoveredArtifact]] = {}
    for a in artifacts:
        by_kind.setdefault(a.kind, []).append(a)

    # Build numbered kind list
    kinds_present: list[tuple[int, str, list[DiscoveredArtifact]]] = []
    idx = 1
    for kind in _KIND_ORDER:
        group = by_kind.get(kind, [])
        if not group:
            continue
        kinds_present.append((idx, kind, group))
        idx += 1

    print(f"\nCascadeGuard — Found {len(artifacts)} artifacts:\n")
    for num, kind, group in kinds_present:
        label = _KIND_LABELS.get(kind, kind)
        print(f"  [{num}] {label} ({len(group)})")
    print()

    print("Exclude groups by number (e.g. 4,5), or press Enter to scan all:")
    try:
        raw = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return []

    if not raw:
        return list(artifacts)

    try:
        exclude_nums = {int(x.strip()) for x in raw.split(",") if x.strip()}
    except ValueError:
        print("Invalid input, scanning all artifacts.")
        return list(artifacts)

    excluded_kinds = {kind for num, kind, _ in kinds_present if num in exclude_nums}
    selected = [a for a in artifacts if a.kind not in excluded_kinds]

    if excluded_kinds:
        labels = [_KIND_LABELS.get(k, k) for k in excluded_kinds]
        print(f"Excluded: {', '.join(labels)}")

    return selected
