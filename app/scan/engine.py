"""Scan engine — orchestrates discovery, analysis, and output."""

from __future__ import annotations
import sys
from pathlib import Path

from .discoverers import discover_all, _EXCLUDED_DIRS
from .models import DiscoveredArtifact, ScanResult
from .report import analyse, build_summary, format_text, format_json

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
    else:
        output = format_text(result)

    if output_file:
        Path(output_file).write_text(output)
        print(f"Report written to {output_file}")
    else:
        print(output)

    # Exit 1 if any high-risk findings
    if summary.by_risk.get("high", 0) > 0:
        return 1
    return 0


def _interactive_select(artifacts: list[DiscoveredArtifact]) -> list[DiscoveredArtifact]:
    """Simple interactive selection (fallback mode — no curses)."""
    # If stdin is not a TTY, select all
    if not sys.stdin.isatty():
        return list(artifacts)

    # Group by kind
    by_kind: dict[str, list[DiscoveredArtifact]] = {}
    for a in artifacts:
        by_kind.setdefault(a.kind, []).append(a)

    print(f"\nCascadeGuard — Found {len(artifacts)} artifacts:\n")

    indexed: list[tuple[int, DiscoveredArtifact]] = []
    idx = 1
    for kind in ("dockerfile", "actions", "compose", "helm", "kustomize", "k8s"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        label = _KIND_LABELS.get(kind, kind)
        print(f"  {label} ({len(group)})")
        for a in group:
            print(f"    [{idx}] {a.path}  — {a.summary}")
            indexed.append((idx, a))
            idx += 1
        print()

    print("Enter numbers to exclude (comma-separated), or press Enter to scan all:")
    try:
        raw = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return []

    if not raw:
        return [a for _, a in indexed]

    try:
        exclude = {int(x.strip()) for x in raw.split(",") if x.strip()}
    except ValueError:
        print("Invalid input, scanning all artifacts.")
        return [a for _, a in indexed]

    return [a for i, a in indexed if i not in exclude]
