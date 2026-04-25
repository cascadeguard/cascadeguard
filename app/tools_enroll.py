#!/usr/bin/env python3
"""
cg tools enroll — detect CI/CD tools from pipeline manifests and add to tools.yaml.

Scans the target directory for CI platform manifests and writes discovered
tools into tools.yaml, merging with any existing entries.

Exit codes:
  0 — success (even if no tools found)
  1 — error
"""

import re
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# GitHub Actions detection
# ---------------------------------------------------------------------------

def _parse_uses_ref(uses: str, wf_rel: str) -> dict:
    """Parse a GitHub Actions 'uses' string into a tool dict."""
    action_ref = uses
    ref = ""
    if "@" in uses:
        action_ref, ref = uses.rsplit("@", 1)

    parts = action_ref.split("/")
    owner = parts[0] if parts else ""
    repo = parts[1] if len(parts) >= 2 else ""

    # Reusable workflow: path contains a .yml/.yaml file segment
    if len(parts) >= 3 and (parts[-1].endswith(".yml") or parts[-1].endswith(".yaml")):
        tool_type = "github-reusable-workflow"
        name = action_ref
    else:
        tool_type = "github-action"
        name = f"{owner}/{repo}" if repo else owner

    return {
        "name": name,
        "type": tool_type,
        "owner": owner,
        "repository": f"{owner}/{repo}" if repo else owner,
        "version": ref if ref else None,
        "sources": [{"platform": "github-actions", "file": wf_rel, "ref": uses}],
    }


def detect_github_actions(root: Path) -> list:
    """
    Scan .github/workflows/*.y*ml for 'uses:' directives.

    Returns list of tool dicts with name, type, owner, repository, version, sources.
    Skips local actions (starting with '.').
    """
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []

    tools = []
    for wf in sorted(workflow_dir.glob("*.y*ml")):
        try:
            data = yaml.safe_load(wf.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        wf_rel = str(wf.relative_to(root))

        for job in (data.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue

            # Job-level 'uses' — reusable workflow call
            job_uses = job.get("uses", "")
            if job_uses and not job_uses.startswith("."):
                tools.append(_parse_uses_ref(job_uses, wf_rel))

            # Step-level 'uses' — action call
            for step in (job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if not uses or uses.startswith("."):
                    continue
                tools.append(_parse_uses_ref(uses, wf_rel))

    return tools


# ---------------------------------------------------------------------------
# GitLab CI detection
# ---------------------------------------------------------------------------

# Heuristic patterns to detect CLI tool installs from script lines
_CLI_INSTALL_PATTERNS = [
    re.compile(r"pip(?:3)?\s+install\s+([A-Za-z0-9_.-]+)"),
    re.compile(r"npm\s+install\s+-g\s+([A-Za-z0-9_@/-]+)"),
    re.compile(r"go\s+install\s+([A-Za-z0-9_./-]+)"),
    re.compile(r"brew\s+install\s+([A-Za-z0-9_.-]+)"),
    re.compile(r"apt(?:-get)?\s+install\s+(?:-y\s+)?([A-Za-z0-9_.-]+)"),
]

# Top-level GitLab CI keys that are not job definitions
_GITLAB_META_KEYS = frozenset(
    ["image", "include", "stages", "variables", "default", "workflow", "services"]
)


def _detect_gitlab_script_tools(scripts: list, source_file: str) -> list:
    """Heuristically extract CLI tool names from script lines."""
    tools = []
    for line in scripts:
        if not isinstance(line, str):
            continue
        for pat in _CLI_INSTALL_PATTERNS:
            m = pat.search(line)
            if m:
                raw = m.group(1).split("==")[0].split(">=")[0].split("[")[0].strip()
                if raw and not raw.startswith("-"):
                    tools.append({
                        "name": raw,
                        "type": "cli-tool",
                        "sources": [{"platform": "gitlab-ci", "file": source_file, "ref": line.strip()}],
                    })
                break
    return tools


def _extract_image_name(image_val) -> str:
    """Extract the image name string from a GitLab CI image directive."""
    if isinstance(image_val, dict):
        return image_val.get("name", "")
    if isinstance(image_val, str):
        return image_val
    return ""


def detect_gitlab_ci(root: Path) -> list:
    """
    Scan .gitlab-ci.yml and included local files.

    Detects:
      - image: -> gitlab-ci-image
      - include: component: -> gitlab-ci-component
      - script: install heuristics -> cli-tool
    """
    main_file = root / ".gitlab-ci.yml"
    if not main_file.exists():
        return []

    tools = []
    files_to_scan = [main_file]
    visited: set = set()

    while files_to_scan:
        ci_file = files_to_scan.pop(0)
        if ci_file in visited:
            continue
        visited.add(ci_file)

        try:
            data = yaml.safe_load(ci_file.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        rel_path = str(ci_file.relative_to(root))

        # Top-level image
        image_str = _extract_image_name(data.get("image"))
        if image_str:
            name, _, version = image_str.partition(":")
            tools.append({
                "name": name,
                "type": "gitlab-ci-image",
                "version": version or None,
                "sources": [{"platform": "gitlab-ci", "file": rel_path, "ref": image_str}],
            })

        # include: (list or single dict)
        includes = data.get("include") or []
        if isinstance(includes, dict):
            includes = [includes]
        for inc in includes:
            if not isinstance(inc, dict):
                continue
            component = inc.get("component")
            if component:
                name = component.split("@")[0]
                version = component.split("@")[1] if "@" in component else None
                tools.append({
                    "name": name,
                    "type": "gitlab-ci-component",
                    "version": version,
                    "sources": [{"platform": "gitlab-ci", "file": rel_path, "ref": component}],
                })
            local = inc.get("local")
            if local:
                local_path = root / local.lstrip("/")
                if local_path.exists():
                    files_to_scan.append(local_path)

        # Per-job images and scripts
        for key, value in data.items():
            if key.startswith(".") or key in _GITLAB_META_KEYS:
                continue
            if not isinstance(value, dict):
                continue

            job_image_str = _extract_image_name(value.get("image"))
            if job_image_str:
                name, _, version = job_image_str.partition(":")
                tools.append({
                    "name": name,
                    "type": "gitlab-ci-image",
                    "version": version or None,
                    "sources": [{"platform": "gitlab-ci", "file": rel_path, "ref": job_image_str}],
                })

            scripts = []
            for script_key in ("script", "before_script", "after_script"):
                val = value.get(script_key)
                if isinstance(val, list):
                    scripts.extend(val)
                elif isinstance(val, str):
                    scripts.append(val)
            tools.extend(_detect_gitlab_script_tools(scripts, rel_path))

    return tools


# ---------------------------------------------------------------------------
# Platform auto-detection
# ---------------------------------------------------------------------------

def detect_platforms(root: Path) -> list:
    """Return list of CI platforms detected in the directory."""
    platforms = []
    if (root / ".github" / "workflows").is_dir():
        platforms.append("github-actions")
    if (root / ".gitlab-ci.yml").exists():
        platforms.append("gitlab-ci")
    return platforms


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _tool_key(tool: dict) -> tuple:
    return (tool.get("name", ""), tool.get("type", ""))


def _merge_sources(existing: list, new: list) -> list:
    """Append source entries not already present (matched by platform+file+ref)."""
    seen = {(s.get("platform"), s.get("file"), s.get("ref")) for s in existing}
    result = list(existing)
    for src in new:
        k = (src.get("platform"), src.get("file"), src.get("ref"))
        if k not in seen:
            result.append(src)
            seen.add(k)
    return result


def deduplicate_discovered(tools: list) -> list:
    """Collapse multiple entries for the same (name, type) from different files."""
    merged: dict = {}
    for tool in tools:
        k = _tool_key(tool)
        if k not in merged:
            merged[k] = dict(tool)
            merged[k].setdefault("sources", [])
        else:
            merged[k]["sources"] = _merge_sources(
                merged[k].get("sources", []),
                tool.get("sources", []),
            )
            if not merged[k].get("version") and tool.get("version"):
                merged[k]["version"] = tool["version"]
    return list(merged.values())


def merge_with_existing(existing_tools: list, discovered: list) -> list:
    """
    Merge discovered tools into existing tools.yaml list.

    - Match by (name, type)
    - Append new source locations; preserve manually set fields
    - Append entirely new tools at the end
    """
    result = list(existing_tools)
    by_key = {_tool_key(t): i for i, t in enumerate(result)}

    for disc in discovered:
        k = _tool_key(disc)
        if k in by_key:
            idx = by_key[k]
            existing = dict(result[idx])
            existing["sources"] = _merge_sources(
                existing.get("sources") or [],
                disc.get("sources") or [],
            )
            result[idx] = existing
        else:
            new_tool: dict = {"name": disc["name"], "type": disc["type"]}
            for field in ("owner", "repository", "version"):
                if disc.get(field):
                    new_tool[field] = disc[field]
            new_tool["sources"] = disc.get("sources", [])
            result.append(new_tool)
            by_key[k] = len(result) - 1

    return result


# ---------------------------------------------------------------------------
# tools.yaml I/O
# ---------------------------------------------------------------------------

def _load_tools_yaml(path: Path) -> list:
    with open(path) as f:
        data = yaml.safe_load(f)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("tools.yaml root must be a list")
    return data


def _write_tools_yaml(path: Path, tools: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("# tools.yaml — CascadeGuard CI/CD tool catalog\n")
        yaml.dump(tools, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Command entry point
# ---------------------------------------------------------------------------

def cmd_tools_enroll(args) -> int:
    """
    Entry point for `cg tools enroll`.

    Returns:
      0 — success
      1 — error
    """
    path_arg = getattr(args, "path", None)
    root = Path(path_arg if path_arg else ".").resolve()
    tools_yaml_path = Path(args.tools_yaml)
    platform = getattr(args, "platform", "auto")
    dry_run = getattr(args, "dry_run", False)

    if not root.is_dir():
        print(f"Error: path '{root}' is not a directory", file=sys.stderr)
        return 1

    # Determine which platforms to scan
    if platform == "auto":
        platforms = detect_platforms(root)
        if not platforms:
            print("No supported CI platforms detected in this directory.")
            return 0
    elif platform in ("github-actions", "gitlab-ci"):
        platforms = [platform]
    else:
        print(f"Error: unknown platform '{platform}'", file=sys.stderr)
        return 1

    # Discover tools
    discovered: list = []
    if "github-actions" in platforms:
        discovered.extend(detect_github_actions(root))
    if "gitlab-ci" in platforms:
        discovered.extend(detect_gitlab_ci(root))

    # Collapse duplicates within this scan
    discovered = deduplicate_discovered(discovered)

    if not discovered:
        print("No tools discovered.")
        return 0

    if dry_run:
        print(f"Discovered {len(discovered)} tool(s) (dry-run, not writing):")
        for t in discovered:
            sources = t.get("sources", [])
            src_summary = ", ".join(s.get("file", "?") for s in sources[:2])
            extra = " ..." if len(sources) > 2 else ""
            print(f"  {t['name']} ({t['type']}) -- {src_summary}{extra}")
        return 0

    # Load existing tools.yaml (start fresh if absent)
    existing: list = []
    if tools_yaml_path.exists():
        try:
            existing = _load_tools_yaml(tools_yaml_path)
        except (ValueError, Exception) as exc:
            print(f"Error reading {tools_yaml_path}: {exc}", file=sys.stderr)
            return 1

    merged = merge_with_existing(existing, discovered)
    new_count = len(merged) - len(existing)

    _write_tools_yaml(tools_yaml_path, merged)

    print(f"Enrolled {new_count} new tool(s); {len(merged) - new_count} existing updated.")
    return 0
