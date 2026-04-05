"""
CascadeGuard — GitHub Actions policy enforcement.

Provides:
  scan_pinning_status — scan workflows and report pinning status per action
  PolicyAuditor       — validates workflow files against an actions-policy.yaml
  load_policy         — loads and validates a policy file
  init_policy         — writes a starter policy file to disk

Policy file schema: .cascadeguard/actions-policy.schema.json

Audit logic (precedence order, highest first):
  1. denied_actions  — explicitly blocked; always a violation
  2. allowed_actions — explicitly permitted; never a violation
  3. exceptions      — one-off overrides with mandatory reason (and optional expiry)
  4. allowed_owners  — all actions from trusted orgs are permitted
  5. default         — 'deny' → violation for anything else; 'allow' → permitted
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Regex — re-uses the same pattern as ActionsPinner in app.py
# ---------------------------------------------------------------------------

_USES_RE = re.compile(
    r'^(\s*(?:-\s+)?uses:\s+)([^@\n\s]+)@([^\s\n#]+)(.*?)$'
)

_SHA_RE = re.compile(r'^[0-9a-f]{40}$')


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PolicyViolation:
    workflow_file: str
    line_number: int
    action: str
    ref: str
    reason: str

    def __str__(self) -> str:
        return (
            f"{self.workflow_file}:{self.line_number}  {self.action}@{self.ref}"
            f"  — {self.reason}"
        )


@dataclass
class AuditResult:
    violations: List[PolicyViolation] = field(default_factory=list)
    allowed: int = 0
    skipped: int = 0   # local / unresolvable actions

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0


@dataclass
class ActionRef:
    """A single action reference found in a workflow file."""
    workflow_file: str
    line_number: int
    action: str
    ref: str
    status: str  # "pinned" | "tag" | "branch" | "local"

    @property
    def mutable(self) -> bool:
        """True if the ref is mutable (tag or branch — not SHA-pinned)."""
        return self.status in {"tag", "branch"}

    def as_dict(self) -> dict:
        return {
            "workflow_file": self.workflow_file,
            "line_number": self.line_number,
            "action": self.action,
            "ref": self.ref,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Pinning-status scan (no policy required)
# ---------------------------------------------------------------------------

def _classify_ref(action: str, ref: str) -> str:
    """
    Classify a ref as 'pinned', 'tag', 'branch', or 'local'.

    - local:  relative path or no owner/repo
    - pinned: 40-char lowercase hex SHA
    - tag:    version-like string (starts with 'v' or digit with dots)
    - branch: everything else (main, master, develop, …)
    """
    if action.startswith("./") or "/" not in action:
        return "local"
    if _SHA_RE.match(ref):
        return "pinned"
    # Heuristic: version tags start with 'v' or a digit followed by a dot
    if ref.startswith("v") or (ref and ref[0].isdigit() and "." in ref):
        return "tag"
    return "branch"


def scan_pinning_status(workflows_dir: Path) -> List[ActionRef]:
    """
    Scan all workflow files in *workflows_dir* and return the pinning
    status of every action reference found.

    Each entry is an ActionRef with status: 'pinned' | 'tag' | 'branch' | 'local'.
    """
    refs: List[ActionRef] = []
    patterns = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    for wf_path in sorted(patterns):
        try:
            lines = wf_path.read_text().splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            m = _USES_RE.match(line)
            if not m:
                continue
            _, action, ref, _ = m.groups()
            status = _classify_ref(action, ref)
            refs.append(ActionRef(
                workflow_file=str(wf_path),
                line_number=lineno,
                action=action,
                ref=ref,
                status=status,
            ))
    return refs


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = {"version"}
_VALID_VERSION = "1"
_VALID_DEFAULTS = {"allow", "deny"}


class PolicyError(ValueError):
    """Raised when a policy file is malformed or fails validation."""


def load_policy(policy_path: Path) -> dict:
    """
    Load and validate an actions-policy.yaml file.

    Returns the parsed policy dict on success.
    Raises PolicyError on any structural or semantic problem.
    """
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {policy_path}")

    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"YAML parse error in {policy_path}: {exc}") from exc

    if not isinstance(policy, dict):
        raise PolicyError(f"{policy_path}: expected a YAML mapping, got {type(policy).__name__}")

    # Required fields
    for field_name in _REQUIRED_FIELDS:
        if field_name not in policy:
            raise PolicyError(f"{policy_path}: missing required field '{field_name}'")

    if str(policy["version"]) != _VALID_VERSION:
        raise PolicyError(
            f"{policy_path}: unsupported version '{policy['version']}' "
            f"(expected '{_VALID_VERSION}')"
        )

    default = policy.get("default", "deny")
    if default not in _VALID_DEFAULTS:
        raise PolicyError(
            f"{policy_path}: 'default' must be one of {sorted(_VALID_DEFAULTS)}, got '{default}'"
        )

    # List fields
    for list_field in ("allowed_owners", "allowed_actions", "denied_actions"):
        val = policy.get(list_field, [])
        if not isinstance(val, list):
            raise PolicyError(f"{policy_path}: '{list_field}' must be a list")

    # Exceptions
    exceptions = policy.get("exceptions", [])
    if not isinstance(exceptions, list):
        raise PolicyError(f"{policy_path}: 'exceptions' must be a list")
    for i, exc in enumerate(exceptions):
        if not isinstance(exc, dict):
            raise PolicyError(f"{policy_path}: exceptions[{i}] must be a mapping")
        if "action" not in exc:
            raise PolicyError(f"{policy_path}: exceptions[{i}] missing required field 'action'")
        if "reason" not in exc:
            raise PolicyError(f"{policy_path}: exceptions[{i}] missing required field 'reason'")

    return policy


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class PolicyAuditor:
    """
    Audits GitHub Actions workflow files against an actions-policy.yaml.

    Usage:
        auditor = PolicyAuditor(policy)
        result  = auditor.audit(workflows_dir)
    """

    def __init__(self, policy: dict):
        self._default: str          = policy.get("default", "deny")
        self._allowed_owners: set   = set(policy.get("allowed_owners", []))
        self._allowed_actions: set  = set(policy.get("allowed_actions", []))
        self._denied_actions: set   = set(policy.get("denied_actions", []))
        self._delay_hours: int      = int(policy.get("delay_window_hours", 0))

        # Build exception lookup: action → {reason, expires}
        self._exceptions: Dict[str, dict] = {}
        for exc in policy.get("exceptions", []):
            self._exceptions[exc["action"]] = exc

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def audit(self, workflows_dir: Path) -> AuditResult:
        """Audit all workflow files in *workflows_dir* and return an AuditResult."""
        result = AuditResult()
        patterns = (
            list(workflows_dir.glob("*.yml"))
            + list(workflows_dir.glob("*.yaml"))
        )
        for wf_path in sorted(patterns):
            self._audit_file(wf_path, result)
        return result

    def audit_file(self, wf_path: Path) -> AuditResult:
        """Audit a single workflow file and return an AuditResult."""
        result = AuditResult()
        self._audit_file(wf_path, result)
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _audit_file(self, wf_path: Path, result: AuditResult) -> None:
        try:
            lines = wf_path.read_text().splitlines()
        except OSError:
            return

        for lineno, line in enumerate(lines, start=1):
            m = _USES_RE.match(line)
            if not m:
                continue

            _, action, ref, _ = m.groups()

            # Skip local composite actions (relative paths or no owner/repo)
            if action.startswith("./") or "/" not in action:
                result.skipped += 1
                continue

            violation_reason = self._evaluate(action)
            if violation_reason is None:
                result.allowed += 1
            else:
                result.violations.append(PolicyViolation(
                    workflow_file=str(wf_path),
                    line_number=lineno,
                    action=action,
                    ref=ref,
                    reason=violation_reason,
                ))

    def _evaluate(self, action: str) -> Optional[str]:
        """
        Evaluate *action* against policy rules.

        Returns None if the action is permitted, or a string reason if it is a violation.
        Precedence: denied_actions > allowed_actions > exceptions > allowed_owners > default.
        """
        owner = action.split("/")[0] if "/" in action else action

        # 1. Explicitly denied — always a violation, exceptions cannot override this.
        if action in self._denied_actions:
            return f"'{action}' is in denied_actions"

        # 2. Explicitly allowed.
        if action in self._allowed_actions:
            return None

        # 3. Exception (with optional expiry check).
        if action in self._exceptions:
            exc = self._exceptions[action]
            expires = exc.get("expires")
            if expires:
                try:
                    expiry_date = date.fromisoformat(str(expires))
                    if date.today() > expiry_date:
                        return (
                            f"'{action}' exception expired on {expires} "
                            f"(reason: {exc['reason']})"
                        )
                except ValueError:
                    pass  # malformed date — treat exception as valid
            return None  # exception is active

        # 4. Trusted owner.
        if owner in self._allowed_owners:
            return None

        # 5. Default disposition.
        if self._default == "deny":
            return (
                f"'{action}' is not in allowed_actions or allowed_owners "
                f"and default policy is 'deny'"
            )
        return None  # default: allow


# ---------------------------------------------------------------------------
# Policy init
# ---------------------------------------------------------------------------

_STARTER_POLICY = """\
# CascadeGuard Actions Policy
# Schema: https://cascadeguard.dev/schemas/actions-policy/v1
#
# All fields except 'version' are optional.
# Provide as much or as little context as you need — sensible defaults apply.

version: "1"

# What to do with actions not matched by any rule below.
# 'deny' (recommended) enforces an explicit allow-list.
# 'allow' trusts everything except items in denied_actions.
default: deny

# GitHub organisations whose actions are trusted by default.
# Any action published under a listed owner is permitted.
allowed_owners:
  - actions          # github.com/actions/*
  - aws-actions      # github.com/aws-actions/*
  - docker           # github.com/docker/*

# Specific actions that are explicitly permitted (owner/repo).
allowed_actions: []

# Specific actions that are always denied, even if the owner is trusted.
denied_actions: []

# One-off exceptions — each must include a 'reason'.
# Optionally set 'expires' (YYYY-MM-DD) to auto-expire the exception.
exceptions: []
#  - action: some-org/some-action
#    reason: "Needed for legacy pipeline; migrating in Q3."
#    expires: "2026-09-30"
"""


def init_policy(output_path: Path, force: bool = False) -> bool:
    """
    Write a starter actions-policy.yaml to *output_path*.

    Returns True if the file was written, False if it already exists (and force=False).
    """
    if output_path.exists() and not force:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_STARTER_POLICY)
    return True
