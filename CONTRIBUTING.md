# Contributing to CascadeGuard

Thank you for your interest in contributing to CascadeGuard! This document covers the development workflow, coding standards, and process for getting your changes merged.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a feature branch off `main`:
   ```bash
   git checkout -b your-name/short-description
   ```
3. Install dependencies:
   ```bash
   task setup
   ```
4. Install the pre-commit hook to block sensitive paths:
   ```bash
   pip install pre-commit && pre-commit install
   ```
   Or standalone (no Python required):
   ```bash
   cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
   ```

## Branch Naming

Use the format `<your-name>/<short-description>` or `<issue-number>/<short-description>`:
- `jane/add-vulnerability-scanner`
- `42/fix-image-pull-timeout`

## Making Changes

### Code Style

- **Python**: Follow PEP 8. Use type hints for function signatures.
- **TypeScript**: Follow the existing conventions in the codebase.
- Keep changes focused — one logical change per PR.

### Testing Requirements

All PRs must include tests for new or changed behavior. We follow a testing pyramid:

- **Unit tests**: Pure functions and business logic. Target 80%+ line coverage for new code.
  - `task test:unit`
- **Integration tests**: Service boundaries, deployment validation.
  - `task test:integration`
- **Acceptance tests**: End-to-end deployment validation.
  - `task test:acceptance`

Run the full suite before submitting:
```bash
task test:all
```

### Pre-commit Hook

A pre-commit hook blocks files in sensitive paths (`.ai/`, `docs/plans/`, `artifacts/`) from being committed. These directories must never enter git history in this public repository.

The hook is installed as part of `pre-commit install` (option A above). To override the blocked paths, set the `BLOCKED_PATHS` environment variable (space-separated path prefixes):

```bash
BLOCKED_PATHS=".ai/ secrets/ private/" git commit -m "..."
```

To adopt this hook in another repo using the pre-commit framework, add the following stanza to that repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cascadeguard/cascadeguard
    rev: v<TAG>  # pin to a release tag
    hooks:
      - id: block-sensitive-paths
```

### Static Analysis

- Linting and type checking must pass with no new warnings.
- Do not commit secrets, credentials, or environment-specific configuration.

## Pull Request Process

1. **Push your branch** and open a PR against `main`.
2. **PR description** must include:
   - A summary of what changed and why.
   - A test plan describing how reviewers can verify the change.
3. **All CI checks must pass** before requesting review. Do not request review until CI is green.
4. **Keep your branch up to date** — the PR author is responsible for resolving merge conflicts with `main`. PRs with unresolved conflicts for >1h will receive a reminder; PRs stale for >4h may be closed.
5. **Review and approval** is required before merge. Do not merge your own PRs.
6. **Respond to review feedback** within 1h. Address reviewer comments in new commits.
7. **Squash or rebase** to keep history clean — avoid merge commits.

## Definition of Done

A change is considered complete when:

- Code is merged to `main` with all CI passing.
- PR is reviewed and approved.
- No new lint warnings or type errors introduced.
- Documentation is updated if user-facing behavior changed.
- Tests cover the new or changed behavior.

## Reporting Issues

Open a GitHub issue with:
- A clear title describing the problem or feature.
- Steps to reproduce (for bugs).
- Expected vs actual behavior.
- Environment details (OS, Python version, Docker version if relevant).

## License

CascadeGuard is licensed under the [Business Source License 1.1](LICENSE) (BUSL-1.1). By contributing, you agree that your contributions will be licensed under the same terms. See the [Licensing section in the README](README.md#licensing) for details on what is and is not permitted.
