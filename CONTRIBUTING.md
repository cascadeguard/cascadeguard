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

## Branch Naming

Use the format `<your-name>/<short-description>` or `<issue-number>/<short-description>`:
- `jane/add-vulnerability-scanner`
- `42/fix-image-pull-timeout`

## Making Changes

### Code Style

- **Python**: Follow PEP 8. Use type hints for function signatures.
- **TypeScript**: Follow the existing cdk8s conventions in `cdk8s/`.
- Keep changes focused — one logical change per PR.

### Testing Requirements

All PRs must include tests for new or changed behavior. We follow a testing pyramid:

- **Unit tests**: Pure functions and business logic. Target 80%+ line coverage for new code.
  - Python app tests: `task app:test:unit`
  - cdk8s tests: `task cdk8s:test:unit`
- **Integration tests**: API endpoints, database queries, service boundaries.
  - `task test:integration`
- **Acceptance tests**: End-to-end Kargo deployment validation.
  - `task test:acceptance`

Run the full suite before submitting:
```bash
task test:all
```

### Static Analysis

- Linting and type checking must pass with no new warnings.
- Do not commit secrets, credentials, or environment-specific configuration.

## Pull Request Process

1. **Push your branch** and open a PR against `main`.
2. **PR description** must include:
   - A summary of what changed and why.
   - A test plan describing how reviewers can verify the change.
3. **All CI checks must pass** before review.
4. **Review and approval** is required before merge. Do not merge your own PRs.
5. **Squash or rebase** to keep history clean — avoid merge commits.

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

By contributing, you agree that your contributions will be licensed under the same license as the project.
