# CascadeGuard Software Development Lifecycle

> **Canonical location:** The full SDLC is maintained in
> [cascadeguard-docs](https://github.com/cascadeguard/cascadeguard-docs/blob/main/docs/sdlc.md)
> as the single source of truth for all CascadeGuard repositories.

This file is a pointer only. All process documentation lives in
[cascadeguard-docs/docs/sdlc.md](https://github.com/cascadeguard/cascadeguard-docs/blob/main/docs/sdlc.md).

## Repo-Specific Notes

- **Branch naming**: `<identifier>/<short-description>` (e.g., `CAS-42/add-vulnerability-scanner`)
- **Setup**: See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup steps, test commands, and coding standards.
- **CI**: All checks (lint, type check, unit tests, integration tests, security scan) must pass before requesting review.
- **Testing**: Run `task test:all` locally before opening a PR.
