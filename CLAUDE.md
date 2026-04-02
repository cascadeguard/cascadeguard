# CascadeGuard

## Project Overview

CascadeGuard is a container image security tool built as a FastAPI application with Kubernetes infrastructure managed via cdk8s.

## SDLC Process

The software development lifecycle for this project is defined in:

**[`SDLC.md`](SDLC.md)**

This is the canonical process for how features move from idea to production.

## Key Requirements

### Pull Requests
- Feature branches off `main`, named `<identifier>/<short-description>` (e.g. `CAS-45/add-billing-endpoint`).
- Every commit includes `Co-Authored-By: Paperclip <noreply@paperclip.ing>`.
- PRs must include: summary, test plan, and link to the Paperclip issue.
- All CI checks must pass before review. No direct commits to `main`.
- Agents do not merge their own PRs.

### Testing Pyramid
- **Static analysis**: linting, type checking, secret scanning (100% of code).
- **Unit tests**: pure functions, business logic (80%+ line coverage target).
- **Integration tests**: API endpoints, DB queries, service boundaries.
- **E2E tests**: critical user flows and deployment smoke tests.
- Every PR must include tests for new/changed behavior. Test failures block merge.

### Definition of Done
- Code merged to `main` with all CI passing.
- PR reviewed and approved by CTO (and board if flagged).
- No new lint warnings or type errors.
- Documentation updated if user-facing behavior changed.
- ADR written if an architectural decision was made.
- Paperclip issue closed with a summary comment.

## Artefact Locations

| Artefact | Path |
|---|---|
| PRDs / feature specs | `/workspace/.ai/projects/cascadeguard/prds/` |
| ADRs | `/workspace/.ai/projects/cascadeguard/adr/` |
| Strategy docs | `/workspace/.ai/projects/cascadeguard/strategy/` |
| Technical designs | `/workspace/.ai/projects/cascadeguard/designs/` |
| SDLC process | `SDLC.md` |
| API specs | `docs/api/` |

## Tech Stack

- **Backend**: Python / FastAPI with SQLAlchemy + Alembic (PostgreSQL)
- **Infrastructure**: cdk8s (TypeScript) for Kubernetes manifests
- **SaaS layer**: Under `saas/`
- **Testing**: pytest (Python), vitest (TypeScript)
- **Task runner**: Taskfile (see `Taskfile.yaml`)

## Repository Structure

| Directory | Purpose |
|---|---|
| `app/` | FastAPI application — API endpoints, models, middleware |
| `saas/` | SaaS platform layer |
| `cdk8s/` | Kubernetes manifests (cdk8s TypeScript) |
| `tests/` | Integration and acceptance tests |
| `docs/api/` | API specifications |

## Development

See `CONTRIBUTING.md` for contribution guidelines, PR process, and testing expectations.

### Quick Start

```bash
# Set up all components
task setup

# Run unit tests
task test:unit

# Run integration tests
task test:integration

# Run all tests
task test:all
```
