# CascadeGuard Agent Conventions

## SDLC Process

All agents working in this repository MUST follow the SDLC defined in:

**`.ai/projects/cascadeguard/sdlc.md`**

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
| PRDs / feature specs | `.ai/projects/cascadeguard/prds/` |
| ADRs | `.ai/projects/cascadeguard/adr/` |
| Strategy docs | `.ai/projects/cascadeguard/strategy/` |
| Technical designs | `.ai/projects/cascadeguard/designs/` |
| SDLC process | `.ai/projects/cascadeguard/sdlc.md` |
| API specs | `docs/api/` |

## Tech Stack

- **Backend**: Python / FastAPI with SQLAlchemy + Alembic (PostgreSQL)
- **Infrastructure**: cdk8s (TypeScript) for Kubernetes manifests
- **SaaS layer**: Under `saas/`
- **Testing**: pytest (Python), vitest (TypeScript)
- **Task runner**: Taskfile (see `Taskfile.yaml`)
