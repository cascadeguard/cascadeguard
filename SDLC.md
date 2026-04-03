# CascadeGuard Software Development Lifecycle

This document describes the software development lifecycle (SDLC) for the CascadeGuard project. It covers how features move from idea to production and how the project is maintained.

For contributor-specific guidelines (setup, code style, PR mechanics), see [CONTRIBUTING.md](CONTRIBUTING.md).

## 1. Feature Lifecycle

```
Idea → Discussion → Backlog → Ready → In Progress → In Review → Done → Released
```

### Idea

Features start as GitHub issues. Anyone can propose a feature or report a bug by opening an issue.

### Discussion

- Feature discussion happens in GitHub issue comments.
- For significant features, a short proposal should be posted in the issue covering: scope, motivation, and trade-offs.
- Maintainers and community members discuss until a decision is reached.
- Small changes (bug fixes, typos, minor improvements) can skip this phase.

### Backlog

An issue enters the backlog when it has:

- A clear title and description (what, not how).
- An assigned priority label (`critical`, `high`, `medium`, `low`).
- Acceptance criteria or a definition of what "done" looks like.

### Ready

An issue is ready to build when:

- The description answers: what are we building, why, and what does done look like?
- Dependencies are identified and unblocked.
- For non-trivial features: a design proposal or ADR exists (see [Architecture Decisions](#7-architecture-decisions)).
- A maintainer has approved it to start (labeled or assigned).

### In Progress

- The assignee creates a feature branch off `main` (see branch naming in CONTRIBUTING.md).
- Work happens in focused commits with clear messages.
- The assignee runs tests locally before opening a PR.

### In Review

- A pull request is opened against `main`.
- All CI checks must pass (lint, type check, tests, security scan).
- At least one maintainer reviews and approves the PR.
- Feedback is addressed in new commits — no force-pushing during review.
- See [Pull Request Process](#3-pull-request-process) for details.

### Done

A change is done when it is merged to `main` with all checks passing. The originating GitHub issue is closed with a comment summarizing the resolution and linking to the merged PR.

## 2. Issue Management

### Creating Issues

- **Bug reports**: Include steps to reproduce, expected vs. actual behavior, and environment details.
- **Feature requests**: Describe the problem being solved, proposed solution, and alternatives considered.
- **One concern per issue** — don't combine unrelated changes.

### Labels

| Label | Meaning |
|---|---|
| `bug` | Something isn't working correctly |
| `feature` | New functionality |
| `enhancement` | Improvement to existing functionality |
| `docs` | Documentation only |
| `tech-debt` | Refactoring or cleanup with no user-facing change |
| `critical` / `high` / `medium` / `low` | Priority |

### Triage Labels

These labels track an issue's progress through the triage pipeline:

| Label | Meaning |
|---|---|
| `triaged` | Issue has been reviewed and categorized |
| `inscope` | Fits the current roadmap |
| `next` | Top prioritized items ready for CTO review |
| `cto-reviewed` | CTO has added technical assessment |
| `ready` | Board-approved, can be scheduled for implementation |
| `needs-info` | Awaiting clarification from the reporter |

### GitHub Issue Triage Lifecycle

GitHub is the source of truth for issue state. Issues stay in GitHub until approved for implementation. The full lifecycle is:

```
New Issue → Triaged → In Scope → Next → CTO Reviewed → Ready → Paperclip Issue → Implementation → PR Merged → GitHub Issue Closed
```

1. **New issue filed** — community member or maintainer opens a GitHub issue.
2. **Triage** — the daily triage process reviews new issues:
   - Categorize (bug, feature, question, security, docs).
   - If in scope: label `triaged` + `inscope`.
   - If out of scope: move to GitHub Discussions with a comment explaining why.
   - If unclear: label `triaged` + `needs-info`, comment asking for clarification.
3. **Prioritization** — `inscope` issues are ranked. Top items receive the `next` label.
4. **CTO review** — `next` items get a technical assessment comment and the `cto-reviewed` label.
5. **Board approval** — board reviews the daily summary and approves items. Approved items receive the `ready` label. Nothing proceeds without board sign-off.
6. **Paperclip handoff** — a Paperclip issue is created only for `ready`-labeled items, assigned to the relevant engineer.
7. **Implementation** — normal feature lifecycle (branch, code, tests, PR).
8. **Closing** — when the PR is merged, the corresponding GitHub issue is closed **with a comment** summarizing what was done and linking to the PR. This ensures the community sees the resolution.

### Closing GitHub Issues

When closing a GitHub issue after implementation:

- Always add a closing comment before or alongside closing the issue.
- The comment should reference the PR that resolved it (e.g., "Resolved in PR #27").
- Briefly describe what changed and any follow-up actions for users.
- Use `state_reason: completed` when the issue is resolved, or `not_planned` when moved to Discussions.

### Milestones

Milestones group issues for release planning. Each milestone corresponds to a planned release version.

## 3. Pull Request Process

### Branch Strategy

Feature branches off `main`. One branch per issue.

Branch naming: `<identifier>/<short-description>` (e.g., `42/add-vulnerability-scanner`).

### PR Creation

1. Push your feature branch.
2. Open a PR against `main` with:
   - **Title**: Short description of the change.
   - **Body**: Summary of what changed and why, a test plan, and a link to the related issue.
3. Ensure all CI checks pass.

### Review

1. Automated checks run first: lint, type check, unit tests, integration tests, security scan.
2. A maintainer reviews for correctness, architecture, and code quality.
3. The reviewer comments on the PR. Author addresses feedback in new commits.
4. Once approved, a maintainer merges to `main`. Contributors do not merge their own PRs.

### PR Rules

- No direct commits to `main`.
- All CI checks must pass before review.
- Squash merge preferred for clean history.
- Delete branch after merge.

## 4. Testing Pyramid

```
         /    E2E    \          ← Few, slow, high confidence
        / Integration  \        ← Moderate, test boundaries
       /   Unit Tests    \      ← Many, fast, isolated
      / Static Analysis    \    ← Lint, type check, security
```

### Layer Details

| Layer | What | Tools | Target |
|---|---|---|---|
| Static analysis | Linting, type checking, secret scanning | Per-language linters, type checkers, gitleaks | 100% of code |
| Unit tests | Pure functions, business logic, utilities | pytest / vitest | 80%+ line coverage |
| Integration tests | Service boundaries, deployment validation | pytest / vitest | Key paths covered |
| E2E tests | Critical user flows, deployment smoke tests | Deployment-level flows | Top 5 user journeys |

### Testing Requirements

- Every PR must include tests for new or changed behavior.
- Run tests locally before opening a PR:
  ```bash
  task test:all
  ```
- CI runs the full pyramid on every PR.
- Test failures block merge. No exceptions.

## 5. Definition of Done

A change is complete when all of the following are true:

- [ ] Code is merged to `main` with all CI passing.
- [ ] PR was reviewed and approved by a maintainer.
- [ ] No new lint warnings or type errors introduced.
- [ ] Tests cover new or changed behavior.
- [ ] Documentation updated if user-facing behavior changed.
- [ ] ADR written if an architectural decision was made.
- [ ] No known regressions in existing functionality.
- [ ] Originating GitHub issue closed with a summary comment linking to the PR.

## 6. Release Process

### Versioning

CascadeGuard follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to public interfaces or behavior.
- **MINOR**: New functionality, backwards-compatible.
- **PATCH**: Bug fixes, backwards-compatible.

### Release Steps

1. A maintainer creates a release branch or tags `main` at the release point.
2. The changelog is updated with a summary of changes since the last release.
3. CI builds and publishes release artifacts (container images, packages).
4. A GitHub Release is created with release notes.

### Hotfix Process

- Critical production bugs skip the normal backlog queue.
- A maintainer creates a `critical` priority issue — immediate `todo`.
- The same PR and review process applies, but review is expedited.
- Hotfix releases are patch version bumps.

## 7. Architecture Decisions

Significant technical decisions are recorded as Architecture Decision Records (ADRs).

### When to Write an ADR

- Introducing a new dependency or technology.
- Changing the data model or public interfaces.
- Choosing between multiple viable approaches.
- Any decision that would be hard to reverse later.

### ADR Format

ADRs are stored in `docs/adr/` and follow the [MADR template](https://adr.github.io/madr/):

```
# NNN - Title

## Status
Proposed / Accepted / Deprecated / Superseded by [NNN]

## Context
What is the issue that we're seeing that is motivating this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult to do because of this change?
```

ADRs are immutable once accepted. New decisions supersede old ones.

## 8. Security

- Never commit secrets, credentials, or environment-specific configuration.
- Security vulnerabilities in dependencies should be addressed promptly.
- Report security issues responsibly — see the project's security policy.
- All code changes go through review; no exceptions for security-sensitive areas.

## 9. Tech Debt

- Tech debt issues are tracked like any other issue with the `tech-debt` label.
- Approximately 20% of development capacity is reserved for tech debt reduction.
- Tech debt follows the same approval and review flow as features.

## 10. Continuous Integration

CI runs automatically on every PR and push to `main`:

1. **Static analysis**: Linting, type checking, secret scanning.
2. **Unit tests**: Fast, isolated tests for business logic.
3. **Integration tests**: Service boundary and deployment validation tests.
4. **Build verification**: Ensure the application builds and container images are valid.

All checks must pass for a PR to be merge-eligible.
