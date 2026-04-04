# GitHub Issues Integration Plan

## Goal

Manage community GitHub issues and PRs across **all CascadeGuard public repos** with board-controlled triage. State lives in GitHub (labels, discussions); issues only move into Paperclip when approved and ready to start that day. A daily routine handles triage, prioritization, vulnerability reporting, PR review tracking, and board reporting.

---

## Repos in Scope

All public CascadeGuard repositories are in scope:

| Repo                                           | Purpose                          |
| ---------------------------------------------- | -------------------------------- |
| `cascadeguard/cascadeguard`                    | Core CLI tool                    |
| `cascadeguard/cascadeguard-open-secure-images` | Hardened container images        |
| `cascadeguard/cascadeguard-app`                | SaaS application                 |
| `cascadeguard/cascadeguard-docs`               | Documentation                    |
| `cascadeguard/cascadeguard-exemplar`           | Example/reference implementation |

The triage routine scans all repos each day. New public repos added to the org are automatically included.

---

## Core Principle: GitHub Is the Source of Truth

Issues stay in GitHub until they are ready for implementation. We use **GitHub labels** to track triage state rather than creating Paperclip issues for every inbound ticket. A Paperclip issue is only created when a task is approved by the board and scheduled to start that day.

---

## Label Taxonomy

| Label          | Meaning                                            |
| -------------- | -------------------------------------------------- |
| `triaged`      | Issue has been reviewed and categorized            |
| `inscope`      | Fits the current roadmap (currently v1)            |
| `next`         | Top 10 prioritized items ready for CTO review      |
| `cto-reviewed` | CTO has added assessment and solution design       |
| `ready`        | Board-approved, can be pulled into Paperclip today |
| `security`     | Vulnerability report (triggers security workflow)  |

Issues that don't fit the current scope are moved to **GitHub Discussions** (not closed — preserves the conversation for future consideration).

---

## Vulnerability Handling

Per the [SECURITY.md](https://github.com/cascadeguard/cascadeguard-open-secure-images/blob/main/SECURITY.md) policy:

### Correct reports (private disclosure)

* Vulnerabilities reported via GitHub Private Vulnerability Reporting or [security@cascadeguard.dev](mailto:security@cascadeguard.dev) follow the SECURITY.md SLA:
  * Acknowledgment: 24h
  * Initial assessment: 48h
  * Critical fix: 24h
  * High fix: 48h
* These are flagged in the daily digest with severity and SLA countdown
* Board is immediately notified of Critical/High reports (not batched to next daily digest)

### Incorrect reports (public issue filed as vulnerability)

* If someone opens a public GitHub issue that discloses a vulnerability:
  1. The triage agent immediately closes the public issue with a standard response directing the reporter to SECURITY.md private channels
  2. The agent creates a private vulnerability advisory on the affected repo capturing the details
  3. The board is notified immediately (not batched)
  4. The CTO assesses severity and begins remediation per the SLA
* This prevents public disclosure while preserving the report

### Daily digest includes

* Count of open security advisories per repo
* SLA status for each active vulnerability (on track / at risk / breached)
* Any new vulnerability reports since last digest

---

## PR Review Tracking

The daily triage routine also covers open pull requests across all repos:

### What gets tracked

* All open PRs, grouped by repo
* PR age (time since opened)
* Review status: awaiting review, changes requested, approved, CI failing
* Assignee / reviewer (if set)

### Review requirements

* All PRs must be reviewed and approved by the assigned engineer or CTO before merge
* External/community PRs follow the same triage flow as issues (labels on the PR)
* CTO reviews code quality, test coverage, and alignment with architecture
* Board approves merge for significant changes (consistent with SDLC manual approval gate)

### Daily digest includes

* Open PRs by repo with age and review status
* PRs awaiting review for >24h flagged as needing attention
* PRs with failing CI flagged for engineer action

---

## Daily Triage Routine

A single Paperclip routine task ("GitHub Daily Triage") runs once per day via agent heartbeat (`intervalSec: 86400`). Covers all repos in scope.

### Step 1 — Triage new issues (all repos)

* Scan all repos for issues without the `triaged` label
* For each new issue:
  * Check if it is a vulnerability report filed as a public issue → trigger security workflow
  * Categorize (bug, feature request, question, security, docs)
  * Assess scope fit against the current roadmap
  * If **in scope**: add `triaged` + `inscope` labels
  * If **out of scope**: move to GitHub Discussions with a comment explaining why
  * If **unclear**: add `triaged` + `needs-info` label, comment asking for clarification

### Step 2 — Prioritize in-scope issues

* Review all `inscope` issues across all repos
* Rank by impact, urgency, and alignment with current sprint goals
* Apply `next` label to the top 10 (remove `next` from any that have fallen out)

### Step 3 — CTO review of `next` items

* For any `next` issue not yet labeled `cto-reviewed`:
  * Add a detailed technical assessment and solution design as an issue comment
  * Create or update PRDs/ADRs as appropriate, raise PR for board review
  * Add `cto-reviewed` label

### Step 4 — PR review check (all repos)

* Scan all repos for open PRs
* Flag any PR without a reviewer assigned
* Flag any PR awaiting review for >24h
* Flag any PR with failing CI
* Ensure engineer/CTO is assigned as reviewer on all open PRs

### Step 5 — Security check (all repos)

* Check for new GitHub Security Advisories across all repos
* Check for public issues that look like vulnerability reports
* Verify SLA compliance on open advisories

### Step 6 — Generate and deliver daily summary

The summary is delivered via **push notification** so the board receives it without checking the Paperclip dashboard. The full summary is also posted as a Paperclip comment on the triage task for history.

**Primary: Pushover (confirmed)**

Pushover key is available in the central secret store. The triage agent calls the Pushover API directly from the heartbeat.

**Future: WhatsApp via OpenClaw**

Once Paperclip/OpenClaw setup issues are resolved, daily summaries route through OpenClaw → WhatsApp.

**Summary contents:**

* **New issues** — issues triaged today with recommended labels/actions (across all repos)
* **Triage status** — counts by label (`inscope`, `next`, `needs-info`, moved to discussions)
* **In-scope pipeline** — summary of all `inscope` issues and their current state
* **Today's top 3** — the highest-priority `next` + `cto-reviewed` issues recommended to start today
* **Open PRs** — all open PRs by repo, with age, review status, and CI status
* **PRs needing attention** — PRs awaiting review >24h or with failing CI
* **Security** — open advisories, SLA status, new vulnerability reports
* **Board decisions needed** — any items requiring approval or scope clarification

### Step 7 — Board approval and Paperclip handoff

* Board reviews the summary (via Pushover notification linking to Paperclip comment)
* Board responds via Paperclip comment on the triage task
* Approved items get the `ready` label on GitHub
* Only then are Paperclip issues created and assigned to the relevant team member
* If no board response within 24h, the next digest flags unanswered items again — nothing proceeds without sign-off

---

## Other GitHub Considerations

* **GitHub Discussions** — monitor for trending topics or questions that indicate documentation gaps
* **Stars / forks trend** — include weekly growth in a separate weekly summary
* **Dependabot alerts** — include in security section of daily digest
* **GitHub Actions status** — flag any workflow failures across repos
* **Release management** — track draft releases and tag status

---

## Board Decisions (All Confirmed 2026-04-02)

1. **Triage flow** — Approved. Label-based triage in GitHub, Paperclip issues only for same-day work.
2. **GitHub CLI auth** — Available. Auth is in place for the cascadeguard repo.
3. **Scope filter** — Confirmed. "v1 roadmap" is the `inscope` boundary.
4. **Capacity** — 20% of Lead Platform Engineer allocated to community issue work.
5. **Notification** — Pushover (key in secret store). WhatsApp via OpenClaw as future enhancement.

### Board Decisions (2026-04-03)

1. **Vulnerability handling** — Added per Security.md. Includes handling of incorrectly filed public vulnerability issues.
2. **PR review tracking** — All open PRs must be reviewed by engineer/CTO. Included in daily digest.
3. **Multi-repo scope** — All public CascadeGuard repos are in scope, not just the main CLI repo.

---

## Implementation Phases

### Phase 1 — Setup and first triage (done)

* Label taxonomy on the GitHub repo
* `gh` CLI access verified
* First manual triage pass
* Pushover notification delivery (blocked on GITHUB_TOKEN refresh)
* Lead Platform Engineer allocated at 20% capacity

### Phase 2 — Automated daily triage routine (next sprint)

* CTO creates a recurring Paperclip triage task with daily heartbeat
* Agent runs the full triage process (Steps 1–7) automatically across all repos
* PR review tracking included
* Vulnerability monitoring included
* CTO review (Step 3) runs as part of the same or a follow-up heartbeat
* Board reviews summary and approves via Paperclip comments

### Phase 3 — Full automation + WhatsApp

* Paperclip issue creation automated for `ready`-labeled items
* OpenClaw/WhatsApp integration added as delivery channel
* Metrics tracking: triage-to-implementation time, community response time
* Weekly growth report (stars, forks, discussions activity)

---

## Summary

GitHub is the source of truth for issue state across all CascadeGuard repos. Labels track triage progress. A single daily Paperclip routine handles triage, CTO review, PR review tracking, vulnerability monitoring, prioritization, and board reporting. Vulnerabilities are handled per SECURITY.md — incorrect public disclosures are immediately closed and moved to private advisories. All PRs require engineer/CTO review. Daily summary delivered via Pushover. Board approves via Paperclip comments — nothing proceeds without sign-off.
