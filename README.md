# CascadeGuard

Guardian of the container cascade. Event-driven image lifecycle management with Kargo and ArgoCD.

## Quick Start

```bash
# Install (macOS / Linux)
curl -sSL https://raw.githubusercontent.com/cascadeguard/cascadeguard/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/cascadeguard/cascadeguard/main/install.ps1 | iex
```

Then in your state repository:

```bash
cg images init                   # Scaffold from seed repo (includes workflows)
cg images validate               # Validate images.yaml
cg images check                  # Discover base images, check drift and upstream tags
```

Requires Python 3.11+. Both `cg` and `cascadeguard` are installed as aliases.

## Overview

CascadeGuard automates the process of monitoring base images, discovering Dockerfile dependencies, and orchestrating intelligent container image rebuilds through a GitOps workflow. It uses Kargo for orchestration and generates Kubernetes resources via CDK8s.

## Repository Structure

```
.
├── app/                    # Python analysis tool for Dockerfile parsing and state generation
├── cdk8s/                  # CDK8s application for generating Kargo resources
│   ├── lib/                # Reusable CDK8s constructs
│   ├── imports/            # Generated Kargo CRD imports
│   └── main.py             # Main CDK8s application
├── tests/                  # Integration and acceptance tests
│   └── integration/        # Integration test suite
├── Dockerfile              # Builds the CascadeGuard Docker image
├── Taskfile.docker.yaml    # Internal Taskfile (baked into Docker image)
├── Taskfile.shared.yaml    # Shared tasks for state repos (docker run wrappers)
└── Taskfile.yaml           # Developer tasks for this repo
```

## How It Works

1. **Image Enrollment**: Images are defined in `images.yaml` in a state repository
2. **State Files**: Detailed configuration for each image in `base-images/` and `images/` directories
3. **CDK8s Generation**: The CDK8s app reads state files and generates Kargo Warehouses, Stages, and AnalysisTemplates
4. **ArgoCD Deployment**: ArgoCD watches the state repository's `dist/` directory and deploys generated manifests
5. **Kargo Orchestration**: Kargo manages the image build and promotion pipeline, running analysis jobs that discover base image dependencies

## Using CascadeGuard

### 1. Install

```bash
# macOS / Linux
curl -sSL https://raw.githubusercontent.com/cascadeguard/cascadeguard/main/install.sh | sh
```

### 2. Set up your state repository

Scaffold a new state repository from the seed repo:

```bash
mkdir my-images && cd my-images && git init
cg images init
```

Or create an `images.yaml` and `.cascadeguard.yaml` manually:

```yaml
# .cascadeguard.yaml
defaults:
  registry: ghcr.io/myorg
  local:
    dir: images        # folder containing per-image Dockerfiles

ci:
  platform: github
```

```yaml
# images.yaml — managed images inherit registry from .cascadeguard.yaml
- name: nginx
  dockerfile: images/nginx/Dockerfile
  image: nginx
  tag: stable-alpine-slim

# Upstream-tracked images (CVE monitoring only, no build)
- name: memcached
  enabled: false
  namespace: library
```

### 3. Validate, generate, and build

```bash
# Validate images.yaml (applies config defaults before checking)
cg images validate

# Enrol a new image
cg images enrol --name myapp --registry ghcr.io --repository org/myapp

# Check for base image drift and new upstream tags
cg images check
cg images check --format json    # JSON output for CI consumption
cg images check --image myapp    # Scope to a single image

# Generate CI/CD pipeline files (GitHub Actions)
cg build generate

# Generate CI with explicit platform or dry-run
cg build generate --platform github --dry-run
```

See [cascadeguard-exemplar](https://github.com/cascadeguard/cascadeguard-exemplar) for a complete working example.

### Config Inheritance

Common fields can be set once in `.cascadeguard.yaml` under `defaults` instead of repeating them on every image:

| Key | Description |
|-----|-------------|
| `defaults.registry` | Default container registry (e.g. `ghcr.io/cascadeguard`) |
| `defaults.repository` | Default repository prefix |
| `defaults.local.dir` | Default folder containing per-image Dockerfiles |

Per-image values in `images.yaml` always override the defaults.

## Generating CI/CD Pipelines

`cg build generate` reads `images.yaml` and emits four GitHub Actions workflow files under `.github/workflows/`:

| File | Trigger | Purpose |
|------|---------|---------|
| `build-image.yaml` | `workflow_call` | Reusable single-image build, scan (Grype + Trivy), SBOM, and Cosign signing |
| `ci.yaml` | `push` to `main`, `pull_request` | Matrix build of all images; pushes and signs on merge to main |
| `scheduled-scan.yaml` | Nightly cron + `workflow_dispatch` | Re-scans all published images; opens a GitHub Issue on new CVEs |
| `release.yaml` | Tag push (`v*`) | Builds, signs, and pushes all images; creates a GitHub Release with changelog |

```bash
cg build generate
cg build generate --dry-run    # preview without writing
```

Commit the generated files. Adding a new image to `images.yaml` and re-running `cg build generate` will automatically include it in every pipeline.

## Development

See [Contributing](CONTRIBUTING.md) for branch naming, PR process, and coding standards.

For local development setup (Python environments, testing, Docker builds), see the [Development Guide](https://github.com/cascadeguard/cascadeguard-docs/blob/main/docs/contributing/development.md).

## Image Types

### Base Images
Foundational container images that application images build upon. CascadeGuard monitors these for updates and triggers rebuilds of dependent images.

### Managed Images
Built by your CI/CD pipeline. CascadeGuard discovers their Dockerfile dependencies and monitors the base images they use.

### External Images
Third-party images tracked directly. CascadeGuard monitors these for new versions.

## Licensing

CascadeGuard is licensed under the [Business Source License 1.1](LICENSE) (BUSL-1.1).

You are free to use, copy, modify, and distribute CascadeGuard for non-production purposes. Production use is permitted provided you are not offering CascadeGuard to third parties as a commercial container image lifecycle management service or a managed image rebuild service.

On **2030-04-04** (the Change Date), the license automatically converts to the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), at which point CascadeGuard becomes fully open source.

For commercial licensing enquiries, contact [licensing@cascadeguard.io](mailto:licensing@cascadeguard.io).

## Related

- [cascadeguard-exemplar](https://github.com/cascadeguard/cascadeguard-exemplar) - Example state repository
- [docs](https://github.com/cascadeguard/docs) - Documentation
- [Kargo](https://kargo.io) - Progressive delivery orchestration
- [CDK8s](https://cdk8s.io) - Kubernetes resource generation
