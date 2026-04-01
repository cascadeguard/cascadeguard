# CascadeGuard

Guardian of the container cascade. Event-driven image lifecycle management with Kargo and ArgoCD.

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

State repositories use CascadeGuard via Docker — no local Python setup required. Include `Taskfile.shared.yaml` from a tagged release:

```yaml
# Taskfile.yaml in your state repo
version: '3'
includes:
  shared:
    taskfile: https://raw.githubusercontent.com/cascadeguard/cascadeguard/v1.0.0/Taskfile.shared.yaml
    flatten: true
```

Then run:

```bash
task generate          # Generate state files from images.yaml
task synth             # Generate Kargo manifests
task generate-and-synth  # Both in sequence
task status            # View generated files
```

See [cascadeguard-exemplar](https://github.com/cascadeguard/cascadeguard-exemplar) for a complete working example.

## Docker Image

The CascadeGuard Docker image is published to `ghcr.io/cascadeguard/cascadeguard` on each release tag.

Mount your state repo at `/workspace`:

```bash
docker run --rm -v $(pwd):/workspace ghcr.io/cascadeguard/cascadeguard:v1.0.0 generate
docker run --rm -v $(pwd):/workspace ghcr.io/cascadeguard/cascadeguard:v1.0.0 synth
docker run --rm -v $(pwd):/workspace ghcr.io/cascadeguard/cascadeguard:v1.0.0 generate-and-synth
```

## Development

### Setup

```bash
task app:setup      # Set up the app Python environment
task cdk8s:setup    # Set up the CDK8s Python environment
```

### Testing

```bash
task test:unit           # Unit tests for app and cdk8s
task test:integration    # Integration tests
task test:acceptance     # Kargo acceptance tests (requires cluster)
```

### Building the Docker Image Locally

```bash
docker build -t cascadeguard:dev .
docker run --rm -v $(pwd)/path/to/state:/workspace cascadeguard:dev generate
```

## Image Types

### Base Images
Foundational container images that application images build upon. CascadeGuard monitors these for updates and triggers rebuilds of dependent images.

### Managed Images
Built by your CI/CD pipeline. CascadeGuard discovers their Dockerfile dependencies and monitors the base images they use.

### External Images
Third-party images tracked directly. CascadeGuard monitors these for new versions.

## Related

- [cascadeguard-exemplar](https://github.com/cascadeguard/cascadeguard-exemplar) - Example state repository
- [docs](https://github.com/cascadeguard/docs) - Documentation
- [Kargo](https://kargo.io) - Progressive delivery orchestration
- [CDK8s](https://cdk8s.io) - Kubernetes resource generation
