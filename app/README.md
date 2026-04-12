# CascadeGuard

Guardian of the container cascade. Event-driven image lifecycle management with Kargo and ArgoCD.

## Install

```bash
pip install cascadeguard
```

Both `cascadeguard` and `cg` are installed as CLI aliases.

## Quick Start

```bash
cg images init                   # Scaffold from seed repo
cg images validate               # Validate images.yaml
cg images check                  # Check base image drift and upstream tags
```

## Commands

| Command | Description |
|---------|-------------|
| `cg images validate` | Validate images.yaml configuration |
| `cg images enrol` | Enrol a new image |
| `cg images check` | Check image drift and upstream tags |
| `cg images status` | Show status of all images |
| `cg images init` | Scaffold a new state repository |
| `cg build generate` | Generate CI/CD pipeline files |
| `cg actions pin` | Pin GitHub Actions to commit SHAs |
| `cg actions audit` | Audit workflows against an actions policy |
| `cg vuln report` | Parse scanner output into diffable reports |
| `cg vuln issues` | Create/update per-CVE GitHub issues |
| `cg scan` | Scan repository for container artifacts |

Requires Python 3.11+.

## Documentation

- [GitHub](https://github.com/cascadeguard/cascadeguard)
- [Docs](https://docs.cascadeguard.io)

## License

[Business Source License 1.1](https://github.com/cascadeguard/cascadeguard/blob/main/LICENSE) — converts to Apache 2.0 on 2030-04-04.
