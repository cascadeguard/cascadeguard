# CascadeGuard Hooks

CascadeGuard provides a generic hook mechanism that lets you extend the `check` command with custom logic — without modifying the CLI itself.

## Hook Points

| Hook Point | When it fires | Data available |
|---|---|---|
| `post-image-check` | After each image is fully processed (state updated, ready to persist) | Image config, registry response, fully-modified state object |

`post-image-check` is the primary hook for enriching state data. By the time it fires, CascadeGuard has already queried the registry and updated all built-in state fields. Your hook receives both the raw registry response and the complete in-memory state, and may return a partial state patch to merge in before the file is written.

> **Note:** A second hook point, `post-registry-fetch`, is reserved for a future release. It would fire immediately after the registry API call, before any state mutation.

## Configuration

Add a `hooks` section to `.cascadeguard.yaml`:

```yaml
hooks:
  post-image-check:
    - path: ./hooks/download-snapshot.sh
    - path: ./hooks/star-tracker.py
      registries:            # optional: only fire for these registries
        - docker.io
```

- **`path`** — path to the hook executable, relative to the repo root.
- **`registries`** — optional list. When present, the hook only fires for images hosted on those registries. Omit to fire for all registries.

Multiple hooks under the same hook point run sequentially. Each hook's output is merged into the state before the next hook runs.

## Input (stdin)

The hook receives a single JSON object on stdin:

```json
{
  "hookPoint": "post-image-check",
  "image": {
    "name": "nginx",
    "namespace": "library",
    "registry": "docker.io"
  },
  "state": {
    "lastChecked": "2026-04-28T06:00:00Z",
    "upstreamTags": { "1.27": { "digest": "sha256:...", "firstSeen": "..." } }
  },
  "registryResponse": {
    "tags": [
      { "name": "1.27", "digest": "sha256:...", "last_updated": "2026-04-20T00:00:00Z" }
    ],
    "error": null
  },
  "timestamp": "2026-04-28T06:01:00Z"
}
```

- **`image`** — the image config entry from `images.yaml`.
- **`state`** — the fully-updated in-memory state object for this image (same shape as the `.yaml` state file). This is the state that will be persisted — your hook can extend it.
- **`registryResponse`** — the raw response from the registry. `error` is `null` on success; a string error code on failure.
- **`timestamp`** — ISO 8601 UTC timestamp of when this hook invocation started.

The hook **may** also make its own additional API calls (e.g. the Docker Hub repo endpoint for pull counts). CascadeGuard does not restrict outbound calls from hooks.

## Output (stdout)

Return a JSON object with the fields you want to merge into the image state, or `{}` for no changes:

```json
{
  "weeklyDownloads": 15234,
  "downloadHistory": [
    { "date": "2026-04-28", "totalPulls": 8431209, "weeklyDelta": 15234 }
  ]
}
```

CascadeGuard performs a shallow merge of your output into the image state before writing the state file. If you return an empty object or `{}`, the state is unchanged.

### Output validation

CascadeGuard validates that the hook output is a valid JSON object. It does **not** validate extension-specific fields — that is the hook's responsibility. The OS schema will never contain private or downstream-specific field definitions.

## Error handling

- If a hook exits with a non-zero code, CascadeGuard logs a warning and continues. The check is not aborted.
- If a hook produces invalid JSON (or non-object JSON), CascadeGuard logs a warning and skips the merge.
- Hooks have a **30-second timeout** per image. If a hook exceeds this, it is killed and a warning is logged.

## Worked example: logging image stats

A simple hook that writes image stats to a local log file:

```bash
#!/usr/bin/env bash
# hooks/log-stats.sh
set -euo pipefail

input=$(cat)                          # read JSON from stdin
name=$(echo "$input" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
ts=$(echo "$input" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4)

echo "$ts  $name" >> /tmp/cascadeguard-image-stats.log

echo '{}'                             # no state changes
```

Make it executable (`chmod +x hooks/log-stats.sh`), then register it:

```yaml
# .cascadeguard.yaml
hooks:
  post-image-check:
    - path: ./hooks/log-stats.sh
```

Run `cascadeguard check` as normal — the hook fires silently for every successfully-checked image.
