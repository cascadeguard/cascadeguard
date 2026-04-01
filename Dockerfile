FROM python:3.11-slim AS base

WORKDIR /build

# Install Task (taskfile runner)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && curl -sL https://taskfile.dev/install.sh | sh -s -- -d -b /usr/local/bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- App venv ---
FROM base AS app-builder
COPY app/pyproject.toml app/
RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir -e app/

# Copy app source
COPY app/ /app/

# --- CDK8s venv ---
FROM base AS cdk8s-builder
COPY cdk8s/pyproject.toml cdk8s/
RUN python3 -m venv /cdk8s/.venv \
    && /cdk8s/.venv/bin/pip install --no-cache-dir -e cdk8s/

# Copy cdk8s source
COPY cdk8s/ /cdk8s/

# --- Final image ---
FROM base

# Copy baked venvs and source
COPY --from=app-builder /app /app
COPY --from=cdk8s-builder /cdk8s /cdk8s

# Copy the internal Taskfile
COPY Taskfile.docker.yaml /Taskfile.yaml

# Workspace is mounted at /workspace by callers
VOLUME /workspace

ENTRYPOINT ["task", "--taskfile", "/Taskfile.yaml"]
