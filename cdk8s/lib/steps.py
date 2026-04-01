"""
Promotion step builders for Kargo stages.
"""
import json


def git_clone_step(repo_url: str, branch: str, path: str = "./repo") -> dict:
    """Build a git-clone promotion step."""
    return {
        "uses": "git-clone",
        "config": {
            "repoURL": repo_url,
            "checkout": [
                {
                    "branch": branch,
                    "path": path
                }
            ]
        }
    }


def http_step(
    alias: str,
    url: str,
    method: str,
    headers: list[dict],
    body: str | None = None
) -> dict:
    """Build an HTTP promotion step."""
    config = {
        "url": url,
        "method": method,
        "headers": headers
    }
    if body:
        config["body"] = body
    
    return {
        "uses": "http",
        "as": alias,
        "config": config
    }


def github_workflow_dispatch_step(
    alias: str,
    repo: str,
    workflow_file: str,
    branch: str,
    inputs: dict,
    token_secret: str = "github-workflow-token"
) -> dict:
    """Build a GitHub workflow_dispatch HTTP step."""
    return http_step(
        alias=alias,
        url=f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches",
        method="POST",
        headers=[
            {"name": "Accept", "value": "application/vnd.github.v3+json"},
            {"name": "Authorization", "value": f"Bearer ${{{{ secret('{token_secret}').token }}}}"},
            {"name": "Content-Type", "value": "application/json"}
        ],
        body=json.dumps({"ref": branch, "inputs": inputs})
    )
