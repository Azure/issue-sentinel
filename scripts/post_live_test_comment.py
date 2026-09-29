"""Post a live-test result and collapse older results from the same bot."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path


WORKFLOW_RUN = re.compile(
    r"^\*\*Workflow run:\*\* https://github\.com/Azure/issue-sentinel/"
    r"actions/runs/\d+\s*$",
    re.MULTILINE,
)
RESULT_HEADER = "## Live test results"


def github_api(path, *, payload=None):
    command = ["gh", "api", path]
    if payload is not None:
        command.extend(["-X", "POST", "--input", "-"])
    try:
        result = subprocess.run(
            command,
            input=json.dumps(payload) if payload is not None else None,
            text=True, capture_output=True, check=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"GitHub API request to {path} failed: {error.stderr.strip()}"
        ) from error
    response = json.loads(result.stdout)
    if isinstance(response, dict) and response.get("errors"):
        raise RuntimeError(f"GitHub API error: {response['errors']}")
    return response


def live_result(comment):
    body = comment.get("body") or ""
    return body.startswith(RESULT_HEADER) and bool(WORKFLOW_RUN.search(body))


def prior_comments(repo, number):
    comments = []
    for page in range(1, 31):
        batch = github_api(
            f"repos/{repo}/issues/{number}/comments?per_page=100&page={page}"
        )
        comments.extend(batch)
        if len(batch) < 100:
            return comments
    raise RuntimeError("PR comment history exceeds the supported pagination limit")


def publish(repo, number, body):
    if repo not in {
        "Azure/azure-cli", "Azure/azure-cli-extensions",
        "Azure/azure-powershell",
    } or not str(number).isdigit():
        raise ValueError("Unsupported live-test pull request")
    if not body.startswith(RESULT_HEADER) or not WORKFLOW_RUN.search(body):
        raise ValueError("Expected a live-test result with a workflow run URL")
    comments = prior_comments(repo, number)
    run_url = WORKFLOW_RUN.search(body).group(0)
    existing = [
        item for item in comments
        if live_result(item) and run_url in (item.get("body") or "")
        and (item.get("user") or {}).get("login") in {
            "x-engineering-agent[bot]", "x-engineering-agent",
        }
    ]
    posted = max(existing, key=lambda item: item["id"]) if existing else github_api(
        f"repos/{repo}/issues/{number}/comments",
        payload={"body": body},
    )
    author = (posted.get("user") or {}).get("id")
    if not author or not isinstance(posted.get("id"), int):
        raise RuntimeError("Posted live-test comment is missing its author or ID")
    older = [
        item for item in comments
        if live_result(item)
        and (item.get("user") or {}).get("id") == author
        and isinstance(item.get("id"), int) and item["id"] < posted["id"]
    ]
    if not older:
        return posted
    ids = [item["node_id"] for item in older]
    for offset in range(0, len(ids), 100):
        batch = ids[offset:offset + 100]
        nodes = github_api("graphql", payload={
            "query": (
                "query($ids: [ID!]!) { nodes(ids: $ids) { "
                "... on IssueComment { id isMinimized viewerCanMinimize } } }"
            ),
            "variables": {"ids": batch},
        })["data"]["nodes"]
        if len(nodes) != len(batch):
            raise RuntimeError("Could not inspect all previous live-test comments")
        for node in nodes:
            if not node or not node.get("id"):
                raise RuntimeError("Could not inspect a previous live-test comment")
            if node["isMinimized"]:
                continue
            if not node["viewerCanMinimize"]:
                raise PermissionError(
                    "GitHub token cannot collapse previous live-test comments"
                )
            result = github_api("graphql", payload={
                "query": (
                    "mutation($id: ID!) { minimizeComment(input: { "
                    "subjectId: $id, classifier: OUTDATED }) { "
                    "minimizedComment { isMinimized } } }"
                ),
                "variables": {"id": node["id"]},
            })
            if not result["data"]["minimizeComment"]["minimizedComment"]["isMinimized"]:
                raise RuntimeError("GitHub did not collapse a previous live-test comment")
    return posted


if __name__ == "__main__":
    publish(os.environ["PR_REPO"], os.environ["PR_NUMBER"],
            Path(sys.argv[1]).read_text(encoding="utf-8"))
