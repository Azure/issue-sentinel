import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

script = Path(__file__).resolve().parents[1] / "scripts/post_live_test_comment.py"
spec = importlib.util.spec_from_file_location("post_live_test_comment", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

RUN = "**Workflow run:** https://github.com/Azure/issue-sentinel/actions/runs/42"
BODY = f"## Live test results — changed test files only\n\nPASS\n\n{RUN}\n"
AUTHOR = {"id": 7, "login": "x-engineering-agent[bot]"}


def test_publish_collapses_only_older_live_tests(monkeypatch):
    comments = [
        {"id": 1, "node_id": "older", "user": AUTHOR,
         "body": BODY.replace("/42", "/41")},
        {"id": 2, "node_id": "already", "user": AUTHOR,
         "body": BODY.replace("/42", "/40")},
        {"id": 3, "node_id": "unrelated", "user": AUTHOR,
         "body": "A normal PR comment"},
        {"id": 4, "node_id": "other-author", "user": {"id": 8},
         "body": BODY.replace("/42", "/39")},
    ]
    calls = []

    def api(path, *, payload=None):
        calls.append((path, payload))
        if path.endswith("comments?per_page=100&page=1"):
            return comments
        if path.endswith("/comments"):
            return {"id": 5, "node_id": "new", "user": AUTHOR, "body": BODY}
        if "query(" in payload["query"]:
            return {"data": {"nodes": [
                {"id": "older", "isMinimized": False, "viewerCanMinimize": True},
                {"id": "already", "isMinimized": True, "viewerCanMinimize": True},
            ]}}
        return {"data": {"minimizeComment": {
            "minimizedComment": {"isMinimized": True},
        }}}

    monkeypatch.setattr(module, "github_api", api)
    assert module.publish("Azure/azure-cli", 34140, BODY)["id"] == 5
    assert [call[1]["variables"] for call in calls if call[0] == "graphql"] == [
        {"ids": ["older", "already"]}, {"id": "older"},
    ]


def test_retry_reuses_same_run_comment_and_finishes_collapsing(monkeypatch):
    old = {"id": 1, "node_id": "old", "user": AUTHOR,
           "body": BODY.replace("/42", "/41")}
    current = {"id": 2, "node_id": "current", "user": AUTHOR, "body": BODY}
    api = Mock(side_effect=[
        [old, current],
        {"data": {"nodes": [{
            "id": "old", "isMinimized": False, "viewerCanMinimize": True,
        }]}},
        {"data": {"minimizeComment": {
            "minimizedComment": {"isMinimized": True},
        }}},
    ])
    monkeypatch.setattr(module, "github_api", api)
    assert module.publish("Azure/azure-powershell", 123, BODY) == current
    assert [call.args[0] for call in api.call_args_list] == [
        "repos/Azure/azure-powershell/issues/123/comments?per_page=100&page=1",
        "graphql", "graphql",
    ]


def test_other_author_cannot_be_collapsed(monkeypatch):
    monkeypatch.setattr(module, "github_api", Mock(side_effect=[
        [{"id": 1, "node_id": "other", "user": {"id": 8},
          "body": BODY.replace("/42", "/41")}],
        {"id": 2, "node_id": "new", "user": AUTHOR, "body": BODY},
    ]))
    assert module.publish("Azure/azure-cli-extensions", 123, BODY)["id"] == 2
    assert module.github_api.call_count == 2


def test_missing_minimization_permission_is_reported(monkeypatch):
    old = {"id": 1, "node_id": "old", "user": AUTHOR,
           "body": BODY.replace("/42", "/41")}
    monkeypatch.setattr(module, "github_api", Mock(side_effect=[
        [old],
        {"id": 2, "node_id": "new", "user": AUTHOR, "body": BODY},
        {"data": {"nodes": [{
            "id": "old", "isMinimized": False, "viewerCanMinimize": False,
        }]}},
    ]))
    with pytest.raises(PermissionError, match="cannot collapse"):
        module.publish("Azure/azure-cli", 123, BODY)
