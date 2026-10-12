#!/usr/bin/env python3
"""Sanitize live reproduction output into ``repro.redacted.json``.

Runs after the Azure sign-out step, with no Azure credentials. Raw command
output stays in ``repro/raw`` on the runner; only the document written here is
uploaded. Redaction applies, in order:

1. exact run values: the resource group (``<rg>``), generated names
   (``<nameN>``), the subscription (``<sub>``), tenant and client IDs and
   the generated password;
2. every rule of ``x_engineering_agent.security.sensitive_data`` (vendored
   verbatim as ``repro_sensitive_data``): private keys, GitHub/AWS tokens,
   storage keys, SAS signatures, JWTs, bearer tokens, credentials,
   cloud identifiers, e-mail addresses, phone and payment card numbers;
3. URL query strings, GUIDs (subscription, tenant and object IDs), IPv4/IPv6
   addresses and long key-like strings.

A field that still trips the sensitive-data scanner afterwards is withheld
(fail closed). Only exit codes, verdicts, an error code and the last few
redacted error lines are kept; stdout bodies are never copied.

Both workflows use this sanitizer: ``live-repro.yml`` (Azure CLI, default
``--runner cli``) and ``live-repro-powershell.yml`` (``--runner powershell``,
plan item C2g), so they share the result schema, artifact names and rules.

Result schema (``x-engineering-agent/live-repro-result`` v1), consumed by the
Agent (plan item C2d)::

    {
      "schema": "x-engineering-agent/live-repro-result",
      "schema_version": 1,
      "issue": "Azure/azure-cli#123",
      "spec_hash": "<64 hex>",
      "pr_number": null | 456,
      "pr_head_sha": null | "<40 hex>",    # PR-head re-runs (C2f)
      "tool": "az" | "az-extension:<name>" | "pwsh-az",
      "module": null | "Az.Storage",       # pwsh-az: the module under test
      "observed_in_issue": {...},          # from the validated spec
      "run": {"id": "...", "attempt": "...", "workflow_sha": "..."},
      "results": [{
        "version": "reported" | "latest" | "dev" | "pr",
        "cli_version": "2.79.0" | null,    # pwsh-az: version of "module"
        "extension_version": "1.0.0" | null,
        "source_sha": "<12 hex>" | null,   # dev / pr checkouts
        "status": "completed" | "setup_failed" | "timeout" | "error",
        "reproduced": true | false | null, # null = inconclusive
        "error": null | "<short reason>",
        "steps": [{
          "phase": "setup" | "repro", "index": 0,
          "command": "az storage account show -g <rg> -n <name1>",
                     # or "Get-AzStorageAccount -ResourceGroupName <rg> ..."
          "exit_code": 3 | null, "timed_out": false, "skipped": false,
          "duration_seconds": 2.5,
          "expect_met": true | false | null,
          "observed_matched": true | false | null,   # repro steps only
          "error_code": "ResourceNotFound" | null,
          "error_excerpt": "<= 12 redacted stderr lines, <= 1500 chars"
        }]
      }],
      "redaction": {"withheld_fields": 0}
    }

``reproduced`` is true when any repro step matched every
``observed_in_issue`` criterion (exit code, fixed-string error/output
substring) on the raw output, false when all steps ran without a match and
null when setup failed, the run timed out or the CLI (module) could not be
installed.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import repro_runner as runner
from repro_sensitive_data import redact_sensitive_text, scan_sensitive_content

_cli_runner = runner
RESULT_FILE_NAME = "repro.redacted.json"
WITHHELD = "[withheld: sensitive data]"
MAX_EXCERPT_LINES = 12
MAX_LINE_CHARS = 300
MAX_EXCERPT_CHARS = 1500
MAX_TEXT_CHARS = 2000
STATUSES = ("completed", "setup_failed", "timeout", "error")

_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?)"
    r"(?![0-9A-Fa-f:])"
)
_URL_QUERY = re.compile(r"(https?://[^\s?#\"'<>]+)\?[^\s\"'<>]+")
_KEY_RUN = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
_ERROR_CODE = re.compile(
    r"\(([A-Z][A-Za-z0-9.]{2,80})\)|"
    r"\b(?:Error)?Code:\s*([A-Z][A-Za-z0-9.]{2,80})\b"
)
_CLI_VERSION = re.compile(r"^\d{1,4}(?:\.\d{1,4}){1,3}(?:(?:a|b|rc|dev)\d{0,3})?$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _known_tokens(known):
    """``{raw value: replacement}`` for exact values known to the run."""
    tokens = {}
    for key, value in (known or {}).items():
        if not isinstance(value, str) or len(value) < 4:
            continue
        if key == "name":
            continue  # alias of name1
        if key == "password":
            tokens[value] = "[REDACTED:password]"
        elif key in ("tenant_id", "client_id"):
            tokens[value] = f"[REDACTED:{key.replace('_id', '')}]"
        else:
            tokens[value] = f"<{key.replace('subscription_id', 'sub')}>"
    return tokens


def _redact_key_run(match):
    run = match.group(0)
    if (any(c.isdigit() for c in run) and any(c.islower() for c in run)
            and any(c.isupper() for c in run)):
        return "[REDACTED:key]"
    return run


def redact_text(text, known=None):
    """Apply every redaction rule to ``text`` (see the module docstring)."""
    text = str(text if text is not None else "")
    for value, token in sorted(
        _known_tokens(known).items(), key=lambda item: -len(item[0]),
    ):
        text = re.sub(re.escape(value), token, text, flags=re.I)
    text = redact_sensitive_text(text)
    text = _URL_QUERY.sub(r"\1?[REDACTED:query]", text)
    text = _GUID.sub("[REDACTED:guid]", text)
    text = _IPV4.sub("[REDACTED:ip]", text)
    text = _IPV6.sub("[REDACTED:ip]", text)
    text = _KEY_RUN.sub(_redact_key_run, text)
    return text


def is_clean(text, known=None):
    """True when no sensitive pattern, GUID or known run value remains."""
    text = str(text or "")
    if _GUID.search(text):
        return False
    lowered = text.lower()
    if any(value.lower() in lowered for value in _known_tokens(known)):
        return False
    return not scan_sensitive_content([{"location": "field", "text": text}])["blocked"]


class _Scrubber:
    def __init__(self, known=None):
        self.known = known or {}
        self.withheld = 0

    def text(self, value, limit=MAX_TEXT_CHARS):
        if value is None:
            return None
        redacted = redact_text(value, self.known)[:limit]
        if not is_clean(redacted, self.known):
            self.withheld += 1
            return WITHHELD
        return redacted

    def tree(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.tree(item) for item in value]
        if isinstance(value, dict):
            return {self.text(str(k), 200): self.tree(v) for k, v in value.items()}
        return value


def _tail(path, max_bytes=256_000):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            return handle.read().decode("utf-8", "replace")
    except (OSError, TypeError):
        return ""


def error_excerpt(stderr_text, scrubber):
    lines = [line.rstrip() for line in stderr_text.splitlines() if line.strip()]
    lines = [line[:MAX_LINE_CHARS] for line in lines[-MAX_EXCERPT_LINES:]]
    excerpt = "\n".join(lines)[-MAX_EXCERPT_CHARS:]
    return scrubber.text(excerpt, MAX_EXCERPT_CHARS) if excerpt else None


def error_code(stderr_text, scrubber):
    match = _ERROR_CODE.search(stderr_text or "")
    if not match:
        return None
    return scrubber.text(match.group(1) or match.group(2), 80)


def _int_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def build_version_result(version, install, raw, scrubber):
    install = install or {}
    cli_version = install.get("cli_version")
    extension_version = install.get("extension_version")
    sha = install.get("source_sha")
    result = {
        "version": version,
        "cli_version": cli_version if isinstance(cli_version, str)
        and _CLI_VERSION.match(cli_version) else None,
        "extension_version": extension_version
        if isinstance(extension_version, str)
        and _CLI_VERSION.match(extension_version) else None,
        "source_sha": sha[:12] if isinstance(sha, str) and _SHA.match(sha) else None,
        "status": "error",
        "reproduced": None,
        "error": None,
        "steps": [],
    }
    if install.get("error") or not install:
        result["error"] = scrubber.text(install.get("error") or "CLI was not installed", 200)
        return result
    if not raw:
        result["error"] = "reproduction did not run"
        return result
    status = raw.get("status")
    result["status"] = status if status in STATUSES else "error"
    reproduced = raw.get("reproduced")
    result["reproduced"] = reproduced if isinstance(reproduced, bool) else None
    if raw.get("error"):
        result["error"] = scrubber.text(raw["error"], 200)
    for step in raw.get("steps") or []:
        stderr_text = _tail(step.get("stderr"))
        result["steps"].append({
            "phase": "setup" if step.get("phase") == "setup" else "repro",
            "index": _int_or_none(step.get("index")),
            "command": scrubber.text(step.get("command"), 1000),
            "exit_code": _int_or_none(step.get("exit_code")),
            "timed_out": bool(step.get("timed_out")),
            "skipped": bool(step.get("skipped")),
            "duration_seconds": float(step.get("duration_seconds") or 0.0),
            "expect_met": step.get("expect_met")
            if isinstance(step.get("expect_met"), bool) else None,
            "observed_matched": step.get("observed_matched")
            if isinstance(step.get("observed_matched"), bool) else None,
            "error_code": error_code(stderr_text, scrubber),
            "error_excerpt": error_excerpt(stderr_text, scrubber),
        })
    return result


def build_document(spec, spec_hash, pr_number, results, scrubber, env=None,
                   runner_module=None):
    env = os.environ if env is None else env
    runner_module = runner_module or runner
    pr = (pr_number or "").strip()
    head = (env.get("REPRO_PR_HEAD_SHA") or "").strip()
    return {
        "schema": runner_module.RESULT_SCHEMA,
        "schema_version": runner_module.RESULT_SCHEMA_VERSION,
        "issue": spec["issue"],
        "spec_hash": spec_hash,
        "pr_number": int(pr) if pr.isdigit() else None,
        "pr_head_sha": head if pr and re.fullmatch(r"[0-9a-f]{40}", head) else None,
        "tool": spec["tool"],
        "module": spec.get("module"),
        "observed_in_issue": scrubber.tree(spec["observed_in_issue"]),
        "run": {
            "id": scrubber.text(env.get("GITHUB_RUN_ID", ""), 40),
            "attempt": scrubber.text(env.get("GITHUB_RUN_ATTEMPT", ""), 10),
            "workflow_sha": scrubber.text(env.get("GITHUB_SHA", ""), 40),
        },
        "results": results,
        "redaction": {"withheld_fields": scrubber.withheld},
    }


def env_known(env=None):
    env = os.environ if env is None else env
    return {
        "subscription_id": env.get("REPRO_SUBSCRIPTION_ID") or None,
        "tenant_id": env.get("REPRO_TENANT_ID") or None,
        "client_id": env.get("REPRO_CLIENT_ID") or None,
    }


def finalize(document, known):
    """Serialize ``document``; fail closed if anything sensitive survived."""
    text = json.dumps(document, indent=2, sort_keys=True)
    if is_clean(text, known):
        return text
    for result in document["results"]:
        for step in result["steps"]:
            step["error_excerpt"] = WITHHELD if step["error_excerpt"] else None
            step["error_code"] = None
            step["command"] = WITHHELD
        result["error"] = WITHHELD if result["error"] else None
    document["observed_in_issue"] = {}
    document["redaction"]["withheld_fields"] += 1
    text = json.dumps(document, indent=2, sort_keys=True)
    if not is_clean(text, known):  # pragma: no cover - defensive
        raise RuntimeError("redacted document is still not clean")
    return text


def sanitize_version(spec, env=None, raw_dir=None, out_dir=None,
                     runner_module=None):
    """Per-version document from ``repro/raw`` (reproduce job)."""
    env = os.environ if env is None else env
    runner = runner_module or _cli_runner
    raw_dir = Path(raw_dir or runner.RAW_DIR)
    out_dir = Path(out_dir or runner.OUT_DIR)
    install = runner._read_json(raw_dir / runner.INSTALL_FILE.name)
    raw = runner._read_json(raw_dir / runner.RAW_RESULT_FILE.name)
    known = {**env_known(env), **((raw or {}).get("redact_values") or {})}
    known = {k: v for k, v in known.items() if v}
    scrubber = _Scrubber(known)
    version = env.get("REPRO_VERSION", "")
    result = build_version_result(version, install, raw, scrubber)
    document = build_document(
        spec, env.get("REPRO_SPEC_HASH", ""), env.get("REPRO_PR_NUMBER", ""),
        [result], scrubber, env, runner,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RESULT_FILE_NAME
    path.write_text(finalize(document, known), encoding="utf-8")
    return path, result


def _missing(version):
    return {
        "version": version, "cli_version": None, "extension_version": None,
        "source_sha": None, "status": "error", "reproduced": None,
        "error": "no result (the job failed before producing one)",
        "steps": [],
    }


def merge(spec, parts_dir, out_path, env=None, runner_module=None):
    """Combine per-version documents into the final ``repro.redacted.json``."""
    env = os.environ if env is None else env
    runner = runner_module or _cli_runner
    spec_hash = env.get("REPRO_SPEC_HASH", "")
    expected = runner.matrix_versions(spec, env.get("REPRO_PR_NUMBER", ""))
    known = {k: v for k, v in env_known(env).items() if v}
    scrubber = _Scrubber(known)
    found = {}
    for path in sorted(Path(parts_dir).glob(f"*/{RESULT_FILE_NAME}")):
        data = runner._read_json(path)
        if not isinstance(data, dict) or (
            data.get("schema") != runner.RESULT_SCHEMA
            or data.get("spec_hash") != spec_hash
            or data.get("issue") != spec["issue"]
        ):
            continue
        for result in data.get("results") or []:
            if isinstance(result, dict) and result.get("version") in expected:
                found.setdefault(result["version"], scrubber.tree(result))
    results = [found.get(version) or _missing(version) for version in expected]
    document = build_document(
        spec, spec_hash, env.get("REPRO_PR_NUMBER", ""), results, scrubber, env,
        runner,
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(finalize(document, known), encoding="utf-8")
    return document


def summary_markdown(document):
    labels = {True: "Reproduced", False: "Not reproduced", None: "Inconclusive"}
    lines = [
        f"### Live reproduction `{document['spec_hash'][:12]}`", "",
        f"| Version | {document.get('module') or 'CLI'} | Status | Result |",
        "|---|---|---|---|",
    ]
    for result in document["results"]:
        cli = result["cli_version"] or "-"
        if result["source_sha"]:
            cli += f" @ {result['source_sha'][:7]}"
        lines.append(
            f"| {result['version']} | {cli} | {result['status']} | "
            f"{labels[result['reproduced']]} |"
        )
    lines += ["", "Command output is redacted and only available in the "
              "`repro-redacted` artifact."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="live-repro sanitizer")
    parser.add_argument("--runner", choices=("cli", "powershell"), default="cli",
                        help="workflow whose runner verifies the spec")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="sanitize this job's raw output")
    merge_parser = sub.add_parser("merge", help="merge per-version documents")
    merge_parser.add_argument("--parts", required=True)
    merge_parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    selected = runner
    if args.runner == "powershell":
        import repro_ps_runner as selected
    try:
        spec = selected.verify_from_env()
    except runner.VerificationError:
        print("::error::ReproSpec rejected; nothing to sanitize.")
        return 1
    if args.command == "version":
        path, result = sanitize_version(spec, runner_module=selected)
        print(f"Wrote {path} ({result['status']}).")
        return 0
    document = merge(spec, args.parts, args.out, runner_module=selected)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(summary_markdown(document))
    ran = [r for r in document["results"] if r["status"] != "error"]
    print(f"Wrote {args.out} ({len(ran)}/{len(document['results'])} version(s) ran).")
    return 0 if ran else 1


if __name__ == "__main__":
    sys.exit(main())
