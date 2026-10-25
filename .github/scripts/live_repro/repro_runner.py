#!/usr/bin/env python3
"""Trusted runner for live-repro.yml; untrusted spec steps never touch a shell or the log."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import repro_env
import repro_policy as policy
import repro_spec

RESULT_SCHEMA = "x-engineering-agent/live-repro-result"
RESULT_SCHEMA_VERSION = 1
VERSION_ORDER = ("reported", "latest", "dev", "pr")
WORKSPACE = Path("repro")
VENV_DIR = WORKSPACE / "venv"
SOURCE_DIR = WORKSPACE / "src"
EXTENSION_DIR = WORKSPACE / "extensions"
WHEEL_DIR = WORKSPACE / "wheels"
WHEEL_MANIFEST = WHEEL_DIR / "manifest.json"
CLI_DISTRIBUTIONS = ("azure_cli_telemetry", "azure_cli_core", "azure_cli")
RAW_DIR = WORKSPACE / "raw"
WORK_DIR = WORKSPACE / "work"
OUT_DIR = WORKSPACE / "out"
INSTALL_FILE = RAW_DIR / "install.json"
RAW_RESULT_FILE = RAW_DIR / "repro.raw.json"
MSI_DIR = WORKSPACE / "msi"
SCRIPT_DIR = RAW_DIR / "scripts"
ENV_DIR = RAW_DIR / "env"
ENV_STATE = ENV_DIR / "state.json"
WINDOWS = os.name == "nt"
RUNNER_LABELS = {"linux": "ubuntu-latest", "windows": "windows-latest",
                 "macos": "macos-latest"}
MSI_LATEST_URL = "https://aka.ms/installazurecliwindowsx64"
MSI_VERSION_URL = "https://azcliprod.blob.core.windows.net/msi/azure-cli-{version}-x64.msi"
GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")
INPUT_FILE_NAME = "repro-input.txt"
INPUT_FILE_TEXT = "x-engineering-agent live reproduction input\n"
CLI_REPOSITORY = "Azure/azure-cli"
EXTENSIONS_REPOSITORY = "Azure/azure-cli-extensions"
DEV_REFS = {CLI_REPOSITORY: "dev", EXTENSIONS_REPOSITORY: "main"}
INSTALL_TIMEOUT_SECONDS = 25 * 60
LIFECYCLE_TIMEOUT_SECONDS = 20 * 60
# Written by rg-create before it creates the group.
GROUP_MARKER = RAW_DIR / "lifecycle" / "group-requested"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PR_NUMBER = re.compile(r"^(?:0|[1-9]\d{0,8})$")
# pr_number 0 verifies an unpublished candidate pushed to this branch on the Agent fork.
CANDIDATE_PR = "0"
CANDIDATE_BRANCH_PREFIX = "xea-candidate/"
_HEAD_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_WHEEL_NAME = re.compile(
    r"^(?P<dist>[A-Za-z0-9_.]+)-(?P<version>[0-9][A-Za-z0-9_.+!]*)"
    r"(?:-[0-9][A-Za-z0-9_.]*)?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$"
)
GITHUB_API = "https://api.github.com"
_RUN_KEY = re.compile(r"[^A-Za-z0-9-]")
# Child processes inherit only these; GitHub and OIDC request tokens are dropped.
_CHILD_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER")
# Windows processes (Python, msiexec, Git Bash, pwsh) fail without these.
# The Windows runner image keeps az's login in AZURE_CONFIG_DIR (C:\azureCli).
_WINDOWS_ENV_KEYS = (
    "AZURE_CONFIG_DIR",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
    "USERPROFILE", "USERNAME", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "PROGRAMDATA", "COMMONPROGRAMFILES",
    "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "OS",
)
_CHILD_ENV_FIXED = {
    "AZURE_CORE_COLLECT_TELEMETRY": "false",
    "AZURE_CORE_NO_COLOR": "true",
    "AZURE_CORE_SURVEY_MESSAGE": "false",
    "PYTHONIOENCODING": "utf-8",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
}


class VerificationError(ValueError):
    """The dispatched spec doesn't match its hash or fails validation."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def verify_dispatch(spec_text, spec_hash, issue, pr_number="", pr_head_sha=""):
    """Checks shared by every reproduction workflow; returns (spec, errors).

    The input must be the canonical JSON of the spec and hash to spec_hash. Raises
    VerificationError when the spec can't be used at all.
    """
    spec_text = spec_text if isinstance(spec_text, str) else ""
    spec_hash = (spec_hash or "").strip()
    pr_number = (pr_number or "").strip()
    pr_head_sha = (pr_head_sha or "").strip()
    if not _HASH.match(spec_hash):
        raise VerificationError(["spec_hash: must be 64 lowercase hex characters"])
    if pr_number and not _PR_NUMBER.match(pr_number):
        raise VerificationError(["pr_number: must be 0 for a candidate or a positive integer"])
    if pr_number and not _HEAD_SHA.match(pr_head_sha):
        raise VerificationError([
            "pr_head_sha: must be the 40 lowercase hex commit SHA of the PR head"
        ])
    if pr_head_sha and not pr_number:
        raise VerificationError(["pr_head_sha: only valid with pr_number"])
    actual = hashlib.sha256(spec_text.encode("utf-8")).hexdigest()
    if actual != spec_hash:
        raise VerificationError(["spec: SHA-256 of the spec input does not match spec_hash"])
    result = repro_spec.validate_spec(spec_text)
    if not result["valid"]:
        raise VerificationError(result["errors"])
    normalized = result["spec"]
    errors = []
    if result["spec_hash"] != spec_hash:
        errors.append("spec: normalized spec hash does not match spec_hash")
    if repro_spec.canonical_spec_json(normalized) != spec_text:
        errors.append("spec: input is not the canonical JSON of the normalized spec")
    if normalized["issue"] != (issue or ""):
        errors.append("issue: does not match the spec")
    return normalized, errors


def verify_spec(spec_text, spec_hash, issue, pr_number="", pr_head_sha=""):
    """Re-validate an az or az-extension spec and return the normalized spec."""
    pr_number = (pr_number or "").strip()
    normalized, errors = verify_dispatch(
        spec_text, spec_hash, issue, pr_number, pr_head_sha,
    )
    if normalized["tool"] == "pwsh-az":
        errors.append("tool: pwsh-az specs run in live-repro-powershell.yml")
    for phase in ("setup", "repro"):
        for index, step in enumerate(normalized[phase]):
            if "shell" in step:
                continue
            argv = step.get("argv")
            if not isinstance(argv, list) or not argv or argv[0] != "az":
                errors.append(f"{phase}[{index}]: only az argv steps run here")
    if pr_number:
        repository = source_repository(normalized)
        if normalized["issue"].split("#", 1)[0] != repository:
            errors.append(
                f"pr_number: PR re-runs need an issue on {repository}"
            )
        elif not agent_fork(repository):
            errors.append(
                f"pr_number: no Agent fork is configured for {repository}"
            )
    if errors:
        raise VerificationError(errors)
    return normalized


def verify_from_env(env=None):
    env = os.environ if env is None else env
    return verify_spec(
        env.get("REPRO_SPEC", ""), env.get("REPRO_SPEC_HASH", ""),
        env.get("REPRO_ISSUE", ""), env.get("REPRO_PR_NUMBER", ""),
        env.get("REPRO_PR_HEAD_SHA", ""),
    )


def agent_fork(repository):
    """The Agent's fork for repository, or None."""
    fork = (repro_spec.REPO_PROFILES.get(repository) or {}).get("agent_fork")
    return fork if isinstance(fork, str) and _REPOSITORY.match(fork) else None


def _fetch_pull_request(repository, pr_number, env=None):
    env = os.environ if env is None else env
    request = urllib.request.Request(
        f"{GITHUB_API}/repos/{repository}/pulls/{int(pr_number)}",
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "issue-sentinel-live-repro"},
    )
    token = env.get("REPRO_GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read(1_000_000).decode("utf-8"))


def candidate_branch(head_sha):
    return f"{CANDIDATE_BRANCH_PREFIX}{head_sha}"


def _fetch_branch(fork, branch, env=None):
    env = os.environ if env is None else env
    request = urllib.request.Request(
        f"{GITHUB_API}/repos/{fork}/branches/{urllib.parse.quote(branch, safe='')}",
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "issue-sentinel-live-repro"},
    )
    token = env.get("REPRO_GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read(1_000_000).decode("utf-8"))


def verify_candidate(fork, head_sha, *, fetch_branch=None):
    """Check that the Agent fork's candidate branch for head_sha points at head_sha.

    Only the Agent can push to its fork, so this proves the Agent produced the commit.
    """
    fetch_branch = fetch_branch or _fetch_branch
    try:
        branch = fetch_branch(fork, candidate_branch(head_sha))
    except (OSError, ValueError, urllib.error.URLError):
        raise VerificationError(["pr_number: the candidate branch could not be read"]) from None
    commit = branch.get("commit") if isinstance(branch, dict) else None
    if not isinstance(commit, dict) or commit.get("sha") != head_sha:
        raise VerificationError(["pr_head_sha: the candidate branch does not point at this commit"])
    return fork


def verify_pull_request(repository, pr_number, head_sha, *, fetch=None, fetch_branch=None):
    """Check that the PR is an open Agent PR whose head is exactly head_sha.

    pr_number 0 checks the Agent fork's candidate branch instead of a PR.
    Returns the fork to check out. Errors use fixed messages; API text is never printed.
    """
    fork = agent_fork(repository)
    if not fork:
        raise VerificationError([f"pr_number: no Agent fork is configured for {repository}"])
    if str(pr_number).strip() == CANDIDATE_PR:
        return verify_candidate(fork, head_sha, fetch_branch=fetch_branch)
    fetch = fetch or _fetch_pull_request
    try:
        pr = fetch(repository, pr_number)
    except (OSError, ValueError, urllib.error.URLError):
        raise VerificationError(["pr_number: the pull request could not be read"]) from None
    if not isinstance(pr, dict):
        raise VerificationError(["pr_number: the pull request could not be read"])
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    head_repo = head.get("repo") if isinstance(head.get("repo"), dict) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
    errors = []
    if pr.get("state") != "open":
        errors.append("pr_number: the pull request is not open")
    if str(base_repo.get("full_name") or "").casefold() != repository.casefold():
        errors.append(f"pr_number: the pull request does not target {repository}")
    if str(head_repo.get("full_name") or "").casefold() != fork.casefold():
        errors.append("pr_number: the pull request head is not the Agent fork")
    if head.get("sha") != head_sha:
        errors.append("pr_head_sha: the pull request head moved; dispatch again")
    if errors:
        raise VerificationError(errors)
    return fork


def extension_name(spec):
    tool = spec["tool"]
    return tool.split(":", 1)[1] if tool.startswith("az-extension:") else None


def source_repository(spec):
    return EXTENSIONS_REPOSITORY if extension_name(spec) else CLI_REPOSITORY


def matrix_versions(spec, pr_number=""):
    """Versions to run: the spec's versions, or dev (before) and pr (after)."""
    if (pr_number or "").strip():
        return ["dev", "pr"]
    return [v for v in VERSION_ORDER if v in spec["versions"]]


def run_key(run_id, version):
    return _RUN_KEY.sub("-", f"{run_id}-{version}")[:20]


def resource_group_for(spec, env=None):
    env = os.environ if env is None else env
    return repro_spec.reproduction_resource_group(
        spec["issue"], run_key(env.get("GITHUB_RUN_ID", "local"),
                               env.get("REPRO_VERSION", "latest")),
    )


def display_step(step):
    """Report text for a step: argv, or the shell and the start of its script."""
    if "shell" in step:
        script = " ".join(step["script"].split())
        return f"{step['shell']}: {script[:400]}"
    return display_command(step["argv"])


def display_command(argv):
    """Unresolved argv for reports, with placeholders shown as <rg> etc."""
    shown = [re.sub(r"\{([a-z0-9]+)\}", r"<\1>", token) for token in argv]
    return " ".join(
        token if re.fullmatch(r"[^\s'\"]+", token) else shlex.quote(token)
        for token in shown
    )


def child_env(extra=None, env=None):
    env = os.environ if env is None else env
    keys = _CHILD_ENV_KEYS + (_WINDOWS_ENV_KEYS if WINDOWS else ())
    result = {k: env[k] for k in keys if env.get(k)}
    result.update(_CHILD_ENV_FIXED)
    result.update(extra or {})
    return result


def run_quiet(argv, log_stem, *, timeout, cwd=None, extra_env=None):
    """Run argv without a shell, sending stdout and stderr to files; output is never printed."""
    log_stem = Path(log_stem)
    log_stem.parent.mkdir(parents=True, exist_ok=True)
    out_path = log_stem.with_suffix(".out")
    err_path = log_stem.with_suffix(".err")
    started = time.monotonic()
    timed_out = False
    exit_code = None
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        try:
            completed = subprocess.run(
                [str(token) for token in argv], shell=False,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                cwd=str(cwd) if cwd else None, env=child_env(extra_env),
                timeout=max(1, int(timeout)), check=False,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as exc:
            err.write(f"failed to start: {exc.strerror}\n".encode("utf-8"))
            exit_code = 127
    return {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 2),
        "stdout": str(out_path),
        "stderr": str(err_path),
    }


def write_outputs(values, env=None):
    env = os.environ if env is None else env
    path = env.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _write_json(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    if private:
        os.chmod(path, 0o600)


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def system_az():
    return shutil.which("az") or "az"


def venv_bin():
    return VENV_DIR / ("Scripts" if WINDOWS else "bin")


def venv_python():
    return venv_bin() / ("python.exe" if WINDOWS else "python")


def venv_az():
    return (venv_bin() / "az").resolve()


# pip's extensionless `az` re-executes Python with os.execl, which on Windows
# spawns a detached child and returns at once, so Git Bash sees no output.
# The MSI ships this bash wrapper in wbin instead; venv installs get the same.
_GIT_BASH_AZ = (
    "#!/usr/bin/env bash\n"
    'AZ_INSTALLER=PIP exec "$(dirname "${BASH_SOURCE[0]}")/python.exe" -m azure.cli "$@"\n'
)


def write_git_bash_az(directory):
    path = Path(directory) / "az"
    path.write_bytes(_GIT_BASH_AZ.encode())
    return path


def az_command(install=None):
    """argv prefix that runs the installed CLI, or None when it is missing."""
    install = install if install is not None else (_read_json(INSTALL_FILE) or {})
    python = install.get("python")
    if python:
        return [python, "-I", "-m", "azure.cli"] if Path(python).exists() else None
    if WINDOWS:
        python = venv_python().resolve()
        return [str(python), "-m", "azure.cli"] if python.exists() else None
    return [str(venv_az())] if venv_az().exists() else None


def bin_dir(install=None):
    """Directory to put first on PATH so scripts run the CLI under test."""
    install = install if install is not None else (_read_json(INSTALL_FILE) or {})
    return install.get("bin_dir") or str(venv_bin().resolve())


def cmd_verify(args):
    """Validate the dispatch and publish the matrix for the reproduce jobs."""
    try:
        spec = verify_from_env()
    except VerificationError as exc:
        import repro_sanitize

        print(f"::error::ReproSpec rejected ({len(exc.errors)} problem(s)).")
        for error in exc.errors:
            print(f"- {repro_sanitize.redact_text(error)[:300]}")
        return 1
    pr_number = os.environ.get("REPRO_PR_NUMBER", "").strip()
    head_sha = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()
    repository = source_repository(spec)
    versions = matrix_versions(spec, pr_number)
    pr_repo = ""
    if pr_number:
        try:
            pr_repo = verify_pull_request(repository, pr_number, head_sha)
        except VerificationError as exc:
            print(f"::error::{'The candidate' if int(pr_number) == 0 else f'PR #{int(pr_number)}'} cannot be re-run "
                  f"({len(exc.errors)} problem(s)).")
            for error in exc.errors:
                print(f"- {error}")
            return 1
    write_outputs({
        "versions": json.dumps(versions),
        "runs_on": repro_env.runs_on(spec, RUNNER_LABELS),
        "isolation": "vm" if repro_env.kind(spec) == "vm" else "host",
        "azure": "false" if spec.get("azure") is False else "true",
        "timeout_minutes": spec["timeout_minutes"],
        "step_timeout_minutes": spec["timeout_minutes"] + 5,
        "source_repo": repository,
        "dev_ref": DEV_REFS[repository],
        "pr_repo": pr_repo,
        "pr_ref": head_sha if pr_number else "",
    })
    steps = len(spec["setup"]) + len(spec["repro"])
    print(
        f"ReproSpec {os.environ['REPRO_SPEC_HASH'][:12]} verified: "
        f"tool {spec['tool']}, {steps} step(s), versions {', '.join(versions)}, "
        f"{repro_env.describe(spec)}"
        f"{'' if spec.get('azure') is not False else ', no Azure sign in'}."
    )
    return 0


def _install_commands(spec, version, wheels=None):
    python = str(venv_python())
    pip = [python, "-m", "pip", "install", "--disable-pip-version-check",
           "--no-input"]
    extension = extension_name(spec)
    commands = [("venv", [sys.executable, "-m", "venv", str(VENV_DIR)])]
    commands.append(("pip-upgrade", [*pip, "--upgrade", "pip"]))
    if version == "pr":
        # Prebuilt wheels only: installing a wheel runs none of its code.
        files = [str((WHEEL_DIR / w["file"]).resolve()) for w in wheels or []]
        if extension:
            commands.append(("azure-cli", [*pip, "azure-cli"]))
            commands.append(("extension", [
                *pip, "--target", str((EXTENSION_DIR / extension).resolve()),
                *files,
            ]))
        else:
            commands.append(("azure-cli", [*pip, *files]))
        return commands
    if extension or version == "latest":
        commands.append(("azure-cli", [*pip, "azure-cli"]))
    elif version == "reported":
        commands.append(("azure-cli", [*pip, f"azure-cli=={spec['reported_version']}"]))
    else:
        source = SOURCE_DIR / "src"
        commands.append(("azure-cli", [
            *pip, str(source / "azure-cli-telemetry"),
            str(source / "azure-cli-core"), str(source / "azure-cli"),
        ]))
    if extension:
        az = [python, "-m", "azure.cli"]
        if version == "reported":
            commands.append(("extension", [
                *az, "extension", "add", "--name", extension, "--version",
                spec["reported_version"], "--yes",
            ]))
        elif version == "latest":
            commands.append(("extension", [
                *az, "extension", "add", "--name", extension, "--yes",
            ]))
        else:
            commands.append(("extension", [
                *pip, "--target", str((EXTENSION_DIR / extension).resolve()),
                str(SOURCE_DIR / "src" / extension),
            ]))
    return commands


def _wheel_info(name):
    match = _WHEEL_NAME.match(name)
    if not match:
        return None
    return {"file": name, "distribution": match["dist"].casefold(),
            "version": match["version"]}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_wheels(spec, wheels):
    """Problems with the built wheel set for spec (empty when usable)."""
    if extension_name(spec):
        return [] if len(wheels) == 1 else ["expected exactly one extension wheel"]
    names = sorted(w["distribution"] for w in wheels)
    return [] if names == sorted(CLI_DISTRIBUTIONS) else [
        "expected the azure-cli, azure-cli-core and azure-cli-telemetry wheels"
    ]


def load_wheel_manifest(spec, head_sha, wheel_dir=None):
    """Verified wheel list for the PR head; raises ValueError otherwise."""
    wheel_dir = Path(wheel_dir or WHEEL_DIR)
    manifest = _read_json(wheel_dir / WHEEL_MANIFEST.name)
    if not isinstance(manifest, dict) or manifest.get("head_sha") != head_sha:
        raise ValueError("PR wheels are missing or were built from another commit")
    wheels = []
    for item in manifest.get("wheels") or []:
        info = _wheel_info(str((item or {}).get("file") or ""))
        path = wheel_dir / info["file"] if info else None
        if not info or not path.is_file() or _sha256(path) != item.get("sha256"):
            raise ValueError("PR wheel does not match the build manifest")
        wheels.append({**info, "sha256": item["sha256"]})
    problems = _expected_wheels(spec, wheels)
    if problems:
        raise ValueError(problems[0])
    return wheels


def _source_sha(log_stem):
    git = run_quiet(["git", "-C", SOURCE_DIR, "rev-parse", "HEAD"], log_stem,
                    timeout=60)
    sha = Path(git["stdout"]).read_text(encoding="utf-8").strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def cmd_build(args):
    """Build wheels from the PR head checkout, with no Azure credentials."""
    spec = verify_from_env()
    head_sha = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()
    if not head_sha:
        print("::error::Only PR-head re-runs build wheels.")
        return 1
    if _source_sha(RAW_DIR / "build" / "git-sha") != head_sha:
        print("::error::The checkout is not the requested PR head commit.")
        return 1
    extension = extension_name(spec)
    source = SOURCE_DIR / "src"
    paths = ([source / extension] if extension else
             [source / "azure-cli-telemetry", source / "azure-cli-core",
              source / "azure-cli"])
    if not all(path.is_dir() for path in paths):
        print("::error::PR head source directory not found.")
        return 1
    if WHEEL_DIR.exists():
        shutil.rmtree(WHEEL_DIR)
    WHEEL_DIR.mkdir(parents=True)
    result = run_quiet([
        sys.executable, "-m", "pip", "wheel", "--no-deps",
        "--disable-pip-version-check", "--no-input",
        "--wheel-dir", str(WHEEL_DIR), *map(str, paths),
    ], RAW_DIR / "build" / "wheel", timeout=INSTALL_TIMEOUT_SECONDS)
    print(f"build wheels: exit {result['exit_code']} ({result['duration_seconds']}s)")
    wheels = [info for info in map(_wheel_info, sorted(
        p.name for p in WHEEL_DIR.glob("*.whl"))) if info]
    problems = _expected_wheels(spec, wheels) if result["exit_code"] == 0 else [
        "pip wheel failed"]
    if problems:
        print(f"::error::Building the PR head failed: {problems[0]}.")
        return 1
    _write_json(WHEEL_MANIFEST, {"head_sha": head_sha, "wheels": [
        {"file": w["file"], "sha256": _sha256(WHEEL_DIR / w["file"])}
        for w in wheels
    ]})
    print(f"Built {len(wheels)} wheel(s) for the PR head.")
    return 0


def msi_url(spec, version):
    if version == "latest":
        return MSI_LATEST_URL
    return MSI_VERSION_URL.format(version=spec["reported_version"])


def find_msi_cli(root):
    """(python, wbin) inside an extracted MSI, or (None, None)."""
    for az_cmd in sorted(Path(root).rglob("az.cmd")):
        if az_cmd.parent.name.lower() == "wbin":
            python = az_cmd.parent.parent / "python.exe"
            if python.is_file():
                return python.resolve(), az_cmd.parent.resolve()
    return None, None


def _install_msi(spec, version):
    """Extract the official Windows MSI (administrative install, no registry).

    Returns install info or an error string. The preinstalled az stays untouched.
    """
    if MSI_DIR.exists():
        shutil.rmtree(MSI_DIR)
    target = (MSI_DIR / "cli").resolve()
    target.mkdir(parents=True)
    package = MSI_DIR / "azure-cli.msi"
    try:
        with urllib.request.urlopen(msi_url(spec, version), timeout=600) as response, \
                open(package, "wb") as handle:
            shutil.copyfileobj(response, handle)
    except (OSError, urllib.error.URLError):
        return "downloading the MSI failed"
    print("install msi-download: done")
    result = run_quiet(
        ["msiexec", "/a", str(package.resolve()), "/qn", f"TARGETDIR={target}",
         "/L*v", str((RAW_DIR / "install" / "msiexec.log").resolve())],
        RAW_DIR / "install" / "msi", timeout=INSTALL_TIMEOUT_SECONDS,
    )
    print(f"install msi: exit {result['exit_code']} ({result['duration_seconds']}s)")
    if result["exit_code"] != 0:
        return "install step `msi` failed"
    python, wbin = find_msi_cli(target)
    if not python:
        return "the MSI layout has no CLI2 python.exe and wbin"
    return {"python": str(python), "bin_dir": str(wbin)}


def cmd_install(args):
    """Install the matrix version of the CLI (and extension) into a venv."""
    spec = verify_from_env()
    version = os.environ.get("REPRO_VERSION", "")
    if version not in VERSION_ORDER:
        print("::error::Unknown reproduction version.")
        return 1
    extension = extension_name(spec)
    if repro_env.kind(spec) == "vm":
        return _install_vm(spec, version, extension)
    wheels = None
    if version == "pr":
        try:
            wheels = load_wheel_manifest(
                spec, os.environ.get("REPRO_PR_HEAD_SHA", "").strip(),
            )
        except ValueError as exc:
            _write_json(INSTALL_FILE, {"version": version, "error": str(exc)})
            print("::error::PR head wheels are missing or do not verify.")
            return 1
    elif version == "dev" and not (SOURCE_DIR / "src").is_dir():
        _write_json(INSTALL_FILE, {"version": version, "error": "source checkout missing"})
        print("::error::Source checkout is missing.")
        return 1
    if extension and version == "dev" and not (
        SOURCE_DIR / "src" / extension
    ).is_dir():
        _write_json(INSTALL_FILE, {"version": version, "error": "extension source not found"})
        print("::error::Extension source directory not found.")
        return 1
    EXTENSION_DIR.mkdir(parents=True, exist_ok=True)
    extra = {"AZURE_EXTENSION_DIR": str(EXTENSION_DIR.resolve())}
    if repro_env.kind(spec) == "container":
        return _install_container(spec, version, extension, wheels, extra)
    msi = None
    if WINDOWS and version in ("latest", "reported") and not extension:
        msi = _install_msi(spec, version)
        if isinstance(msi, str):
            _write_json(INSTALL_FILE, {"version": version, "error": msi})
            print(f"::error::Installing the {version} CLI failed.")
            return 1
    commands = [] if msi else _install_commands(spec, version, wheels)
    for name, argv in commands:
        result = run_quiet(
            argv, RAW_DIR / "install" / name, timeout=INSTALL_TIMEOUT_SECONDS,
            extra_env=extra,
        )
        print(f"install {name}: exit {result['exit_code']} ({result['duration_seconds']}s)")
        if result["exit_code"] != 0:
            _write_json(INSTALL_FILE, {
                "version": version, "error": f"install step `{name}` failed",
            })
            print(f"::error::Installing the {version} CLI failed.")
            return 1
    if WINDOWS and not msi:
        write_git_bash_az(venv_bin())
    info = {"version": version, "error": None, "cli_version": None,
            "extension_version": None, "source_sha": None, **(msi or {})}
    if version == "pr":
        # No PR code runs before the sandboxed `run` step.
        _pr_wheel_info(info, wheels, extension)
        _write_json(INSTALL_FILE, info)
        write_outputs({"source_ref": info["source_sha"]})
        print("Installed the PR head wheels.")
        return 0
    result = run_quiet([*az_command(info), "version", "-o", "json"],
                       RAW_DIR / "install" / "az-version", timeout=300,
                       extra_env=extra)
    data = _read_json(result["stdout"]) or {}
    info["cli_version"] = data.get("azure-cli")
    if extension:
        info["extension_version"] = (data.get("extensions") or {}).get(extension)
    if version == "dev":
        info["source_sha"] = _source_sha(RAW_DIR / "install" / "git-sha")
    _write_json(INSTALL_FILE, info)
    write_outputs({"source_ref": source_ref(spec, info)})
    print(f"Installed azure-cli {info['cli_version'] or 'unknown'} for `{version}`.")
    return 0


def _install_failed(version, error):
    _write_json(INSTALL_FILE, {"version": version, "error": error})
    print(f"::error::Installing the {version} CLI failed.")
    return 1


def _pr_wheel_info(info, wheels, extension):
    by_name = {w["distribution"]: w["version"] for w in wheels}
    info["cli_version"] = by_name.get("azure_cli")
    if extension:
        info["extension_version"] = wheels[0]["version"]
    info["source_sha"] = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()


def _install_container(spec, version, extension, wheels, extra):
    """Install inside the running environment container (distro package or pip)."""
    state = _read_json(ENV_STATE) or {}
    if state.get("kind") != "container":
        return _install_failed(version, "the environment container is not running")
    source = (SOURCE_DIR / "src").resolve()
    files = [(WHEEL_DIR / w["file"]).resolve() for w in wheels or []]
    if version == "pr":
        cli_paths = ext_paths = files
    else:
        cli_paths = [source / name for name in
                     ("azure-cli-telemetry", "azure-cli-core", "azure-cli")]
        ext_paths = [source / extension] if extension else []
    installed = repro_env.container_install(
        spec, version, run=run_quiet, state=state, log_dir=RAW_DIR / "install",
        workspace=WORKSPACE, timeout=INSTALL_TIMEOUT_SECONDS, extension=extension,
        cli_paths=cli_paths, ext_paths=ext_paths, ext_dir=EXTENSION_DIR,
    )
    if isinstance(installed, str):
        return _install_failed(version, installed)
    print(f"install {spec['environment']}: done")
    info = {"version": version, "error": None, "cli_version": None,
            "extension_version": None, "source_sha": None,
            "container_az": installed["az"]}
    if version == "pr":
        # No PR code runs before the `run` step, as on the host.
        _pr_wheel_info(info, wheels, extension)
    else:
        result = run_quiet(
            repro_env.container_exec(state, [installed["az"], "version", "-o", "json"],
                                     env=repro_env.container_env(state, extra)),
            RAW_DIR / "install" / "az-version", timeout=300,
        )
        data = _read_json(result["stdout"]) or {}
        info["cli_version"] = data.get("azure-cli")
        if extension:
            info["extension_version"] = (data.get("extensions") or {}).get(extension)
        if version == "dev":
            info["source_sha"] = _source_sha(RAW_DIR / "install" / "git-sha")
    _write_json(INSTALL_FILE, info)
    write_outputs({"source_ref": source_ref(spec, info)})
    print(f"Installed azure-cli {info['cli_version'] or 'unknown'} for `{version}` "
          f"in {spec['environment']}.")
    return 0


def _install_vm(spec, version, extension):
    """Install the real MSI (and dev or PR source) inside the environment VM."""
    state = _read_json(ENV_STATE) or {}
    if state.get("kind") != "vm":
        return _install_failed(version, "the environment VM was not created")
    repository = source_repository(spec)
    sha = None
    if version == "dev":
        sha = repro_env.resolve_dev_sha(repository, DEV_REFS[repository], run=run_quiet,
                                        log_dir=RAW_DIR / "install")
        if not sha:
            return _install_failed(version, "resolving the dev commit failed")
    elif version == "pr":
        sha = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()
        repository = agent_fork(repository)
        if not repository or not _HEAD_SHA.match(sha):
            return _install_failed(version, "the PR head is not an Agent fork commit")
    cli = "latest" if extension or version in ("dev", "pr") else version
    config = repro_env.vm_install_config(
        spec, version, msi_url=msi_url(spec, cli), extension=extension,
        source_repo=repository, source_sha=sha,
    )
    result = repro_env.vm_invoke(
        state, config, run=run_quiet, az=system_az(), log_stem=RAW_DIR / "install" / "vm",
        timeout=INSTALL_TIMEOUT_SECONDS * 2, attempts=repro_env.VM_INVOKE_ATTEMPTS,
    )
    if not result or not result.get("ok"):
        reason = str((result or {}).get("error") or "the VM run command failed")[:300]
        return _install_failed(version, f"installing in the VM failed: {reason}")
    info = {"version": version, "error": None,
            "cli_version": result.get("cli_version"),
            "extension_version": result.get("extension_version"),
            "source_sha": sha, "vm_source": result.get("source"), "vm_ready": True}
    _write_json(INSTALL_FILE, info)
    print(f"Installed azure-cli {info['cli_version'] or 'unknown'} for `{version}` "
          f"in {spec['environment']}.")
    return 0


def source_ref(spec, info):
    """Git ref of the source that matches the installed CLI (for REPRO_SOURCE_DIR)."""
    if info.get("source_sha"):
        return info["source_sha"]
    if not extension_name(spec) and info.get("cli_version"):
        return f"azure-cli-{info['cli_version']}"
    return DEV_REFS[source_repository(spec)]


def expires_at(now=None, hours=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    hours = policy.REPRO_RESOURCE_GROUP_TTL_HOURS if hours is None else hours
    return (now + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mark_group_requested(group):
    """Record that rg-create was attempted for group in this job."""
    GROUP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    GROUP_MARKER.write_text(group + "\n", encoding="utf-8")


def group_requested(group):
    """Whether rg-create was attempted for group in this job.

    If the job failed earlier, e.g. at Azure login, there is nothing to delete.
    """
    try:
        return GROUP_MARKER.read_text(encoding="utf-8").strip() == group
    except OSError:
        return False


def cmd_rg_create(args):
    """Create the per-run resource group tagged with expiresAt."""
    spec = verify_from_env()
    group = resource_group_for(spec)
    mark_group_requested(group)
    result = run_quiet([
        system_az(), "group", "create", "--name", group,
        "--location", spec["location"], "--tags",
        f"{policy.REPRO_EXPIRES_TAG}={expires_at()}",
        "createdBy=x-engineering-agent", "purpose=live-repro",
        f"specHash={os.environ['REPRO_SPEC_HASH'][:16]}",
        "--only-show-errors", "-o", "none",
    ], RAW_DIR / "lifecycle" / "group-create", timeout=LIFECYCLE_TIMEOUT_SECONDS)
    print(f"Resource group create: exit {result['exit_code']}.")
    if result["exit_code"] == 0:
        return 0
    code = repro_env.arm_error_code(result["stderr"]) or ("timeout" if result.get("timed_out") else "unknown")
    print(f"::error::Resource group create failed ({code}).")
    if code == "unknown":
        import repro_sanitize  # imports this module
        excerpt = repro_sanitize.error_excerpt(
            repro_sanitize._tail(result["stderr"]),
            repro_sanitize._Scrubber(repro_sanitize.env_known()),
        )
        for line in (excerpt or "").splitlines():
            print(f"  {line}")
    return 1


def cmd_rg_delete(args):
    """Delete the per-run resource group; the janitor is the backstop."""
    try:
        spec = verify_from_env()
    except VerificationError:
        print("Spec not verified; nothing was created.")
        return 0
    group = resource_group_for(spec)
    if not group_requested(group):
        print("No resource group was created in this job; nothing to delete.")
        return 0
    exists = run_quiet([system_az(), "group", "exists", "--name", group],
                       RAW_DIR / "lifecycle" / "group-exists", timeout=300)
    text = Path(exists["stdout"]).read_text(encoding="utf-8").strip().lower()
    if exists["exit_code"] == 0 and text == "false":
        print("Resource group does not exist; nothing to delete.")
        return 0
    result = run_quiet([
        system_az(), "group", "delete", "--name", group, "--yes",
        "--only-show-errors",
    ], RAW_DIR / "lifecycle" / "group-delete", timeout=LIFECYCLE_TIMEOUT_SECONDS)
    if result["exit_code"] == 0:
        print("Resource group deleted.")
        return 0
    print("::warning::Resource group deletion failed; the janitor deletes it "
          "after expiresAt.")
    return 1


def cmd_logout(args):
    for name, argv in (("logout", [system_az(), "logout"]),
                       ("account-clear", [system_az(), "account", "clear"])):
        run_quiet(argv, RAW_DIR / "lifecycle" / name, timeout=120)
    print("Signed out of Azure.")
    return 0


def generate_password():
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(20))
    return f"Xr{core}9!a"


def _matches(criteria, exit_code, stdout_text, stderr_text, found=(), group=""):
    """Whether a step's result meets criteria.

    found holds group.key ids a VM guest matched against output too long to return.
    """
    checks = []
    if "exit_code" in criteria:
        checks.append(exit_code == criteria["exit_code"])
    if "error_substring" in criteria:
        checks.append(criteria["error_substring"] in stderr_text
                      or f"{group}.error_substring" in found)
    if "output_substring" in criteria:
        checks.append(criteria["output_substring"] in stdout_text
                      or f"{group}.output_substring" in found)
    return bool(checks) and all(checks)


def _read_text(path, limit=2_000_000):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def prepare_run(spec, *, resource_group, run_id, subscription_id=None,
                work_dir=WORK_DIR):
    """Fresh work directory plus resolved placeholders: (values, resolved)."""
    work_dir = Path(work_dir)
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)
    file_name = repro_spec.input_file_name(spec) or INPUT_FILE_NAME
    for name in spec.get("workdir_dirs", []):
        (work_dir / name).mkdir()
    digest = repro_spec._hash_canonical(repro_spec.canonical_spec_json(spec))
    password = generate_password()
    values = repro_spec.placeholder_values(
        digest, run_id, resource_group=resource_group,
        location=spec["location"], subscription_id=subscription_id,
        password=password, file_path=file_name,
    )
    resolved = repro_spec.resolve_placeholders(spec, values, strict=True)
    content = (resolved.get("input_file") or {}).get("content", INPUT_FILE_TEXT)
    (work_dir / file_name).write_text(content, encoding="utf-8")
    return values, resolved


_SCRIPT_SUFFIX = {"bash": ".sh", "sh": ".sh", "pwsh": ".ps1", "powershell": ".ps1",
                  "cmd": ".cmd"}


def shell_argv(shell, path, windows=WINDOWS):
    """argv that runs a script file in shell (Git Bash for bash on Windows)."""
    path = str(path)
    if shell == "bash":
        bash = str(GIT_BASH) if windows and GIT_BASH.exists() else (
            shutil.which("bash") or "bash")
        return [bash, "--noprofile", "--norc", path]
    if shell == "sh":
        return [shutil.which("sh") or "sh", path]
    if shell == "pwsh":
        return [shutil.which("pwsh") or "pwsh", "-NoLogo", "-NoProfile",
                "-NonInteractive", "-File", path]
    if shell == "powershell":
        return [shutil.which("powershell") or "powershell.exe", "-NoLogo", "-NoProfile",
                "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]
    return [os.environ.get("COMSPEC") or "cmd.exe", "/d", "/c", path]


def write_script(shell, script, path):
    path = Path(path).with_suffix(_SCRIPT_SUFFIX[shell])
    path.parent.mkdir(parents=True, exist_ok=True)
    text = script if script.endswith("\n") else script + "\n"
    if shell == "cmd":
        text = "@echo off\r\n" + text.replace("\n", "\r\n")
    path.write_bytes(text.encode("utf-8"))
    return path


def execute(spec, *, az_path, resource_group, run_id, subscription_id=None,
            deadline_seconds=None, raw_dir=RAW_DIR, work_dir=WORK_DIR,
            log=print, path_dir=None, source_dir=None, environment=None):
    """Run the setup and repro steps and return the raw, unredacted result.

    az_path is the argv prefix (or a single path) that runs the CLI under test.
    environment is (state, install) when steps run in a container or VM.
    """
    raw_dir, work_dir = Path(raw_dir), Path(work_dir)
    az = [az_path] if isinstance(az_path, str) else list(az_path)
    values, resolved = prepare_run(
        spec, resource_group=resource_group, run_id=run_id,
        subscription_id=subscription_id, work_dir=work_dir,
    )
    extra = {"AZURE_EXTENSION_DIR": str(EXTENSION_DIR.resolve())}
    if path_dir:
        extra["PATH"] = os.pathsep.join(
            p for p in (str(path_dir), os.environ.get("PATH", "")) if p)
    if source_dir:
        extra["REPRO_SOURCE_DIR"] = str(source_dir)

    def launch(phase, index, step, remaining):
        stem = raw_dir / "steps" / f"{phase}-{index}"
        if "shell" in step:
            script = write_script(
                step["shell"], step["script"],
                raw_dir / "scripts" / f"{phase}-{index}",
            )
            env = dict(extra)
            if WINDOWS and step["shell"] == "bash" and source_dir:
                env["REPRO_SOURCE_DIR"] = Path(source_dir).as_posix()
            return run_quiet(
                shell_argv(step["shell"], script.resolve()), stem,
                timeout=remaining, cwd=work_dir, extra_env=env,
            )
        return run_quiet(
            [*az, *step["argv"][1:]], stem, timeout=remaining, cwd=work_dir,
            extra_env=extra,
        )

    if environment and environment[0].get("kind") == "container":
        launch = _container_launch(environment[0], az, extra, raw_dir, work_dir)
    elif environment and environment[0].get("kind") == "vm":
        launch = _vm_launch(spec, environment, raw_dir, work_dir)
    return run_steps(
        spec, resolved, values, launch=launch, display=display_step,
        deadline_seconds=deadline_seconds, log=log,
    )


def _container_launch(state, az, extra, raw_dir, work_dir):
    env = repro_env.container_env(state, extra)

    def launch(phase, index, step, remaining):
        if "shell" in step:
            script = write_script(step["shell"], step["script"],
                                  raw_dir / "scripts" / f"{phase}-{index}")
            command = repro_env.container_shell(step["shell"], script.resolve())
        else:
            command = [az[0], *step["argv"][1:]]
        return run_quiet(
            repro_env.container_exec(state, command, env=env, cwd=work_dir),
            raw_dir / "steps" / f"{phase}-{index}", timeout=remaining,
        )
    return launch


def _vm_launch(spec, environment, raw_dir, work_dir):
    state, install = environment
    prepared = []

    def launch(phase, index, step, remaining):
        stem = raw_dir / "steps" / f"{phase}-{index}"
        if not prepared:
            ready = repro_env.vm_invoke(
                state, repro_env.vm_prepare_config(work_dir, spec.get("workdir_dirs", [])),
                run=run_quiet, az=system_az(), log_stem=raw_dir / "env" / "prepare",
                timeout=900, attempts=repro_env.VM_INVOKE_ATTEMPTS,
            )
            if not (ready or {}).get("ok"):
                return repro_env.write_step_logs(None, stem)
            prepared.append(True)
        script_bytes = script_name = None
        if "shell" in step:
            path = write_script(step["shell"], step["script"],
                                raw_dir / "scripts" / f"{phase}-{index}")
            script_bytes, script_name = path.read_bytes(), path.name
        config = repro_env.vm_step_config(
            step, timeout=remaining, script_bytes=script_bytes, script_name=script_name,
            env=repro_env.vm_env(_CHILD_ENV_FIXED, install.get("vm_source"),
                                 step.get("shell")),
            found_needles=repro_env.needles(spec, phase, index),
        )
        result = repro_env.vm_invoke(
            state, config, run=run_quiet, az=system_az(),
            log_stem=raw_dir / "env" / f"{phase}-{index}", timeout=remaining + 600,
        )
        return repro_env.write_step_logs(result, stem)
    return launch


_MISSING_PROVIDER = re.compile(
    r"MissingSubscriptionRegistration.*?namespace '([A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)'",
    re.S,
)


def missing_provider(stderr_text):
    """The resource provider namespace a step needs registered, or None."""
    match = _MISSING_PROVIDER.search(stderr_text or "")
    return match.group(1) if match else None


def register_provider(namespace, remaining):
    """Register a resource provider on the repro subscription and wait for it."""
    result = run_quiet(
        [system_az(), "provider", "register", "--namespace", namespace, "--wait",
         "--only-show-errors", "-o", "none"],
        RAW_DIR / "lifecycle" / f"register-{namespace}",
        timeout=max(1, min(remaining, 10 * 60)),
    )
    return result["exit_code"] == 0


def run_steps(spec, resolved, values, *, launch, display,
              deadline_seconds=None, log=print, register=register_provider):
    """Run resolved steps with launch(phase, index, step, remaining).

    Stops at the first setup step that misses its expect, or when time runs out.
    A step refused because the subscription lacks a resource provider registers
    it and runs once more.
    """
    budget = deadline_seconds or spec["timeout_minutes"] * 60
    deadline = time.monotonic() + budget
    registered = set()
    steps = []
    status = "completed"
    for phase in ("setup", "repro"):
        for index, step in enumerate(resolved[phase]):
            original = spec[phase][index]
            entry = {
                "phase": phase, "index": index,
                "command": display(original),
                "exit_code": None, "timed_out": False, "skipped": False,
                "duration_seconds": 0.0, "expect_met": None,
                "observed_matched": None, "stdout": None, "stderr": None,
            }
            remaining = deadline - time.monotonic()
            if status != "completed" or remaining < 1:
                if status == "completed":
                    status = "timeout"
                entry["skipped"] = True
                steps.append(entry)
                continue
            result = dict(launch(phase, index, step, remaining))
            namespace = None
            if result.get("exit_code") not in (0, None) and not result.get("timed_out"):
                namespace = missing_provider(_read_text(result["stderr"]))
            if namespace and namespace not in registered:
                registered.add(namespace)
                ok = register(namespace, deadline - time.monotonic())
                log(f"Registered resource provider {namespace}: {'ok' if ok else 'failed'}.")
                remaining = deadline - time.monotonic()
                if ok and remaining >= 1:
                    result = dict(launch(phase, index, step, remaining))
            found = result.pop("found", None) or ()
            infra_error = result.pop("infra_error", False)
            entry.update(result)
            stdout_text = _read_text(result["stdout"])
            stderr_text = _read_text(result["stderr"])
            expect = original.get("expect") or (
                {"exit_code": 0} if phase == "setup" else None
            )
            if expect:
                entry["expect_met"] = _matches(
                    expect, result["exit_code"], stdout_text, stderr_text,
                    found, "expect",
                )
            if phase == "repro":
                entry["observed_matched"] = _matches(
                    spec["observed_in_issue"], result["exit_code"],
                    stdout_text, stderr_text, found, "observed",
                )
            steps.append(entry)
            verdict = ""
            if entry["observed_matched"] is not None:
                verdict = (" (observed behaviour: matched)"
                           if entry["observed_matched"] else
                           " (observed behaviour: not matched)")
            shown = "timeout" if result["timed_out"] else f"exit {result['exit_code']}"
            log(f"{phase}[{index}]: {shown} ({result['duration_seconds']}s){verdict}")
            if infra_error:
                status = "error"
            elif result["timed_out"]:
                status = "timeout"
            elif phase == "setup" and not entry["expect_met"]:
                status = "setup_failed"
    repro_steps = [s for s in steps if s["phase"] == "repro"]
    if any(s["observed_matched"] for s in repro_steps):
        reproduced = True
    elif status == "completed":
        reproduced = False
    else:
        reproduced = None
    return {
        "status": status,
        "reproduced": reproduced,
        "steps": steps,
        # Exact values the sanitizer replaces; never leaves the runner.
        "redact_values": {
            k: v for k, v in values.items() if k not in ("location", "file")
        },
    }


def cmd_run(args):
    """Run the verified spec against the installed CLI version."""
    spec = verify_from_env()
    install = _read_json(INSTALL_FILE) or {}
    state = _read_json(ENV_STATE) if repro_env.kind(spec) in ("container", "vm") else None
    if state and state.get("kind") == "container":
        az = [install["container_az"]] if install.get("container_az") else None
    elif state and state.get("kind") == "vm":
        az = ["az"] if install.get("vm_ready") else None
    else:
        az = az_command(install)
    if install.get("error") or not az:
        _write_json(RAW_RESULT_FILE, {"status": "error", "reproduced": None,
                                      "steps": [], "error": "CLI not installed",
                                      "redact_values": {}}, private=True)
        print("::error::The CLI version was not installed.")
        return 1
    group = resource_group_for(spec)
    source = SOURCE_DIR.resolve() if SOURCE_DIR.is_dir() else None
    raw = execute(
        spec, az_path=az, resource_group=group,
        path_dir=bin_dir(install), source_dir=source,
        environment=(state, install) if state else None,
        run_id=run_key(os.environ.get("GITHUB_RUN_ID", "local"),
                       os.environ.get("REPRO_VERSION", "latest")),
        subscription_id=os.environ.get("REPRO_SUBSCRIPTION_ID") or None,
    )
    _write_json(RAW_RESULT_FILE, raw, private=True)
    verdict = {True: "reproduced", False: "not reproduced", None: "inconclusive"}
    print(f"Result ({os.environ.get('REPRO_VERSION')}): {raw['status']}, "
          f"{verdict[raw['reproduced']]}.")
    return 0


def cmd_env_up(args):
    """Start the spec's container, or create its VM in the per-run resource group."""
    spec = verify_from_env()
    kind = repro_env.kind(spec)
    version = os.environ.get("REPRO_VERSION", "")
    if kind == "container":
        state = repro_env.container_up(
            spec, run=run_quiet, workspace=WORKSPACE, log_dir=ENV_DIR,
            key=run_key(os.environ.get("GITHUB_RUN_ID", "local"), version),
            azure=spec.get("azure") is not False,
        )
    elif kind == "vm":
        state = repro_env.vm_up(
            spec, run=run_quiet, az=system_az(), group=resource_group_for(spec),
            log_dir=ENV_DIR, password=generate_password(),
        )
    else:
        print("This spec runs directly on the runner.")
        return 0
    if isinstance(state, str):
        _write_json(INSTALL_FILE, {"version": version, "error": state})
        print(f"::error::The {spec['environment']} environment did not start.")
        return 1
    _write_json(ENV_STATE, state)
    print(f"Environment {spec['environment']} is up ({kind}).")
    return 0


def cmd_env_down(args):
    """Remove the spec's container; VMs go with the per-run resource group."""
    state = _read_json(ENV_STATE)
    if not state or state.get("kind") != "container":
        print("No environment container to remove.")
        return 0
    result = repro_env.container_down(state, run=run_quiet, log_dir=ENV_DIR)
    print(f"Environment container removed: exit {result['exit_code']}.")
    return 0


_SOURCE_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_SOURCE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


def cmd_checkout_source(args):
    """Fetch SRC_REPO at SRC_REF into repro/src with plain git.

    actions/checkout cannot be used here: its credential cleanup runs
    `git submodule foreach`, which fails on azure-cli-extensions' stray
    `projects` gitlink (no .gitmodules entry)."""
    repo = os.environ.get("SRC_REPO", "")
    ref = os.environ.get("SRC_REF", "")
    if not _SOURCE_REPO.match(repo) or not _SOURCE_REF.match(ref) or ".." in ref:
        print("::error::Source repository or ref is not valid.")
        return 1
    log_dir = RAW_DIR / "host"
    steps = (
        (["git", "init", "-q", SOURCE_DIR], "src-init", 60),
        (["git", "-C", SOURCE_DIR, "fetch", "-q", "--depth", "1", "--no-recurse-submodules",
          f"https://github.com/{repo}.git", ref], "src-fetch", 900),
        (["git", "-C", SOURCE_DIR, "checkout", "-q", "FETCH_HEAD"], "src-checkout", 900),
    )
    for argv, stem, timeout in steps:
        result = run_quiet(argv, log_dir / stem, timeout=timeout)
        if result["exit_code"] != 0:
            print(f"::error::Source {stem} failed (exit {result['exit_code']}).")
            return 1
    print(f"Checked out {repo} at {ref}.")
    return 0


def cmd_host_setup(args):
    """Windows only: let git check out the CLI's long test recording paths."""
    if WINDOWS:
        result = run_quiet(["git", "config", "--global", "core.longpaths", "true"],
                           RAW_DIR / "host" / "longpaths", timeout=60)
        print(f"git core.longpaths: exit {result['exit_code']}.")
        return 0 if result["exit_code"] == 0 else 1
    print("Nothing to set up on this runner.")
    return 0


COMMANDS = {
    "host-setup": cmd_host_setup,
    "checkout-source": cmd_checkout_source,
    "verify": cmd_verify,
    "build": cmd_build,
    "install": cmd_install,
    "rg-create": cmd_rg_create,
    "env-up": cmd_env_up,
    "env-down": cmd_env_down,
    "run": cmd_run,
    "rg-delete": cmd_rg_delete,
    "logout": cmd_logout,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="live-repro trusted runner")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except VerificationError as exc:
        print(f"::error::ReproSpec rejected ({len(exc.errors)} problem(s)).")
        return 1
    except repro_spec.ReproSpecError:
        print("::error::ReproSpec placeholders could not be resolved.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
