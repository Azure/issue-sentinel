#!/usr/bin/env python3
"""Trusted runner for ``live-repro-powershell.yml`` (Azure/issue-sentinel).

The PowerShell counterpart of ``repro_runner.py`` (plan item C2g). It reuses
that runner's verification, quiet process execution, step loop, result
files and resource group naming, and differs only in how the tool is
installed, how Azure sign-in works and how a step is launched:

- ``install``: ``Install-Module Az.<X> -RequiredVersion <v>`` for the
  validated module (``reported``: the spec's ``reported_version``;
  ``latest``: the newest gallery version, resolved first and then pinned),
  a ``dotnet msbuild build.proj /p:TargetModule=<X>`` build of the checked
  out ``main`` source (``dev``) or the verified PR build (``pr``, below);
- ``connect``: federated ``Connect-AzAccount`` with a GitHub OIDC token
  fetched here (no secret, no PAT; the token reaches pwsh only through the
  child environment and is never printed);
- ``run``: one ``pwsh -NoProfile -NonInteractive -File repro_ps.ps1``
  process per step. The step's validated parameter hashtable is written to
  a private request file and splatted into the cmdlet by ``repro_ps.ps1``;
  there is no ``-Command``, no script text and no ``Invoke-Expression``.

All output goes to files under ``repro/raw``; ``repro_sanitize.py
--runner powershell`` writes the only uploaded file, ``repro.redacted.json``.

PR-head re-runs (``pr_number`` + ``pr_head_sha``, plan item C2f) use the
trust model of ``repro_runner.py``: ``verify`` only accepts an open PR on
Azure/azure-powershell from the configured Agent fork whose head is exactly
``pr_head_sha``. ``build`` runs in a separate job with no Azure credentials,
no secrets and no OIDC permission: it builds the module under test from that
commit (running the PR's build code) and packs the build output into
``module.tar.gz`` plus a SHA-256 manifest. In the reproduce job, ``install``
never checks out or runs PR code: it verifies the manifest, extracts the
archive with path and file-type checks and reads the module version from the
``.psd1`` text. The PR module is first imported by ``repro_ps.ps1`` in the
``run`` step, the sandbox designed to run cmdlets with the BAMI login.

Environment: as ``repro_runner.py`` (including ``REPRO_PR_HEAD_SHA`` and,
for ``verify``, ``REPRO_GITHUB_TOKEN``), plus ``REPRO_CLIENT_ID``,
``REPRO_TENANT_ID``, ``REPRO_SUBSCRIPTION_ID`` (``connect``, ``rg-delete``)
and ``ACTIONS_ID_TOKEN_REQUEST_URL`` / ``ACTIONS_ID_TOKEN_REQUEST_TOKEN``
(set by GitHub when the job has ``id-token: write``).
"""

import argparse
import json
import tarfile
import os
import re
import shutil
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import repro_policy as policy
import repro_runner as runner
import repro_spec
from repro_runner import (
    INSTALL_FILE, OUT_DIR, RAW_DIR, RAW_RESULT_FILE, RESULT_SCHEMA,
    RESULT_SCHEMA_VERSION, SOURCE_DIR, VERSION_ORDER, WORK_DIR, WORKSPACE,
    VerificationError, _read_json, _write_json, run_key, run_quiet,
    write_outputs,
)

__all__ = [
    "INSTALL_FILE", "OUT_DIR", "RAW_DIR", "RAW_RESULT_FILE", "RESULT_SCHEMA",
    "RESULT_SCHEMA_VERSION", "VerificationError", "matrix_versions",
    "verify_from_env", "verify_spec",
]

POWERSHELL_REPOSITORY = "Azure/azure-powershell"
DEV_REF = "main"
PS_SCRIPT = Path(__file__).resolve().parent / "repro_ps.ps1"
REQUEST_DIR = RAW_DIR / "requests"
BUILD_OUTPUT_DIR = SOURCE_DIR / "artifacts" / "Debug"
# PR build artifact (``build-pr`` job -> ``repro-pr-module``) and the
# directory the reproduce job extracts it to.
PR_MODULE_DIR = WORKSPACE / "pr-module"
PR_MODULE_ARCHIVE = "module.tar.gz"
PR_MODULE_MANIFEST = "manifest.json"
PR_MODULE_ROOT = WORKSPACE / "modules"
PR_ARCHIVE_MAX_MEMBERS = 20_000
PR_ARCHIVE_MAX_BYTES = 2 * 1024 ** 3
OIDC_AUDIENCE = "api://AzureADTokenExchange"
BASE_MODULES = ("Az.Accounts", "Az.Resources")
# Az context and MSAL token caches removed by ``logout``.
AZ_CACHE_DIRS = (".Azure", ".IdentityService", ".local/.IdentityService")
INSTALL_TIMEOUT_SECONDS = 15 * 60
BUILD_TIMEOUT_SECONDS = 45 * 60
LIFECYCLE_TIMEOUT_SECONDS = runner.LIFECYCLE_TIMEOUT_SECONDS
_MODULE = re.compile(r"^Az\.[A-Za-z]{2,40}$")
_MODULE_VERSION = re.compile(r"^\d{1,4}(?:\.\d{1,4}){1,3}$")
_PSD1_VERSION = re.compile(r"^\s*ModuleVersion\s*=\s*['\"]([0-9.]{3,20})['\"]", re.M)
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_PS_EXTRA_ENV = {
    "POWERSHELL_TELEMETRY_OPTOUT": "1",
    "POWERSHELL_UPDATECHECK": "Off",
    "SuppressAzurePowerShellBreakingChangeWarnings": "true",
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_NOLOGO": "1",
}


# Spec verification -----------------------------------------------------------

def verify_spec(spec_text, spec_hash, issue, pr_number="", pr_head_sha=""):
    """Re-validate a dispatched ``pwsh-az`` spec; return the normalized spec.

    Same checks as ``repro_runner.verify_dispatch`` (a PR-head re-run needs
    ``pr_head_sha``); additionally only ``pwsh-az`` specs with cmdlet steps
    run here, and a PR-head re-run needs an Azure/azure-powershell issue and
    a configured Agent fork (``verify_pull_request`` checks the PR itself).
    """
    pr_number = (pr_number or "").strip()
    normalized, errors = runner.verify_dispatch(
        spec_text, spec_hash, issue, pr_number, pr_head_sha,
    )
    if normalized["tool"] != "pwsh-az":
        errors.append("tool: only pwsh-az specs run in live-repro-powershell.yml")
    for phase in ("setup", "repro"):
        for index, step in enumerate(normalized[phase]):
            if not isinstance(step.get("cmdlet"), str) or "argv" in step:
                errors.append(f"{phase}[{index}]: only cmdlet steps run here")
    module = normalized.get("module")
    if normalized["tool"] == "pwsh-az" and (
        not isinstance(module, str) or not _MODULE.match(module)
        or module not in policy.REPRO_PS_ALLOWED_MODULES
    ):
        errors.append("module: missing or not allowlisted")
    if pr_number:
        if normalized["issue"].split("#", 1)[0] != POWERSHELL_REPOSITORY:
            errors.append(
                f"pr_number: PR re-runs need an issue on {POWERSHELL_REPOSITORY}"
            )
        elif not runner.agent_fork(POWERSHELL_REPOSITORY):
            errors.append(
                f"pr_number: no Agent fork is configured for {POWERSHELL_REPOSITORY}"
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


def matrix_versions(spec, pr_number=""):
    return runner.matrix_versions(spec, pr_number)


def step_modules(spec):
    """Every module a step needs, the module under test first."""
    modules = [spec["module"]]
    for phase in ("setup", "repro"):
        for step in spec[phase]:
            module = repro_spec.ps_cmdlet_module(step["cmdlet"])
            if module and module not in modules:
                modules.append(module)
    return modules


def short_module_name(module):
    return module.split(".", 1)[1]


def display_cmdlet(step):
    """Unresolved cmdlet line for reports, e.g. ``Get-AzX -Name <name1>``."""
    parts = [step["cmdlet"]]
    for name, value in step.get("parameters", {}).items():
        if isinstance(value, bool):
            parts.append(f"-{name}:${str(value).lower()}")
            continue
        items = value if isinstance(value, list) else [value]
        shown = []
        for item in items:
            text = re.sub(r"\{([a-z0-9]+)\}", r"<\1>", str(item))
            if not re.fullmatch(r"[A-Za-z0-9<>._:/@+=-]+", text):
                text = "'" + text.replace("'", "''") + "'"
            shown.append(text)
        parts.append(f"-{name} {','.join(shown)}")
    return " ".join(parts)


# pwsh invocation --------------------------------------------------------------

def pwsh():
    return shutil.which("pwsh") or "pwsh"


def pwsh_argv(action, request_file):
    """Fixed argv for ``repro_ps.ps1``; never ``-Command``."""
    return [
        pwsh(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
        str(PS_SCRIPT), "-Action", action,
        "-RequestFile", str(Path(request_file).resolve()),
    ]


def run_pwsh(action, request, log_stem, *, timeout, cwd=None, extra_env=None):
    """Write ``request`` to a private file and run one ``repro_ps.ps1`` action."""
    log_stem = Path(log_stem)
    request_file = REQUEST_DIR / f"{log_stem.parent.name}-{log_stem.name}.json"
    _write_json(request_file, request, private=True)
    try:
        return run_quiet(
            pwsh_argv(action, request_file), log_stem, timeout=timeout,
            cwd=cwd, extra_env={**_PS_EXTRA_ENV, **(extra_env or {})},
        )
    finally:
        request_file.unlink(missing_ok=True)


# Subcommands -----------------------------------------------------------------

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
    versions = matrix_versions(spec, pr_number)
    pr_repo = ""
    if pr_number:
        try:
            pr_repo = runner.verify_pull_request(
                POWERSHELL_REPOSITORY, pr_number, head_sha,
            )
        except VerificationError as exc:
            print(f"::error::PR #{int(pr_number)} cannot be re-run "
                  f"({len(exc.errors)} problem(s)).")
            for error in exc.errors:
                print(f"- {error}")
            return 1
    write_outputs({
        "versions": json.dumps(versions),
        "timeout_minutes": spec["timeout_minutes"],
        "step_timeout_minutes": spec["timeout_minutes"] + 5,
        "source_repo": POWERSHELL_REPOSITORY,
        "dev_ref": DEV_REF,
        "pr_repo": pr_repo,
        "pr_ref": head_sha if pr_number else "",
        "module": spec["module"],
    })
    steps = len(spec["setup"]) + len(spec["repro"])
    print(
        f"ReproSpec {os.environ['REPRO_SPEC_HASH'][:12]} verified: "
        f"{spec['module']}, {steps} step(s), versions {', '.join(versions)}."
    )
    return 0


def install_request(spec, version):
    """Modules ``repro_ps.ps1 -Action Install`` installs from PSGallery.

    ``version`` null means the newest gallery version (resolved by
    ``Find-Module`` and then installed with ``-RequiredVersion``).
    """
    target = spec["module"]
    modules = []
    if version in ("reported", "latest"):
        modules.append({
            "name": target,
            "version": spec["reported_version"] if version == "reported" else None,
        })
    for module in [*step_modules(spec)[1:], *BASE_MODULES]:
        if module != target and all(m["name"] != module for m in modules):
            modules.append({"name": module, "version": None})
    for module in modules:
        if not _MODULE.match(module["name"]) or (
            module["version"] is not None
            and not _MODULE_VERSION.match(module["version"])
        ):
            raise VerificationError([f"module: invalid install request {module['name']}"])
    return {"modules": modules}


def build_module(spec, log_dir=None):
    """Build the module under test from ``repro/src``; return its directory."""
    log_dir = Path(log_dir or RAW_DIR / "install")
    short = short_module_name(spec["module"])
    result = run_quiet(
        ["dotnet", "msbuild", "build.proj", f"/p:TargetModule={short}",
         "/p:Configuration=Debug", "-nologo", "-verbosity:minimal"],
        log_dir / "build", timeout=BUILD_TIMEOUT_SECONDS,
        cwd=SOURCE_DIR, extra_env=_PS_EXTRA_ENV,
    )
    print(f"{log_dir.name} build: exit {result['exit_code']} ({result['duration_seconds']}s)")
    module_dir = BUILD_OUTPUT_DIR / spec["module"]
    if result["exit_code"] != 0 or not (module_dir / f"{spec['module']}.psd1").is_file():
        return None
    return module_dir.resolve()


def module_version_from_manifest(module_dir, module):
    try:
        text = (Path(module_dir) / f"{module}.psd1").read_text(encoding="utf-8-sig")
    except OSError:
        return None
    match = _PSD1_VERSION.search(text)
    return match.group(1) if match else None


def _source_sha(log_stem):
    git = run_quiet(["git", "-C", SOURCE_DIR, "rev-parse", "HEAD"], log_stem,
                    timeout=60)
    try:
        sha = Path(git["stdout"]).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def pack_module_build(spec, head_sha, output_dir=None):
    """Pack the ``Az.*`` build output into ``module.tar.gz`` + manifest.

    The whole ``artifacts/Debug`` module set is kept (``Az.Accounts`` is
    built with the target), matching the ``dev`` import path. Only regular
    files and directories are packed.
    """
    output_dir = Path(output_dir or PR_MODULE_DIR)
    modules = sorted(
        path.name for path in BUILD_OUTPUT_DIR.iterdir()
        if path.is_dir() and not path.is_symlink() and _MODULE.match(path.name)
    )
    if spec["module"] not in modules:
        raise ValueError("the module under test was not built")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    def regular_only(member):
        return member if member.isfile() or member.isdir() else None

    archive = output_dir / PR_MODULE_ARCHIVE
    with tarfile.open(archive, "w:gz") as tar:
        for module in modules:
            tar.add(BUILD_OUTPUT_DIR / module, arcname=module,
                    filter=regular_only)
    manifest = {
        "head_sha": head_sha, "module": spec["module"], "modules": modules,
        "archive": PR_MODULE_ARCHIVE, "sha256": runner._sha256(archive),
    }
    _write_json(output_dir / PR_MODULE_MANIFEST, manifest)
    return manifest


def load_module_manifest(spec, head_sha, module_dir=None):
    """Verified PR build manifest for ``head_sha``, or raise ``ValueError``."""
    module_dir = Path(module_dir or PR_MODULE_DIR)
    manifest = _read_json(module_dir / PR_MODULE_MANIFEST)
    if not isinstance(manifest, dict) or manifest.get("head_sha") != head_sha:
        raise ValueError("PR module build is missing or was built from another commit")
    modules = manifest.get("modules")
    if (manifest.get("module") != spec["module"]
            or not isinstance(modules, list) or spec["module"] not in modules
            or not all(isinstance(m, str) and _MODULE.match(m) for m in modules)):
        raise ValueError("PR module build is not for the module under test")
    archive = module_dir / PR_MODULE_ARCHIVE
    if (manifest.get("archive") != PR_MODULE_ARCHIVE or not archive.is_file()
            or archive.is_symlink()
            or runner._sha256(archive) != manifest.get("sha256")):
        raise ValueError("PR module archive does not match the build manifest")
    return {**manifest, "modules": list(modules)}


def extract_module_build(spec, manifest, module_dir=None, dest=None):
    """Extract the verified archive; return the module-under-test directory.

    Accepts only regular files and directories below the manifest's module
    directories (no links, devices, absolute paths or ``..``), within size
    limits; extraction additionally uses tarfile's ``data`` filter.
    """
    archive = Path(module_dir or PR_MODULE_DIR) / PR_MODULE_ARCHIVE
    dest = Path(dest or PR_MODULE_ROOT)
    allowed = set(manifest["modules"])
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > PR_ARCHIVE_MAX_MEMBERS:
            raise ValueError("PR module archive has too many entries")
        total = 0
        for member in members:
            parts = Path(member.name).parts
            if (not parts or member.name.startswith("/") or "\\" in member.name
                    or ".." in parts or parts[0] not in allowed
                    or not (member.isfile() or member.isdir())):
                raise ValueError("PR module archive has an unexpected entry")
            total += max(member.size, 0)
        if total > PR_ARCHIVE_MAX_BYTES:
            raise ValueError("PR module archive is too large")
        tar.extractall(dest, members=members, filter="data")
    module_path = dest / spec["module"]
    manifest_file = module_path / f"{spec['module']}.psd1"
    if not manifest_file.is_file() or manifest_file.is_symlink():
        raise ValueError("PR module build has no module manifest")
    return module_path.resolve()


def cmd_build(args):
    """Build the module under test from the PR head (no Azure credentials)."""
    spec = verify_from_env()
    head_sha = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()
    if not os.environ.get("REPRO_PR_NUMBER", "").strip() or not head_sha:
        print("::error::Only PR-head re-runs build the module here.")
        return 1
    if _source_sha(RAW_DIR / "build" / "git-sha") != head_sha:
        print("::error::The checkout is not the requested PR head commit.")
        return 1
    if not (SOURCE_DIR / "build.proj").is_file():
        print("::error::PR head source checkout is missing build.proj.")
        return 1
    if build_module(spec, RAW_DIR / "build") is None:
        print(f"::error::Building {spec['module']} from the PR head failed.")
        return 1
    try:
        manifest = pack_module_build(spec, head_sha)
    except (OSError, ValueError, tarfile.TarError):
        print("::error::Packing the PR module build failed.")
        return 1
    print(f"Built {spec['module']} for the PR head "
          f"({len(manifest['modules'])} module(s) packed).")
    return 0


def _install_pr_module(spec, info):
    """Use the verified ``build-pr`` artifact; never runs PR code."""
    head_sha = os.environ.get("REPRO_PR_HEAD_SHA", "").strip()
    try:
        manifest = load_module_manifest(spec, head_sha)
        module_dir = extract_module_build(spec, manifest)
    except (OSError, ValueError, tarfile.TarError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else "PR module archive is unreadable"
        _write_json(INSTALL_FILE, {**info, "error": message})
        print("::error::The PR module build is missing or does not verify.")
        return False
    info["module_path"] = str(module_dir)
    info["modules"][spec["module"]] = module_version_from_manifest(
        module_dir, spec["module"],
    )
    info["source_sha"] = head_sha
    return True


def _install_dev_module(spec, info):
    if not (SOURCE_DIR / "build.proj").is_file():
        _write_json(INSTALL_FILE, {**info, "error": "source checkout missing"})
        print("::error::Source checkout is missing.")
        return False
    module_dir = build_module(spec)
    if module_dir is None:
        _write_json(INSTALL_FILE, {**info, "error": "module build failed"})
        print(f"::error::Building {spec['module']} from source failed.")
        return False
    info["module_path"] = str(module_dir)
    info["modules"][spec["module"]] = module_version_from_manifest(
        module_dir, spec["module"],
    )
    info["source_sha"] = _source_sha(RAW_DIR / "install" / "git-sha")
    return True


def cmd_install(args):
    """Install the matrix version of the module under test (and helpers)."""
    spec = verify_from_env()
    version = os.environ.get("REPRO_VERSION", "")
    if version not in VERSION_ORDER:
        print("::error::Unknown reproduction version.")
        return 1
    info = {"version": version, "error": None, "cli_version": None,
            "extension_version": None, "source_sha": None,
            "module": spec["module"], "modules": {}, "module_path": None}
    if version == "pr" and not _install_pr_module(spec, info):
        return 1
    if version == "dev" and not _install_dev_module(spec, info):
        return 1
    request = install_request(spec, version)
    request["result_file"] = str((RAW_DIR / "install" / "modules.json").resolve())
    result = run_pwsh("Install", request, RAW_DIR / "install" / "modules",
                      timeout=INSTALL_TIMEOUT_SECONDS)
    print(f"install modules: exit {result['exit_code']} ({result['duration_seconds']}s)")
    installed = _read_json(request["result_file"]) or {}
    if result["exit_code"] != 0 or not isinstance(installed, dict):
        _write_json(INSTALL_FILE, {**info, "error": "Install-Module failed"})
        print("::error::Installing the Az modules failed.")
        return 1
    for name, installed_version in installed.items():
        if (isinstance(name, str) and _MODULE.match(name)
                and isinstance(installed_version, str)
                and _MODULE_VERSION.match(installed_version)):
            info["modules"].setdefault(name, installed_version)
    info["cli_version"] = info["modules"].get(spec["module"])
    if not info["cli_version"]:
        _write_json(INSTALL_FILE, {**info, "error": "module version unknown"})
        print("::error::The module under test was not installed.")
        return 1
    _write_json(INSTALL_FILE, info)
    print(f"Installed {spec['module']} {info['cli_version']} for `{version}`.")
    return 0


def fetch_oidc_token(env=None, opener=None):
    """GitHub OIDC ID token for Azure federation (``api://AzureADTokenExchange``)."""
    env = os.environ if env is None else env
    url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not url.startswith("https://") or not bearer:
        raise RuntimeError("OIDC is not available (the job needs id-token: write)")
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        url + separator + urllib.parse.urlencode({"audience": OIDC_AUDIENCE}),
        headers={"Authorization": f"Bearer {bearer}",
                 "Accept": "application/json; api-version=2.0"},
    )
    opener = opener or urllib.request.urlopen
    with opener(request, timeout=30) as response:
        token = json.loads(response.read().decode("utf-8")).get("value")
    if not isinstance(token, str) or token.count(".") != 2:
        raise RuntimeError("OIDC response did not contain a token")
    return token


def connect(env=None, opener=None, log_name="connect"):
    """Federated ``Connect-AzAccount``; returns the pwsh exit code."""
    env = os.environ if env is None else env
    ids = {key: (env.get(key) or "").strip() for key in (
        "REPRO_CLIENT_ID", "REPRO_TENANT_ID", "REPRO_SUBSCRIPTION_ID",
    )}
    if not all(_GUID.match(value) for value in ids.values()):
        print("::error::Azure client, tenant and subscription IDs must be GUIDs.")
        return 1
    try:
        token = fetch_oidc_token(env, opener)
    except (OSError, ValueError, RuntimeError):
        print("::error::Could not get a GitHub OIDC token for Azure.")
        return 1
    result = run_pwsh(
        "Connect", {}, RAW_DIR / "lifecycle" / log_name,
        timeout=300, extra_env={**ids, "REPRO_FEDERATED_TOKEN": token},
    )
    print(f"Connect-AzAccount (federated): exit {result['exit_code']}.")
    return 0 if result["exit_code"] == 0 else 1


def cmd_connect(args):
    verify_from_env()
    return connect()


def cmd_rg_create(args):
    """Create the per-run resource group tagged with ``expiresAt``."""
    spec = verify_from_env()
    result = run_pwsh("NewGroup", {
        "name": runner.resource_group_for(spec),
        "location": spec["location"],
        "tags": {
            policy.REPRO_EXPIRES_TAG: runner.expires_at(),
            "createdBy": "x-engineering-agent",
            "purpose": "live-repro",
            "specHash": os.environ["REPRO_SPEC_HASH"][:16],
        },
    }, RAW_DIR / "lifecycle" / "group-create", timeout=LIFECYCLE_TIMEOUT_SECONDS)
    print(f"Resource group create: exit {result['exit_code']}.")
    return 0 if result["exit_code"] == 0 else 1


def cmd_rg_delete(args):
    """Delete the per-run resource group (always runs; janitor is the backstop)."""
    try:
        spec = verify_from_env()
    except VerificationError:
        print("Spec not verified; nothing was created.")
        return 0
    # The steps may have outlived the first token; sign in again (best effort).
    connect(log_name="reconnect")
    result = run_pwsh("RemoveGroup", {"name": runner.resource_group_for(spec)},
                      RAW_DIR / "lifecycle" / "group-delete",
                      timeout=LIFECYCLE_TIMEOUT_SECONDS)
    if result["exit_code"] == 0:
        print("Resource group deleted (or never created).")
        return 0
    print("::warning::Resource group deletion failed; the janitor deletes it "
          "after expiresAt.")
    return 1


def cmd_logout(args):
    run_pwsh("Disconnect", {}, RAW_DIR / "lifecycle" / "logout", timeout=120)
    for cache in AZ_CACHE_DIRS:
        shutil.rmtree(Path.home() / cache, ignore_errors=True)
    print("Signed out of Azure.")
    return 0


def invoke_request(step, spec, install):
    """Request for ``repro_ps.ps1 -Action Invoke`` (one resolved step)."""
    module = repro_spec.ps_cmdlet_module(step["cmdlet"])
    request = {
        "cmdlet": step["cmdlet"],
        "module": module,
        "required_version": None,
        "module_path": None,
        "parameters": step.get("parameters") or {},
        "denied_parameters": sorted(policy.REPRO_PS_DENIED_PARAMETERS),
    }
    if module == spec["module"]:
        if install.get("module_path"):
            request["module_path"] = install["module_path"]
        else:
            request["required_version"] = install.get("cli_version")
    return request


def execute(spec, *, install, resource_group, run_id, subscription_id=None,
            deadline_seconds=None, raw_dir=RAW_DIR, work_dir=WORK_DIR,
            log=print):
    """Run the setup and repro cmdlets; return the raw (unredacted) result."""
    raw_dir, work_dir = Path(raw_dir), Path(work_dir)
    values, resolved = runner.prepare_run(
        spec, resource_group=resource_group, run_id=run_id,
        subscription_id=subscription_id, work_dir=work_dir,
    )

    def launch(phase, index, step, remaining):
        return run_pwsh(
            "Invoke", invoke_request(step, spec, install),
            raw_dir / "steps" / f"{phase}-{index}", timeout=remaining,
            cwd=work_dir,
        )

    return runner.run_steps(
        spec, resolved, values, launch=launch, display=display_cmdlet,
        deadline_seconds=deadline_seconds, log=log,
    )


def cmd_run(args):
    """Run the verified spec against the installed module version."""
    spec = verify_from_env()
    install = _read_json(INSTALL_FILE) or {}
    if install.get("error") or not install.get("cli_version"):
        _write_json(RAW_RESULT_FILE, {"status": "error", "reproduced": None,
                                      "steps": [], "error": "module not installed",
                                      "redact_values": {}}, private=True)
        print("::error::The module version was not installed.")
        return 1
    raw = execute(
        spec, install=install, resource_group=runner.resource_group_for(spec),
        run_id=run_key(os.environ.get("GITHUB_RUN_ID", "local"),
                       os.environ.get("REPRO_VERSION", "latest")),
        subscription_id=os.environ.get("REPRO_SUBSCRIPTION_ID") or None,
    )
    _write_json(RAW_RESULT_FILE, raw, private=True)
    verdict = {True: "reproduced", False: "not reproduced", None: "inconclusive"}
    print(f"Result ({os.environ.get('REPRO_VERSION')}): {raw['status']}, "
          f"{verdict[raw['reproduced']]}.")
    return 0


COMMANDS = {
    "verify": cmd_verify,
    "build": cmd_build,
    "install": cmd_install,
    "connect": cmd_connect,
    "rg-create": cmd_rg_create,
    "run": cmd_run,
    "rg-delete": cmd_rg_delete,
    "logout": cmd_logout,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="live-repro PowerShell runner")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args(argv)
    WORKSPACE.mkdir(exist_ok=True)
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
