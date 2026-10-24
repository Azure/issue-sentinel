"""Tests for the PowerShell live reproduction runner; pwsh tests skip without pwsh."""

import hashlib
import io
import json
import re
import shutil
import stat
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "live_repro"
sys.path.insert(0, str(SCRIPTS))

from test_live_repro_injection_corpus import (  # noqa: E402
    PS_CORPUS,
    PS_MODULE_CORPUS,
    _ps,
)
from test_live_repro_runner import (  # noqa: E402
    CLIENT,
    KNOWN_ENV,
    SUB,
    TENANT,
)

import repro_janitor  # noqa: E402
import repro_policy as settings  # noqa: E402
import repro_ps_runner  # noqa: E402
import repro_runner  # noqa: E402
import repro_sanitize  # noqa: E402
import repro_sensitive_data  # noqa: E402
import repro_spec  # noqa: E402

PS1 = SCRIPTS / "repro_ps.ps1"
ISSUE = "Azure/azure-powershell#27001"
PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
# Fake token assembled at runtime so secret scanners do not flag a literal.
OIDC_TOKEN = ".".join(['eyJhbGciOiJSUzI1NiJ9', 'eyJzdWIiOiJyZXBvIn0', 'c2lnbmF0dXJlLXZhbHVl'])


def _spec(**overrides):
    spec = {
        "issue": ISSUE,
        "tool": "pwsh-az",
        "versions": ["reported", "latest", "dev"],
        "reported_version": "6.1.0",
        "location": "westus3",
        "setup": [{"cmdlet": "New-AzStorageAccount", "parameters": {
            "ResourceGroupName": "{rg}", "Name": "{name1}",
            "SkuName": "Standard_LRS", "Location": "{location}",
            "EnableHttpsTrafficOnly": True,
        }}],
        "repro": [{"cmdlet": "Get-AzStorageAccount", "parameters": {
            "ResourceGroupName": "{rg}", "Name": "{name1}",
        }}],
        "observed_in_issue": {"error_substring": "ResourceNotFound"},
        "timeout_minutes": 10,
    }
    spec.update(overrides)
    return spec


def _dispatch(spec=None):
    result = repro_spec.validate_spec(spec or _spec())
    assert result["valid"], result["errors"]
    return {
        "issue": result["spec"]["issue"],
        "spec": repro_spec.canonical_spec_json(result["spec"]),
        "spec_hash": result["spec_hash"],
    }


def _env(inputs, **extra):
    env = {
        "REPRO_ISSUE": inputs["issue"], "REPRO_SPEC": inputs["spec"],
        "REPRO_SPEC_HASH": inputs["spec_hash"], "REPRO_PR_NUMBER": "",
    }
    env.update(extra)
    return env


def _set_env(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


# Parity with the Agent's validator is checked in the Agent repository.

@pytest.mark.parametrize("module", list(PS_MODULE_CORPUS.values()),
                         ids=list(PS_MODULE_CORPUS))
def test_vendored_validator_rejects_module_corpus(module):
    spec = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    spec["module"] = module
    vendored = repro_spec.validate_spec(spec)
    assert vendored["valid"] is False
    assert all(error.startswith("module") for error in vendored["errors"])


@pytest.mark.parametrize("prefix", sorted(settings.REPRO_PS_ALLOWED_NOUN_PREFIXES))
def test_vendored_cmdlet_module_maps_allowed_prefixes(prefix):
    module = repro_spec.ps_cmdlet_module(f"Get-Az{prefix}X")
    assert module is not None
    assert module in settings.REPRO_PS_NOUN_MODULES.values()


@pytest.mark.parametrize("cmdlet", [case[0] for case in PS_CORPUS.values()])
def test_vendored_cmdlet_module_is_stable_on_corpus(cmdlet):
    module = repro_spec.ps_cmdlet_module(cmdlet)
    assert module is None or module in settings.REPRO_PS_NOUN_MODULES.values()


def test_verify_accepts_exact_powershell_dispatch():
    inputs = _dispatch()
    spec = repro_ps_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE)
    assert spec["module"] == "Az.Storage"
    assert repro_ps_runner.verify_from_env(_env(inputs)) == spec


def test_cli_and_powershell_runners_refuse_each_others_specs():
    ps = _dispatch()
    with pytest.raises(repro_runner.VerificationError, match="live-repro-powershell"):
        repro_runner.verify_spec(ps["spec"], ps["spec_hash"], ISSUE)
    cli = _dispatch({
        "issue": "Azure/azure-cli#1", "tool": "az",
        "repro": [{"argv": ["az", "version"]}],
        "observed_in_issue": {"exit_code": 1},
    })
    with pytest.raises(repro_ps_runner.VerificationError) as exc:
        repro_ps_runner.verify_spec(cli["spec"], cli["spec_hash"], cli["issue"])
    assert "only pwsh-az specs" in str(exc.value)
    assert "only cmdlet steps" in str(exc.value)


@pytest.mark.parametrize("mutate, message", [
    (lambda i: {**i, "spec_hash": "0" * 64}, "does not match spec_hash"),
    (lambda i: {**i, "issue": "Azure/azure-powershell#1"}, "issue: does not match"),
    (lambda i: {**i, "pr_number": "$(iex)", "pr_head_sha": HEAD},
     "pr_number: must be 0 for a candidate or a positive integer"),
    (lambda i: {**i, "pr_number": "5"}, "pr_head_sha"),
    (lambda i: {**i, "pr_number": "5", "pr_head_sha": "C" * 40}, "pr_head_sha"),
    (lambda i: {**i, "pr_number": "5", "pr_head_sha": "c" * 39}, "pr_head_sha"),
    (lambda i: {**i, "pr_number": "5", "pr_head_sha": "refs/pull/5/head"},
     "pr_head_sha"),
    (lambda i: {**i, "pr_head_sha": HEAD}, "only valid with pr_number"),
])
def test_verify_rejects_tampered_dispatch(mutate, message):
    inputs = mutate(_dispatch())
    with pytest.raises(repro_ps_runner.VerificationError) as exc:
        repro_ps_runner.verify_spec(inputs["spec"], inputs["spec_hash"],
                                    inputs["issue"], inputs.get("pr_number", ""),
                                    inputs.get("pr_head_sha", ""))
    assert message in str(exc.value)


@pytest.mark.parametrize("name", list(PS_CORPUS))
def test_verify_rejects_powershell_injection_even_when_hash_matches(name):
    cmdlet, parameters = PS_CORPUS[name]
    text = json.dumps(_ps(cmdlet, parameters), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(repro_ps_runner.VerificationError):
        repro_ps_runner.verify_spec(text, digest, _ps("x", {})["issue"])


HEAD = "c" * 40


def test_pr_head_reruns_are_accepted_with_an_exact_head_sha():
    inputs = _dispatch()
    spec = repro_ps_runner.verify_spec(inputs["spec"], inputs["spec_hash"],
                                       ISSUE, "812", HEAD)
    assert repro_ps_runner.matrix_versions(spec, "812") == ["dev", "pr"]
    assert repro_ps_runner.verify_from_env(_env(
        inputs, REPRO_PR_NUMBER="812", REPRO_PR_HEAD_SHA=HEAD)) == spec
    assert repro_ps_runner.matrix_versions(spec) == ["reported", "latest", "dev"]


def test_pr_head_reruns_need_a_configured_agent_fork(monkeypatch):
    profile = repro_spec.REPO_PROFILES["Azure/azure-powershell"]
    assert profile["agent_fork"].endswith("/azure-powershell")
    assert repro_runner.agent_fork("Azure/azure-powershell") == profile["agent_fork"]
    monkeypatch.setitem(repro_spec.REPO_PROFILES, "Azure/azure-powershell",
                        {"kind": "powershell", "repro_tools": ("pwsh-az",),
                         "agent_fork": None})
    inputs = _dispatch()
    with pytest.raises(repro_ps_runner.VerificationError, match="no Agent fork"):
        repro_ps_runner.verify_spec(inputs["spec"], inputs["spec_hash"],
                                    ISSUE, "812", HEAD)


def _pull(**overrides):
    pr = {
        "state": "open",
        "base": {"repo": {"full_name": "Azure/azure-powershell"}},
        "head": {"repo": {"full_name": repro_runner.agent_fork("Azure/azure-powershell")},
                 "sha": HEAD},
    }
    pr.update(overrides)
    return pr


def test_verify_command_pr_mode_outputs_fork_and_sha(tmp_path, monkeypatch, capsys):
    inputs = _dispatch()
    output = tmp_path / "out.txt"
    _set_env(monkeypatch, _env(inputs, GITHUB_OUTPUT=str(output),
                               REPRO_PR_NUMBER="812", REPRO_PR_HEAD_SHA=HEAD))
    monkeypatch.chdir(tmp_path)
    calls = []

    def fetch(repository, number):
        calls.append((repository, number))
        return _pull()

    monkeypatch.setattr(repro_runner, "_fetch_pull_request", fetch)
    assert repro_ps_runner.main(["verify"]) == 0
    assert calls == [("Azure/azure-powershell", "812")]
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["versions"]) == ["dev", "pr"]
    assert values["pr_repo"] == repro_runner.agent_fork("Azure/azure-powershell")
    assert values["pr_ref"] == HEAD

    for pr, message in [
        (_pull(head={"repo": {"full_name": "attacker/azure-powershell"}, "sha": HEAD}),
         "not the Agent fork"),
        (_pull(state="closed"), "not open"),
        (_pull(base={"repo": {"full_name": "Azure/azure-cli"}}), "does not target"),
        (_pull(head={"repo": {"full_name": repro_runner.agent_fork(
            "Azure/azure-powershell")}, "sha": "d" * 40}), "head moved"),
    ]:
        output.write_text("")
        monkeypatch.setattr(repro_runner, "_fetch_pull_request", lambda *_, pr=pr: pr)
        assert repro_ps_runner.main(["verify"]) == 1
        assert output.read_text() == ""
        assert message in capsys.readouterr().out


def test_verify_command_writes_outputs_and_rejects_quietly(tmp_path, monkeypatch, capsys):
    inputs = _dispatch()
    output = tmp_path / "out.txt"
    _set_env(monkeypatch, _env(inputs, GITHUB_OUTPUT=str(output)))
    monkeypatch.chdir(tmp_path)

    assert repro_ps_runner.main(["verify"]) == 0
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["versions"]) == ["reported", "latest", "dev"]
    assert values["source_repo"] == "Azure/azure-powershell"
    assert values["dev_ref"] == "main" and values["pr_ref"] == ""
    assert values["module"] == "Az.Storage"
    assert values["step_timeout_minutes"] == "15"

    monkeypatch.setenv("REPRO_SPEC_HASH", "f" * 64)
    assert repro_ps_runner.main(["verify"]) == 1
    assert inputs["spec"] not in capsys.readouterr().out


def test_install_request_pins_the_module_under_test():
    spec = repro_ps_runner.verify_from_env(_env(_dispatch()))
    reported = repro_ps_runner.install_request(spec, "reported")["modules"]
    assert reported == [
        {"name": "Az.Storage", "version": "6.1.0"},
        {"name": "Az.Accounts", "version": None},
        {"name": "Az.Resources", "version": None},
    ]
    latest = repro_ps_runner.install_request(spec, "latest")["modules"]
    assert latest[0] == {"name": "Az.Storage", "version": None}
    dev = repro_ps_runner.install_request(spec, "dev")["modules"]
    assert "Az.Storage" not in [m["name"] for m in dev]


def test_install_request_adds_other_step_modules():
    spec = _spec(module="Az.Storage", repro=[
        {"cmdlet": "Get-AzStorageAccount", "parameters": {"ResourceGroupName": "{rg}"}},
        {"cmdlet": "Get-AzVM", "parameters": {"ResourceGroupName": "{rg}"}},
    ])
    spec = repro_ps_runner.verify_from_env(_env(_dispatch(spec)))
    names = [m["name"] for m in repro_ps_runner.install_request(spec, "reported")["modules"]]
    assert names == ["Az.Storage", "Az.Compute", "Az.Accounts", "Az.Resources"]


@pytest.mark.parametrize("version", ["dev", "pr"])
def test_install_request_keeps_gallery_resources_when_it_is_under_test(version):
    # NewGroup/RemoveGroup import Az.Resources from the gallery install even
    # when the steps import a source-built Az.Resources by path.
    spec = repro_ps_runner.verify_from_env(_env(_dispatch(_spec(
        module="Az.Resources", setup=[],
        repro=[{"cmdlet": "Get-AzResourceProvider",
                "parameters": {"ProviderNamespace": "Microsoft.Resources"}}],
    ))))
    modules = repro_ps_runner.install_request(spec, version)["modules"]
    assert modules == [
        {"name": "Az.Accounts", "version": None},
        {"name": "Az.Resources", "version": None},
    ]


def _fake_run_pwsh(calls, installed):
    def run_pwsh(action, request, log_stem, *, timeout, cwd=None, extra_env=None):
        calls.append((action, request, extra_env))
        if action == "Install":
            Path(request["result_file"]).parent.mkdir(parents=True, exist_ok=True)
            Path(request["result_file"]).write_text(json.dumps(installed))
        return {"exit_code": 0, "timed_out": False, "duration_seconds": 0.1,
                "stdout": "", "stderr": ""}
    return run_pwsh


def test_install_reported_records_module_version(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch(), REPRO_VERSION="reported"))
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {
        "Az.Storage": "6.1.0", "Az.Accounts": "3.0.0", "Az.Resources": "7.0.0",
        "Az.Evil; iex": "1.0.0",
    }))

    assert repro_ps_runner.main(["install"]) == 0
    [(action, request, _env_)] = calls
    assert action == "Install"
    assert request["modules"][0] == {"name": "Az.Storage", "version": "6.1.0"}
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert info["cli_version"] == "6.1.0" and info["module"] == "Az.Storage"
    assert set(info["modules"]) == {"Az.Storage", "Az.Accounts", "Az.Resources"}
    assert "Installed Az.Storage 6.1.0" in capsys.readouterr().out


def test_install_dev_builds_the_module_from_source(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch(), REPRO_VERSION="dev"))
    source = tmp_path / "repro" / "src"
    source.mkdir(parents=True)
    (source / repro_ps_runner.BUILD_SCRIPT).parent.mkdir(parents=True)
    (source / repro_ps_runner.BUILD_SCRIPT).write_text("param()")
    commands = []

    def run_quiet(argv, log_stem, *, timeout, cwd=None, extra_env=None):
        commands.append((list(map(str, argv)), cwd))
        out = Path(str(log_stem) + ".out")
        out.parent.mkdir(parents=True, exist_ok=True)
        if argv[0] == "pwsh":
            module = source / "artifacts" / "Debug" / "Az.Storage"
            module.mkdir(parents=True)
            (module / "Az.Storage.psd1").write_text(
                "@{\n  ModuleVersion = '6.2.0'\n  RootModule = 'x'\n}\n",
            )
        out.write_text("a" * 40 if argv[0] == "git" else "")
        return {"exit_code": 0, "timed_out": False, "duration_seconds": 1.0,
                "stdout": str(out), "stderr": ""}

    monkeypatch.setattr(repro_ps_runner, "run_quiet", run_quiet)
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {
        "Az.Accounts": "3.0.0", "Az.Resources": "7.0.0",
    }))

    assert repro_ps_runner.main(["install"]) == 0
    build_argv, build_cwd = commands[0]
    # build.proj's default target ignores TargetModule and builds every module.
    assert build_argv == ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
                          "-File", "tools/BuildScripts/BuildModules.ps1",
                          "-RepoRoot", str(source.resolve()),
                          "-Configuration", "Debug", "-TargetModule", "Storage"]
    assert Path(build_cwd) == Path("repro/src")
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert info["cli_version"] == "6.2.0"
    assert info["source_sha"] == "a" * 40
    assert info["module_path"].endswith("artifacts/Debug/Az.Storage")


def _fake_build_output(tmp_path, modules=("Az.Accounts", "Az.Storage")):
    debug = tmp_path / "repro" / "src" / "artifacts" / "Debug"
    for module in modules:
        (debug / module / "lib").mkdir(parents=True, exist_ok=True)
        (debug / module / f"{module}.psd1").write_text(
            "@{\n  ModuleVersion = '6.3.0'\n  RootModule = 'x'\n}\n",
        )
        (debug / module / "lib" / f"{module}.dll").write_bytes(b"MZ" + module.encode())
    return debug


def _pr_env(monkeypatch, **extra):
    _set_env(monkeypatch, _env(_dispatch(), REPRO_PR_NUMBER="812",
                               REPRO_PR_HEAD_SHA=HEAD, **extra))
    return repro_ps_runner.verify_from_env()


def test_build_requires_the_verified_head_and_writes_a_manifest(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    spec = _pr_env(monkeypatch)
    source = tmp_path / "repro" / "src"
    source.mkdir(parents=True)
    (source / repro_ps_runner.BUILD_SCRIPT).parent.mkdir(parents=True)
    (source / repro_ps_runner.BUILD_SCRIPT).write_text("param()")
    commands = []
    sha = "d" * 40

    def run_quiet(argv, log_stem, *, timeout, cwd=None, extra_env=None):
        argv = list(map(str, argv))
        commands.append(argv)
        out = Path(str(log_stem) + ".out")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(sha + "\n" if argv[0] == "git" else "")
        if argv[0] == "pwsh":
            _fake_build_output(tmp_path)
        return {"exit_code": 0, "timed_out": False, "duration_seconds": 1.0,
                "stdout": str(out), "stderr": str(out)}

    monkeypatch.setattr(repro_ps_runner, "run_quiet", run_quiet)
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", lambda *a, **k: pytest.fail("pwsh"))
    assert repro_ps_runner.main(["build"]) == 1
    assert "not the requested PR head" in capsys.readouterr().out
    assert not any(c[0] == "pwsh" for c in commands)

    sha = HEAD
    assert repro_ps_runner.main(["build"]) == 0
    build = next(c for c in commands if c[0] == "pwsh")
    assert build[build.index("-TargetModule") + 1] == "Storage"
    manifest = repro_ps_runner.load_module_manifest(spec, HEAD)
    assert manifest["module"] == "Az.Storage"
    assert manifest["modules"] == ["Az.Accounts", "Az.Storage"]
    assert sorted(p.name for p in (tmp_path / "repro" / "pr-module").iterdir()) == [
        "manifest.json", "module.tar.gz",
    ]
    assert not (tmp_path / "repro" / "raw" / "install.json").exists()


def test_build_refuses_non_pr_runs_and_missing_modules(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch()))
    assert repro_ps_runner.main(["build"]) == 1
    spec = _pr_env(monkeypatch)
    _fake_build_output(tmp_path, modules=("Az.Accounts",))
    with pytest.raises(ValueError, match="not built"):
        repro_ps_runner.pack_module_build(spec, HEAD)


def _packed(tmp_path, monkeypatch, **extra):
    monkeypatch.chdir(tmp_path)
    spec = _pr_env(monkeypatch, **extra)
    _fake_build_output(tmp_path)
    repro_ps_runner.pack_module_build(spec, HEAD)
    shutil.rmtree(tmp_path / "repro" / "src")
    return spec


def test_pr_install_uses_only_the_verified_build(tmp_path, monkeypatch):
    _packed(tmp_path, monkeypatch, REPRO_VERSION="pr")
    monkeypatch.setattr(repro_ps_runner, "run_quiet",
                        lambda *a, **k: pytest.fail("no process may run PR code"))
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {
        "Az.Accounts": "3.0.0", "Az.Resources": "7.0.0",
    }))

    assert repro_ps_runner.main(["install"]) == 0
    [(action, request, _extra)] = calls
    assert action == "Install"
    assert "Az.Storage" not in [m["name"] for m in request["modules"]]
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert info["cli_version"] == "6.3.0"
    assert info["source_sha"] == HEAD
    module_path = Path(info["module_path"])
    assert module_path == (tmp_path / "repro" / "modules" / "Az.Storage").resolve()
    assert (module_path / "lib" / "Az.Storage.dll").read_bytes() == b"MZAz.Storage"
    assert (module_path.parent / "Az.Accounts" / "Az.Accounts.psd1").is_file()


def _rewrite_manifest(tmp_path, **changes):
    path = tmp_path / "repro" / "pr-module" / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest.update(changes)
    path.write_text(json.dumps(manifest))


@pytest.mark.parametrize("tamper, message", [
    (lambda t: (t / "repro" / "pr-module" / "manifest.json").unlink(), "missing"),
    (lambda t: _rewrite_manifest(t, head_sha="d" * 40), "another commit"),
    (lambda t: _rewrite_manifest(t, module="Az.Compute"), "module under test"),
    (lambda t: _rewrite_manifest(t, modules=["Az.Storage", "../x"]), "module under test"),
    (lambda t: _rewrite_manifest(t, archive="../module.tar.gz"), "does not match"),
    (lambda t: (t / "repro" / "pr-module" / "module.tar.gz").write_bytes(b"tampered"),
     "does not match"),
    (lambda t: (t / "repro" / "pr-module" / "module.tar.gz").unlink(), "does not match"),
])
def test_pr_install_rejects_a_build_that_does_not_verify(tmp_path, monkeypatch, tamper, message):
    _packed(tmp_path, monkeypatch, REPRO_VERSION="pr")
    tamper(tmp_path)
    monkeypatch.setattr(repro_ps_runner, "run_pwsh",
                        lambda *a, **k: pytest.fail("nothing may be installed"))
    assert repro_ps_runner.main(["install"]) == 1
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert message in info["error"]
    assert info["module_path"] is None
    assert not (tmp_path / "repro" / "modules").exists()


def _evil_archive(tmp_path, add):
    directory = tmp_path / "repro" / "pr-module"
    directory.mkdir(parents=True)
    archive = directory / "module.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        psd1 = tmp_path / "Az.Storage.psd1"
        psd1.write_text("@{ ModuleVersion = '1.0.0' }")
        tar.add(psd1, arcname="Az.Storage/Az.Storage.psd1")
        add(tar, tmp_path)
    (directory / "manifest.json").write_text(json.dumps({
        "head_sha": HEAD, "module": "Az.Storage", "modules": ["Az.Storage"],
        "archive": "module.tar.gz",
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }))


def _member(name, kind=tarfile.REGTYPE, linkname=""):
    def add(tar, tmp_path):
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = linkname
        data = b"x" if kind == tarfile.REGTYPE else b""
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data) if data else None)
    return add


@pytest.mark.parametrize("add", [
    _member("../escape.ps1"),
    _member("/etc/profile.ps1"),
    _member("Az.Storage/../../escape.ps1"),
    _member("Az.Other/Az.Other.psd1"),
    _member("Az.Storage/link", tarfile.SYMTYPE, "/home/runner/.Azure"),
    _member("Az.Storage/hard", tarfile.LNKTYPE, "Az.Storage/Az.Storage.psd1"),
    _member("Az.Storage/fifo", tarfile.FIFOTYPE),
], ids=["dotdot", "absolute", "nested-dotdot", "foreign-module", "symlink",
        "hardlink", "fifo"])
def test_pr_install_rejects_unsafe_archive_entries(tmp_path, monkeypatch, add):
    monkeypatch.chdir(tmp_path)
    _pr_env(monkeypatch, REPRO_VERSION="pr")
    _evil_archive(tmp_path, add)
    monkeypatch.setattr(repro_ps_runner, "run_pwsh",
                        lambda *a, **k: pytest.fail("nothing may be installed"))
    assert repro_ps_runner.main(["install"]) == 1
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert "unexpected entry" in info["error"]
    assert not (tmp_path / "escape.ps1").exists()
    assert not (tmp_path / "repro" / "modules" / "Az.Storage" / "link").exists()


def test_install_failure_is_recorded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch(), REPRO_VERSION="dev"))
    assert repro_ps_runner.main(["install"]) == 1
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert info["error"] == "source checkout missing"


class _Response:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_oidc_token_requests_the_azure_audience():
    seen = []

    def opener(request, timeout):
        seen.append(request)
        return _Response(json.dumps({"value": OIDC_TOKEN}).encode())

    env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions/x?api-version=2.0",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-bearer"}
    assert repro_ps_runner.fetch_oidc_token(env, opener) == OIDC_TOKEN
    [request] = seen
    assert request.full_url == (
        "https://token.actions/x?api-version=2.0&audience=api%3A%2F%2FAzureADTokenExchange"
    )
    assert request.get_header("Authorization") == "Bearer request-bearer"


@pytest.mark.parametrize("env", [
    {},
    {"ACTIONS_ID_TOKEN_REQUEST_URL": "http://insecure/x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"},
    {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://ok/x"},
])
def test_fetch_oidc_token_needs_https_and_a_request_token(env):
    with pytest.raises(RuntimeError):
        repro_ps_runner.fetch_oidc_token(env, opener=lambda *a, **k: None)


def test_connect_passes_the_token_only_through_the_child_env(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {}))
    env = {"REPRO_CLIENT_ID": CLIENT, "REPRO_TENANT_ID": TENANT,
           "REPRO_SUBSCRIPTION_ID": SUB,
           "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions/x",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-bearer"}
    opener = lambda request, timeout: _Response(json.dumps({"value": OIDC_TOKEN}).encode())  # noqa: E731

    assert repro_ps_runner.connect(env, opener) == 0
    [(action, request, extra_env)] = calls
    assert action == "Connect" and request == {}
    assert extra_env == {"REPRO_CLIENT_ID": CLIENT, "REPRO_TENANT_ID": TENANT,
                         "REPRO_SUBSCRIPTION_ID": SUB,
                         "REPRO_FEDERATED_TOKEN": OIDC_TOKEN}
    printed = capsys.readouterr().out
    for value in (OIDC_TOKEN, "request-bearer", CLIENT, TENANT, SUB):
        assert value not in printed


def test_connect_rejects_non_guid_ids(monkeypatch, capsys):
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", lambda *a, **k: pytest.fail("ran"))
    env = {"REPRO_CLIENT_ID": "x; iex", "REPRO_TENANT_ID": TENANT,
           "REPRO_SUBSCRIPTION_ID": SUB}
    assert repro_ps_runner.connect(env) == 1
    assert "x; iex" not in capsys.readouterr().out


def test_logout_removes_az_context_caches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {}))
    for cache in repro_ps_runner.AZ_CACHE_DIRS:
        (tmp_path / cache).mkdir(parents=True)
        (tmp_path / cache / "AzureRmContext.json").write_text("{}")
    assert repro_ps_runner.main(["logout"]) == 0
    assert [c[0] for c in calls] == ["Disconnect"]
    assert not any((tmp_path / cache).exists() for cache in repro_ps_runner.AZ_CACHE_DIRS)


def test_rg_delete_reconnects_and_tolerates_unverified_specs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch(), GITHUB_RUN_ID="9", REPRO_VERSION="dev"))
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {}))
    monkeypatch.setattr(repro_ps_runner, "connect", lambda **k: calls.append(("connect",)) or 0)
    # The job failed before rg-create (e.g. at Azure login): no sign-in, no delete.
    assert repro_ps_runner.main(["rg-delete"]) == 0
    assert calls == []
    assert "No resource group was created" in capsys.readouterr().out

    assert repro_ps_runner.main(["rg-create"]) == 0
    calls.clear()
    assert repro_ps_runner.main(["rg-delete"]) == 0
    assert calls[0] == ("connect",)
    assert calls[1][0] == "RemoveGroup"
    assert calls[1][1] == {"name": "xea-repro-azure-powershell-27001-9-dev"}

    monkeypatch.setenv("REPRO_SPEC_HASH", "0" * 64)
    assert repro_ps_runner.main(["rg-delete"]) == 0
    assert "nothing was created" in capsys.readouterr().out


def test_rg_create_tags_expiry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    inputs = _dispatch()
    _set_env(monkeypatch, _env(inputs, GITHUB_RUN_ID="9", REPRO_VERSION="latest"))
    calls = []
    monkeypatch.setattr(repro_ps_runner, "run_pwsh", _fake_run_pwsh(calls, {}))
    assert repro_ps_runner.main(["rg-create"]) == 0
    [(action, request, _e)] = calls
    assert action == "NewGroup"
    assert request["name"] == "xea-repro-azure-powershell-27001-9-latest"
    assert request["location"] == "westus3"
    assert set(request["tags"]) == {settings.REPRO_EXPIRES_TAG, "createdBy",
                                    "purpose", "specHash"}
    assert request["tags"]["specHash"] == inputs["spec_hash"][:16]


def test_janitor_covers_powershell_resource_groups():
    group = repro_spec.reproduction_resource_group(ISSUE, "9-dev")
    past = "2000-01-01T00:00:00Z"
    assert repro_janitor.select_expired([
        {"name": group, "tags": {settings.REPRO_EXPIRES_TAG: past}},
    ]) == [group]


def test_pwsh_argv_runs_the_trusted_file_never_a_command(tmp_path):
    argv = repro_ps_runner.pwsh_argv("Invoke", tmp_path / "req.json")
    assert argv[1:6] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                         str(PS1)]
    assert argv[6:] == ["-Action", "Invoke", "-RequestFile",
                        str((tmp_path / "req.json").resolve())]
    assert not any(token.lower() in ("-command", "-c", "-encodedcommand", "-e")
                   for token in argv)


def test_runner_sources_never_build_commands_from_strings():
    ps1 = re.sub(r"<#.*?#>", "", PS1.read_text(encoding="utf-8"), flags=re.S)
    code = "\n".join(line for line in ps1.splitlines()
                     if not line.lstrip().startswith("#"))
    for forbidden in ("Invoke-Expression", "iex ", "Invoke-Command", "Add-Type",
                      "[scriptblock]::Create", "NewScriptBlock", "Start-Process",
                      "ExecutionContext", "Start-Job", "& $cmdlet", "& \"", "& '"):
        assert forbidden.lower() not in code.lower(), forbidden
    assert not re.search(r"(?<![\w-])-(?:Encoded)?Command\b", code, flags=re.I)
    assert "& $command @splat" in code
    runner = (SCRIPTS / "repro_ps_runner.py").read_text(encoding="utf-8")
    assert "shell=True" not in runner and '"-Command"' not in runner


def test_display_cmdlet():
    step = {"cmdlet": "New-AzStorageAccount", "parameters": {
        "ResourceGroupName": "{rg}", "Name": "{name1}", "Tag": ["a b", "c"],
        "EnableHttpsTrafficOnly": True, "Kind": "it's",
    }}
    assert repro_ps_runner.display_cmdlet(step) == (
        "New-AzStorageAccount -ResourceGroupName <rg> -Name <name1> "
        "-Tag 'a b',c -EnableHttpsTrafficOnly:$true -Kind 'it''s'"
    )


FAKE_PWSH = r'''
import json, os, sys
args = sys.argv[1:]
request = json.load(open(args[args.index("-RequestFile") + 1]))
action = args[args.index("-Action") + 1]
mode = {mode!r}
print(json.dumps({{"argv": args, "env": sorted(os.environ), "cwd": os.listdir("."),
                   "request": request}}))
if mode == "sleep":
    import time; time.sleep(30)
if action == "Invoke" and request["cmdlet"].startswith("Get-") and mode == "reproduced":
    print("ERROR: The Resource 'Microsoft.Storage/storageAccounts/"
          + request["parameters"]["Name"] + "' under resource group '"
          + request["parameters"]["ResourceGroupName"] + "' was not found.",
          file=sys.stderr)
    print("ErrorCode: ResourceNotFound", file=sys.stderr)
    sys.exit(1)
if action == "Invoke" and request["cmdlet"].startswith("New-") and mode == "setup_fail":
    print("REJECTED: nope", file=sys.stderr)
    sys.exit(2)
'''


def _fake_pwsh(tmp_path, monkeypatch, mode="reproduced"):
    path = tmp_path / f"pwsh-{mode}"
    path.write_text(f"#!{sys.executable}\n" + FAKE_PWSH.format(mode=mode))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(repro_ps_runner, "pwsh", lambda: str(path))


def _execute(tmp_path, monkeypatch, mode="reproduced", install=None, deadline=None):
    _fake_pwsh(tmp_path, monkeypatch, mode)
    spec = repro_ps_runner.verify_from_env(_env(_dispatch()))
    group = repro_runner.resource_group_for(
        spec, {"GITHUB_RUN_ID": "99", "REPRO_VERSION": "latest"},
    )
    raw = repro_ps_runner.execute(
        spec, install=install or {"cli_version": "6.1.0"}, resource_group=group,
        run_id="99-latest", subscription_id=SUB, deadline_seconds=deadline,
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work",
    )
    return spec, group, raw


def test_execute_splats_resolved_parameters_without_printing_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-request-token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example/oidc")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    _spec_, group, raw = _execute(tmp_path, monkeypatch)

    printed = capsys.readouterr().out
    assert "setup[0]: exit 0" in printed and "repro[0]: exit 1" in printed
    for value in (SUB, group, raw["redact_values"]["password"],
                  raw["redact_values"]["name1"]):
        assert value not in printed
    assert raw["status"] == "completed" and raw["reproduced"] is True
    setup, repro = raw["steps"]
    assert setup["command"] == (
        "New-AzStorageAccount -EnableHttpsTrafficOnly:$true -Location <location> "
        "-Name <name1> -ResourceGroupName <rg> -SkuName Standard_LRS"
    )
    seen = json.loads(Path(setup["stdout"]).read_text())
    assert seen["argv"][:4] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-File"]
    assert seen["cwd"] == ["repro-input.txt"]
    for key in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                "GITHUB_TOKEN", "REPRO_FEDERATED_TOKEN"):
        assert key not in seen["env"]
    assert "POWERSHELL_TELEMETRY_OPTOUT" in seen["env"]
    request = seen["request"]
    assert request["cmdlet"] == "New-AzStorageAccount"
    assert request["module"] == "Az.Storage"
    assert request["required_version"] == "6.1.0" and request["module_path"] is None
    assert request["parameters"] == {
        "ResourceGroupName": group, "Name": raw["redact_values"]["name1"],
        "SkuName": "Standard_LRS", "Location": "westus3",
        "EnableHttpsTrafficOnly": True,
    }
    assert request["denied_parameters"] == sorted(settings.REPRO_PS_DENIED_PARAMETERS)
    # Request files hold resolved values and are removed after each step.
    assert not list((tmp_path / "repro" / "raw" / "requests").iterdir())


def test_execute_uses_the_built_module_for_dev(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _s, _g, raw = _execute(tmp_path, monkeypatch, install={
        "cli_version": "6.2.0", "module_path": "/w/repro/src/artifacts/Debug/Az.Storage",
    })
    request = json.loads(Path(raw["steps"][0]["stdout"]).read_text())["request"]
    assert request["module_path"] == "/w/repro/src/artifacts/Debug/Az.Storage"
    assert request["required_version"] is None


@pytest.mark.parametrize("mode, status, reproduced", [
    ("not_reproduced", "completed", False),
    ("setup_fail", "setup_failed", None),
])
def test_execute_outcomes(tmp_path, monkeypatch, mode, status, reproduced):
    monkeypatch.chdir(tmp_path)
    _s, _g, raw = _execute(tmp_path, monkeypatch, mode)
    assert (raw["status"], raw["reproduced"]) == (status, reproduced)


def test_execute_timeout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _s, _g, raw = _execute(tmp_path, monkeypatch, "sleep", deadline=1.5)
    assert raw["status"] == "timeout" and raw["reproduced"] is None
    assert raw["steps"][1]["skipped"] is True


def test_run_without_install_records_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_env(monkeypatch, _env(_dispatch(), REPRO_VERSION="latest"))
    assert repro_ps_runner.main(["run"]) == 1
    raw = json.loads((tmp_path / "repro" / "raw" / "repro.raw.json").read_text())
    assert raw["status"] == "error" and raw["error"] == "module not installed"


def _sanitized(tmp_path, monkeypatch, mode="reproduced"):
    monkeypatch.chdir(tmp_path)
    inputs = _dispatch()
    spec, group, raw = _execute(tmp_path, monkeypatch, mode)
    (tmp_path / "raw" / "repro.raw.json").write_text(json.dumps(raw))
    (tmp_path / "raw" / "install.json").write_text(json.dumps({
        "version": "latest", "error": None, "cli_version": "6.1.0",
        "extension_version": None, "source_sha": None, "module": "Az.Storage",
    }))
    env = _env(inputs, REPRO_VERSION="latest", **KNOWN_ENV)
    path, _ = repro_sanitize.sanitize_version(
        spec, env, raw_dir=tmp_path / "raw", out_dir=tmp_path / "out",
        runner_module=repro_ps_runner,
    )
    return path, raw, group


def test_sanitized_powershell_document_uses_the_shared_schema(tmp_path, monkeypatch):
    path, raw, group = _sanitized(tmp_path, monkeypatch)
    assert path.name == "repro.redacted.json"
    text = path.read_text()
    values = raw["redact_values"]
    for value in (SUB, TENANT, CLIENT, group, values["password"], values["name1"]):
        assert value.lower() not in text.lower(), value
    assert not repro_sensitive_data.scan_sensitive_content(
        [{"location": "doc", "text": text}])["blocked"]
    document = json.loads(text)
    assert document["schema"] == repro_runner.RESULT_SCHEMA
    assert (document["tool"], document["module"]) == ("pwsh-az", "Az.Storage")
    [result] = document["results"]
    assert result["cli_version"] == "6.1.0"
    assert (result["status"], result["reproduced"]) == ("completed", True)
    _setup, repro = result["steps"]
    assert repro["command"] == (
        "Get-AzStorageAccount -Name <name1> -ResourceGroupName <rg>"
    )
    assert repro["error_code"] == "ResourceNotFound"
    assert "<rg>" in repro["error_excerpt"] and "<name1>" in repro["error_excerpt"]


def test_cli_documents_carry_a_null_module(tmp_path, monkeypatch):
    scrubber = repro_sanitize._Scrubber()
    spec = repro_spec.validate_spec({
        "issue": "Azure/azure-cli#1", "tool": "az",
        "repro": [{"argv": ["az", "version"]}],
        "observed_in_issue": {"exit_code": 1},
    })["spec"]
    document = repro_sanitize.build_document(spec, "a" * 64, "", [], scrubber, {})
    assert document["module"] is None


def test_merge_and_sanitize_cli_with_powershell_runner(tmp_path, monkeypatch, capsys):
    path, _raw, _group = _sanitized(tmp_path, monkeypatch)
    parts = tmp_path / "parts" / "repro-redacted-latest"
    parts.mkdir(parents=True)
    (parts / "repro.redacted.json").write_text(path.read_text())
    _set_env(monkeypatch, _env(_dispatch(), REPRO_VERSION="latest", **KNOWN_ENV))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    out = tmp_path / "result" / "repro.redacted.json"
    assert repro_sanitize.main(["--runner", "powershell", "merge", "--parts",
                                str(tmp_path / "parts"), "--out", str(out)]) == 0
    document = json.loads(out.read_text())
    assert [r["version"] for r in document["results"]] == ["reported", "latest", "dev"]
    assert document["module"] == "Az.Storage"
    assert "| Version | Az.Storage | Status | Result |" in summary.read_text()
    assert "| latest | 6.1.0 | completed | Reproduced |" in summary.read_text()
    # The CLI runner refuses the PowerShell spec, so the default fails closed.
    assert repro_sanitize.main(["merge", "--parts", "p", "--out", "o"]) == 1
    assert SUB not in capsys.readouterr().out


FAKE_MODULE = r'''
function New-AzStorageAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][Alias('ResourceGroup')][string] $ResourceGroupName,
        [Parameter(Mandatory)][Alias('AccountName')][string] $Name,
        [string] $SkuName, [string] $Location,
        [switch] $EnableHttpsTrafficOnly,
        [string[]] $Tag,
        [securestring] $Password,
        [Alias('AzContext', 'AzureRmContext', 'AzureCredential')][object] $DefaultProfile,
        [scriptblock] $Filter,
        [pscredential] $Account
    )
    $confirmSet = $PSBoundParameters.ContainsKey('Confirm')
    [pscustomobject]@{
        ResourceGroupName = $ResourceGroupName; Name = $Name; SkuName = $SkuName
        Https = [bool] $EnableHttpsTrafficOnly; Tag = $Tag
        PasswordIsSecure = ($Password -is [securestring])
        Confirm = $confirmSet
        Env = @(Get-ChildItem env: | ForEach-Object Name)
    }
}

function Get-AzStorageAccount {
    [CmdletBinding()]
    param([string] $ResourceGroupName, [string] $Name)
    Write-Warning "Upcoming breaking changes in the cmdlet"
    $exception = [System.Exception]::new(
        "The Resource 'Microsoft.Storage/storageAccounts/$Name' under resource group " +
        "'$ResourceGroupName' was not found in subscription __SUB__.")
    $exception | Add-Member -NotePropertyName ErrorCode -NotePropertyValue 'ResourceNotFound'
    throw $exception
}

function Get-AzStorageAccountKey { param([string] $Name) 'key' }

Export-ModuleMember -Function New-AzStorageAccount, Get-AzStorageAccount
'''


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """HOME with a fake Az.Storage 6.1.0 in the pwsh user module path."""
    home = tmp_path / "home"
    module = home / ".local" / "share" / "powershell" / "Modules" / "Az.Storage" / "6.1.0"
    module.mkdir(parents=True)
    (module / "Az.Storage.psm1").write_text(FAKE_MODULE.replace("__SUB__", SUB))
    (module / "Az.Storage.psd1").write_text(
        "@{ RootModule = 'Az.Storage.psm1'; ModuleVersion = '6.1.0'; "
        "GUID = '0b1f6471-1bf0-4dda-aec3-000000000001'; "
        "FunctionsToExport = @('New-AzStorageAccount', 'Get-AzStorageAccount') }\n"
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    return home


def _invoke(cmdlet="New-AzStorageAccount", parameters=None, **request):
    base = {
        "cmdlet": cmdlet, "module": "Az.Storage", "required_version": "6.1.0",
        "module_path": None,
        "parameters": {"ResourceGroupName": "rg1", "Name": "n1"}
        if parameters is None else parameters,
        "denied_parameters": sorted(settings.REPRO_PS_DENIED_PARAMETERS),
    }
    base.update(request)
    result = repro_ps_runner.run_pwsh(
        "Invoke", base, Path("repro/raw/steps/test"), timeout=120,
        cwd=Path.cwd(),
    )
    return (result["exit_code"], Path(result["stdout"]).read_text(),
            Path(result["stderr"]).read_text())


@needs_pwsh
def test_ps1_splats_values_as_literal_data(fake_home, tmp_path):
    marker = tmp_path / "pwned"
    hostile = f"$(New-Item -Path '{marker}');`$x; Remove-Item * | iex"
    code, out, err = _invoke(parameters={
        "ResourceGroupName": hostile, "AccountName": "n1",
        "EnableHttpsTrafficOnly": True, "Tag": ["a;b", "$(x)"],
        "Password": "Xr0secret9!a",
    })
    assert code == 0, err
    data = json.loads(out)
    assert data["ResourceGroupName"] == hostile
    assert data["Name"] == "n1"  # bound through its alias
    assert data["Https"] is True and data["Tag"] == ["a;b", "$(x)"]
    assert data["PasswordIsSecure"] is True
    assert data["Confirm"] is True  # -Confirm:$false added by the script
    assert not marker.exists()
    assert "REPRO_FEDERATED_TOKEN" not in data["Env"]


@needs_pwsh
def test_ps1_keeps_iso_date_strings_as_sent(fake_home):
    """ConvertFrom-Json would turn these into culture-formatted DateTimes.

    That broke the expiresAt tag and date-valued cmdlet parameters.
    """
    code, out, err = _invoke(parameters={
        "ResourceGroupName": "2026-10-12T10:41:00Z", "Name": "n1",
        "SkuName": "2024-01-01T00:00:00.5+02:00",
    })
    assert code == 0, err
    data = json.loads(out)
    assert data["ResourceGroupName"] == "2026-10-12T10:41:00Z"
    assert data["SkuName"] == "2024-01-01T00:00:00.5+02:00"


@needs_pwsh
def test_ps1_reports_errors_with_code_and_warnings_on_stderr(fake_home):
    code, out, err = _invoke("Get-AzStorageAccount")
    assert code == 1 and out == ""
    assert "ERROR: The Resource 'Microsoft.Storage/storageAccounts/n1'" in err
    assert "ErrorCode: ResourceNotFound" in err
    assert "WARNING: Upcoming breaking changes" in err


@needs_pwsh
@pytest.mark.parametrize("parameters, message", [
    ({"AzureRmContext": "x"}, "-AzureRmContext is not allowed"),
    ({"AzContext": "x"}, "-AzContext is not allowed"),
    ({"DefaultProfile": "x"}, "-DefaultProfile is not allowed"),
    ({"Debug": True}, "-Debug is not allowed"),
    ({"ErrorAction": "Inquire"}, "-ErrorAction must be Stop"),
    ({"OutVariable": "x"}, "-OutVariable is not allowed"),
    ({"DefaultP": "x"}, "-DefaultP is not a parameter"),
    ({"ResourceGroupN": "x"}, "-ResourceGroupN is not a parameter"),
    ({"ScriptBlock": "Get-Process"}, "-ScriptBlock is not allowed"),
    ({"Credential": "x"}, "-Credential is not allowed"),
    ({"Filter": "Get-Process"}, "takes code or credentials"),
    ({"Account": "x"}, "takes code or credentials"),
    ({"Name; iex": "x"}, "invalid parameter name"),
    ({"Name": {"a": 1}}, "must be a scalar value"),
    ({"Tag": [["nested"]]}, "flat list of scalars"),
    ({"EnableHttpsTrafficOnly": "yes"}, "needs true or false"),
    ({"Name": "a", "AccountName": "b"}, "is given twice"),
], ids=["azurerm-context", "az-context", "default-profile", "debug",
        "error-action", "out-variable", "abbreviated-denied", "abbreviated",
        "script-block", "credential", "scriptblock-type", "credential-type",
        "bad-name", "hashtable", "nested-list",
        "switch-string", "duplicate-alias"])
def test_ps1_rejects_parameters_the_validator_would_never_emit(fake_home, parameters, message):
    code, out, err = _invoke(parameters=parameters)
    assert code == 2, err
    assert message in err and out == ""


@needs_pwsh
@pytest.mark.parametrize("request_, code, message", [
    ({"cmdlet": "Invoke-Expression"}, 2, "invalid cmdlet name"),
    ({"cmdlet": "Get-AzStorageAccount; iex x"}, 2, "invalid cmdlet name"),
    ({"cmdlet": "Get-AzStorageAccountKey"}, 2, "is not exported by Az.Storage"),
    ({"module": "Az.Storage; iex"}, 2, "invalid module name"),
    ({"required_version": "1.0; iex"}, 2, "invalid version"),
    ({"required_version": "9.9.9"}, 3, "could not be imported"),
    ({"denied_parameters": []}, 2, "denied parameter list is missing"),
], ids=["iex", "chained", "not-exported", "module", "version",
        "missing-version", "no-denylist"])
def test_ps1_rejects_bad_invoke_requests(fake_home, request_, code, message):
    exit_code, _out, err = _invoke(**request_)
    assert exit_code == code, err
    assert message in err


@needs_pwsh
@pytest.mark.parametrize("action, request_, message", [
    ("Install", {"modules": [{"name": "Az.Storage; iex", "version": None}],
                 "result_file": "x"}, "invalid module name"),
    ("Install", {"modules": [{"name": "Az.Storage", "version": "1.0 -Force"}],
                 "result_file": "x"}, "invalid version"),
    ("Connect", {}, "REPRO_CLIENT_ID must be a GUID"),
    ("NewGroup", {"name": "production", "location": "westus3", "tags": {}},
     "invalid resource group name"),
    ("NewGroup", {"name": "xea-repro-a-1-b", "location": "west us; iex",
                  "tags": {}}, "invalid location"),
    ("RemoveGroup", {"name": "xea-repro-$(iex)"}, "invalid resource group name"),
])
def test_ps1_lifecycle_requests_are_validated(fake_home, action, request_, message):
    result = repro_ps_runner.run_pwsh(action, request_, Path("repro/raw/lifecycle/t"),
                                      timeout=120)
    assert result["exit_code"] == 2
    assert message in Path(result["stderr"]).read_text()


@needs_pwsh
def test_end_to_end_with_real_pwsh_is_sanitized(fake_home, tmp_path, monkeypatch):
    inputs = _dispatch()
    spec = repro_ps_runner.verify_from_env(_env(inputs))
    group = repro_runner.resource_group_for(spec, {"GITHUB_RUN_ID": "7", "REPRO_VERSION": "reported"})
    raw = repro_ps_runner.execute(
        spec, install={"cli_version": "6.1.0"}, resource_group=group,
        run_id="7-reported", subscription_id=SUB,
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work", log=lambda *_: None,
    )
    assert raw["status"] == "completed" and raw["reproduced"] is True
    assert [s["exit_code"] for s in raw["steps"]] == [0, 1]
    (tmp_path / "raw" / "repro.raw.json").write_text(json.dumps(raw))
    (tmp_path / "raw" / "install.json").write_text(json.dumps({
        "version": "reported", "error": None, "cli_version": "6.1.0",
    }))
    path, result = repro_sanitize.sanitize_version(
        spec, _env(inputs, REPRO_VERSION="reported", **KNOWN_ENV),
        raw_dir=tmp_path / "raw", out_dir=tmp_path / "out",
        runner_module=repro_ps_runner,
    )
    text = path.read_text()
    for value in (SUB, group, raw["redact_values"]["name1"]):
        assert value not in text
    step = result["steps"][1]
    assert step["error_code"] == "ResourceNotFound"
    assert "<sub>" in step["error_excerpt"] and "<rg>" in step["error_excerpt"]
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["repro.redacted.json"]

