"""Tests for the live reproduction runner, sanitizer and janitor."""

import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "live_repro"
sys.path.insert(0, str(SCRIPTS))

from test_live_repro_injection_corpus import (  # noqa: E402
    AZ_CORPUS,
    PS_CORPUS,
    _az,
    _ps,
)

import repro_janitor  # noqa: E402
import repro_runner  # noqa: E402
import repro_sanitize  # noqa: E402
import repro_spec  # noqa: E402
import repro_sensitive_data  # noqa: E402

ISSUE = "Azure/azure-cli#34187"
SUB = "6c1f3a2e-9d4b-4c8e-8f0a-1b2c3d4e5f60"
TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
CLIENT = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
SECRETS = {
    "sas": "sig=abcdEFGH1234ijklMNOP5678qrstUVWX9012yzAB%3D",
    "email": "jane.doe@contoso.com",
    "ip": "10.20.30.40",
    "token": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "objectid": "0b1f6471-1bf0-4dda-aec3-111122223333",
}


def _spec(**overrides):
    spec = {
        "issue": ISSUE,
        "tool": "az",
        "versions": ["reported", "latest", "dev"],
        "reported_version": "2.77.0",
        "location": "westus3",
        "setup": [{"argv": [
            "az", "sql", "server", "create", "-g", "{rg}", "-n", "{name1}",
            "--admin-user", "reproadmin", "--admin-password", "{password}",
        ]}],
        "repro": [{"argv": [
            "az", "monitor", "metrics", "list", "--resource",
            "/subscriptions/{sub}/resourceGroups/{rg}/providers/"
            "Microsoft.Sql/servers/{name1}",
        ]}],
        "observed_in_issue": {"error_substring": "ResourceNotFound"},
        "timeout_minutes": 10,
    }
    spec.update(overrides)
    return spec


def _dispatch(spec=None):
    """Inputs exactly as `dispatch_reproduction` sends them."""
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


# Parity with the Agent's validator is checked in the Agent repository;
# here the vendored copy must reject the corpus on its own.

def _corpus_cases():
    cases = {}
    for name, argv in AZ_CORPUS.items():
        cases[f"az-{name}"] = _az(*argv)
        cases[f"az-setup-{name}"] = _az("version", setup=[{"argv": ["az", *argv]}])
    for name, (cmdlet, parameters) in PS_CORPUS.items():
        cases[f"ps-{name}"] = _ps(cmdlet, parameters)
    cases["valid-az"] = _az("storage", "account", "list", "-g", "{rg}")
    cases["valid-version"] = _az("version")
    cases["valid-ps"] = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    cases["valid-runner"] = _spec()
    cases["valid-extension"] = _spec(
        issue="Azure/azure-cli-extensions#9000", tool="az-extension:containerapp",
        setup=[], repro=[{"argv": ["az", "containerapp", "env", "list", "-g", "{rg}"]}],
    )
    cases["not-json"] = "{not json"
    cases["wrong-repo"] = _spec(issue="Azure/unknown-repo#1")
    return cases


CASES = _corpus_cases()


@pytest.mark.parametrize("name", list(CASES))
def test_vendored_validator_verdicts(name):
    result = repro_spec.validate_spec(CASES[name])

    assert result["valid"] is name.startswith("valid-"), result["errors"]
    if result["valid"]:
        assert result["spec_hash"] == repro_spec.spec_hash(result["spec"])
    else:
        assert result["errors"]
        assert result["spec_hash"] is None


def test_corpus_rejects_every_injection():
    rejected = [n for n in CASES if n.startswith(("az-", "ps-"))]
    assert len(rejected) == 2 * len(AZ_CORPUS) + len(PS_CORPUS)
    for name in rejected:
        assert repro_spec.validate_spec(CASES[name])["valid"] is False, name


def test_vendored_helpers():
    spec = repro_spec.validate_spec(_spec())["spec"]
    digest = repro_spec.spec_hash(spec)
    canonical = repro_spec.canonical_spec_json(spec)
    assert digest == hashlib.sha256(canonical.encode()).hexdigest()
    assert json.loads(canonical) == spec
    group = repro_spec.reproduction_resource_group(ISSUE, "123-dev")
    assert group.startswith(repro_janitor.PREFIX)
    assert group == repro_spec.reproduction_resource_group(ISSUE, "123-dev")
    kwargs = dict(resource_group="rg1", location="westus3", subscription_id=SUB,
                  password="Pw-1", file_path="f.txt")
    values = repro_spec.placeholder_values(digest, "r1", **kwargs)
    assert values == repro_spec.placeholder_values(digest, "r1", **kwargs)
    assert values["rg"] == "rg1" and values["sub"] == SUB


@pytest.mark.parametrize("text, secret", [
    (f"key {SECRETS['token']} and {SECRETS['email']}", SECRETS["token"]),
    ("AccountKey=" + "a" * 86 + "==", "a" * 86),
])
def test_vendored_sensitive_data_redacts(text, secret):
    assert secret not in repro_sensitive_data.redact_sensitive_text(text)


def test_vendored_sensitive_data_keeps_plain_text():
    text = "nothing to see here"
    assert repro_sensitive_data.redact_sensitive_text(text) == text


def test_verify_accepts_exact_dispatch():
    inputs = _dispatch()
    spec = repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE)
    assert spec["issue"] == ISSUE
    assert repro_runner.verify_from_env(_env(inputs)) == spec


@pytest.mark.parametrize("mutate, message", [
    (lambda i: {**i, "spec_hash": "0" * 64}, "does not match spec_hash"),
    (lambda i: {**i, "spec_hash": "ABC"}, "64 lowercase hex"),
    (lambda i: {**i, "issue": "Azure/azure-cli#1"}, "issue: does not match"),
    (lambda i: {**i, "pr_number": "1; rm -rf /"}, "positive integer"),
])
def test_verify_rejects_tampered_dispatch(mutate, message):
    inputs = mutate(_dispatch())
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"],
                                 inputs["issue"], inputs.get("pr_number", ""))
    assert message in str(exc.value)


def test_verify_rejects_non_canonical_text_even_with_matching_hash():
    inputs = _dispatch()
    pretty = json.dumps(json.loads(inputs["spec"]), indent=2)
    digest = hashlib.sha256(pretty.encode()).hexdigest()
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_spec(pretty, digest, ISSUE)
    assert "canonical JSON" in str(exc.value)


@pytest.mark.parametrize("name", [n for n in AZ_CORPUS])
def test_verify_rejects_injection_even_when_hash_matches(name):
    spec = _az(*AZ_CORPUS[name])
    text = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(repro_runner.VerificationError):
        repro_runner.verify_spec(text, digest, ISSUE)


def test_verify_rejects_powershell_specs():
    spec = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    inputs = _dispatch(spec)
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], inputs["issue"])
    assert "live-repro-powershell.yml" in str(exc.value)


HEAD = "c" * 40


def test_pr_mode_needs_an_issue_on_the_source_repository():
    inputs = _dispatch()
    spec = repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE,
                                    "42", HEAD)
    assert repro_runner.matrix_versions(spec, "42") == ["dev", "pr"]
    ext_issue = _dispatch(_spec(issue="Azure/azure-cli-extensions#9000",
                                tool="az", setup=[],
                                repro=[{"argv": ["az", "version"]}]))
    with pytest.raises(repro_runner.VerificationError):
        repro_runner.verify_spec(ext_issue["spec"], ext_issue["spec_hash"],
                                 ext_issue["issue"], "42", HEAD)


@pytest.mark.parametrize("pr_number, head, message", [
    ("42", "", "pr_head_sha"),
    ("42", "C" * 40, "pr_head_sha"),
    ("42", "c" * 39, "pr_head_sha"),
    ("42", "refs/pull/42/head", "pr_head_sha"),
    ("", HEAD, "only valid with pr_number"),
])
def test_pr_mode_requires_an_exact_head_sha(pr_number, head, message):
    inputs = _dispatch()
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE,
                                 pr_number, head)
    assert message in str(exc.value)


def test_agent_forks_come_from_vendored_repo_profiles():
    profile = repro_spec.REPO_PROFILES["Azure/azure-cli"]
    assert profile["agent_fork"]
    assert repro_runner.agent_fork("Azure/azure-cli") == profile["agent_fork"]
    assert repro_runner.agent_fork("Azure/azure-cli-extensions").endswith(
        "/azure-cli-extensions")
    assert repro_runner.agent_fork("Azure/unknown") is None


def _pull(**overrides):
    pr = {
        "state": "open",
        "base": {"repo": {"full_name": "Azure/azure-cli"}},
        "head": {"repo": {"full_name": repro_runner.agent_fork("Azure/azure-cli")},
                 "sha": HEAD},
    }
    pr.update(overrides)
    return pr


def test_verify_pull_request_accepts_only_the_agent_fork_head():
    fork = repro_runner.agent_fork("Azure/azure-cli")
    calls = []

    def fetch(repository, number):
        calls.append((repository, number))
        return _pull()

    assert repro_runner.verify_pull_request(
        "Azure/azure-cli", "42", HEAD, fetch=fetch) == fork
    assert calls == [("Azure/azure-cli", "42")]


@pytest.mark.parametrize("pr, message", [
    (_pull(state="closed"), "not open"),
    (_pull(head={"repo": {"full_name": "attacker/azure-cli"}, "sha": HEAD}),
     "not the Agent fork"),
    (_pull(head={"repo": None, "sha": HEAD}), "not the Agent fork"),
    (_pull(base={"repo": {"full_name": "Azure/azure-cli-extensions"}}),
     "does not target"),
    (_pull(head={"repo": {"full_name": "a0x1ab/azure-cli"}, "sha": "d" * 40}),
     "head moved"),
    ("not a dict", "could not be read"),
])
def test_verify_pull_request_rejects_other_prs(pr, message):
    if isinstance(pr, dict) and message != "head moved":
        pr["head"].setdefault("sha", HEAD)
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_pull_request(
            "Azure/azure-cli", "42", HEAD, fetch=lambda *_: pr)
    assert message in str(exc.value)


def test_verify_pull_request_fails_closed_on_api_errors():
    def fetch(*_):
        raise OSError("boom")

    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_pull_request("Azure/azure-cli", "42", HEAD, fetch=fetch)
    assert "boom" not in str(exc.value)


def test_candidate_mode_checks_the_agent_fork_branch_not_a_pr():
    fork = repro_runner.agent_fork("Azure/azure-cli")
    calls = []

    def fetch_branch(repository, branch):
        calls.append((repository, branch))
        return {"name": branch, "commit": {"sha": HEAD}}

    def fetch(*_):
        raise AssertionError("candidate mode must not read a PR")

    assert repro_runner.verify_pull_request(
        "Azure/azure-cli", "0", HEAD, fetch=fetch, fetch_branch=fetch_branch) == fork
    assert calls == [(fork, f"xea-candidate/{HEAD}")]


@pytest.mark.parametrize("branch, message", [
    ({"commit": {"sha": "d" * 40}}, "does not point at this commit"),
    ({"commit": None}, "does not point at this commit"),
    ("not a dict", "does not point at this commit"),
    (OSError("boom"), "could not be read"),
])
def test_candidate_mode_fails_closed(branch, message):
    def fetch_branch(*_):
        if isinstance(branch, Exception):
            raise branch
        return branch

    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_pull_request(
            "Azure/azure-cli", "0", HEAD, fetch_branch=fetch_branch)
    assert message in str(exc.value) and "boom" not in str(exc.value)


def test_candidate_mode_is_a_valid_dispatch_with_dev_and_pr_versions():
    inputs = _dispatch()
    spec = repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE, "0", HEAD)
    assert repro_runner.matrix_versions(spec, "0") == ["dev", "pr"]
    with pytest.raises(repro_runner.VerificationError) as exc:
        repro_runner.verify_spec(inputs["spec"], inputs["spec_hash"], ISSUE, "00", HEAD)
    assert "positive integer" in str(exc.value)


def test_verify_command_pr_mode_outputs_fork_and_sha(tmp_path, monkeypatch, capsys):
    inputs = _dispatch()
    output = tmp_path / "out.txt"
    env = _env(inputs, GITHUB_OUTPUT=str(output), REPRO_PR_NUMBER="42",
               REPRO_PR_HEAD_SHA=HEAD)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(repro_runner, "_fetch_pull_request", lambda *_: _pull())
    assert repro_runner.main(["verify"]) == 0
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["versions"]) == ["dev", "pr"]
    assert values["pr_repo"] == repro_runner.agent_fork("Azure/azure-cli")
    assert values["pr_ref"] == HEAD

    output.write_text("")
    monkeypatch.setattr(repro_runner, "_fetch_pull_request", lambda *_: _pull(
        head={"repo": {"full_name": "someone/azure-cli"}, "sha": HEAD}))
    assert repro_runner.main(["verify"]) == 1
    assert output.read_text() == ""
    assert "not the Agent fork" in capsys.readouterr().out


def _wheels(directory, names, head=HEAD):
    directory.mkdir(parents=True, exist_ok=True)
    entries = []
    for name in names:
        (directory / name).write_bytes(name.encode())
        entries.append({"file": name,
                        "sha256": hashlib.sha256(name.encode()).hexdigest()})
    (directory / "manifest.json").write_text(json.dumps(
        {"head_sha": head, "wheels": entries}))


CLI_WHEELS = ["azure_cli-2.80.0-py3-none-any.whl",
              "azure_cli_core-2.80.0-py3-none-any.whl",
              "azure_cli_telemetry-1.1.0-py3-none-any.whl"]


def test_wheel_manifest_is_verified(tmp_path):
    spec = repro_runner.verify_from_env(_env(_dispatch()))
    _wheels(tmp_path / "w", CLI_WHEELS)
    wheels = repro_runner.load_wheel_manifest(spec, HEAD, tmp_path / "w")
    assert {w["distribution"] for w in wheels} == set(repro_runner.CLI_DISTRIBUTIONS)
    with pytest.raises(ValueError):
        repro_runner.load_wheel_manifest(spec, "d" * 40, tmp_path / "w")
    (tmp_path / "w" / CLI_WHEELS[0]).write_bytes(b"tampered")
    with pytest.raises(ValueError):
        repro_runner.load_wheel_manifest(spec, HEAD, tmp_path / "w")
    _wheels(tmp_path / "x", CLI_WHEELS[:2])
    with pytest.raises(ValueError):
        repro_runner.load_wheel_manifest(spec, HEAD, tmp_path / "x")


def test_pr_install_uses_only_prebuilt_wheels():
    spec = {"tool": "az"}
    wheels = [{"file": name} for name in CLI_WHEELS]
    commands = dict(repro_runner._install_commands(spec, "pr", wheels))
    argv = commands["azure-cli"]
    assert all(arg.endswith(".whl") for arg in argv[argv.index("--no-input") + 1:])
    assert "extension" not in commands
    ext = dict(repro_runner._install_commands(
        {"tool": "az-extension:containerapp"}, "pr",
        [{"file": "containerapp-1.2.0-py2.py3-none-any.whl"}]))
    assert ext["azure-cli"][-1] == "azure-cli"
    assert ext["extension"][-1].endswith("containerapp-1.2.0-py2.py3-none-any.whl")
    assert "--target" in ext["extension"]
    for argv in (*commands.values(), *ext.values()):
        assert not any("repro/src" in str(arg) for arg in argv)


def test_pr_install_never_runs_pr_code(tmp_path, monkeypatch):
    inputs = _dispatch()
    for key, value in _env(inputs, REPRO_PR_NUMBER="42", REPRO_PR_HEAD_SHA=HEAD,
                           REPRO_VERSION="pr").items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(tmp_path)
    _wheels(tmp_path / "repro" / "wheels", CLI_WHEELS)
    calls = []

    def fake_run(argv, log_stem, **kwargs):
        calls.append([str(a) for a in argv])
        Path(log_stem).parent.mkdir(parents=True, exist_ok=True)
        return {"exit_code": 0, "duration_seconds": 0.1, "timed_out": False,
                "stdout": str(tmp_path / "none"), "stderr": str(tmp_path / "none")}

    monkeypatch.setattr(repro_runner, "run_quiet", fake_run)
    assert repro_runner.main(["install"]) == 0
    assert [c[1:3] for c in calls if "pip" not in c] == [["-m", "venv"]]
    assert not any(c[0].endswith("/az") or "version" in c for c in calls)
    info = json.loads((tmp_path / "repro" / "raw" / "install.json").read_text())
    assert info["cli_version"] == "2.80.0" and info["source_sha"] == HEAD

    (tmp_path / "repro" / "wheels" / "manifest.json").unlink()
    assert repro_runner.main(["install"]) == 1


def test_build_requires_the_verified_head(tmp_path, monkeypatch, capsys):
    inputs = _dispatch()
    for key, value in _env(inputs, REPRO_PR_NUMBER="42",
                           REPRO_PR_HEAD_SHA=HEAD).items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(tmp_path)
    for name in ("azure-cli-telemetry", "azure-cli-core", "azure-cli"):
        (tmp_path / "repro" / "src" / "src" / name).mkdir(parents=True)
    calls = []

    def fake_run(argv, log_stem, **kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        out = Path(str(log_stem) + ".out")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(sha + "\n")
        if "wheel" in argv:
            for name in CLI_WHEELS:
                (tmp_path / "repro" / "wheels" / name).write_bytes(name.encode())
        return {"exit_code": 0, "duration_seconds": 0.1, "timed_out": False,
                "stdout": str(out), "stderr": str(out)}

    monkeypatch.setattr(repro_runner, "run_quiet", fake_run)
    sha = "d" * 40
    assert repro_runner.main(["build"]) == 1
    assert "not the requested PR head" in capsys.readouterr().out
    assert not any("wheel" in c for c in calls)

    sha = HEAD
    assert repro_runner.main(["build"]) == 0
    wheel = next(c for c in calls if "wheel" in c)
    assert "--no-deps" in wheel
    spec = repro_runner.verify_from_env(_env(inputs))
    assert len(repro_runner.load_wheel_manifest(
        spec, HEAD, tmp_path / "repro" / "wheels")) == 3


def test_sanitized_pr_document_records_the_head(tmp_path, monkeypatch):
    inputs = _dispatch()
    scrubber = repro_sanitize._Scrubber()
    spec = repro_runner.verify_from_env(_env(inputs))
    env = _env(inputs, REPRO_PR_NUMBER="42", REPRO_PR_HEAD_SHA=HEAD)
    document = repro_sanitize.build_document(
        spec, inputs["spec_hash"], "42", [], scrubber, env)
    assert document["pr_number"] == 42 and document["pr_head_sha"] == HEAD
    text = repro_sanitize.finalize(document, {})
    assert json.loads(text)["pr_head_sha"] == HEAD
    plain = repro_sanitize.build_document(
        spec, inputs["spec_hash"], "", [], scrubber,
        _env(inputs, REPRO_PR_HEAD_SHA=HEAD))
    assert plain["pr_head_sha"] is None


def test_matrix_versions_and_source_repository():
    spec = repro_runner.verify_from_env(_env(_dispatch()))
    assert repro_runner.matrix_versions(spec) == ["reported", "latest", "dev"]
    latest = repro_runner.verify_from_env(_env(_dispatch(_spec(versions=["latest"]))))
    assert repro_runner.matrix_versions(latest) == ["latest"]
    assert repro_runner.source_repository(spec) == "Azure/azure-cli"
    ext = {"tool": "az-extension:containerapp"}
    assert repro_runner.source_repository(ext) == "Azure/azure-cli-extensions"
    assert repro_runner.extension_name(ext) == "containerapp"


def test_verify_command_writes_outputs_and_rejects_quietly(tmp_path, monkeypatch, capsys):
    inputs = _dispatch()
    output = tmp_path / "out.txt"
    for key, value in _env(inputs, GITHUB_OUTPUT=str(output)).items():
        monkeypatch.setenv(key, value)

    assert repro_runner.main(["verify"]) == 0
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(values["versions"]) == ["reported", "latest", "dev"]
    assert values["step_timeout_minutes"] == "15"
    assert values["source_repo"] == "Azure/azure-cli"
    assert values["dev_ref"] == "dev" and values["pr_ref"] == ""

    monkeypatch.setenv("REPRO_SPEC_HASH", "f" * 64)
    assert repro_runner.main(["verify"]) == 1
    assert inputs["spec"] not in capsys.readouterr().out


def test_resource_group_and_expiry():
    spec = repro_runner.verify_from_env(_env(_dispatch()))
    group = repro_runner.resource_group_for(
        spec, {"GITHUB_RUN_ID": "1234567890", "REPRO_VERSION": "reported"},
    )
    assert group.startswith(repro_janitor.PREFIX)
    assert group == repro_spec.reproduction_resource_group(ISSUE, "1234567890-reported")
    now = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    assert repro_runner.expires_at(now, 6) == "2025-01-01T06:00:00Z"


def test_rg_delete_skips_when_rg_create_never_ran(tmp_path, monkeypatch, capsys):
    """A job that failed at Azure login has no group and no az session."""
    monkeypatch.chdir(tmp_path)
    for key, value in _env(_dispatch(), GITHUB_RUN_ID="9", REPRO_VERSION="latest").items():
        monkeypatch.setenv(key, value)
    calls = []

    def fake_run_quiet(argv, stem, **kwargs):
        calls.append(argv[1:3])
        stdout = tmp_path / "stdout"
        stdout.write_text("false" if argv[2] == "exists" else "")
        return {"exit_code": 0, "stdout": str(stdout)}

    monkeypatch.setattr(repro_runner, "run_quiet", fake_run_quiet)
    monkeypatch.setattr(repro_runner, "system_az", lambda: "az")
    assert repro_runner.main(["rg-delete"]) == 0
    assert calls == []
    assert "No resource group was created" in capsys.readouterr().out

    assert repro_runner.main(["rg-create"]) == 0
    assert repro_runner.main(["rg-delete"]) == 0
    assert calls == [["group", "create"], ["group", "exists"]]


FAKE_AZ = r'''
import json, os, sys, time
args = sys.argv[1:]
mode = {mode!r}
if mode == "sleep":
    time.sleep(30)
leak = " ".join([{sub!r}, {sas!r}, {email!r}, {ip!r}, {token!r}, {oid!r}])
print("stdout:", " ".join(args), leak)
print("env:", json.dumps(sorted(os.environ)))
print("cwd:", os.listdir("."))
if "sql" in args:
    code = 1 if mode == "setup_fail" else 0
    if code:
        print("ERROR: (AuthorizationFailed) denied", file=sys.stderr)
    sys.exit(code)
if mode == "not_reproduced":
    sys.exit(0)
print("ERROR: (ResourceNotFound) The Resource '" + " ".join(args) + "' "
      "under subscription " + {sub!r} + " was not found. " + leak,
      file=sys.stderr)
print("Code: ResourceNotFound", file=sys.stderr)
sys.exit(3)
'''


def _fake_az(tmp_path, mode="reproduced"):
    path = tmp_path / f"az-{mode}"
    path.write_text(f"#!{sys.executable}\n" + FAKE_AZ.format(
        mode=mode, sub=SUB, sas=SECRETS["sas"], email=SECRETS["email"],
        ip=SECRETS["ip"], token=SECRETS["token"], oid=SECRETS["objectid"],
    ))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def _execute(tmp_path, mode="reproduced", deadline=None, monkeypatch=None):
    spec = repro_runner.verify_from_env(_env(_dispatch()))
    group = repro_runner.resource_group_for(spec, {"GITHUB_RUN_ID": "99", "REPRO_VERSION": "latest"})
    raw = repro_runner.execute(
        spec, az_path=_fake_az(tmp_path, mode), resource_group=group,
        run_id="99-latest", subscription_id=SUB, deadline_seconds=deadline,
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work",
    )
    return spec, group, raw


def test_execute_reproduces_without_printing_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-request-token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example/oidc")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    monkeypatch.chdir(tmp_path)
    _spec_, group, raw = _execute(tmp_path)

    printed = capsys.readouterr().out
    assert "setup[0]: exit 0" in printed and "repro[0]: exit 3" in printed
    for value in (SUB, group, *SECRETS.values(), raw["redact_values"]["password"]):
        assert value not in printed
    assert raw["status"] == "completed" and raw["reproduced"] is True
    setup, repro = raw["steps"]
    assert setup["expect_met"] is True and repro["observed_matched"] is True
    assert repro["command"].startswith("az monitor metrics list --resource /subscriptions/<sub>")
    stdout = Path(repro["stdout"]).read_text()
    env_keys = json.loads(stdout.split("env: ", 1)[1].splitlines()[0])
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in env_keys
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" not in env_keys
    assert "GITHUB_TOKEN" not in env_keys
    assert "repro-input.txt" in stdout  # runs inside the empty work dir
    assert f"/subscriptions/{SUB}/resourceGroups/{group}/" in stdout


def test_prepare_run_creates_requested_empty_workdir_dirs(tmp_path):
    spec = repro_spec.validate_spec(_spec(workdir_dirs=["redis"]))["spec"]
    repro_runner.prepare_run(
        spec, resource_group="rg", run_id="1-latest", subscription_id=SUB,
        work_dir=tmp_path / "work",
    )
    assert (tmp_path / "work" / "redis").is_dir()
    assert not any((tmp_path / "work" / "redis").iterdir())
    assert not repro_spec.validate_spec(_spec(workdir_dirs=["../x"]))["valid"]


@pytest.mark.parametrize("mode, status, reproduced", [
    ("not_reproduced", "completed", False),
    ("setup_fail", "setup_failed", None),
])
def test_execute_outcomes(tmp_path, monkeypatch, mode, status, reproduced):
    monkeypatch.chdir(tmp_path)
    _s, _g, raw = _execute(tmp_path, mode)
    assert (raw["status"], raw["reproduced"]) == (status, reproduced)
    if mode == "setup_fail":
        assert raw["steps"][1]["skipped"] is True


def test_execute_timeout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _s, _g, raw = _execute(tmp_path, "sleep", deadline=1.5)
    assert raw["status"] == "timeout"
    assert raw["reproduced"] is None
    assert raw["steps"][0]["timed_out"] is True
    assert raw["steps"][1]["skipped"] is True


def test_run_quiet_never_uses_a_shell(tmp_path):
    marker = tmp_path / "pwned"
    result = repro_runner.run_quiet(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", f"x; touch {marker}"],
        tmp_path / "log", timeout=30,
    )
    assert result["exit_code"] == 0
    assert not marker.exists()
    assert Path(result["stdout"]).read_text().strip() == f"x; touch {marker}"


KNOWN_ENV = {"REPRO_SUBSCRIPTION_ID": SUB, "REPRO_TENANT_ID": TENANT,
             "REPRO_CLIENT_ID": CLIENT, "GITHUB_RUN_ID": "99",
             "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "c" * 40}


def _sanitized(tmp_path, monkeypatch, mode="reproduced"):
    monkeypatch.chdir(tmp_path)
    inputs = _dispatch()
    spec, group, raw = _execute(tmp_path, mode)
    (tmp_path / "raw" / "repro.raw.json").write_text(json.dumps(raw))
    (tmp_path / "raw" / "install.json").write_text(json.dumps({
        "version": "latest", "error": None, "cli_version": "2.79.0",
        "extension_version": None, "source_sha": None,
    }))
    env = _env(inputs, REPRO_VERSION="latest", **KNOWN_ENV)
    path, _ = repro_sanitize.sanitize_version(
        spec, env, raw_dir=tmp_path / "raw", out_dir=tmp_path / "out",
    )
    return path, raw, group


def test_sanitized_document_contains_no_sensitive_values(tmp_path, monkeypatch):
    path, raw, group = _sanitized(tmp_path, monkeypatch)
    assert path.name == "repro.redacted.json"
    text = path.read_text()
    values = raw["redact_values"]
    for value in (SUB, TENANT, CLIENT, group, values["password"], values["name1"],
                  *SECRETS.values(), "sig=abcd"):
        assert value.lower() not in text.lower(), value
    assert not repro_sensitive_data.scan_sensitive_content(
        [{"location": "doc", "text": text}])["blocked"]

    document = json.loads(text)
    assert document["schema"] == repro_runner.RESULT_SCHEMA
    assert document["schema_version"] == 1
    assert document["issue"] == ISSUE and document["pr_number"] is None
    [result] = document["results"]
    assert result["version"] == "latest" and result["cli_version"] == "2.79.0"
    assert (result["status"], result["reproduced"]) == ("completed", True)
    setup, repro = result["steps"]
    assert setup["command"].endswith("--admin-password <password>")
    assert repro["error_code"] == "ResourceNotFound"
    assert "<rg>" in repro["error_excerpt"] and "<sub>" in repro["error_excerpt"]
    assert "stdout" not in repro and "stdout:" not in text
    assert set(repro) == {
        "phase", "index", "command", "exit_code", "timed_out", "skipped",
        "duration_seconds", "expect_met", "observed_matched", "error_code",
        "error_excerpt",
    }


def test_redact_text_rules():
    known = {"rg": "xea-repro-azure-cli-1-abc", "name1": "xeaabc123",
             "sub": SUB, "password": "Xr1234567890abcdefghij9!a",
             "tenant_id": TENANT}
    text = (f"rg xea-repro-azure-cli-1-ABC name xeaabc123 sub {SUB} "
            f"tenant {TENANT} pw Xr1234567890abcdefghij9!a "
            f"url https://x.blob.core.windows.net/c?sv=1&se=2 guid {SECRETS['objectid']} "
            f"ip {SECRETS['ip']} ip6 2001:db8:85a3:0:0:8a2e:370:7334 "
            f"mail {SECRETS['email']} tok {SECRETS['token']} "
            "key Ab3dEf6hIj9lMn2pQr5tUv8xYz1bCd4fGh7j")
    redacted = repro_sanitize.redact_text(text, known)
    for token in ("<rg>", "<name1>", "<sub>", "[REDACTED:password]",
                  "[REDACTED:tenant]", "?[REDACTED:query]"):
        assert token in redacted
    for value in (SUB, TENANT, SECRETS["objectid"], SECRETS["ip"],
                  "2001:db8", SECRETS["email"], SECRETS["token"], "sv=1",
                  "Ab3dEf6hIj9lMn2pQr5tUv8xYz1bCd4fGh7j"):
        assert value not in redacted
    assert repro_sanitize.is_clean(redacted, known)
    assert repro_sanitize.redact_text("version 2.79.0 took 3.5s") == "version 2.79.0 took 3.5s"


def test_redaction_reuses_sensitive_data_rules():
    for text in (f"token {SECRETS['token']}", "AccountKey=" + "b" * 86 + "==",
                 "Authorization: Bearer abc.def.ghi"):
        expected = repro_sensitive_data.redact_sensitive_text(text)
        assert repro_sanitize.redact_text(text) == expected or (
            repro_sanitize.is_clean(repro_sanitize.redact_text(text))
        )
        assert repro_sensitive_data.scan_sensitive_content(
            [{"location": "x", "text": repro_sanitize.redact_text(text)}],
        )["blocked"] is False


def test_finalize_fails_closed():
    document = {
        "observed_in_issue": {"error_substring": "x"},
        "results": [{"error": "boom", "steps": [{
            "command": "az x", "error_code": "Bad",
            "error_excerpt": f"leaked {SUB}",
        }]}],
        "redaction": {"withheld_fields": 0},
    }
    text = repro_sanitize.finalize(document, {"sub": SUB})
    assert SUB not in text
    data = json.loads(text)
    step = data["results"][0]["steps"][0]
    assert step["error_excerpt"] == repro_sanitize.WITHHELD
    assert data["redaction"]["withheld_fields"] == 1


def test_scrubber_withholds_what_redaction_cannot_fix():
    scrubber = repro_sanitize._Scrubber({"sub": SUB})
    assert scrubber.text("plain text") == "plain text"
    assert scrubber.text(f"x {SUB} y") == "x <sub> y"
    assert scrubber.withheld == 0


def test_install_failure_yields_error_result():
    scrubber = repro_sanitize._Scrubber()
    result = repro_sanitize.build_version_result(
        "reported", {"version": "reported", "error": "install step `azure-cli` failed"},
        None, scrubber,
    )
    assert result["status"] == "error" and result["reproduced"] is None
    assert result["error"] == "install step `azure-cli` failed"


def test_merge_combines_versions_and_fills_missing(tmp_path, monkeypatch):
    path, _raw, _group = _sanitized(tmp_path, monkeypatch)
    parts = tmp_path / "parts"
    (parts / "repro-redacted-latest").mkdir(parents=True)
    (parts / "repro-redacted-latest" / "repro.redacted.json").write_text(path.read_text())
    (parts / "repro-redacted-dev").mkdir()
    (parts / "repro-redacted-dev" / "repro.redacted.json").write_text(json.dumps({
        "schema": repro_runner.RESULT_SCHEMA, "spec_hash": "0" * 64,
        "issue": ISSUE, "results": [{"version": "dev", "status": "completed"}],
    }))
    inputs = _dispatch()
    spec = repro_runner.verify_from_env(_env(inputs))
    out = tmp_path / "result" / "repro.redacted.json"
    document = repro_sanitize.merge(spec, parts, out, _env(inputs, **KNOWN_ENV))

    assert [r["version"] for r in document["results"]] == ["reported", "latest", "dev"]
    by_version = {r["version"]: r for r in document["results"]}
    assert by_version["latest"]["reproduced"] is True
    assert by_version["reported"]["status"] == "error"
    assert by_version["dev"]["status"] == "error"  # foreign spec hash ignored
    assert json.loads(out.read_text()) == document
    summary = repro_sanitize.summary_markdown(document)
    assert "| latest | 2.79.0 | completed | Reproduced |" in summary


def test_sanitize_cli_writes_only_redacted_file(tmp_path, monkeypatch, capsys):
    path, _raw, _group = _sanitized(tmp_path, monkeypatch)
    for key, value in _env(_dispatch(), REPRO_VERSION="latest", **KNOWN_ENV).items():
        monkeypatch.setenv(key, value)
    path.unlink()
    assert repro_sanitize.main(["version"]) == 0
    assert sorted(p.name for p in (tmp_path / "repro" / "out").iterdir()) == [
        "repro.redacted.json",
    ]
    assert SUB not in capsys.readouterr().out


def test_raw_result_file_is_private(tmp_path):
    repro_runner._write_json(tmp_path / "raw.json", {"a": 1}, private=True)
    assert stat.S_IMODE(os.stat(tmp_path / "raw.json").st_mode) == 0o600


def test_janitor_selects_only_expired_reproduction_groups():
    now = dt.datetime(2025, 1, 1, 12, tzinfo=dt.timezone.utc)
    tag = repro_spec.settings.REPRO_EXPIRES_TAG
    groups = [
        {"name": repro_janitor.PREFIX + "old", "tags": {tag: "2025-01-01T11:00:00Z"}},
        {"name": repro_janitor.PREFIX + "new", "tags": {tag: "2025-01-01T13:00:00Z"}},
        {"name": repro_janitor.PREFIX + "untagged", "tags": None},
        {"name": repro_janitor.PREFIX + "garbage", "tags": {tag: "soon"}},
        {"name": "production-rg", "tags": {tag: "2000-01-01T00:00:00Z"}},
        "not-a-dict",
    ]
    assert repro_janitor.select_expired(groups, now) == [
        repro_janitor.PREFIX + "garbage", repro_janitor.PREFIX + "old",
        repro_janitor.PREFIX + "untagged",
    ]


def test_prepare_run_writes_input_file(tmp_path):
    spec = repro_spec.validate_spec({
        "issue": ISSUE, "tool": "az",
        "repro": [{"argv": ["az", "bicep", "build", "--file", "{file}"]}],
        "observed_in_issue": {"exit_code": 1},
        "input_file": {"extension": "bicep",
                       "content": "param l string = '{location}'\n"},
    })["spec"]
    values, resolved = repro_runner.prepare_run(
        spec, resource_group="rg", run_id="1", work_dir=tmp_path / "w",
    )
    assert values["file"] == "repro-input.bicep"
    assert resolved["repro"][0]["argv"][-1] == "repro-input.bicep"
    text = (tmp_path / "w" / "repro-input.bicep").read_text()
    assert text == f"param l string = '{spec['location']}'\n"


# Operating systems and shell steps (azure: false) ---------------------------

def _local_spec(**overrides):
    spec = {
        "issue": ISSUE, "tool": "az", "os": "windows", "azure": False,
        "versions": ["latest", "dev"],
        "repro": [{"shell": "bash", "script": 'source "$REPRO_SOURCE_DIR/az.completion"\necho done\n'}],
        "observed_in_issue": {"output_substring": "done"},
    }
    spec.update(overrides)
    return spec


def test_verify_publishes_runner_os_and_azure_mode(tmp_path, monkeypatch):
    for spec, runs_on, azure in ((_spec(), "ubuntu-latest", "true"),
                                 (_local_spec(), "windows-latest", "false"),
                                 (_local_spec(os="macos", repro=[{"shell": "sh", "script": "echo done"}]),
                                  "macos-latest", "false")):
        output = tmp_path / f"{runs_on}.txt"
        for key, value in _env(_dispatch(spec), GITHUB_OUTPUT=str(output)).items():
            monkeypatch.setenv(key, value)
        assert repro_runner.main(["verify"]) == 0
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert values["runs_on"] == runs_on and values["azure"] == azure


def test_shell_steps_only_verify_without_azure():
    assert repro_runner.verify_from_env(_env(_dispatch(_local_spec())))["azure"] is False
    assert not repro_spec.validate_spec(_local_spec(azure=True))["valid"]


def test_shell_argv_and_script_files(tmp_path):
    path = tmp_path / "s"
    assert repro_runner.shell_argv("pwsh", path, windows=True)[-2:] == ["-File", str(path)]
    assert repro_runner.shell_argv("bash", path, windows=False)[1:] == ["--noprofile", "--norc", str(path)]
    cmd = repro_runner.write_script("cmd", "echo a\necho b", tmp_path / "c")
    assert cmd.suffix == ".cmd" and cmd.read_bytes() == b"@echo off\r\necho a\r\necho b\r\n"
    bash = repro_runner.write_script("bash", "echo a", tmp_path / "b")
    assert bash.suffix == ".sh" and bash.read_bytes() == b"echo a\n"
    assert repro_runner.display_step({"shell": "bash", "script": "a\n  b"}) == "bash: a b"


def test_find_msi_cli_locates_python_and_wbin(tmp_path):
    cli = tmp_path / "Microsoft SDKs" / "Azure" / "CLI2"
    (cli / "wbin").mkdir(parents=True)
    (cli / "wbin" / "az.cmd").write_text("")
    (cli / "python.exe").write_text("")
    python, wbin = repro_runner.find_msi_cli(tmp_path)
    assert python == (cli / "python.exe").resolve() and wbin == (cli / "wbin").resolve()
    assert repro_runner.find_msi_cli(tmp_path / "Microsoft SDKs" / "missing") == (None, None)
    assert repro_runner.msi_url({"reported_version": "2.77.0"}, "reported").endswith("azure-cli-2.77.0-x64.msi")
    assert repro_runner.source_ref({"tool": "az"}, {"cli_version": "2.86.0"}) == "azure-cli-2.86.0"
    assert repro_runner.source_ref({"tool": "az"}, {"source_sha": "a" * 40}) == "a" * 40


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_shell_steps_run_with_the_cli_on_path_and_source_dir(tmp_path):
    spec = repro_runner.verify_from_env(_env(_dispatch(_local_spec(
        os="linux",
        repro=[{"shell": "bash", "script": 'az\necho "src=$REPRO_SOURCE_DIR"\ntest -z "$REPRO_SECRET"\n'}],
        observed_in_issue={"output_substring": "fake az"},
    ))))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "az"
    fake.write_text("#!/bin/sh\necho fake az\n")
    fake.chmod(0o755)
    os.environ["REPRO_SECRET"] = "x"
    try:
        raw = repro_runner.execute(
            spec, az_path=[str(fake)], resource_group="rg", run_id="1",
            raw_dir=tmp_path / "raw", work_dir=tmp_path / "work", log=lambda _m: None,
            path_dir=bin_dir, source_dir=tmp_path / "src",
        )
    finally:
        del os.environ["REPRO_SECRET"]
    step = raw["steps"][0]
    assert step["exit_code"] == 0 and raw["reproduced"] is True
    out = Path(step["stdout"]).read_text()
    assert f"src={tmp_path / 'src'}" in out
    assert step["command"].startswith("bash: az echo")


def test_windows_venv_az_matches_the_msi_bash_wrapper(tmp_path):
    path = repro_runner.write_git_bash_az(tmp_path)
    text = path.read_bytes().decode()
    assert "\r" not in text and "execl" not in text
    assert text.startswith("#!/usr/bin/env bash\n")
    assert 'exec "$(dirname "${BASH_SOURCE[0]}")/python.exe" -m azure.cli "$@"' in text
