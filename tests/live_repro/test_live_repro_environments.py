"""Tests for named reproduction environments: distro containers and Windows VMs."""

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "live_repro"
WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "live-repro.yml"
sys.path.insert(0, str(SCRIPTS))

from test_live_repro_runner import ISSUE, _dispatch, _env, _spec  # noqa: E402

import repro_env  # noqa: E402
import repro_runner  # noqa: E402
import repro_spec  # noqa: E402

HEAD = "c" * 40


def _local_spec(**overrides):
    spec = _spec(
        azure=False, versions=["latest"], setup=[],
        repro=[{"shell": "bash", "script": "az group list --help\n"}],
        observed_in_issue={"error_substring": "boom"},
    )
    spec.pop("location", None)
    spec.update(overrides)
    return spec


def _valid(spec):
    result = repro_spec.validate_spec(spec)
    assert result["valid"], result["errors"]
    return result["spec"]


class FakeRun:
    """Stands in for run_quiet: records argv and writes canned stdout."""

    def __init__(self, tmp_path, outputs=None, codes=None):
        self.calls = []
        self.tmp_path = tmp_path
        self.outputs = list(outputs or [])
        self.codes = list(codes or [])

    def __call__(self, argv, log_stem, *, timeout, cwd=None, extra_env=None):
        self.calls.append([str(a) for a in argv])
        stem = Path(log_stem)
        stem.parent.mkdir(parents=True, exist_ok=True)
        out, err = stem.with_suffix(".out"), stem.with_suffix(".err")
        out.write_text(self.outputs.pop(0) if self.outputs else "")
        err.write_text("")
        code = self.codes.pop(0) if self.codes else 0
        return {"exit_code": code, "timed_out": False, "duration_seconds": 0.1,
                "stdout": str(out), "stderr": str(err)}


@pytest.mark.parametrize("environment, label, isolation", [
    (None, "ubuntu-latest", "host"),
    ("windows-server-2025", "windows-2025", "host"),
    ("macos-14", "macos-14", "host"),
    ("rhel-9", "ubuntu-latest", "host"),
    ("windows-11", "ubuntu-latest", "vm"),
])
def test_verify_routes_each_environment(tmp_path, monkeypatch, environment, label,
                                        isolation):
    spec = _spec() if environment is None else (
        _local_spec(environment=environment) if isolation == "vm"
        else _spec(environment=environment))
    output = tmp_path / "out.txt"
    for key, value in _env(_dispatch(spec), GITHUB_OUTPUT=str(output)).items():
        monkeypatch.setenv(key, value)
    assert repro_runner.main(["verify"]) == 0
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["runs_on"] == label
    assert values["isolation"] == isolation


def test_container_up_mounts_the_workspace_and_azure_dir_only(tmp_path, monkeypatch):
    run = FakeRun(tmp_path, codes=[1, 0, 0])
    spec = _valid(_spec(environment="debian-12"))
    monkeypatch.setattr(repro_env.time, "sleep", lambda _s: None)
    state = repro_env.container_up(spec, run=run, key="7-latest", workspace=tmp_path / "ws",
                                   log_dir=tmp_path / "log", azure=True, home=tmp_path)
    workspace = str((tmp_path / "ws").resolve())
    assert [c[:2] for c in run.calls] == [["docker", "pull"]] * 2 + [["docker", "run"]]
    started = run.calls[-1]
    assert started[started.index("--security-opt") + 1] == "no-new-privileges"
    mounts = [started[i + 1] for i, a in enumerate(started) if a == "-v"]
    assert mounts == [f"{workspace}:{workspace}", f"{tmp_path / '.azure'}:/xea-azure"]
    assert "docker.io/library/debian:12" in started
    assert "--privileged" not in started
    assert state["azure_dir"] == "/xea-azure"
    assert state["name"] == "xea-repro-7-latest"


def test_container_up_without_azure_mounts_no_credentials(tmp_path):
    run = FakeRun(tmp_path)
    spec = _valid(_local_spec(environment="alpine-3"))
    state = repro_env.container_up(spec, run=run, key="k", workspace=tmp_path / "ws",
                                   log_dir=tmp_path / "log", azure=False, home=tmp_path)
    assert ".azure" not in " ".join(run.calls[-1])
    assert repro_env.container_env(state, {})["AZURE_CONFIG_DIR"] == "/tmp/xea-home/.azure"


def test_container_up_reports_pull_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(repro_env.time, "sleep", lambda _s: None)
    run = FakeRun(tmp_path, codes=[1, 1, 1])
    spec = _valid(_spec(environment="rhel-8"))
    assert repro_env.container_up(spec, run=run, key="k", workspace=tmp_path,
                                  log_dir=tmp_path, azure=True, home=tmp_path) == (
        "pulling the environment image failed")


@pytest.mark.parametrize("version, extension, expected", [
    ("reported", None, {"REPRO_CLI": "reported", "REPRO_CLI_VERSION": "2.77.0"}),
    ("latest", None, {"REPRO_CLI": "latest"}),
    ("dev", None, {"REPRO_CLI": "source", "REPRO_CLI_PATHS": "/s/a /s/b"}),
    ("pr", None, {"REPRO_CLI": "wheels", "REPRO_CLI_PATHS": "/s/a /s/b"}),
    ("reported", "ssh", {"REPRO_CLI": "latest", "REPRO_EXT_MODE": "add",
                         "REPRO_EXT_VERSION": "2.77.0"}),
    ("pr", "ssh", {"REPRO_CLI": "latest", "REPRO_EXT_MODE": "target",
                   "REPRO_EXT_PATHS": "/e/x.whl"}),
])
def test_container_install_env(version, extension, expected):
    spec = _valid(_spec(environment="rhel-9"))
    state = {"owner": "1001:1001", "workspace": "/w"}
    env = repro_env.container_install_env(
        spec, version, extension=extension, cli_paths=["/s/a", "/s/b"],
        ext_paths=["/e/x.whl"], ext_dir="/w/ext", state=state)
    assert env["REPRO_FAMILY"] == "rhel"
    assert env["REPRO_INSTALL"] == "package"
    assert env["REPRO_RELEASE"] == "9"
    for key, value in expected.items():
        assert env[key] == value, key


def test_container_install_runs_the_trusted_script_as_root(tmp_path):
    spec = _valid(_spec(environment="azurelinux-3", install="pip"))
    state = {"kind": "container", "name": "c", "owner": "1001:1001",
             "workspace": str(tmp_path), "azure_dir": None}
    run = FakeRun(tmp_path, outputs=["noise\nXEA_AZ=/usr/local/bin/az\n"])
    result = repro_env.container_install(
        spec, "latest", run=run, state=state, log_dir=tmp_path / "log", workspace=tmp_path,
        timeout=60, extension=None, cli_paths=[], ext_paths=[], ext_dir=tmp_path / "ext")
    assert result == {"az": "/usr/local/bin/az"}
    argv = run.calls[0]
    assert argv[:4] == ["docker", "exec", "-u", "0"]
    assert argv[-3:] == ["c", "sh", str((tmp_path / "raw" / "env" / "install.sh").resolve())]
    assert "REPRO_INSTALL=pip" in argv
    copied = (tmp_path / "raw" / "env" / "install.sh").read_text()
    assert copied == repro_env.CONTAINER_INSTALL.read_text()


def test_container_steps_run_as_the_runner_user(tmp_path, monkeypatch):
    spec = _valid(_local_spec(environment="debian-12", repro=[
        {"shell": "bash", "script": "az group list --help\n"},
        {"argv": ["az", "version"]},
    ]))
    state = {"kind": "container", "name": "c", "owner": "1001:1001",
             "workspace": str(tmp_path), "azure_dir": None}
    run = FakeRun(tmp_path)
    monkeypatch.setattr(repro_runner, "run_quiet", run)
    raw = repro_runner.execute(
        spec, az_path=["/usr/bin/az"], resource_group="rg", run_id="r",
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work", log=lambda *_: None,
        environment=(state, {"container_az": "/usr/bin/az"}))
    assert raw["status"] == "completed"
    shell_call, argv_call = run.calls
    for call in run.calls:
        assert call[:4] == ["docker", "exec", "-u", "1001:1001"]
        assert call[call.index("-w") + 1] == str((tmp_path / "work").resolve())
        assert "HOME=/tmp/xea-home" in call
        assert not any(a.startswith("PATH=") for a in call)
    assert shell_call[-4:-1] == ["bash", "--noprofile", "--norc"]
    assert argv_call[-2:] == ["/usr/bin/az", "version"]


def test_container_install_script_is_valid_posix_sh():
    subprocess.run(["sh", "-n", str(repro_env.CONTAINER_INSTALL)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-s", "sh", "-e", "SC2086",
                        str(repro_env.CONTAINER_INSTALL)], check=True)


def test_vm_create_has_no_public_ip_nsg_or_identity(tmp_path):
    run = FakeRun(tmp_path)
    spec = _valid(_local_spec(environment="windows-11"))
    state = repro_env.vm_up(spec, run=run, az="az", group="xea-repro-x",
                            log_dir=tmp_path, password="Xrsecret9!a")
    argv = run.calls[0]
    assert argv[argv.index("--public-ip-address") + 1] == ""
    assert argv[argv.index("--nsg") + 1] == ""
    assert argv[argv.index("--image") + 1].startswith("MicrosoftWindowsDesktop:windows-11:")
    assert argv[argv.index("--size") + 1] == "Standard_D2s_v5"
    for forbidden in ("--assign-identity", "--scope", "--role", "--custom-data"):
        assert forbidden not in argv
    assert state == {"kind": "vm", "group": "xea-repro-x", "name": "xeavm"}


def test_vm_create_failure_reports_only_the_arm_code(tmp_path):
    class Failing(FakeRun):
        def __call__(self, argv, log_stem, **kwargs):
            result = super().__call__(argv, log_stem, **kwargs)
            Path(result["stderr"]).write_text(
                "ERROR: (SkuNotAvailable) The requested size for resource "
                "'/subscriptions/0000/xeavm' is currently not available\nCode: SkuNotAvailable\n")
            return result

    spec = _valid(_local_spec(environment="windows-11"))
    state = repro_env.vm_up(spec, run=Failing(tmp_path, codes=[1]), az="az",
                            group="g", log_dir=tmp_path, password="x")
    assert state == "creating the environment VM failed (SkuNotAvailable)"
    (tmp_path / "e.err").write_text("ERROR: something odd\n")
    assert repro_env.arm_error_code(tmp_path / "e.err") is None


def test_guest_script_carries_only_encoded_config():
    config = {"action": "step", "arguments": "'; Remove-Item C:\\ -Recurse #"}
    text = repro_env.guest_script(config)
    assert repro_env.VM_CONFIG_MARKER not in text
    assert "Remove-Item C:" not in text
    encoded = text.split("FromBase64String('", 1)[1].split("'", 1)[0]
    assert json.loads(base64.b64decode(encoded)) == config


def test_parse_invoke_reads_the_result_line():
    payload = base64.b64encode(json.dumps({"ok": True}).encode()).decode()
    text = json.dumps({"value": [
        {"code": "ComponentStatus/StdOut/succeeded",
         "message": f"noise\nXEA-RESULT:{payload}\n"},
        {"code": "ComponentStatus/StdErr/succeeded", "message": "XEA-RESULT:bad"},
    ]})
    assert repro_env.parse_invoke(text) == {"ok": True}
    assert repro_env.parse_invoke("not json") is None
    assert repro_env.parse_invoke(json.dumps({"value": []})) is None


def test_vm_install_config_fetches_shell_tools_and_pinned_source():
    spec = _valid(_local_spec(environment="windows-10", repro=[
        {"shell": "bash", "script": "az group list --help\n"},
        {"shell": "pwsh", "script": "az group list --help\n"},
        {"shell": "cmd", "script": "az group list --help\n"},
    ]))
    config = repro_env.vm_install_config(
        spec, "pr", msi_url="https://aka.ms/x", extension=None,
        source_repo="a0x1ab/azure-cli", source_sha=HEAD)
    assert config["tools"] == ["git", "pwsh"]
    assert config["source_url"] == f"https://codeload.github.com/a0x1ab/azure-cli/zip/{HEAD}"
    assert config["source_root"] == f"azure-cli-{HEAD}"
    assert config["source_dirs"] == list(repro_env.CLI_SOURCE_DIRS)
    assert config["git_url"].startswith(
        "https://github.com/git-for-windows/git/releases/download/v")
    latest = repro_env.vm_install_config(
        spec, "latest", msi_url="u", extension=None, source_repo="Azure/azure-cli",
        source_sha=None)
    assert latest["source_url"] is None


def test_vm_step_config_quotes_argv_for_windows():
    step = {"argv": ["az", "group", "list", "--query", "[?name=='a b']"]}
    config = repro_env.vm_step_config(step, env={}, timeout=30)
    assert config["file"] == repro_env.VM_PYTHON
    assert config["arguments"] == '-m azure.cli group list --query "[?name==\'a b\']"'
    shell = repro_env.vm_step_config({"shell": "powershell", "script": "x"}, env={},
                                     timeout=30, script_bytes=b"x", script_name="r-0.ps1")
    assert shell["file"].endswith("powershell.exe")
    assert shell["arguments"].endswith("-File C:\\xea\\scripts\\r-0.ps1")
    assert base64.b64decode(shell["script"]) == b"x"


def test_vm_steps_match_needles_found_in_the_guest(tmp_path, monkeypatch):
    spec = _valid(_local_spec(environment="windows-11", repro=[
        {"shell": "cmd", "script": "az group list --help\n"},
    ]))
    payloads = []

    def invoke(state, config, **kwargs):
        payloads.append(config)
        if config["action"] == "prepare":
            return {"ok": True}
        return {"exit_code": 1, "timed_out": False, "duration_seconds": 2,
                "stdout": "", "stderr": "tail only", "found": "observed.error_substring"}

    monkeypatch.setattr(repro_env, "vm_invoke", invoke)
    raw = repro_runner.execute(
        spec, az_path=["az"], resource_group="rg", run_id="r",
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work", log=lambda *_: None,
        environment=({"kind": "vm", "group": "rg", "name": "xeavm"},
                     {"vm_ready": True, "vm_source": None}))
    assert raw["reproduced"] is True
    assert [p["action"] for p in payloads] == ["prepare", "step"]
    assert payloads[1]["needles"] == [
        {"id": "observed.error_substring", "stream": "stderr", "text": "boom"}]
    assert payloads[1]["env"]["AZURE_CONFIG_DIR"] == "C:\\xea\\azure"
    assert "found" not in raw["steps"][0]


def test_vm_run_command_failure_is_inconclusive(tmp_path, monkeypatch):
    spec = _valid(_local_spec(environment="windows-11"))
    monkeypatch.setattr(repro_env, "vm_invoke",
                        lambda state, config, **_: {"ok": True}
                        if config["action"] == "prepare" else None)
    raw = repro_runner.execute(
        spec, az_path=["az"], resource_group="rg", run_id="r",
        raw_dir=tmp_path / "raw", work_dir=tmp_path / "work", log=lambda *_: None,
        environment=({"kind": "vm", "group": "rg", "name": "xeavm"}, {"vm_ready": True}))
    assert raw["status"] == "error"
    assert raw["reproduced"] is None
    assert "infra_error" not in raw["steps"][0]


@pytest.mark.skipif(not shutil.which("pwsh"), reason="pwsh not installed")
def test_vm_guest_script_parses():
    command = ("$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("
               f"'{repro_env.VM_GUEST}', [ref]$null, [ref]$e) | Out-Null; "
               "if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }")
    subprocess.run(["pwsh", "-NoProfile", "-Command", command], check=True)


def _job(name):
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return data["jobs"][name]


@pytest.mark.parametrize("job", ["reproduce", "reproduce-local"])
def test_containers_start_before_install_and_always_stop(job):
    steps = _job(job)["steps"]
    names = [s["name"] for s in steps]
    up = next(i for i, n in enumerate(names) if n.startswith("Start the repro environment"))
    down = next(i for i, n in enumerate(names) if n.startswith("Stop the repro environment"))
    run = next(i for i, n in enumerate(names) if n.startswith("Run ReproSpec"))
    install = next(i for i, n in enumerate(names) if n.startswith("Install CLI"))
    assert up < install < run < down
    assert steps[up]["run"].endswith("repro_runner.py\" env-up")
    assert steps[down]["run"].endswith("repro_runner.py\" env-down")
    assert steps[down]["if"] == "always()"


def test_vm_job_order_and_no_source_checkout():
    job = _job("reproduce-vm")
    assert job["permissions"] == {"id-token": "write", "contents": "read"}
    steps = job["steps"]
    names = [s["name"] for s in steps]
    order = ["Azure login", "Create per-run resource group", "Start the repro environment",
             "Install CLI", "Run ReproSpec", "Delete per-run resource group", "Sign out",
             "Sanitize", "Upload redacted result"]
    positions = [next(i for i, n in enumerate(names) if n.startswith(p)) for p in order]
    assert positions == sorted(positions)
    for prefix in order[5:]:
        assert next(s for s in steps if s["name"].startswith(prefix))["if"] == "always()"
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1 and checkouts[0]["with"]["path"] == "sentinel"
    run = next(s for s in steps if s["name"].startswith("Run ReproSpec"))
    assert "env" not in run
    assert "download-artifact" not in str(job)
