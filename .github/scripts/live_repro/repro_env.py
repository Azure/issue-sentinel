"""Named reproduction environments: distro containers and Windows VMs.

A spec's "environment" picks a GitHub runner image, a distro container on an Ubuntu runner,
or a throwaway Windows VM in the per-run BAMI resource group. Containers get the CLI from the
distro's own package (or pip) through the trusted repro_container_install.sh, with the steps
run as the runner user so the host's Azure CLI files stay usable. VMs are only for specs with
"azure": false: the VM has no identity and never signs in, the host only creates it and drives
it with Run Command through the trusted repro_vm_guest.ps1.
Standard library only.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import repro_policy as policy

HERE = Path(__file__).resolve().parent
CONTAINER_INSTALL = HERE / "repro_container_install.sh"
VM_GUEST = HERE / "repro_vm_guest.ps1"
VM_CONFIG_MARKER = "__XEA_CONFIG__"
CONTAINER_AZURE_DIR = "/xea-azure"
CONTAINER_HOME = "/tmp/xea-home"
VM_NAME = "xeavm"
VM_ADMIN = "xearepro"
VM_ROOT = "C:\\xea"
VM_WORK_DIR = VM_ROOT + "\\work"
VM_SCRIPT_DIR = VM_ROOT + "\\scripts"
VM_CONFIG_DIR = VM_ROOT + "\\azure"
VM_EXTENSION_DIR = VM_ROOT + "\\ext"
VM_PYTHON = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\python.exe"
VM_PATH_PREFIX = ";".join((
    "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin",
    "C:\\Program Files\\Git\\cmd",
    "C:\\Program Files\\PowerShell\\7",
))
VM_SHELLS = {
    "bash": ("C:\\Program Files\\Git\\bin\\bash.exe", ["--noprofile", "--norc"]),
    "pwsh": ("C:\\Program Files\\PowerShell\\7\\pwsh.exe",
             ["-NoLogo", "-NoProfile", "-NonInteractive", "-File"]),
    "powershell": ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                    "Bypass", "-File"]),
    "cmd": ("C:\\Windows\\System32\\cmd.exe", ["/d", "/c"]),
}
# Pinned installers, fetched by the guest only when a step uses the shell.
GIT_FOR_WINDOWS_URL = ("https://github.com/git-for-windows/git/releases/download/"
                       "v2.56.0.windows.3/Git-2.56.0.3-64-bit.exe")
POWERSHELL_URL = ("https://github.com/PowerShell/PowerShell/releases/download/"
                  "v7.6.8/PowerShell-7.6.8-win-x64.msi")
CLI_SOURCE_DIRS = ("src/azure-cli-telemetry", "src/azure-cli-core", "src/azure-cli")
PULL_ATTEMPTS = 3
VM_INVOKE_ATTEMPTS = 3
RESULT_PREFIX = "XEA-RESULT:"
_SHA = re.compile(r"^([0-9a-f]{40})\s")


def entry(spec):
    """Catalog entry for the spec's environment, or None."""
    return policy.REPRO_ENVIRONMENTS.get(spec.get("environment") or "")


def kind(spec):
    """runner, container or vm; None without a named environment."""
    found = entry(spec)
    return found["kind"] if found else None


def runs_on(spec, labels):
    """GitHub runner label for the job that runs spec."""
    found = entry(spec)
    if not found:
        return labels[spec.get("os", "linux")]
    if found["kind"] == "runner":
        return found["runner"]
    return labels["linux"]


def describe(spec):
    found = entry(spec)
    if not found:
        return f"os {spec.get('os', 'linux')}"
    text = f"environment {spec['environment']} ({found['kind']}"
    if spec.get("install"):
        text += f", {spec['install']} install"
    return text + ")"


def shells_used(spec):
    return {step["shell"] for phase in ("setup", "repro") for step in spec[phase]
            if "shell" in step}


def container_name(key):
    return f"xea-repro-{key}"


def container_owner():
    return f"{os.getuid()}:{os.getgid()}"


def container_up(spec, *, run, key, workspace, log_dir, azure, home=None):
    """Pull the image and start the container; returns state or an error string.

    The workspace is mounted at the same absolute path, so host paths stay valid inside.
    """
    image = entry(spec)["image"]
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, PULL_ATTEMPTS + 1):
        pulled = run(["docker", "pull", "--quiet", image], Path(log_dir) / f"pull-{attempt}",
                     timeout=900)
        if pulled["exit_code"] == 0:
            break
        if attempt == PULL_ATTEMPTS:
            return "pulling the environment image failed"
        time.sleep(15)
    name = container_name(key)
    mounts = ["-v", f"{workspace}:{workspace}"]
    state = {"kind": "container", "name": name, "owner": container_owner(),
             "workspace": str(workspace), "azure_dir": None}
    if azure:
        # Created first so docker doesn't create it as root; azure/login fills it later.
        azure_dir = Path(home or Path.home()) / ".azure"
        azure_dir.mkdir(parents=True, exist_ok=True)
        mounts += ["-v", f"{azure_dir}:{CONTAINER_AZURE_DIR}"]
        state["azure_dir"] = CONTAINER_AZURE_DIR
    started = run([
        "docker", "run", "-d", "--name", name, "--pull", "never",
        "--security-opt", "no-new-privileges", *mounts, "--entrypoint", "",
        image, "tail", "-f", "/dev/null",
    ], Path(log_dir) / "run", timeout=300)
    if started["exit_code"] != 0:
        return "starting the environment container failed"
    return state


def container_env(state, extra):
    env = dict(extra)
    env["HOME"] = CONTAINER_HOME
    env["AZURE_CONFIG_DIR"] = state["azure_dir"] or f"{CONTAINER_HOME}/.azure"
    env.pop("PATH", None)
    return env


def container_exec(state, command, *, env, cwd=None, root=False):
    argv = ["docker", "exec", "-u", "0" if root else state["owner"]]
    if cwd:
        argv += ["-w", str(Path(cwd).resolve())]
    for key in sorted(env):
        argv += ["-e", f"{key}={env[key]}"]
    return [*argv, state["name"], *[str(token) for token in command]]


def container_install_env(spec, version, *, extension, cli_paths, ext_paths, ext_dir,
                          state):
    """Env vars for repro_container_install.sh."""
    found = entry(spec)
    env = {
        "REPRO_FAMILY": found["family"],
        "REPRO_INSTALL": spec.get("install") or policy.REPRO_CONTAINER_INSTALLS[found["family"]][0],
        "REPRO_RELEASE": found.get("release", ""),
        "REPRO_OWNER": state["owner"],
        "REPRO_WORKSPACE": state["workspace"],
        "REPRO_HOME": CONTAINER_HOME,
        "REPRO_EXT_DIR": str(Path(ext_dir).resolve()),
    }
    if extension:
        env["REPRO_CLI"] = "latest"
        env["REPRO_EXT"] = extension
        if version in ("dev", "pr"):
            env["REPRO_EXT_MODE"] = "target"
            env["REPRO_EXT_PATHS"] = " ".join(str(p) for p in ext_paths)
        else:
            env["REPRO_EXT_MODE"] = "add"
            if version == "reported":
                env["REPRO_EXT_VERSION"] = spec["reported_version"]
        return env
    if version == "reported":
        env.update(REPRO_CLI="reported", REPRO_CLI_VERSION=spec["reported_version"])
    elif version == "latest":
        env["REPRO_CLI"] = "latest"
    else:
        env["REPRO_CLI"] = "source" if version == "dev" else "wheels"
        env["REPRO_CLI_PATHS"] = " ".join(str(p) for p in cli_paths)
    return env


def container_install(spec, version, *, run, state, log_dir, workspace, timeout, **paths):
    """Install the CLI in the container; returns {"az": path} or an error string."""
    script = Path(workspace) / "raw" / "env" / "install.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CONTAINER_INSTALL, script)
    env = container_install_env(spec, version, state=state, **paths)
    result = run(container_exec(state, ["sh", script.resolve()], env=env, root=True),
                 Path(log_dir) / "container", timeout=timeout)
    if result["exit_code"] != 0:
        return "installing the CLI in the environment container failed"
    text = Path(result["stdout"]).read_text(encoding="utf-8", errors="replace")
    found = re.findall(r"^XEA_AZ=(/\S+)$", text, re.MULTILINE)
    if not found:
        return "the environment container has no az after the install"
    return {"az": found[-1]}


def container_shell(shell, path):
    if shell == "bash":
        return ["bash", "--noprofile", "--norc", str(path)]
    return ["sh", str(path)]


def container_down(state, *, run, log_dir):
    if not state or state.get("kind") != "container":
        return None
    return run(["docker", "rm", "-f", state["name"]], Path(log_dir) / "rm", timeout=300)


def vm_up(spec, *, run, az, group, log_dir, password):
    """Create the VM: no public IP, no NSG, no identity. Returns state or an error string."""
    result = run([
        az, "vm", "create", "--resource-group", group, "--name", VM_NAME,
        "--computer-name", VM_NAME, "--image", entry(spec)["image"],
        "--size", policy.REPRO_VM_SIZE, "--location", spec["location"],
        "--admin-username", VM_ADMIN, "--admin-password", password,
        "--public-ip-address", "", "--nsg", "", "--only-show-errors", "-o", "none",
    ], Path(log_dir) / "vm-create", timeout=40 * 60)
    if result["exit_code"] != 0:
        code = arm_error_code(result["stderr"])
        return "creating the environment VM failed" + (f" ({code})" if code else "")
    return {"kind": "vm", "group": group, "name": VM_NAME}


_ARM_CODE = re.compile(r"\(([A-Z][A-Za-z0-9.]{2,60})\)|\b(?:Error)?Code:\s*([A-Z][A-Za-z0-9.]{2,60})\b")


def arm_error_code(stderr_path):
    """ARM error codes in az's stderr, outer first (bare identifiers, never message text)."""
    try:
        text = Path(stderr_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    codes = []
    for match in _ARM_CODE.finditer(text):
        code = match.group(1) or match.group(2)
        if code not in codes:
            codes.append(code)
    return ", ".join(codes[:4]) or None


def guest_script(config):
    encoded = base64.b64encode(json.dumps(config, sort_keys=True).encode("utf-8")).decode()
    text = VM_GUEST.read_text(encoding="utf-8")
    assert text.count(VM_CONFIG_MARKER) == 1
    return text.replace(VM_CONFIG_MARKER, encoded)


def parse_invoke(stdout_text):
    """The guest's XEA-RESULT payload from `az vm run-command invoke -o json`, or None."""
    try:
        data = json.loads(stdout_text)
    except ValueError:
        return None
    for status in data.get("value") or []:
        if "StdOut" not in str(status.get("code", "")):
            continue
        for line in str(status.get("message", "")).splitlines():
            line = line.strip()
            if line.startswith(RESULT_PREFIX):
                try:
                    return json.loads(base64.b64decode(line[len(RESULT_PREFIX):]))
                except ValueError:
                    return None
    return None


def vm_invoke(state, config, *, run, az, log_stem, timeout, attempts=1):
    """Run the guest wrapper with config; returns its result dict or None."""
    log_stem = Path(log_stem)
    script = log_stem.with_suffix(".ps1")
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(guest_script(config), encoding="utf-8")
    for attempt in range(1, attempts + 1):
        result = run([
            az, "vm", "run-command", "invoke", "--resource-group", state["group"],
            "--name", state["name"], "--command-id", "RunPowerShellScript",
            "--scripts", f"@{script.resolve()}", "--only-show-errors", "-o", "json",
        ], log_stem.with_name(f"{log_stem.name}-{attempt}"), timeout=timeout)
        if result["exit_code"] == 0:
            text = Path(result["stdout"]).read_text(encoding="utf-8", errors="replace")
            parsed = parse_invoke(text)
            if parsed is not None:
                return parsed
        if attempt < attempts:
            time.sleep(30)
    return None


def resolve_dev_sha(repository, ref, *, run, log_dir):
    result = run(["git", "ls-remote", f"https://github.com/{repository}",
                  f"refs/heads/{ref}"], Path(log_dir) / "ls-remote", timeout=120)
    text = Path(result["stdout"]).read_text(encoding="utf-8", errors="replace")
    match = _SHA.match(text)
    return match.group(1) if match else None


def vm_install_config(spec, version, *, msi_url, extension, source_repo, source_sha):
    config = {
        "action": "install", "msi_url": msi_url,
        "config_dir": VM_CONFIG_DIR, "extension_dir": VM_EXTENSION_DIR,
        "extension": extension, "extension_version": None,
        "source_url": None, "source_root": None, "source_dirs": [],
        "tools": sorted({"bash": "git", "pwsh": "pwsh"}[s]
                        for s in shells_used(spec) if s in ("bash", "pwsh")),
        "git_url": GIT_FOR_WINDOWS_URL, "pwsh_url": POWERSHELL_URL,
    }
    if extension and version == "reported":
        config["extension_version"] = spec["reported_version"]
    if version in ("dev", "pr"):
        config["source_url"] = f"https://codeload.github.com/{source_repo}/zip/{source_sha}"
        config["source_root"] = f"{source_repo.split('/')[1]}-{source_sha}"
        config["source_dirs"] = [f"src/{extension}"] if extension else list(CLI_SOURCE_DIRS)
    return config


def vm_prepare_config(work_dir, dirs):
    work_dir = Path(work_dir)
    files = {
        path.relative_to(work_dir).as_posix(): base64.b64encode(path.read_bytes()).decode()
        for path in sorted(work_dir.rglob("*")) if path.is_file()
    }
    return {"action": "prepare", "work_dir": VM_WORK_DIR, "script_dir": VM_SCRIPT_DIR,
            "dirs": list(dirs), "files": files}


def needles(spec, phase, index):
    """Substrings to look for in the guest, by id phase.key."""
    result = []
    groups = [("expect", spec[phase][index].get("expect") or {})]
    if phase == "repro":
        groups.append(("observed", spec["observed_in_issue"]))
    for group, criteria in groups:
        for key, stream in (("error_substring", "stderr"), ("output_substring", "stdout")):
            if key in criteria:
                result.append({"id": f"{group}.{key}", "stream": stream,
                               "text": criteria[key]})
    return result


def vm_step_config(step, *, env, timeout, script_bytes=None, script_name=None,
                   found_needles=()):
    if "shell" in step:
        program, args = VM_SHELLS[step["shell"]]
        command = [program, *args, f"{VM_SCRIPT_DIR}\\{script_name}"]
    else:
        command = [VM_PYTHON, "-m", "azure.cli", *step["argv"][1:]]
    return {
        "action": "step", "work_dir": VM_WORK_DIR, "script_dir": VM_SCRIPT_DIR,
        "file": command[0], "arguments": subprocess.list2cmdline(command[1:]),
        "script_name": script_name,
        "script": base64.b64encode(script_bytes).decode() if script_bytes else None,
        "env": env, "path_prefix": VM_PATH_PREFIX, "timeout": int(max(1, timeout)),
        "needles": list(found_needles),
    }


def vm_env(fixed, source_dir, shell=None):
    env = dict(fixed)
    env["AZURE_CONFIG_DIR"] = VM_CONFIG_DIR
    env["AZURE_EXTENSION_DIR"] = VM_EXTENSION_DIR
    if source_dir:
        env["REPRO_SOURCE_DIR"] = (source_dir.replace("\\", "/") if shell == "bash"
                                   else source_dir)
    return env


def write_step_logs(result, log_stem):
    """Write the guest's output tails where run_steps reads them; returns launch's dict."""
    log_stem = Path(log_stem)
    log_stem.parent.mkdir(parents=True, exist_ok=True)
    out_path, err_path = log_stem.with_suffix(".out"), log_stem.with_suffix(".err")
    if result is None or "exit_code" not in result and "timed_out" not in result:
        out_path.write_text("", encoding="utf-8")
        err_path.write_text("xea: the VM run command failed\n", encoding="utf-8")
        return {"exit_code": None, "timed_out": False, "duration_seconds": 0.0,
                "stdout": str(out_path), "stderr": str(err_path), "infra_error": True}
    found = result.get("found") or []
    found = [found] if isinstance(found, str) else list(found)
    out_path.write_text(result.get("stdout") or "", encoding="utf-8")
    err_path.write_text(result.get("stderr") or "", encoding="utf-8")
    return {"exit_code": result.get("exit_code"), "timed_out": bool(result.get("timed_out")),
            "duration_seconds": float(result.get("duration_seconds") or 0.0),
            "stdout": str(out_path), "stderr": str(err_path),
            "found": found}
