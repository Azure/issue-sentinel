"""Structure and security checks for the PowerShell live reproduction workflow."""

import re

import pytest

import repro_spec
from test_live_repro_workflow import (
    REPRO,
    SHA_PIN,
    WORKFLOWS,
    _load,
    _render,
    _step,
    _steps,
    reproduction_run_title,
    settings,
)

PS_REPRO = WORKFLOWS / "live-repro-powershell.yml"
BAMI = {
    "REPRO_CLIENT_ID": "${{ secrets.BAMI_CLIENT_ID }}",
    "REPRO_TENANT_ID": "${{ secrets.BAMI_TENANT_ID }}",
    "REPRO_SUBSCRIPTION_ID": "${{ secrets.BAMI_SUBSCRIPTION_ID }}",
}


@pytest.fixture(scope="module")
def ps():
    return _load(PS_REPRO)


@pytest.fixture(scope="module")
def cli():
    return _load(REPRO)


def test_workflow_file_name_matches_agent_setting():
    profile = repro_spec.REPO_PROFILES["Azure/azure-powershell"]
    assert PS_REPRO.name == settings.LIVE_REPRO_POWERSHELL_WORKFLOW
    assert profile["kind"] == "powershell"
    assert "pwsh-az" in profile["repro_tools"]


def test_permissions_are_oidc_and_read_only(ps):
    assert ps["permissions"] == {"id-token": "write", "contents": "read"}
    for name, job in ps["jobs"].items():
        permissions = job["permissions"]
        assert set(permissions) <= {"id-token", "contents"}
        assert permissions["contents"] == "read"
        assert ("id-token" in permissions) == (name == "reproduce"), name


def test_no_key_vault_pat_client_secret_or_azure_login(ps):
    text = PS_REPRO.read_text(encoding="utf-8")
    lowered = text.lower()
    for forbidden in ("keyvault", "key-vault", "github_pat", "gh_token",
                      "secrets.github_token", "pat_secret", "client_secret",
                      "client-secret", "azure/login", "azure/powershell",
                      "enable-azpssession", "creds:"):
        assert forbidden not in lowered, forbidden
    assert set(re.findall(r"secrets\.(\w+)", text)) == {
        "BAMI_CLIENT_ID", "BAMI_TENANT_ID", "BAMI_SUBSCRIPTION_ID",
    }


def test_run_steps_only_call_trusted_scripts_and_never_echo(ps):
    runs = [(job, step) for job, step in _steps(ps) if "run" in step]
    assert len(runs) == 10
    for _job, step in runs:
        script = step["run"].strip()
        assert "\n" not in script, step["name"]
        assert "${{" not in script, step["name"]
        assert re.fullmatch(
            r'python3 "\$RUNNER_SCRIPTS/'
            r'(repro_ps_runner\.py" [\w-]+'
            r'|repro_sanitize\.py" --runner powershell '
            r'(version|merge --parts parts --out result/repro\.redacted\.json))',
            script,
        ), script
        for word in ("echo", "cat ", "tee", "printf", "set -x", "az ",
                     "pwsh", "Invoke-Expression", "-Command", "iex"):
            assert word not in script


def test_secrets_reach_only_connect_delete_run_and_sanitize(ps):
    with_secrets = {
        step["name"].split(" (")[0]: step["env"]
        for _job, step in _steps(ps)
        if "secrets." in str(step.get("env", {}))
    }
    assert with_secrets == {
        "Azure login": BAMI,
        "Run ReproSpec cmdlets": {
            "REPRO_SUBSCRIPTION_ID": BAMI["REPRO_SUBSCRIPTION_ID"],
        },
        "Delete per-run resource group": BAMI,
        "Sanitize output": BAMI,
    }
    for _job, step in _steps(ps):
        assert "secrets." not in str(step.get("with", {})), step.get("name")


def test_actions_are_pinned_and_checkouts_do_not_persist_credentials(ps):
    for _job, step in _steps(ps):
        if "uses" not in step:
            continue
        assert SHA_PIN.match(step["uses"].split(" ")[0]), step["uses"]
        if step["uses"].startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_shared_actions_use_the_same_pins_as_the_cli_workflow(ps, cli):
    cli_pins = {s["uses"].split("@")[0]: s["uses"]
                for _j, s in _steps(cli) if "uses" in s}
    for _job, step in _steps(ps):
        action = step.get("uses", "").split("@")[0]
        if action in cli_pins:
            assert step["uses"] == cli_pins[action]


def test_inputs_run_name_and_env_match_the_cli_workflow(ps, cli):
    assert set(ps["on"]) == {"workflow_dispatch"}
    cli_inputs = cli["on"]["workflow_dispatch"]["inputs"]
    assert set(ps["on"]["workflow_dispatch"]["inputs"]) == set(cli_inputs)
    for name, spec in cli_inputs.items():
        ps_spec = ps["on"]["workflow_dispatch"]["inputs"][name]
        assert {k: v for k, v in ps_spec.items() if k != "description"} == {
            k: v for k, v in spec.items() if k != "description"
        }
    assert ps["on"]["workflow_dispatch"]["inputs"]["pr_head_sha"] == (
        cli_inputs["pr_head_sha"]
    )
    assert ps["env"] == cli["env"]
    assert ps["run-name"] == cli["run-name"]
    assert ps["concurrency"]["group"] == cli["concurrency"]["group"].replace(
        "live-repro-", "live-repro-ps-", 1,
    )
    assert "inputs.pr_head_sha" in ps["concurrency"]["group"]


@pytest.mark.parametrize("pr_number", [None, 4567])
def test_run_name_equals_agent_run_title(ps, pr_number):
    digest = "b" * 64
    issue = "Azure/azure-powershell#27001"
    head = None if pr_number is None else "c" * 40
    inputs = {"issue": issue, "spec": "{}", "spec_hash": digest,
              "pr_number": "" if pr_number is None else str(pr_number),
              "pr_head_sha": head or ""}
    assert _render(ps["run-name"], inputs) == reproduction_run_title(
        issue, digest, pr_number, head,
    )


def test_matrix_and_runner_checkout(ps):
    prepare = ps["jobs"]["prepare"]
    reproduce = ps["jobs"]["reproduce"]
    assert reproduce["needs"] == ["prepare", "build-pr"]
    # build-pr is skipped outside PR mode; reproduce still runs.
    assert reproduce["if"] == "always() && needs.prepare.result == 'success'"
    assert reproduce["strategy"]["fail-fast"] is False
    assert reproduce["strategy"]["matrix"] == {
        "version": "${{ fromJSON(needs.prepare.outputs.versions) }}",
    }
    assert _step(ps, "prepare", "Re-validate")["run"].endswith(
        'repro_ps_runner.py" verify'
    )
    assert reproduce["timeout-minutes"] <= 120
    for job in ps["jobs"].values():
        checkout = job["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["path"] == "sentinel"
    assert set(prepare["outputs"]) == {
        "versions", "step_timeout_minutes", "source_repo", "dev_ref",
        "pr_repo", "pr_ref",
    }


def test_source_checkout_and_dotnet_only_for_dev(ps):
    source = _step(ps, "reproduce", "Checkout Azure PowerShell source")
    dotnet = _step(ps, "reproduce", "Set up .NET")
    for step in (source, dotnet):
        assert step["if"] == "matrix.version == 'dev'"
    assert source["with"]["path"] == "repro/src"
    assert source["with"]["repository"] == "${{ needs.prepare.outputs.source_repo }}"
    assert source["with"]["ref"] == "${{ needs.prepare.outputs.dev_ref }}"
    assert dotnet["uses"].startswith("actions/setup-dotnet@")


def test_pr_mode_validates_the_agent_fork_pr_in_prepare(ps, cli):
    prepare = ps["jobs"]["prepare"]
    verify = _step(ps, "prepare", "Re-validate")
    assert verify["env"] == {"REPRO_GITHUB_TOKEN": "${{ github.token }}"}
    assert verify["env"] == _step(cli, "prepare", "Re-validate")["env"]
    assert prepare["permissions"] == {"contents": "read"}
    assert prepare["outputs"]["pr_repo"] == "${{ steps.verify.outputs.pr_repo }}"
    assert prepare["outputs"]["pr_ref"] == "${{ steps.verify.outputs.pr_ref }}"


def test_build_pr_job_has_no_azure_credentials(ps, cli):
    build = ps["jobs"]["build-pr"]
    assert build["needs"] == "prepare"
    assert build["if"] == cli["jobs"]["build-pr"]["if"] == "inputs.pr_number != ''"
    assert build["permissions"] == {"contents": "read"}
    text = str(build)
    for forbidden in ("secrets.", "azure/login", "id-token", "connect",
                      "github.token", "REPRO_GITHUB_TOKEN", "rg-create"):
        assert forbidden not in text, forbidden
    runs = [s["run"] for s in build["steps"] if "run" in s]
    assert runs == ['python3 "$RUNNER_SCRIPTS/repro_ps_runner.py" build']
    checkout = _step(ps, "build-pr", "Checkout the verified PR head")
    assert checkout["with"] == _step(cli, "build-pr", "Checkout the verified PR head")["with"]
    assert checkout["with"] == {
        "repository": "${{ needs.prepare.outputs.pr_repo }}",
        "ref": "${{ needs.prepare.outputs.pr_ref }}",
        "path": "repro/src",
        "fetch-depth": 1,
        "persist-credentials": False,
    }
    assert _step(ps, "build-pr", "Set up .NET")["uses"].startswith(
        "actions/setup-dotnet@")
    upload = _step(ps, "build-pr", "Upload")
    assert upload["with"]["name"] == "repro-pr-module"
    assert upload["with"]["path"] == "repro/pr-module/"
    assert upload["with"]["retention-days"] == 1


def test_reproduce_job_never_checks_out_pr_code(ps):
    reproduce = ps["jobs"]["reproduce"]
    steps = reproduce["steps"]
    checkouts = [s for s in steps[1:] if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["if"] == "matrix.version == 'dev'"
    assert "pr_ref" not in str(reproduce) and "pr_repo" not in str(reproduce)
    download = _step(ps, "reproduce", "Download PR head module")
    assert download["if"] == "matrix.version == 'pr'"
    assert download["with"] == {"name": "repro-pr-module", "path": "repro/pr-module"}
    names = [s["name"] for s in steps]
    assert names.index(download["name"]) < names.index(
        next(n for n in names if n.startswith("Install"))
    ) < names.index(next(n for n in names if n.startswith("Azure login")))


def test_workflow_documents_the_pr_trust_model():
    text = PS_REPRO.read_text(encoding="utf-8")
    for phrase in ("Agent's own fork", "pr_head_sha", "persist-credentials: false",
                   "no secrets, no id-token", "never checks out"):
        assert phrase in text, phrase


def test_reproduce_step_order_and_cleanup(ps):
    steps = ps["jobs"]["reproduce"]["steps"]
    names = [s["name"] for s in steps]
    order = ["Install Az module", "Azure login", "Create per-run resource group",
             "Run ReproSpec", "Delete per-run resource group", "Sign out",
             "Sanitize", "Upload redacted result"]
    positions = [next(i for i, n in enumerate(names) if n.startswith(p))
                 for p in order]
    assert positions == sorted(positions)
    for prefix in order[4:]:
        step = next(s for s in steps if s["name"].startswith(prefix))
        assert step.get("if") == "always()", prefix
    for prefix in order[:4]:
        step = next(s for s in steps if s["name"].startswith(prefix))
        assert "if" not in step, prefix
    commands = {
        "Install Az module": "install", "Azure login": "connect",
        "Create per-run": "rg-create", "Run ReproSpec": "run",
        "Delete per-run": "rg-delete", "Sign out": "logout",
    }
    for prefix, command in commands.items():
        assert _step(ps, "reproduce", prefix)["run"].endswith(
            f'repro_ps_runner.py" {command}'
        )
    run = _step(ps, "reproduce", "Run ReproSpec")
    assert run["timeout-minutes"] == (
        "${{ fromJSON(needs.prepare.outputs.step_timeout_minutes) }}"
    )


def test_only_redacted_json_is_uploaded_under_the_shared_artifact_names(ps, cli):
    def uploads(workflow):
        return {(job, s["with"]["name"], s["with"]["path"])
                for job, s in _steps(workflow)
                if s.get("uses", "").startswith("actions/upload-artifact@")}

    shared = {
        ("reproduce", "repro-redacted-${{ matrix.version }}",
         "repro/out/repro.redacted.json"),
        ("report", "repro-redacted", "result/repro.redacted.json"),
    }
    assert uploads(ps) == shared | {("build-pr", "repro-pr-module", "repro/pr-module/")}
    assert uploads(cli) == shared | {
        ("build-pr", "repro-pr-wheels", "repro/wheels/"),
        ("reproduce-local", "repro-redacted-${{ matrix.version }}",
         "repro/out/repro.redacted.json"),
    }
    for job, step in _steps(ps):
        if step.get("uses", "").startswith("actions/upload-artifact@"):
            assert step["with"]["if-no-files-found"] == "error"
            if job != "build-pr":
                assert step["if"] == "always()"
    assert _step(ps, "report", "Download")["with"]["pattern"] == "repro-redacted-*"
    assert ps["jobs"]["report"]["if"] == cli["jobs"]["report"]["if"]


def test_raw_output_never_leaves_the_runner(ps):
    text = PS_REPRO.read_text(encoding="utf-8")
    assert "repro/raw" not in text
    assert "GITHUB_STEP_SUMMARY" not in text

