"""Security checks for the live reproduction workflows the Agent dispatches."""

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
REPRO = WORKFLOWS / "live-repro.yml"
JANITOR = WORKFLOWS / "live-repro-janitor.yml"
SCRIPTS = ROOT / ".github" / "scripts" / "live_repro"
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
sys.path.insert(0, str(SCRIPTS))

import repro_policy as settings  # noqa: E402


def reproduction_run_title(issue, digest, pr_number=None, head_sha=None):
    """Run title the Agent looks up.

    PR-head re-runs append " PR <n> head <sha>" inside the parentheses.
    """
    suffix = ""
    if pr_number is not None:
        suffix = f" PR {int(pr_number)} head {head_sha or ''}"
    return f"Live Repro ({issue} @ {digest}{suffix})"


def _load(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on` key as boolean True.
    data["on"] = data.pop(True, data.get("on"))
    return data


@pytest.fixture(scope="module")
def repro():
    return _load(REPRO)


@pytest.fixture(scope="module")
def janitor():
    return _load(JANITOR)


def _steps(workflow):
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            yield job_name, step


def _step(workflow, job, name_part):
    matches = [s for s in workflow["jobs"][job]["steps"]
               if name_part in s.get("name", "")]
    assert len(matches) == 1, name_part
    return matches[0]


def test_workflow_file_name_matches_agent_setting():
    assert REPRO.name == settings.LIVE_REPRO_WORKFLOW


@pytest.mark.parametrize("path", [REPRO, JANITOR], ids=["repro", "janitor"])
def test_permissions_are_oidc_and_read_only(path):
    workflow = _load(path)
    assert workflow["permissions"] == {"id-token": "write", "contents": "read"}
    for job in workflow["jobs"].values():
        permissions = job.get("permissions", {})
        assert set(permissions) <= {"id-token", "contents"}
        assert permissions.get("contents", "read") == "read"


@pytest.mark.parametrize("path", [REPRO, JANITOR], ids=["repro", "janitor"])
def test_no_key_vault_or_pat(path):
    text = path.read_text(encoding="utf-8").lower()
    for forbidden in ("keyvault", "key-vault", "az keyvault", "github_pat",
                      "gh_token", "secrets.github_token", "pat_secret"):
        assert forbidden not in text
    secrets = set(re.findall(r"secrets\.(\w+)", path.read_text(encoding="utf-8")))
    assert secrets == {"BAMI_CLIENT_ID", "BAMI_TENANT_ID", "BAMI_SUBSCRIPTION_ID"}


@pytest.mark.parametrize("path", [REPRO, JANITOR], ids=["repro", "janitor"])
def test_run_steps_only_call_trusted_scripts_and_never_echo(path):
    workflow = _load(path)
    runs = [(job, step) for job, step in _steps(workflow) if "run" in step]
    assert runs
    for _job, step in runs:
        script = step["run"].strip()
        assert "\n" not in script, step["name"]
        assert "${{" not in script, step["name"]
        assert re.fullmatch(
            r'python3? ("\$RUNNER_SCRIPTS|sentinel/\.github/scripts/live_repro)'
            r'/repro_(runner|sanitize|janitor)\.py"?( [\w-]+)*'
            r'( --parts parts --out result/repro\.redacted\.json)?',
            script,
        ), script
        for word in ("echo", "cat ", "tee", "printf", "set -x", "az "):
            assert word not in script


@pytest.mark.parametrize("path", [REPRO, JANITOR], ids=["repro", "janitor"])
def test_actions_are_pinned_and_checkouts_do_not_persist_credentials(path):
    for _job, step in _steps(_load(path)):
        if "uses" not in step:
            continue
        assert SHA_PIN.match(step["uses"]), step["uses"]
        if step["uses"].startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_dispatch_inputs_match_dispatch_reproduction(repro):
    inputs = repro["on"]["workflow_dispatch"]["inputs"]
    assert set(repro["on"]) == {"workflow_dispatch"}
    assert set(inputs) == {"issue", "spec", "spec_hash", "pr_number", "pr_head_sha"}
    for name in ("issue", "spec", "spec_hash"):
        assert inputs[name]["required"] is True
    for name in ("pr_number", "pr_head_sha"):
        assert inputs[name]["required"] is False
        assert inputs[name]["default"] == ""


def _render(expression_text, inputs):
    """Evaluate the small subset of expressions used by `run-name`."""
    def evaluate(match):
        expr = match.group(1).strip()
        simple = re.fullmatch(r"inputs\.(\w+)", expr)
        if simple:
            return inputs[simple.group(1)]
        conditional = re.fullmatch(
            r"inputs\.(\w+) != '' && format\('([^']*)', ((?:inputs\.\w+(?:, )?)+)\)"
            r" \|\| ''",
            expr,
        )
        assert conditional, expr
        name, template, args = conditional.groups()
        if inputs[name] == "":
            return ""
        for index, arg in enumerate(re.findall(r"inputs\.(\w+)", args)):
            template = template.replace(f"{{{index}}}", inputs[arg])
        return template
    return re.sub(r"\$\{\{(.*?)\}\}", evaluate, expression_text)


@pytest.mark.parametrize("pr_number", [None, 4567])
def test_run_name_equals_agent_run_title(repro, pr_number):
    digest = "a" * 64
    head = None if pr_number is None else "b" * 40
    inputs = {"issue": "Azure/azure-cli#34187", "spec": "{}",
              "spec_hash": digest,
              "pr_number": "" if pr_number is None else str(pr_number),
              "pr_head_sha": head or ""}
    assert _render(repro["run-name"], inputs) == reproduction_run_title(
        "Azure/azure-cli#34187", digest, pr_number, head,
    )


def test_each_pr_head_gets_its_own_run(repro):
    assert "inputs.pr_head_sha" in repro["concurrency"]["group"]
    assert repro["env"]["REPRO_PR_HEAD_SHA"] == "${{ inputs.pr_head_sha }}"


def test_matrix_comes_from_verified_spec(repro):
    prepare = repro["jobs"]["prepare"]
    reproduce = repro["jobs"]["reproduce"]
    assert "id-token" not in prepare["permissions"]
    local = repro["jobs"]["reproduce-local"]
    # build-pr is skipped outside PR mode; reproduce still runs. Exactly one
    # of the two reproduce jobs runs, chosen by the verified spec.
    vm = repro["jobs"]["reproduce-vm"]
    routes = (
        (reproduce, "needs.prepare.outputs.azure == 'true'"),
        (local, "needs.prepare.outputs.azure == 'false' && "
                "needs.prepare.outputs.isolation != 'vm'"),
        (vm, "needs.prepare.outputs.isolation == 'vm'"),
    )
    for job, route in routes:
        assert job["needs"] == ["prepare", "build-pr"]
        assert job["if"] == (
            "always() && needs.prepare.result == 'success' && " + route
        )
        assert job["runs-on"] == "${{ needs.prepare.outputs.runs_on }}"
        assert job["defaults"] == {"run": {"shell": "bash"}}
        strategy = job["strategy"]
        assert strategy["fail-fast"] is False
        assert strategy["matrix"] == {
            "version": "${{ fromJSON(needs.prepare.outputs.versions) }}",
        }
        assert job["timeout-minutes"] <= 240
    for name in ("versions", "runs_on", "azure", "isolation"):
        assert prepare["outputs"][name] == f"${{{{ steps.verify.outputs.{name} }}}}"
    assert "verify" in _step(repro, "prepare", "Re-validate")["run"]


def test_local_job_never_reaches_azure_credentials(repro):
    local = repro["jobs"]["reproduce-local"]
    assert local["permissions"] == {"contents": "read"}
    text = str(local)
    for forbidden in ("secrets.", "azure/login", "id-token", "rg-create", "logout"):
        assert forbidden not in text
    names = [s["name"] for s in local["steps"]]
    order = ["Install CLI", "Checkout the matching source", "Run ReproSpec",
             "Sanitize", "Upload redacted result"]
    positions = [next(i for i, n in enumerate(names) if n.startswith(p)) for p in order]
    assert positions == sorted(positions)


def test_runner_checkout_is_pinned_to_workflow_commit(repro):
    for job in repro["jobs"].values():
        checkout = job["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"]["repository"] == "${{ github.repository }}"
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["path"] == "sentinel"


def test_reproduce_step_order_and_cleanup(repro):
    steps = repro["jobs"]["reproduce"]["steps"]
    names = [s["name"] for s in steps]
    order = ["Azure login", "Create per-run resource group", "Run ReproSpec",
             "Delete per-run resource group", "Sign out", "Sanitize",
             "Upload redacted result"]
    positions = [next(i for i, n in enumerate(names) if n.startswith(p))
                 for p in order]
    assert positions == sorted(positions)
    for prefix in order[3:]:
        step = next(s for s in steps if s["name"].startswith(prefix))
        assert step.get("if") == "always()", prefix
    run = _step(repro, "reproduce", "Run ReproSpec")
    assert run["timeout-minutes"] == (
        "${{ fromJSON(needs.prepare.outputs.step_timeout_minutes) }}"
    )
    assert run["run"].endswith("repro_runner.py\" run")
    assert _step(repro, "reproduce", "Delete per-run")["run"].endswith("rg-delete")
    sanitize = _step(repro, "reproduce", "Sanitize")
    assert "repro_sanitize.py" in sanitize["run"]


def test_azure_login_uses_bami_oidc(repro, janitor):
    for workflow in (repro, janitor):
        logins = [s for _j, s in _steps(workflow)
                  if s.get("uses", "").startswith("azure/login@")]
        assert len(logins) == (2 if workflow is repro else 1)
        for login in logins:
            assert login["with"] == {
                "client-id": "${{ secrets.BAMI_CLIENT_ID }}",
                "tenant-id": "${{ secrets.BAMI_TENANT_ID }}",
                "subscription-id": "${{ secrets.BAMI_SUBSCRIPTION_ID }}",
                "allow-no-subscriptions": False,
            }
    assert {job for job, s in _steps(repro)
            if s.get("uses", "").startswith("azure/login@")} == {"reproduce", "reproduce-vm"}
    assert "azure/login" not in str(repro["jobs"]["prepare"])
    assert "azure/login" not in str(repro["jobs"]["report"])


def test_only_redacted_json_is_uploaded(repro):
    uploads = [(job, s) for job, s in _steps(repro)
               if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert {(job, s["with"]["name"]) for job, s in uploads} == {
        ("build-pr", "repro-pr-wheels"),
        ("reproduce", "repro-redacted-${{ matrix.version }}"),
        ("reproduce-local", "repro-redacted-${{ matrix.version }}"),
        ("reproduce-vm", "repro-redacted-${{ matrix.version }}"),
        ("report", "repro-redacted"),
    }
    # The credential-less build job only uploads the PR head wheels.
    wheels = _step(repro, "build-pr", "Upload")
    assert wheels["with"]["path"] == "repro/wheels/"
    uploads = [(job, s) for job, s in uploads if job != "build-pr"]
    for _job, step in uploads:
        assert Path(step["with"]["path"]).name == "repro.redacted.json"
        assert "\n" not in step["with"]["path"]
        assert step["with"]["if-no-files-found"] == "error"
        assert step["if"] == "always()"
    download = _step(repro, "report", "Download")
    assert download["with"]["pattern"] == "repro-redacted-*"


def test_report_job_runs_after_all_versions(repro):
    report = repro["jobs"]["report"]
    assert report["needs"] == ["prepare", "reproduce", "reproduce-local", "reproduce-vm"]
    assert report["if"] == "always() && needs.prepare.result == 'success'"
    assert "merge" in _step(repro, "report", "Merge")["run"]


def test_raw_output_never_leaves_the_runner(repro):
    text = REPRO.read_text(encoding="utf-8")
    assert "repro/raw" not in text
    assert "GITHUB_STEP_SUMMARY" not in text


def test_janitor_is_scheduled_and_dry_run_capable(janitor):
    assert janitor["on"]["schedule"][0]["cron"]
    assert janitor["on"]["workflow_dispatch"]["inputs"]["dry_run"]["type"] == "boolean"
    steps = janitor["jobs"]["janitor"]["steps"]
    delete = next(s for s in steps if "repro_janitor.py" in s.get("run", ""))
    assert delete["env"] == {"REPRO_JANITOR_DRY_RUN": "${{ inputs.dry_run }}"}
    assert steps[-1]["if"] == "always()"
    assert steps[-1]["run"].endswith("logout")


def test_generated_modules_carry_the_do_not_edit_header():
    for name in ("repro_policy.py", "repro_sensitive_data.py", "repro_spec.py"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert text.startswith("# GENERATED FILE - DO NOT EDIT.\n"), name
        assert "scripts/sync_issue_sentinel_repro.py" in text.splitlines()[2], name


def test_runner_scripts_use_only_the_standard_library():
    allowed_local = {p.stem for p in SCRIPTS.glob("*.py")}
    for path in SCRIPTS.glob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:from|import) ([\w.]+)", line)
            if not match:
                continue
            top = match.group(1).split(".")[0]
            assert top in allowed_local or top in _stdlib(), (path.name, top)


def _stdlib():
    import sys

    return set(sys.stdlib_module_names) | {"__future__"}


def test_pr_mode_validates_the_agent_fork_pr_in_prepare(repro):
    prepare = repro["jobs"]["prepare"]
    verify = _step(repro, "prepare", "Re-validate")
    assert verify["env"] == {"REPRO_GITHUB_TOKEN": "${{ github.token }}"}
    assert prepare["permissions"] == {"contents": "read"}
    assert prepare["outputs"]["pr_repo"] == "${{ steps.verify.outputs.pr_repo }}"
    assert prepare["outputs"]["pr_ref"] == "${{ steps.verify.outputs.pr_ref }}"


def test_build_pr_job_has_no_azure_credentials(repro):
    build = repro["jobs"]["build-pr"]
    assert build["needs"] == "prepare"
    assert build["if"] == "inputs.pr_number != ''"
    assert build["permissions"] == {"contents": "read"}
    text = str(build)
    assert "secrets." not in text
    assert "azure/login" not in text
    assert "id-token" not in text
    checkout = _step(repro, "build-pr", "Checkout the verified PR head")
    assert checkout["with"] == {
        "repository": "${{ needs.prepare.outputs.pr_repo }}",
        "ref": "${{ needs.prepare.outputs.pr_ref }}",
        "path": "repro/src",
        "fetch-depth": 1,
        "persist-credentials": False,
    }
    assert _step(repro, "build-pr", "Build wheels")["run"].endswith(
        'repro_runner.py" build'
    )


def test_reproduce_job_never_checks_out_pr_code(repro):
    steps = repro["jobs"]["reproduce"]["steps"]
    assert not [s for s in steps[1:] if s.get("uses", "").startswith("actions/checkout@")]
    source = _step(repro, "reproduce", "Checkout CLI source (dev)")
    assert source["if"] == "matrix.version == 'dev'"
    assert source["env"] == {"SRC_REPO": "${{ needs.prepare.outputs.source_repo }}",
                             "SRC_REF": "${{ needs.prepare.outputs.dev_ref }}"}
    assert source["run"].endswith("repro_runner.py\" checkout-source")
    assert "pr_ref" not in str(repro["jobs"]["reproduce"])
    download = _step(repro, "reproduce", "Download PR head wheels")
    assert download["if"] == "matrix.version == 'pr'"
    assert download["with"] == {"name": "repro-pr-wheels", "path": "repro/wheels"}
    names = [s["name"] for s in steps]
    assert names.index(download["name"]) < names.index(
        next(n for n in names if n.startswith("Install"))
    ) < names.index(next(n for n in names if n.startswith("Azure login")))


def test_workflow_documents_the_pr_trust_model():
    text = REPRO.read_text(encoding="utf-8")
    for phrase in ("Agent's own fork", "pr_head_sha", "persist-credentials: false",
                   "no secrets, no id-token"):
        assert phrase in text, phrase
