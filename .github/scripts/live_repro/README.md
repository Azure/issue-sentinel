# Live reproduction workflows

The X Engineering Agent dispatches these workflows to reproduce Azure CLI,
CLI extension and Azure PowerShell issues from a validated ReproSpec. This repository is the source of truth for the
workflows and the trusted runner scripts. The tests in `tests/live_repro`
check them; the `live-repro-tests.yml` workflow runs those tests.

Paths below are relative to the repository root.

| File | Purpose |
|---|---|
| `.github/workflows/live-repro.yml` | `workflow_dispatch` target of `dispatch_reproduction` (inputs `issue`, `spec`, `spec_hash`, `pr_number`, `pr_head_sha`; run name `Live Repro (<issue> @ <spec_hash>[ PR <n> head <sha>])`). |
| `.github/workflows/live-repro-powershell.yml` | Same inputs and run name for `pwsh-az` specs (Azure/azure-powershell issues; `LIVE_REPRO_POWERSHELL_WORKFLOW`). PR-head re-runs build the module under test in a credential-free `build-pr` job (see below). |
| `.github/workflows/live-repro-janitor.yml` | Scheduled backstop that deletes expired `xea-repro-*` resource groups. |
| `.github/scripts/live_repro/repro_runner.py` | Trusted runner: re-validates the spec against `spec_hash`, installs the CLI version, manages the resource group, runs argv steps without a shell, writes all output to files. |
| `.github/scripts/live_repro/repro_ps_runner.py` | PowerShell runner: reuses `repro_runner.py`'s verification, step loop and result files; installs `Az.<X>` with `Install-Module -RequiredVersion` (builds it from source for `dev`; imports the verified `build-pr` output for `pr`), signs in with a federated `Connect-AzAccount`. |
| `.github/scripts/live_repro/repro_ps.ps1` | Trusted pwsh script run with `-File` (never `-Command`): installs modules, signs in, manages the resource group and calls one allowlisted cmdlet by splatting a checked parameter hashtable. |
| `.github/scripts/live_repro/repro_sanitize.py` | Builds `repro.redacted.json`; the comment above `RESULT_FILE_NAME` documents the result schema the Agent consumes. |
| `.github/scripts/live_repro/repro_janitor.py` | Janitor logic. |
| `.github/scripts/live_repro/repro_spec.py`, `repro_policy.py`, `repro_sensitive_data.py` | **Generated** stdlib copies of the Agent's ReproSpec validator, its policy and `src/security/sensitive_data.py`. Do not edit (see below). |
| `.github/workflows/live-repro-tests.yml` | Runs `tests/live_repro` on pull requests and pushes to `main` that touch these files. No secrets. |

## Security model

- Same BAMI OIDC login and secrets as `live-test.yml` (`BAMI_TENANT_ID`,
  `BAMI_SUBSCRIPTION_ID`, `BAMI_CLIENT_ID`). No Key Vault or GitHub PAT step;
  workflow permissions are `id-token: write` and `contents: read` only.
- Runner scripts are checked out from the workflow's own commit
  (`github.sha`), never from the dispatch inputs.
- The spec input must be the canonical JSON of a valid spec whose SHA-256 is
  `spec_hash`; every job re-validates it before running anything.
- Steps run as argv lists in an empty directory with a minimal environment
  (no GitHub or OIDC request tokens). Output goes to `repro/raw` and never to
  the log; only exit codes and verdicts are printed.
- Sanitizing runs after sign-out. Only `repro.redacted.json` is uploaded:
  `repro-redacted-<version>` per matrix entry and the merged `repro-redacted`
  artifact, which is the one the Agent downloads.
- PowerShell: the Az module must be allowlisted (`REPRO_PS_NOUN_MODULES`),
  modules are installed with `Install-Module -RequiredVersion` (the
  `latest` version is resolved with `Find-Module` first) and sign-in is a
  federated `Connect-AzAccount` with the job's OIDC token (no secret, no
  `azure/login`). Each step is one `pwsh -NoProfile -NonInteractive -File
  repro_ps.ps1` process that resolves the cmdlet with `Get-Command`, accepts
  only exact parameter names or aliases that are not denied (no prefixes,
  no `-ScriptBlock`/credential parameters, no common parameters) and splats
  the values as data; there is no `Invoke-Expression` or script text. `dev`
  builds the module with `tools/BuildScripts/BuildModules.ps1 -TargetModule <X>` in
  the reproduce job (trusted `main`); `pr` uses the same build, run in
  `build-pr` (below).
- Matrix: the spec's `versions` (`reported`, `latest`, `dev`), or `dev` +
  `pr` when `pr_number` is set (Before/After).

### PR-head mode (`pr_number`)

The PR is Agent-authored on the Agent's fork, but its code is still treated
as untrusted:

- `pr_number` requires `pr_head_sha` (40 lowercase hex). `prepare` checks via
  the GitHub API (read-only `github.token`) that the PR is open against the
  issue's repository, that its head repository is the configured Agent fork
  (`agent_fork` in the vendored profiles) and that its head is exactly
  `pr_head_sha`; anything else fails closed.
- `build-pr` checks out that SHA from the fork with
  `persist-credentials: false`, has no Azure login, no secrets, no
  `id-token` and only `contents: read`, and builds wheels with
  `pip wheel --no-deps` (no install, no `az` run). The wheels and a SHA-256
  manifest are the only upload (`repro-pr-wheels`).
- `reproduce` never checks out PR code. It verifies the manifest and installs
  only those wheels (an extension PR installs `azure-cli` from PyPI plus the
  extension wheel); PR code first runs in the sandboxed step runner, which is
  designed for that.
- PowerShell (`live-repro-powershell.yml`) follows the same model: `prepare`
  verifies the PR against Azure/azure-powershell and its Agent fork;
  `build-pr` (same credential-free permissions, plus `setup-dotnet`) runs
  `tools/BuildScripts/BuildModules.ps1 -TargetModule <X>` for the spec's `module`
  only and uploads the `Az.*` build output as `module.tar.gz` with a SHA-256
  manifest (`repro-pr-module`). The `pr` reproduce job downloads it, checks
  the manifest (head SHA, module, archive hash), extracts only regular
  files and directories under the built `Az.*` module directories (no
  links, absolute paths or `..`; tarfile `data` filter), reads the version
  from the `.psd1` text and installs helper modules from PSGallery. The PR
  module is first imported by `repro_ps.ps1` in the `run` step.
- The spec and `spec_hash` are the ones validated for the issue (the same
  `repro:<spec_hash>` marker), so Before and After are comparable.
- One resource group per version, `xea-repro-<repo>-<issue>-<run>-<version>`,
  tagged `expiresAt` (now + `REPRO_RESOURCE_GROUP_TTL_HOURS`) and deleted with
  `if: always()`; the janitor runs every 3 hours and covers both workflows.

## Tests

```bash
python -m pip install -r tests/live_repro/requirements.txt
python -m pytest -q tests/live_repro
```

The tests use only the standard library, pytest and PyYAML. The `pwsh`
tests run `repro_ps.ps1` against a fake module and are skipped when `pwsh`
is not installed.

## Generated files

`repro_spec.py`, `repro_policy.py` and `repro_sensitive_data.py` are
generated from the X Engineering Agent sources
(`src/tools/live_tests/reproduction.py`, `src/config/settings/reproduction.py`,
`src/security/sensitive_data.py` and the repository profiles). Do not edit
them here.

1. In an X Engineering Agent checkout, regenerate them into a checkout of
   this repository:

       python scripts/sync_issue_sentinel_repro.py --target <issue-sentinel checkout>

   `--check` exits non-zero while the files in the checkout are stale.
   Parity between the generated copies and the Agent validator is tested in
   the Agent repository.
2. Run `tests/live_repro` here and open a PR with the regenerated files.
3. After it merges, check that the repository secrets above exist, run the
   janitor once with `dry_run`. Live reproduction always runs for every
   repository profile with `live_repro: True` in the Agent (Azure CLI, CLI
   extensions and Azure PowerShell), so merge workflow changes here before
   deploying the Agent and confirm one manual dispatch of each succeeds.
