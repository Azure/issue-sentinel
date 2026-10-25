# GENERATED FILE - DO NOT EDIT.
# Vendored from x-engineering-agent `src/config/settings/reproduction.py` by
# `scripts/sync_issue_sentinel_repro.py`; edit the source and re-run it.
"""Settings for live bug reproduction in the BAMI sandbox."""

import os


# Label shown while a live reproduction runs.
LIVE_REPRO_WAITING_LABEL = "agent: reproducing"
# Lets a maintainer queue a fix even if the reproduction said "fixed" or "not reproduced".
LIVE_REPRO_OVERRIDE_LABEL = os.environ.get(
    "LIVE_REPRO_OVERRIDE_LABEL", "agent: fix without reproduction",
)
# Below AGENT_DRAFT_CONFIDENCE_THRESHOLD, so a fix without a reproduction stays a draft.
LIVE_REPRO_BLOCKED_CONFIDENCE_CAP = min(1.0, max(0.0, float(
    os.environ.get("LIVE_REPRO_BLOCKED_CONFIDENCE_CAP", "0.4")
)))
LIVE_REPRO_WORKFLOW = os.environ.get("LIVE_REPRO_WORKFLOW", "live-repro.yml")
LIVE_REPRO_POWERSHELL_WORKFLOW = os.environ.get(
    "LIVE_REPRO_POWERSHELL_WORKFLOW", "live-repro-powershell.yml",
)

# A run that fails at sandbox sign-in or runner setup is re-run after these delays
# (minutes) before the Fixer may continue without a reproduction.
REPRO_INFRA_RETRY_MINUTES = tuple(
    int(item) for item in os.environ.get(
        "LIVE_REPRO_INFRA_RETRY_MINUTES", "30,120,360",
    ).split(",") if item.strip()
)

REPRO_SCHEMA_VERSION = 1
# Empty directories created in the step working directory (cwd-dependent bugs).
REPRO_MAX_WORKDIR_DIRS = 5
# Observed text kept in results.
REPRO_MAX_TEXT_CHARS = 200
REPRO_DEFAULT_TIMEOUT_MINUTES = 20
REPRO_MAX_TIMEOUT_MINUTES = 120
REPRO_MAX_CONCURRENT_RUNS = max(
    1, int(os.environ.get("LIVE_REPRO_MAX_CONCURRENT_RUNS", "3"))
)
REPRO_MAX_NAME_PLACEHOLDERS = 9

# Versions the workflow installs, in canonical order.
REPRO_VERSIONS = ("reported", "latest", "dev")
REPRO_DEFAULT_VERSIONS = ("latest", "dev")

# GitHub-hosted runner OS for the steps. Windows installs reported/latest with the
# official MSI (Git Bash, PowerShell and cmd are available); others use pip.
REPRO_OPERATING_SYSTEMS = ("linux", "windows", "macos")
REPRO_DEFAULT_OS = "linux"
# Shell steps run in every spec; "azure": false runs them in a job that never signs in.
REPRO_SHELLS = {
    "linux": ("bash", "sh", "pwsh"),
    "macos": ("bash", "sh", "pwsh"),
    "windows": ("bash", "pwsh", "powershell", "cmd"),
}

# Real environments a spec may name in "environment". Kinds:
# - runner: a pinned GitHub-hosted runner image.
# - container: a distro image run under docker on the Linux runner; the CLI under test is
#   installed inside it ("install": "package" from packages.microsoft.com or the distro, or
#   "pip" into a venv). Azure specs reach the runner's sign in through a mounted config dir.
# - vm: a throwaway BAMI VM in the per-run resource group with no managed identity and no
#   public IP. The runner signs in only to create, drive (az vm run-command) and delete it;
#   steps run in the guest, never signed in, so these specs need "azure": false.
REPRO_ENVIRONMENTS = {
    "ubuntu-22.04": {"os": "linux", "kind": "runner", "runner": "ubuntu-22.04"},
    "ubuntu-24.04": {"os": "linux", "kind": "runner", "runner": "ubuntu-24.04"},
    "windows-server-2022": {"os": "windows", "kind": "runner", "runner": "windows-2022"},
    "windows-server-2025": {"os": "windows", "kind": "runner", "runner": "windows-2025"},
    "macos-13": {"os": "macos", "kind": "runner", "runner": "macos-13"},
    "macos-14": {"os": "macos", "kind": "runner", "runner": "macos-14"},
    "macos-15": {"os": "macos", "kind": "runner", "runner": "macos-15"},
    "ubuntu-20.04": {"os": "linux", "kind": "container", "family": "debian",
                     "image": "docker.io/library/ubuntu:20.04"},
    "debian-11": {"os": "linux", "kind": "container", "family": "debian",
                  "image": "docker.io/library/debian:11"},
    "debian-12": {"os": "linux", "kind": "container", "family": "debian",
                  "image": "docker.io/library/debian:12"},
    "rhel-8": {"os": "linux", "kind": "container", "family": "rhel", "release": "8",
               "image": "registry.access.redhat.com/ubi8/ubi:latest"},
    "rhel-9": {"os": "linux", "kind": "container", "family": "rhel", "release": "9",
               "image": "registry.access.redhat.com/ubi9/ubi:latest"},
    "centos-stream-9": {"os": "linux", "kind": "container", "family": "rhel", "release": "9",
                        "image": "quay.io/centos/centos:stream9"},
    "fedora-41": {"os": "linux", "kind": "container", "family": "rhel", "release": "9",
                  "image": "docker.io/library/fedora:41"},
    "amazonlinux-2023": {"os": "linux", "kind": "container", "family": "rhel", "release": "9",
                         "image": "public.ecr.aws/amazonlinux/amazonlinux:2023"},
    "azurelinux-3": {"os": "linux", "kind": "container", "family": "tdnf",
                     "image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
    "cbl-mariner-2": {"os": "linux", "kind": "container", "family": "tdnf",
                      "image": "mcr.microsoft.com/cbl-mariner/base/core:2.0"},
    "opensuse-leap-15": {"os": "linux", "kind": "container", "family": "suse",
                         "image": "registry.opensuse.org/opensuse/leap:15.6"},
    "sles-15": {"os": "linux", "kind": "container", "family": "suse",
                "image": "registry.suse.com/bci/bci-base:15.6"},
    "alpine-3": {"os": "linux", "kind": "container", "family": "alpine",
                 "image": "docker.io/library/alpine:3.20"},
    "windows-11": {"os": "windows", "kind": "vm",
                   "image": "MicrosoftWindowsDesktop:windows-11:win11-24h2-ent:latest"},
    "windows-10": {"os": "windows", "kind": "vm",
                   "image": "MicrosoftWindowsDesktop:windows-10:win10-22h2-ent-g2:latest"},
    "windows-server-2019": {"os": "windows", "kind": "vm",
                            "image": "MicrosoftWindowsServer:WindowsServer:2019-datacenter-gensecond:latest"},
    "windows-server-2016": {"os": "windows", "kind": "vm",
                            "image": "MicrosoftWindowsServer:WindowsServer:2016-datacenter-gensecond:latest"},
}
# Install methods per container family; the first is the default. Alpine has no package.
REPRO_CONTAINER_INSTALLS = {
    "debian": ("package", "pip"), "rhel": ("package", "pip"), "tdnf": ("package", "pip"),
    "suse": ("package", "pip"), "alpine": ("pip",),
}
REPRO_CONTAINER_SHELLS = ("bash", "sh")
# Windows VMs install the official MSI; Git Bash and PowerShell 7 install only when a step uses them.
REPRO_VM_SHELLS = ("bash", "pwsh", "powershell", "cmd")
REPRO_VM_SIZE = "Standard_D2s_v5"
REPRO_VM_MAX_MINUTES = 60

# The PR-head re-run gates ready-for-review; a run slower than this counts as blocked.
REPRO_AFTER_TIMEOUT_MINUTES = max(
    10, int(os.environ.get("LIVE_REPRO_AFTER_TIMEOUT_MINUTES", "180"))
)
REPRO_AFTER_MAX_POLL_FAILURES = 3

REPRO_RESOURCE_GROUP_PREFIX = "xea-repro"
REPRO_EXPIRES_TAG = "expiresAt"
REPRO_RESOURCE_GROUP_TTL_HOURS = 6

REPRO_DEFAULT_LOCATION = "westus3"

REPRO_PS_ALLOWED_NOUN_PREFIXES = {
    "Storage": None, "KeyVault": None, "VirtualNetwork": None,
    "Network": None, "PublicIpAddress": None, "LoadBalancer": None,
    "ApplicationGateway": None, "PrivateEndpoint": None, "Dns": None,
    "PrivateDns": None, "WebApp": None, "AppServicePlan": None,
    "FunctionApp": None, "Sql": None, "CosmosDB": None, "RedisCache": None,
    "ServiceBus": None, "EventHub": None, "EventGrid": None,
    "ContainerRegistry": None, "ContainerGroup": None, "ContainerApp": None,
    "CognitiveServices": None, "VM": None, "Vmss": None, "Disk": None,
    "Snapshot": None, "UserAssignedIdentity": None, "Metric": ("Get",),
    "ActivityLog": ("Get",), "DiagnosticSetting": None, "ActionGroup": None,
    "OperationalInsights": None, "AppConfigurationStore": None,
    "PostgreSqlFlexibleServer": None, "MySqlFlexibleServer": None,
    "ResourceGroup": ("Get",), "Resource": ("Get",),
    "ResourceProvider": ("Get",), "Location": ("Get",),
    "AutoscaleSetting": None, "Aks": None, "DataFactoryV2": None,
    "CostManagement": ("Get", "Invoke"), "PolicyState": ("Get",),
    "PolicyRemediation": ("Get",), "PortalDashboard": None,
    "ApiManagement": None,
}
# The workflow installs exactly these modules; a new noun prefix needs its module here.
REPRO_PS_NOUN_MODULES = {
    "Storage": "Az.Storage", "KeyVault": "Az.KeyVault",
    "VirtualNetwork": "Az.Network", "Network": "Az.Network",
    "PublicIpAddress": "Az.Network", "LoadBalancer": "Az.Network",
    "ApplicationGateway": "Az.Network", "PrivateEndpoint": "Az.Network",
    "Dns": "Az.Dns", "PrivateDns": "Az.PrivateDns", "WebApp": "Az.Websites",
    "AppServicePlan": "Az.Websites", "FunctionApp": "Az.Functions",
    "Sql": "Az.Sql", "CosmosDB": "Az.CosmosDB", "RedisCache": "Az.RedisCache",
    "ServiceBus": "Az.ServiceBus", "EventHub": "Az.EventHub",
    "EventGrid": "Az.EventGrid", "ContainerRegistry": "Az.ContainerRegistry",
    "ContainerGroup": "Az.ContainerInstance", "ContainerApp": "Az.App",
    "CognitiveServices": "Az.CognitiveServices", "VM": "Az.Compute",
    "Vmss": "Az.Compute", "Disk": "Az.Compute", "Snapshot": "Az.Compute",
    "UserAssignedIdentity": "Az.ManagedServiceIdentity",
    "Metric": "Az.Monitor", "ActivityLog": "Az.Monitor",
    "DiagnosticSetting": "Az.Monitor", "ActionGroup": "Az.Monitor",
    "OperationalInsights": "Az.OperationalInsights",
    "AppConfigurationStore": "Az.AppConfiguration",
    "PostgreSqlFlexibleServer": "Az.PostgreSql",
    "MySqlFlexibleServer": "Az.MySql", "ResourceGroup": "Az.Resources",
    "Resource": "Az.Resources", "ResourceProvider": "Az.Resources",
    "Location": "Az.Resources", "AutoscaleSetting": "Az.Monitor",
    "Aks": "Az.Aks", "DataFactoryV2": "Az.DataFactory",
    "CostManagement": "Az.CostManagement", "PolicyState": "Az.PolicyInsights",
    "PolicyRemediation": "Az.PolicyInsights", "PortalDashboard": "Az.Portal",
    "ApiManagement": "Az.ApiManagement",
}
