# GENERATED FILE - DO NOT EDIT.
# Vendored from x-engineering-agent `src/config/settings/reproduction.py` by
# `scripts/sync_issue_sentinel_repro.py`; edit the source and re-run it.
"""Live bug reproduction (BAMI sandbox) settings.

Reproductions reuse the live-test setup: the same ``Azure/issue-sentinel``
repository, BAMI OIDC login and dispatch code. Only the workflow differs.
Commands come from a validated ``ReproSpec`` (see
``x_engineering_agent.tools.live_tests.reproduction``); the allowlists and
denylists below are the policy that validator enforces. Adding a command
group, SKU or location here widens what issue-derived specs may run, so
changes need the Agent owner and the owning team's approval.
"""

import os


# Reproductions always run live for repositories whose profile names a
# reproduction workflow (``live_repro``).
# Waiting label while a live reproduction runs.
LIVE_REPRO_WAITING_LABEL = "agent: reproducing"
# Decision table (plan item C2e): a maintainer adds this label to queue a fix
# although the live reproduction said "fixed in a later version" or "not
# reproduced" (``submit_issue`` refuses the job otherwise).
LIVE_REPRO_OVERRIDE_LABEL = os.environ.get(
    "LIVE_REPRO_OVERRIDE_LABEL", "agent: fix without reproduction",
)
# Highest confidence a fix may carry when the live reproduction was blocked
# (code-reading only); always kept below AGENT_DRAFT_CONFIDENCE_THRESHOLD so
# the PR stays a draft with do-not-merge.
LIVE_REPRO_BLOCKED_CONFIDENCE_CAP = min(1.0, max(0.0, float(
    os.environ.get("LIVE_REPRO_BLOCKED_CONFIDENCE_CAP", "0.4")
)))
LIVE_REPRO_WORKFLOW = os.environ.get("LIVE_REPRO_WORKFLOW", "live-repro.yml")
LIVE_REPRO_POWERSHELL_WORKFLOW = os.environ.get(
    "LIVE_REPRO_POWERSHELL_WORKFLOW", "live-repro-powershell.yml",
)

REPRO_SCHEMA_VERSION = 1
REPRO_MAX_STEPS = 10
REPRO_MAX_ARGS_PER_STEP = 40
REPRO_MAX_ARG_CHARS = 256
REPRO_MAX_QUERY_CHARS = 512
REPRO_MAX_TEXT_CHARS = 200
REPRO_MAX_PS_PARAMETERS = 30
REPRO_MAX_LIST_ITEMS = 10
REPRO_DEFAULT_TIMEOUT_MINUTES = 20
REPRO_MAX_TIMEOUT_MINUTES = 30
REPRO_MAX_CONCURRENT_RUNS = max(
    1, int(os.environ.get("LIVE_REPRO_MAX_CONCURRENT_RUNS", "3"))
)
REPRO_MAX_INSTANCE_COUNT = 2
REPRO_MAX_NAME_PLACEHOLDERS = 9

# Versions the workflow installs, in canonical order.
REPRO_VERSIONS = ("reported", "latest", "dev")
REPRO_DEFAULT_VERSIONS = ("latest", "dev")

# Before/After on Agent PRs (plan item C2f): the PR-head ("after") re-run of
# a reproduced issue's spec gates ready-for-review. A run that has not
# finished this many minutes after dispatch counts as blocked (no infinite
# wait); transient poll failures are retried this many rounds.
REPRO_AFTER_TIMEOUT_MINUTES = max(
    10, int(os.environ.get("LIVE_REPRO_AFTER_TIMEOUT_MINUTES", "180"))
)
REPRO_AFTER_MAX_POLL_FAILURES = 3

REPRO_RESOURCE_GROUP_PREFIX = "xea-repro"
REPRO_EXPIRES_TAG = "expiresAt"
REPRO_RESOURCE_GROUP_TTL_HOURS = 6

REPRO_ALLOWED_LOCATIONS = (
    "westus3", "eastus2", "eastus", "westus2", "centralus",
    "northeurope", "westeurope", "uksouth", "australiaeast",
    "southeastasia",
)
REPRO_DEFAULT_LOCATION = "westus3"

# Cheap SKUs, sizes and tiers (compared case-insensitively).
REPRO_ALLOWED_SKUS = frozenset(s.casefold() for s in (
    # Storage
    "Standard_LRS", "Standard_ZRS", "Standard_GRS", "Premium_LRS",
    # App Service plans
    "F1", "FREE", "D1", "SHARED", "B1", "B2", "S1", "P0v3", "P1v3", "Y1",
    "EP1", "FC1",
    # Virtual machines, scale sets and flexible servers
    "Standard_B1s", "Standard_B1ms", "Standard_B2s", "Standard_B1ls",
    "Standard_DS1_v2", "Standard_D2s_v3", "Standard_D2s_v5",
    # Generic tiers
    "Free", "Basic", "Standard", "Developer", "Consumption", "Burstable",
    "Standard_B1", "B_Standard_B1ms", "GP_Gen5_2", "S0", "F0",
    # Networking
    "Standard_v2", "Basic_v2",
    # Key Vault, Container Registry, Redis
    "standard", "premium", "C0",
    # Cosmos DB, Event Hubs, Service Bus, Search, SignalR
    "Free_F1", "Standard_S1",
))

# Azure CLI command groups (leading command tokens) a step may run. A longer
# entry narrows a group to read-only commands, for example ``group show``.
REPRO_AZ_ALLOWED_COMMANDS = tuple(tuple(c.split()) for c in (
    "version",
    "group show", "group list", "group exists",
    "resource show", "resource list",
    "provider show", "provider list",
    "storage", "network", "keyvault", "webapp", "functionapp", "appservice",
    "monitor", "sql", "cosmosdb", "redis", "servicebus", "eventhubs",
    "eventgrid", "acr", "container", "containerapp", "cognitiveservices",
    "vm", "vmss", "disk", "snapshot", "image", "identity", "appconfig",
    "postgres", "mysql", "search", "signalr", "staticwebapp", "logicapp",
    "backup", "batch", "iot", "relay", "notification-hub", "dns",
    "private-dns", "afd", "cdn", "loganalytics",
))

# Commands denied even inside an allowed group (prefix match), plus groups
# that must never run (login, identity, RBAC, templates, extensions, ...).
REPRO_AZ_DENIED_COMMANDS = tuple(tuple(c.split()) for c in (
    "login", "logout", "account", "ad", "role", "rest", "config", "cloud",
    "extension", "upgrade", "self-test", "interactive", "find", "bicep",
    "deployment", "deployment-scripts", "ts", "policy", "lock", "feature",
    "ssh", "aks", "tag", "group create", "group delete", "group update",
    "keyvault secret", "keyvault key download", "keyvault key backup",
    "keyvault certificate download", "keyvault certificate backup",
    "keyvault set-policy", "keyvault delete-policy", "keyvault role",
    "containerapp secret", "containerapp exec", "containerapp ssh",
    "container exec", "container attach", "webapp up", "webapp ssh",
    "webapp deploy", "webapp deployment", "webapp create-remote-connection",
    "functionapp deploy", "functionapp deployment", "staticwebapp secrets",
    "vm run-command", "vm extension", "vm user", "vm secret",
    "vm access", "vmss run-command", "vmss extension", "network bastion",
))

# Command-path tokens denied anywhere (credential and remote-exec verbs).
REPRO_AZ_DENIED_COMMAND_TOKENS = frozenset({
    "keys", "list-keys", "regenerate-key", "renew-keys",
    "show-connection-string", "connection-string", "connection-strings",
    "generate-sas", "credential", "credentials", "list-credentials",
    "get-credentials", "list-secrets", "show-secret", "secrets",
    "list-publishing-profiles", "list-publishing-credentials",
    "run-command", "exec", "attach", "ssh", "tunnel", "console",
    "remote-connection", "create-remote-connection", "access-token",
    "get-access-token", "role-assignment", "role-assignments",
    "authorization-rule",
})

# ``az rest`` is the one denied group with a narrow exception: GET on ARM
# inside the run's resource group.
REPRO_AZ_REST_HOSTS = ("management.azure.com",)

# Arguments that must never appear (also rejected when abbreviated).
REPRO_AZ_DENIED_ARGUMENTS = frozenset({
    "--subscription", "--tenant", "--template-file", "--template-uri",
    "--template-spec", "--scripts", "--script", "--custom-data",
    "--user-data", "--source", "--src", "--src-path", "--command",
    "--command-id", "--exec-command", "--startup-file", "--assignee",
    "--assignee-object-id", "--role", "--show-values", "--show-secrets",
    "--headers", "--sas-token", "--account-key", "--connection-string",
    "--ssh-key-values", "--ssh-key-value", "--skip-authorization-header",
    "--secrets", "--secret-value",
})
# Arguments whose value must be the workflow-generated file ``{file}``.
REPRO_AZ_FILE_ARGUMENTS = frozenset({
    "--file", "-f", "--file-path", "--local-path",
})
# Arguments whose value must be the workflow-generated ``{password}``.
REPRO_AZ_PASSWORD_ARGUMENTS = frozenset({
    "--password", "--admin-password", "--administrator-login-password",
    "--admin-user-password", "--client-secret", "--secret",
})
# Real az flags that happen to be prefixes of a restricted flag above; they are
# not treated as abbreviations (their values still go through every check).
REPRO_AZ_PREFIX_SAFE_ARGUMENTS = frozenset({
    "--admin-user",
})
REPRO_AZ_RESOURCE_GROUP_ARGUMENTS = frozenset({
    "-g", "--resource-group", "--resource-group-name",
})
REPRO_AZ_LOCATION_ARGUMENTS = frozenset({"-l", "--location"})
REPRO_AZ_SKU_ARGUMENTS = frozenset({
    "--sku", "--sku-name", "--size", "--vm-size", "--node-vm-size",
    "--tier", "--sku-tier",
})
REPRO_AZ_COUNT_ARGUMENTS = frozenset({
    "--count", "--instance-count", "--node-count", "--capacity",
    "--number-of-workers", "--replica-count",
})
REPRO_AZ_OUTPUT_FORMATS = frozenset({
    "json", "jsonc", "table", "tsv", "yaml", "yamlc", "none",
})

# Container images may only come from these registries.
REPRO_ALLOWED_IMAGE_HOSTS = ("mcr.microsoft.com",)
# URLs and host names in arguments are allowed only for resources the run
# creates: ``{nameN}`` followed by one of these Azure suffixes.
REPRO_PLACEHOLDER_HOST_SUFFIXES = (
    ".blob.core.windows.net", ".file.core.windows.net",
    ".queue.core.windows.net", ".table.core.windows.net",
    ".dfs.core.windows.net", ".vault.azure.net", ".azurewebsites.net",
    ".azurecr.io", ".database.windows.net", ".documents.azure.com",
    ".servicebus.windows.net", ".redis.cache.windows.net",
    ".azconfig.io", ".search.windows.net", ".cognitiveservices.azure.com",
)

# Azure PowerShell: approved verbs and noun prefixes (after ``Az``). A tuple
# narrows the verbs allowed for that prefix.
REPRO_PS_ALLOWED_VERBS = frozenset({
    "Get", "New", "Set", "Update", "Remove", "Add", "Start", "Stop",
    "Restart", "Test", "Enable", "Disable", "Move", "Reset", "Resize",
})
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
}
# PowerShell Gallery module that ships each noun prefix above. The workflow
# installs exactly these modules (``Install-Module -RequiredVersion``), so a
# new prefix needs its module here too.
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
    "Location": "Az.Resources",
}
REPRO_PS_ALLOWED_MODULES = frozenset(REPRO_PS_NOUN_MODULES.values())
# Denied noun patterns (case-sensitive regular expressions on the noun).
REPRO_PS_DENIED_NOUN_PATTERNS = (
    r"Key$", r"Keys$", r"Credential", r"Secret", r"Password", r"Token",
    r"Sas", r"ConnectionString", r"PublishingProfile", r"RunCommand",
    r"Extension", r"AccessPolicy", r"Role", r"Policy", r"Lock",
    r"Deployment", r"^AzAD", r"Context", r"Subscription", r"Tenant",
)
REPRO_PS_DENIED_PARAMETERS = frozenset(p.casefold() for p in (
    "Subscription", "SubscriptionId", "SubscriptionName", "Tenant",
    "TenantId", "DefaultProfile", "AzContext", "Context", "TemplateFile",
    "TemplateUri", "TemplateParameterFile", "TemplateParameterUri",
    "TemplateObject", "TemplateParameterObject", "ScriptPath",
    "ScriptString", "ScriptBlock", "Script", "ScriptUri", "CustomData",
    "UserData", "Credential", "CommandId", "Command", "RoleDefinitionName",
    "ObjectId", "ApplicationId", "ServicePrincipalName", "SignInName",
    "AccessToken", "SasToken", "StorageAccountKey", "ConnectionString",
    "FileUri", "SshKeyValue", "ShowSecret", "AzureRmContext",
    "AzureCredential",
    # Common parameters the workflow controls (output streams, error
    # handling, background jobs and variables).
    "Debug", "Verbose", "ErrorAction", "WarningAction", "InformationAction",
    "ProgressAction", "ErrorVariable", "WarningVariable",
    "InformationVariable", "OutVariable", "OutBuffer", "PipelineVariable",
    "AsJob", "Confirm",
))
REPRO_PS_FILE_PARAMETERS = frozenset(p.casefold() for p in (
    "File", "FilePath", "Path", "Source", "SourcePath", "LocalPath",
))
REPRO_PS_SKU_PARAMETERS = frozenset(p.casefold() for p in (
    "Sku", "SkuName", "Size", "VmSize", "Tier", "SkuTier",
))
REPRO_PS_COUNT_PARAMETERS = frozenset(p.casefold() for p in (
    "Capacity", "InstanceCount", "Count", "NumberOfWorkers",
))
