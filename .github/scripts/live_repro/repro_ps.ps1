#Requires -Version 7.2
<#
.SYNOPSIS
    Runs one allowlisted Az cmdlet for live-repro-powershell.yml by splatting checked parameters.

.DESCRIPTION
    Only repro_ps_runner.py calls this. Values are bound as data, never evaluated.
    Exit codes: 0 success, 1 the cmdlet failed, 2 request rejected, 3 module import failed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Install', 'Connect', 'NewGroup', 'RemoveGroup', 'Invoke', 'Disconnect')]
    [string] $Action,

    [Parameter(Mandatory)]
    [string] $RequestFile
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$CmdletPattern = '^[A-Z][a-z]+-Az[A-Za-z][A-Za-z0-9]{1,80}$'
$ParameterPattern = '^[A-Za-z][A-Za-z0-9]{0,63}$'
$ModulePattern = '^Az\.[A-Za-z]{2,40}$'
$VersionPattern = '^\d{1,4}(\.\d{1,4}){1,3}$'
$GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$GroupPattern = '^xea-repro-[A-Za-z0-9-]{1,80}$'
$LocationPattern = '^[a-z0-9]{2,40}$'

function Stop-Rejected([string] $Reason) {
    [Console]::Error.WriteLine("REJECTED: $Reason")
    exit 2
}

function Get-ErrorCode($Exception) {
    while ($null -ne $Exception) {
        foreach ($name in 'ErrorCode', 'Code') {
            $property = $Exception.PSObject.Properties[$name]
            if ($property -and $property.Value -is [string] -and $property.Value) {
                return $property.Value
            }
        }
        $body = $Exception.PSObject.Properties['Body']
        if ($body -and $null -ne $body.Value) {
            $code = $body.Value.PSObject.Properties['Code']
            if ($code -and $code.Value) { return [string] $code.Value }
        }
        $Exception = $Exception.InnerException
    }
    return $null
}

function Write-ErrorRecord($Record) {
    [Console]::Error.WriteLine("ERROR: $($Record.Exception.Message)")
    [Console]::Error.WriteLine("FullyQualifiedErrorId: $($Record.FullyQualifiedErrorId)")
    $code = Get-ErrorCode $Record.Exception
    if ($code) { [Console]::Error.WriteLine("ErrorCode: $code") }
}

function Assert-Module([string] $Name, $Version) {
    if ($Name -cnotmatch $ModulePattern) { Stop-Rejected 'invalid module name' }
    if ($null -ne $Version -and ([string] $Version) -notmatch $VersionPattern) {
        Stop-Rejected "invalid version for $Name"
    }
}

function Test-ScalarValue($Value) {
    return ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or
        $Value -is [long] -or $Value -is [double] -or $Value -is [decimal])
}

function ConvertTo-ParameterValue($Value, $Metadata) {
    $type = $Metadata.ParameterType
    foreach ($forbidden in [scriptblock], [scriptblock[]], [pscredential]) {
        if ($type -eq $forbidden) { Stop-Rejected "parameter -$($Metadata.Name) takes code or credentials" }
    }
    if ($Value -is [array]) {
        if ($Value.Count -gt 50) { Stop-Rejected "too many values for -$($Metadata.Name)" }
        foreach ($item in $Value) {
            if (-not (Test-ScalarValue $item)) { Stop-Rejected "-$($Metadata.Name) must be a flat list of scalars" }
        }
        return , @($Value)
    }
    if (-not (Test-ScalarValue $Value)) { Stop-Rejected "-$($Metadata.Name) must be a scalar value" }
    if ($type -eq [switch]) {
        if ($Value -isnot [bool]) { Stop-Rejected "switch -$($Metadata.Name) needs true or false" }
        return [switch] $Value
    }
    if ($type -eq [securestring]) {
        if ($Value -isnot [string]) { Stop-Rejected "-$($Metadata.Name) needs a string" }
        return ConvertTo-SecureString -String $Value -AsPlainText -Force
    }
    return $Value
}

function Read-Request {
    try {
        $text = Get-Content -LiteralPath $RequestFile -Raw -Encoding utf8
        # -DateKind String (7.5+) keeps ISO-8601 strings exactly as sent.
        return $text | ConvertFrom-Json -AsHashtable -Depth 6 -DateKind String
    } catch {
        Stop-Rejected 'request file is not valid JSON'
    }
}

function Invoke-Install($Request) {
    $installed = [ordered]@{}
    foreach ($module in @($Request['modules'])) {
        $name = [string] $module['name']
        $version = $module['version']
        Assert-Module $name $version
        if ($null -eq $version) {
            $version = [string] (Find-Module -Name $name -Repository PSGallery).Version
            Assert-Module $name $version
        }
        Install-Module -Name $name -RequiredVersion $version -Repository PSGallery `
            -Scope CurrentUser -Force -AllowClobber -AcceptLicense
        $installed[$name] = [string] $version
    }
    $installed | ConvertTo-Json | Set-Content -LiteralPath $Request['result_file'] -Encoding utf8
}

function Invoke-Connect {
    foreach ($name in 'REPRO_CLIENT_ID', 'REPRO_TENANT_ID', 'REPRO_SUBSCRIPTION_ID') {
        if ([Environment]::GetEnvironmentVariable($name) -notmatch $GuidPattern) {
            Stop-Rejected "$name must be a GUID"
        }
    }
    $token = $env:REPRO_FEDERATED_TOKEN
    Remove-Item Env:REPRO_FEDERATED_TOKEN -ErrorAction SilentlyContinue
    if (-not $token) { Stop-Rejected 'no federated token' }
    Import-Module Az.Accounts
    $null = Enable-AzContextAutosave -Scope CurrentUser
    try { $null = Clear-AzContext -Scope CurrentUser -Force } catch { }
    $null = Connect-AzAccount -ServicePrincipal -ApplicationId $env:REPRO_CLIENT_ID `
        -Tenant $env:REPRO_TENANT_ID -Subscription $env:REPRO_SUBSCRIPTION_ID `
        -FederatedToken $token -Environment AzureCloud -Scope CurrentUser
}

function Invoke-NewGroup($Request) {
    $name = [string] $Request['name']
    $location = [string] $Request['location']
    if ($name -cnotmatch $GroupPattern) { Stop-Rejected 'invalid resource group name' }
    if ($location -cnotmatch $LocationPattern) { Stop-Rejected 'invalid location' }
    $tags = @{}
    foreach ($key in $Request['tags'].Keys) {
        if ($key -cnotmatch $ParameterPattern) { Stop-Rejected 'invalid tag name' }
        $tags[$key] = [string] $Request['tags'][$key]
    }
    Import-Module Az.Resources
    $null = New-AzResourceGroup -Name $name -Location $location -Tag $tags -Force
}

function Invoke-RemoveGroup($Request) {
    $name = [string] $Request['name']
    if ($name -cnotmatch $GroupPattern) { Stop-Rejected 'invalid resource group name' }
    Import-Module Az.Resources
    $group = Get-AzResourceGroup -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $group) {
        'absent'
        return
    }
    $null = Remove-AzResourceGroup -Name $name -Force
    'deleted'
}

function Invoke-Disconnect {
    try {
        Import-Module Az.Accounts
        $null = Disconnect-AzAccount -Scope CurrentUser
    } catch { }
    try { $null = Clear-AzContext -Scope CurrentUser -Force } catch { }
}

function Invoke-ReproStep($Request) {
    $cmdlet = [string] $Request['cmdlet']
    $module = [string] $Request['module']
    $requiredVersion = $Request['required_version']
    $modulePath = $Request['module_path']
    if ($cmdlet -cnotmatch $CmdletPattern) { Stop-Rejected 'invalid cmdlet name' }
    Assert-Module $module $requiredVersion
    $parameters = $Request['parameters']
    if ($parameters -isnot [System.Collections.IDictionary]) { Stop-Rejected 'parameters must be an object' }
    $denied = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($Request['denied_parameters'])) { $null = $denied.Add([string] $name) }
    if ($denied.Count -eq 0) { Stop-Rejected 'denied parameter list is missing' }

    try {
        if ($modulePath) {
            $manifest = Join-Path $modulePath "$module.psd1"
            if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "no manifest" }
            $env:PSModulePath = (Split-Path -Parent $modulePath) + [IO.Path]::PathSeparator + $env:PSModulePath
            Import-Module -Name $manifest
        } elseif ($null -ne $requiredVersion) {
            Import-Module -Name $module -RequiredVersion $requiredVersion
        } else {
            Import-Module -Name $module
        }
    } catch {
        [Console]::Error.WriteLine("ERROR: module $module could not be imported")
        exit 3
    }

    $command = Get-Command -Name $cmdlet -Module $module -CommandType Cmdlet, Function `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command -or $command.Name -cne $cmdlet) {
        Stop-Rejected "$cmdlet is not exported by $module"
    }

    $lookup = @{}
    foreach ($metadata in $command.Parameters.Values) {
        $lookup[$metadata.Name] = $metadata
        foreach ($alias in $metadata.Aliases) { $lookup[$alias] = $metadata }
    }
    $splat = @{}
    foreach ($key in @($parameters.Keys)) {
        if ($key -cnotmatch $ParameterPattern) { Stop-Rejected 'invalid parameter name' }
        if ($denied.Contains($key)) { Stop-Rejected "-$key is not allowed" }
        # Exact names only; PowerShell would otherwise accept a unique prefix like -DefaultP.
        if (-not $lookup.ContainsKey($key)) { Stop-Rejected "-$key is not a parameter of $cmdlet" }
        $metadata = $lookup[$key]
        foreach ($name in @($metadata.Name) + @($metadata.Aliases)) {
            if ($denied.Contains($name)) { Stop-Rejected "-$key is not allowed" }
        }
        if ($splat.ContainsKey($metadata.Name)) { Stop-Rejected "-$($metadata.Name) is given twice" }
        $splat[$metadata.Name] = ConvertTo-ParameterValue $parameters[$key] $metadata
    }
    if ($command.Parameters.ContainsKey('Confirm')) { $splat['Confirm'] = $false }
    if (-not $splat.ContainsKey('ErrorAction')) { $splat['ErrorAction'] = 'Stop' }
    elseif ([string]$splat['ErrorAction'] -notin 'Stop', 'Continue', 'SilentlyContinue', 'Ignore') {
        Stop-Rejected '-ErrorAction must be Stop, Continue, SilentlyContinue or Ignore'
    }
    $splat['WarningAction'] = 'SilentlyContinue'
    $splat['WarningVariable'] = 'reproWarnings'
    $reproWarnings = $null

    try {
        $output = & $command @splat
    } catch {
        Write-ErrorRecord $_
        exit 1
    } finally {
        foreach ($warning in @($reproWarnings)) {
            if ($null -ne $warning) { [Console]::Error.WriteLine("WARNING: $warning") }
        }
    }
    if ($null -ne $output) {
        try {
            $output | ConvertTo-Json -Depth 3 -WarningAction SilentlyContinue
        } catch {
            $output | Out-String -Width 250
        }
    }
}

$request = Read-Request
if ($request -isnot [System.Collections.IDictionary]) { Stop-Rejected 'request must be an object' }
try {
    switch ($Action) {
        'Install' { Invoke-Install $request }
        'Connect' { Invoke-Connect }
        'NewGroup' { Invoke-NewGroup $request }
        'RemoveGroup' { Invoke-RemoveGroup $request }
        'Invoke' { Invoke-ReproStep $request }
        'Disconnect' { Invoke-Disconnect }
    }
} catch {
    Write-ErrorRecord $_
    exit 1
}
exit 0
