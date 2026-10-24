# Trusted guest wrapper for live repro Windows VMs (Windows PowerShell 5.1).
# repro_env.py sends this file through `az vm run-command invoke` with one base64 JSON config
# substituted for the marker below; issue-derived text only ever arrives inside that config.
# The VM has no identity and never signs in, so nothing here can reach Azure credentials.
# Run Command returns only the last 4096 bytes, so the result is one compact XEA-RESULT line.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__XEA_CONFIG__')) | ConvertFrom-Json
$root = 'C:\xea'
$cli2 = 'C:\Program Files\Microsoft SDKs\Azure\CLI2'
$python = Join-Path $cli2 'python.exe'

function Emit($data) {
    $json = $data | ConvertTo-Json -Compress -Depth 5
    Write-Output ('XEA-RESULT:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
}

function Fetch($url, $path) {
    for ($i = 1; $i -le 3; $i++) {
        try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path; return }
        catch { if ($i -eq 3) { throw } ; Start-Sleep -Seconds 10 }
    }
}

function Run($file, $arguments, $timeoutSeconds, $workDir, $envVars) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $file
    $info.Arguments = $arguments
    $info.WorkingDirectory = $workDir
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.CreateNoWindow = $true
    if ($envVars) {
        foreach ($p in $envVars.PSObject.Properties) { $info.EnvironmentVariables[$p.Name] = [string]$p.Value }
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $proc = [Diagnostics.Process]::Start($info)
    $proc.StandardInput.Close()
    $out = $proc.StandardOutput.ReadToEndAsync()
    $err = $proc.StandardError.ReadToEndAsync()
    $timedOut = -not $proc.WaitForExit([int]([Math]::Max(1, $timeoutSeconds) * 1000))
    if ($timedOut) {
        try { & taskkill.exe /T /F /PID $proc.Id *> $null } catch { }
        $proc.WaitForExit(30000) | Out-Null
    } else {
        $proc.WaitForExit()
    }
    $stdout = if ($out.Wait(30000)) { $out.Result } else { '' }
    $stderr = if ($err.Wait(30000)) { $err.Result } else { '' }
    return @{
        exit_code = $(if ($timedOut) { $null } else { $proc.ExitCode })
        timed_out = $timedOut
        duration_seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 2)
        stdout = $stdout
        stderr = $stderr
    }
}

function Quote($arg) {
    $arg = [string]$arg
    if ($arg -and $arg -notmatch '[\s"]') { return $arg }
    return '"' + ($arg -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Exec($file, $argv, $label) {
    $r = Run $file (($argv | ForEach-Object { Quote $_ }) -join ' ') 1800 $root $null
    if ($r.exit_code -ne 0) { throw "$label exit $($r.exit_code): $(Tail $r.stderr 200)" }
    return $r
}

function Tail($text, $limit) {
    if ($text.Length -le $limit) { return $text }
    return $text.Substring($text.Length - $limit)
}

function Install-Cli {
    New-Item -ItemType Directory -Force -Path $root, "$root\dl", $cfg.extension_dir, $cfg.config_dir | Out-Null
    # Long source paths, as on developer machines with long paths enabled.
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1
    $msi = "$root\dl\azure-cli.msi"
    Fetch $cfg.msi_url $msi
    $p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec exit $($p.ExitCode)" }
    if (-not (Test-Path $python)) { throw 'CLI2 python.exe missing after the MSI install' }
    $env:AZURE_CONFIG_DIR = $cfg.config_dir
    $env:AZURE_EXTENSION_DIR = $cfg.extension_dir
    $source = $null
    if ($cfg.source_url) {
        $zip = "$root\dl\source.zip"
        Fetch $cfg.source_url $zip
        New-Item -ItemType Directory -Force -Path "$root\s" | Out-Null
        $members = @($cfg.source_dirs | ForEach-Object { "$($cfg.source_root)/$_" })
        Exec 'tar.exe' (@('-xf', $zip, '-C', "$root\s", '--exclude', '*/tests/*') + $members) 'tar' | Out-Null
        $source = Join-Path "$root\s" $cfg.source_root
        $paths = @($cfg.source_dirs | ForEach-Object { Join-Path $source ($_ -replace '/', '\') })
        $pip = @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input')
        if ($cfg.extension) { $pip += @('--target', (Join-Path $cfg.extension_dir $cfg.extension)) }
        Exec $python ($pip + $paths) 'pip' | Out-Null
    } elseif ($cfg.extension) {
        $add = @('-m', 'azure.cli', 'extension', 'add', '--name', $cfg.extension, '--yes')
        if ($cfg.extension_version) { $add += @('--version', $cfg.extension_version) }
        Exec $python $add 'extension add' | Out-Null
    }
    foreach ($tool in $cfg.tools) {
        if ($tool -eq 'git') {
            Fetch $cfg.git_url "$root\dl\git.exe"
            $p = Start-Process "$root\dl\git.exe" -ArgumentList @('/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES', '/SP-') -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "Git for Windows exit $($p.ExitCode)" }
        } elseif ($tool -eq 'pwsh') {
            Fetch $cfg.pwsh_url "$root\dl\pwsh.msi"
            $p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$root\dl\pwsh.msi`"", '/qn', '/norestart') -Wait -PassThru
            if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "PowerShell 7 exit $($p.ExitCode)" }
        }
    }
    $version = (Exec $python @('-m', 'azure.cli', 'version', '-o', 'json') 'az version').stdout | ConvertFrom-Json
    $ext = $null
    if ($cfg.extension -and $version.extensions) { $ext = $version.extensions.($cfg.extension) }
    Emit @{ ok = $true; cli_version = $version.'azure-cli'; extension_version = $ext; source = $source }
}

function Prepare-Work {
    if (Test-Path $cfg.work_dir) { Remove-Item -Recurse -Force $cfg.work_dir }
    New-Item -ItemType Directory -Force -Path $cfg.work_dir, $cfg.script_dir | Out-Null
    foreach ($d in $cfg.dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $cfg.work_dir $d) | Out-Null }
    foreach ($f in $cfg.files.PSObject.Properties) {
        [IO.File]::WriteAllBytes((Join-Path $cfg.work_dir $f.Name), [Convert]::FromBase64String($f.Value))
    }
    Emit @{ ok = $true }
}

function Invoke-Step {
    if ($cfg.script_name) {
        [IO.File]::WriteAllBytes((Join-Path $cfg.script_dir $cfg.script_name), [Convert]::FromBase64String($cfg.script))
    }
    # Run Command's process predates the installs, so put the new tools first on PATH.
    $env:PATH = $cfg.path_prefix + ';' + [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $r = Run $cfg.file $cfg.arguments $cfg.timeout $cfg.work_dir $cfg.env
    $found = @()
    foreach ($n in $cfg.needles) {
        $text = if ($n.stream -eq 'stderr') { $r.stderr } else { $r.stdout }
        if ($text.Contains([string]$n.text)) { $found += $n.id }
    }
    $limit = 900
    do {
        $data = @{
            exit_code = $r.exit_code; timed_out = $r.timed_out
            duration_seconds = $r.duration_seconds; found = $found
            stdout = (Tail $r.stdout $limit); stderr = (Tail $r.stderr $limit)
        }
        $size = [Text.Encoding]::UTF8.GetByteCount(($data | ConvertTo-Json -Compress -Depth 5))
        $limit = [int]($limit / 2)
    } while ($size -gt 2600 -and $limit -gt 16)
    Emit $data
}

try {
    switch ($cfg.action) {
        'install' { Install-Cli }
        'prepare' { Prepare-Work }
        'step' { Invoke-Step }
        default { throw 'unknown action' }
    }
} catch {
    Emit @{ ok = $false; error = ([string]$_.Exception.Message).Substring(0, [Math]::Min(300, ([string]$_.Exception.Message).Length)) }
}
