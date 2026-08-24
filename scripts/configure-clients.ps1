<#
.SYNOPSIS
Audits or configures Agent Bridge registrations for Codex, Claude Code, and Claude Desktop on Windows.

.DESCRIPTION
Dry-run is the default. Use -Apply only after all Agent Bridge clients have been closed. Every changed
file is copied to a timestamped backup with a restore manifest before any registration is written.

.EXAMPLE
.\scripts\configure-clients.ps1

.EXAMPLE
.\scripts\configure-clients.ps1 -Apply

.EXAMPLE
.\scripts\configure-clients.ps1 -RestoreFrom 'C:\path\to\backup'

.EXAMPLE
.\scripts\configure-clients.ps1 -RestoreFrom 'C:\path\to\backup' -Apply
#>
[CmdletBinding()]
param(
    [string]$UserProfile = $env:USERPROFILE,
    [string]$AppData = $env:APPDATA,
    [string]$LocalAppData = $env:LOCALAPPDATA,
    [string]$InstallRoot,
    [string]$NodePath,
    [string]$BackupRoot,
    [string]$RestoreFrom,
    [switch]$Apply,
    [string]$MutationContextToken,
    [int]$MutationOwnerPid,
    [switch]$InternalMutation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'cutover-lock.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'cutover-quiescence.psm1') -Force

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path)
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Write-Utf8Atomic([string]$Path, [string]$Content) {
    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $replaceBackup = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.replaced')
            try { [IO.File]::Replace($temporary, $Path, $replaceBackup) }
            finally { if (Test-Path -LiteralPath $replaceBackup) { Remove-Item -LiteralPath $replaceBackup -Force } }
        } else {
            Move-Item -LiteralPath $temporary -Destination $Path
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Write-BytesAtomic([string]$Path, [byte[]]$Content) {
    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary, $Content)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $replaceBackup = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.replaced')
            try { [IO.File]::Replace($temporary, $Path, $replaceBackup) }
            finally { if (Test-Path -LiteralPath $replaceBackup) { Remove-Item -LiteralPath $replaceBackup -Force } }
        } else {
            Move-Item -LiteralPath $temporary -Destination $Path
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Set-ObjectProperty($Object, [string]$Name, $Value) {
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function ConvertTo-TomlString([string]$Value) {
    return ($Value | ConvertTo-Json -Compress)
}

function Get-TargetProcesses([string]$Root) {
    $rootWindows = $Root.TrimEnd('\', '/')
    $rootForward = $rootWindows.Replace('\', '/')
    return @(CimCmdlets\Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction Stop | Where-Object {
        if (-not $_.CommandLine -or $_.CommandLine -notmatch '(?i)agent-bridge') { return $false }
        $commandForward = $_.CommandLine.Replace('\', '/')
        return $_.CommandLine.IndexOf($rootWindows, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $commandForward.IndexOf($rootForward, [StringComparison]::OrdinalIgnoreCase) -ge 0
    } | ForEach-Object {
        [ordered]@{ pid = $_.ProcessId; parentPid = $_.ParentProcessId; commandLine = $null }
    })
}

function Get-TomlSections([string]$Text) {
    $matches = [regex]::Matches($Text, '(?m)^[ \t]*\[([^\]\r\n]+)\][ \t]*(?:#[^\r\n]*)?\r?$')
    $sections = @()
    for ($index = 0; $index -lt $matches.Count; $index++) {
        $end = if ($index + 1 -lt $matches.Count) { $matches[$index + 1].Index } else { $Text.Length }
        $sections += [pscustomobject]@{
            Name = $matches[$index].Groups[1].Value.Trim()
            Start = $matches[$index].Index
            End = $end
            Text = $Text.Substring($matches[$index].Index, $end - $matches[$index].Index)
        }
    }
    return @($sections)
}

function Test-AgentBridgeTomlName([string]$Name, [switch]$Environment) {
    $normalized = $Name.ToLowerInvariant().Replace('"', '').Replace("'", '')
    $expected = if ($Environment) {
        @('mcp_servers.agent_bridge.env', 'mcp_servers.agent-bridge.env')
    } else {
        @('mcp_servers.agent_bridge', 'mcp_servers.agent-bridge')
    }
    return $normalized -in $expected
}

function Remove-TomlInlineComment([string]$Value) {
    $inBasicString = $false
    $inLiteralString = $false
    $escaped = $false
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $character = $Value[$index]
        if ($inBasicString) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') { $inBasicString = $false }
            continue
        }
        if ($inLiteralString) {
            if ($character -eq "'") { $inLiteralString = $false }
            continue
        }
        if ($character -eq '"') { $inBasicString = $true; continue }
        if ($character -eq "'") { $inLiteralString = $true; continue }
        if ($character -eq '#') { return $Value.Substring(0, $index).TrimEnd() }
    }
    return $Value.TrimEnd()
}

function Get-TomlAssignmentValues([string]$Text, [string]$Name) {
    $pattern = '(?m)^[ \t]*' + [regex]::Escape($Name) + '[ \t]*=[ \t]*([^\r\n]*)\r?$'
    return @([regex]::Matches($Text, $pattern) | ForEach-Object { Remove-TomlInlineComment $_.Groups[1].Value })
}

function New-TomlPlan([string]$Path, [string]$Shim, [string]$Config, [string]$Node) {
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $text = if ($exists) { [IO.File]::ReadAllText($Path) } else { '' }
    $sections = @(Get-TomlSections $text)
    $baseSections = @($sections | Where-Object { Test-AgentBridgeTomlName $_.Name })
    $envSections = @($sections | Where-Object { Test-AgentBridgeTomlName $_.Name -Environment })
    $errors = @()
    if ($baseSections.Count -gt 1) { $errors += 'multiple Agent Bridge MCP tables exist' }
    if ($envSections.Count -gt 1) { $errors += 'multiple Agent Bridge MCP environment tables exist' }
    if ($baseSections.Count -eq 0 -and $envSections.Count -gt 0) { $errors += 'an Agent Bridge environment table exists without its parent table' }

    $tomlShim = ConvertTo-TomlString $Shim
    $tomlConfig = ConvertTo-TomlString $Config
    $tomlNode = ConvertTo-TomlString $Node
    $commands = @(if ($baseSections.Count -eq 1) { Get-TomlAssignmentValues $baseSections[0].Text 'command' })
    $arguments = @(if ($baseSections.Count -eq 1) { Get-TomlAssignmentValues $baseSections[0].Text 'args' })
    $configs = @(if ($envSections.Count -eq 1) { Get-TomlAssignmentValues $envSections[0].Text 'AGENT_BRIDGE_CONFIG' })
    $correct = $baseSections.Count -eq 1 -and $envSections.Count -eq 1 -and
        $commands.Count -eq 1 -and $commands[0] -ceq $tomlNode -and
        $arguments.Count -eq 1 -and $arguments[0] -ceq "[$tomlShim]" -and
        $configs.Count -eq 1 -and $configs[0] -ceq $tomlConfig
    $activeAssignments = @($commands + $arguments + $configs) -join "`n"
    $state = if ($errors.Count) { 'ambiguous' } elseif ($correct) { 'correct' } elseif ($baseSections.Count -eq 0) {
        'absent'
    } elseif ($activeAssignments -match '(?is)agent-bridge.{0,16}releases') { 'direct-release' } else { 'stale' }

    $desired = @"
[mcp_servers.agent_bridge]
command = $tomlNode
args = [$tomlShim]
enabled = true
startup_timeout_sec = 30

[mcp_servers.agent_bridge.env]
AGENT_BRIDGE_CONFIG = $tomlConfig
"@
    $newText = $text
    if (-not $correct -and -not $errors.Count) {
        foreach ($section in @($baseSections + $envSections | Sort-Object Start -Descending)) {
            $newText = $newText.Remove($section.Start, $section.End - $section.Start)
        }
        $newText = $newText.TrimEnd() + $(if ($newText.Trim().Length) { "`r`n`r`n" } else { '' }) + $desired.Trim() + "`r`n"
    }
    return [pscustomobject]@{
        Client = 'codex'
        Path = $Path
        Exists = $exists
        State = $state
        ChangeRequired = -not $correct -and -not $errors.Count
        PlannedAction = if ($correct) { 'none' } elseif ($exists) { 'update' } else { 'create' }
        Errors = $errors
        OriginalText = $text
        NewText = $newText
    }
}

function New-JsonPlan([string]$Client, [string]$Path, [string]$Shim, [string]$Config, [string]$Node) {
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $text = if ($exists) { [IO.File]::ReadAllText($Path) } else { "{}`r`n" }
    $errors = @()
    $root = $null
    try {
        $root = $text | ConvertFrom-Json
        if ($null -eq $root -or $root -isnot [pscustomobject]) { throw 'root must be a JSON object' }
    } catch {
        $errors += "invalid JSON: $($_.Exception.Message)"
    }

    $registration = $null
    $registrationName = 'agent-bridge'
    if (-not $errors.Count) {
        $serversProperty = @($root.PSObject.Properties | Where-Object { $_.Name -ceq 'mcpServers' })
        if ($serversProperty.Count -eq 0) {
            Set-ObjectProperty $root 'mcpServers' ([pscustomobject][ordered]@{})
        } elseif ($serversProperty[0].Value -isnot [pscustomobject]) {
            $errors += 'mcpServers must be a JSON object'
        }
    }
    if (-not $errors.Count) {
        $aliases = @($root.mcpServers.PSObject.Properties | Where-Object { $_.Name -match '^(?i:agent[-_]bridge)$' })
        if ($aliases.Count -gt 1) {
            $errors += 'multiple Agent Bridge MCP registrations exist'
        } elseif ($aliases.Count -eq 1) {
            $registrationName = $aliases[0].Name
            $registration = $aliases[0].Value
            if ($registration -isnot [pscustomobject]) { $errors += 'Agent Bridge registration must be a JSON object' }
        }
    }

    $correct = $false
    $serializedRegistration = ''
    if (-not $errors.Count -and $null -ne $registration) {
        $serializedRegistration = $registration | ConvertTo-Json -Depth 30 -Compress
        $commandCorrect = $registration.PSObject.Properties.Name -contains 'command' -and [string]$registration.command -ceq $Node
        $argsCorrect = $registration.PSObject.Properties.Name -contains 'args' -and $registration.args -is [array] -and
            $registration.args.Count -eq 1 -and [string]$registration.args[0] -ceq $Shim
        $envCorrect = $registration.PSObject.Properties.Name -contains 'env' -and $registration.env -is [pscustomobject] -and
            $registration.env.PSObject.Properties.Name -contains 'AGENT_BRIDGE_CONFIG' -and
            [string]$registration.env.AGENT_BRIDGE_CONFIG -ceq $Config
        $correct = $commandCorrect -and $argsCorrect -and $envCorrect
    }
    $state = if ($errors.Count) { 'ambiguous' } elseif ($correct) { 'correct' } elseif ($null -eq $registration) {
        'absent'
    } elseif ($serializedRegistration -match '(?is)agent-bridge.{0,8}releases') { 'direct-release' } else { 'stale' }

    $newText = $text
    if (-not $correct -and -not $errors.Count) {
        if ($null -eq $registration) {
            $registration = [pscustomobject][ordered]@{}
            Set-ObjectProperty $root.mcpServers $registrationName $registration
        }
        Set-ObjectProperty $registration 'command' $Node
        Set-ObjectProperty $registration 'args' @($Shim)
        if ($registration.PSObject.Properties.Name -notcontains 'env' -or $registration.env -isnot [pscustomobject]) {
            Set-ObjectProperty $registration 'env' ([pscustomobject][ordered]@{})
        }
        Set-ObjectProperty $registration.env 'AGENT_BRIDGE_CONFIG' $Config
        $newText = ($root | ConvertTo-Json -Depth 100) + "`r`n"
    }
    return [pscustomobject]@{
        Client = $Client
        Path = $Path
        Exists = $exists
        State = $state
        ChangeRequired = -not $correct -and -not $errors.Count
        PlannedAction = if ($correct) { 'none' } elseif ($exists) { 'update' } else { 'create' }
        Errors = $errors
        OriginalText = $text
        NewText = $newText
    }
}

function Convert-PlanForReport($Plan) {
    return [ordered]@{
        client = $Plan.Client
        path = $Plan.Path
        exists = $Plan.Exists
        state = $Plan.State
        changeRequired = $Plan.ChangeRequired
        plannedAction = $Plan.PlannedAction
        errors = @($Plan.Errors)
    }
}

function Write-ReportAndExit($Report, [int]$ExitCode) {
    if ($InternalMutation) { return [pscustomobject]$Report }
    $Report | ConvertTo-Json -Depth 10
    exit $ExitCode
}

$profileRoot = Get-FullPath $UserProfile
$install = Get-FullPath $(if ([string]::IsNullOrWhiteSpace($InstallRoot)) { Join-Path $profileRoot '.codex\agent-bridge' } else { $InstallRoot })
$shimPath = Join-Path $install 'agent-bridge.mjs'
$configPath = Join-Path $install 'config.json'
$backupBase = Get-FullPath $(if ([string]::IsNullOrWhiteSpace($BackupRoot)) { Join-Path $install 'client-registration-backups' } else { $BackupRoot })

$processError = $null
$activeProcesses = @()
try { $activeProcesses = @(Get-TargetProcesses $install) } catch { $processError = 'process inventory failed closed' }

if (-not [string]::IsNullOrWhiteSpace($RestoreFrom)) {
    $restoreRoot = Get-FullPath $RestoreFrom
    $manifestPath = Join-Path $restoreRoot 'restore-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "restore manifest not found: $manifestPath" }
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $manifestFiles = @($manifest.files)
    $restoreItems = @($manifestFiles | ForEach-Object {
        [ordered]@{ path = [string]$_.originalPath; action = if ([bool]$_.existed) { 'restore' } else { 'remove-created' }; backupFile = $_.backupFile }
    })
    $errors = @()
    if ((Get-FullPath ([string]$manifest.installRoot)) -ne $install) { $errors += 'restore manifest belongs to a different install root' }
    $fixedRestoreTargets = @(
        (Get-FullPath (Join-Path $profileRoot '.codex\config.toml')),
        (Get-FullPath (Join-Path $profileRoot '.claude.json')),
        (Get-FullPath (Join-Path (Get-FullPath $AppData) 'Claude\claude_desktop_config.json'))
    )
    $packageRestoreRoot = (Get-FullPath (Join-Path (Get-FullPath $LocalAppData) 'Packages')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $seenRestoreTargets = @{}
    foreach ($entry in $manifestFiles) {
        $target = Get-FullPath ([string]$entry.originalPath)
        $relativePackageTarget = if ($target.StartsWith($packageRestoreRoot, [StringComparison]::OrdinalIgnoreCase)) { $target.Substring($packageRestoreRoot.Length) } else { '' }
        $isPackagedTarget = $relativePackageTarget -match '^Claude_[^\\]+\\LocalCache\\Roaming\\Claude\\claude_desktop_config\.json$'
        if ($target -notin $fixedRestoreTargets -and -not $isPackagedTarget) { $errors += "restore target is outside known client config paths: $target" }
        if ($seenRestoreTargets.ContainsKey($target.ToLowerInvariant())) { $errors += "duplicate restore target: $target" }
        $seenRestoreTargets[$target.ToLowerInvariant()] = $true
        if ([bool]$entry.existed) {
            $source = Get-FullPath (Join-Path $restoreRoot ([string]$entry.backupFile))
            $prefix = $restoreRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
            if (-not $source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $source -PathType Leaf)) {
                $errors += "unsafe or missing restore source: $source"
            } elseif ($entry.originalSha256 -and (Get-Sha256 $source) -ne [string]$entry.originalSha256) {
                $errors += "restore source SHA-256 mismatch: $source"
            }
        }
    }
    if ($processError) { $errors += "could not inspect Agent Bridge processes: $processError" }
    if ($activeProcesses.Count) { $errors += "refusing restore while $($activeProcesses.Count) Agent Bridge process(es) use $install" }
    $report = [ordered]@{
        schemaVersion = 1; operation = 'restore'; apply = [bool]$Apply
        status = if ($errors.Count) { 'refused' } elseif ($Apply) { 'restored' } else { 'dry-run' }
        installRoot = $install; restoreFrom = $restoreRoot; activeProcesses = $activeProcesses
        changes = $restoreItems; errors = $errors
    }
    if ($errors.Count -and $Apply) { return (Write-ReportAndExit $report 2) }
    if ($Apply) {
        $lock = $null
        if ($MutationContextToken) {
            if (-not $InternalMutation) { throw 'Agent Bridge cutover context requires an in-process mutation invocation' }
            Assert-AgentBridgeMutationChildContext -InstallRoot $install -Token $MutationContextToken -OwnerPid $MutationOwnerPid
        }
        else { $lock = Enter-AgentBridgeMutationLock -InstallRoot $install }
        try {
            Assert-AgentBridgeNoActiveProcesses -InstallRoot $install
            if (-not $InternalMutation) {
                Assert-AgentBridgeOperationalQuiescence -InstallRoot $install -Samples 2 -IntervalMilliseconds 1500 | Out-Null
            }
            $prefix = $restoreRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
            foreach ($entry in @($manifest.files)) {
                $target = Get-FullPath ([string]$entry.originalPath)
                if ([bool]$entry.existed) {
                    $source = Get-FullPath (Join-Path $restoreRoot ([string]$entry.backupFile))
                    if (-not $source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $source -PathType Leaf)) {
                        throw "unsafe or missing restore source: $source"
                    }
                    $bytes = [IO.File]::ReadAllBytes($source)
                    Write-BytesAtomic $target $bytes
                } elseif (Test-Path -LiteralPath $target -PathType Leaf) {
                    Remove-Item -LiteralPath $target -Force
                }
            }
        } finally { if ($null -ne $lock) { Exit-AgentBridgeMutationLock $lock } }
    }
    return (Write-ReportAndExit $report 0)
}

if ([string]::IsNullOrWhiteSpace($NodePath)) {
    $nodeCommand = Get-Command node.exe -ErrorAction Stop
    $NodePath = $nodeCommand.Source
}
$node = Get-FullPath $NodePath
$plans = @()
$plans += New-TomlPlan (Join-Path $profileRoot '.codex\config.toml') $shimPath $configPath $node
$plans += New-JsonPlan 'claude-code' (Join-Path $profileRoot '.claude.json') $shimPath $configPath $node
$plans += New-JsonPlan 'claude-desktop-legacy' (Join-Path (Get-FullPath $AppData) 'Claude\claude_desktop_config.json') $shimPath $configPath $node

$packagesRoot = Join-Path (Get-FullPath $LocalAppData) 'Packages'
$packageCandidates = @()
if (Test-Path -LiteralPath $packagesRoot -PathType Container) {
    $packageCandidates = @(Get-ChildItem -LiteralPath $packagesRoot -Directory -Filter 'Claude_*' -ErrorAction Stop | Sort-Object FullName)
    foreach ($package in $packageCandidates) {
        $desktopPath = Join-Path $package.FullName 'LocalCache\Roaming\Claude\claude_desktop_config.json'
        $plans += New-JsonPlan 'claude-desktop-packaged' $desktopPath $shimPath $configPath $node
    }
}

$errors = @($plans | ForEach-Object { $_.Errors } | Where-Object { $_ })
$prerequisites = [ordered]@{
    nodeExists = (Test-Path -LiteralPath $node -PathType Leaf)
    shimExists = (Test-Path -LiteralPath $shimPath -PathType Leaf)
    configExists = (Test-Path -LiteralPath $configPath -PathType Leaf)
}
if (-not $prerequisites.nodeExists) { $errors += "Node executable does not exist: $node" }
if (-not $prerequisites.shimExists) { $errors += "stable shim does not exist: $shimPath" }
if (-not $prerequisites.configExists) { $errors += "shared config does not exist: $configPath" }
if ($packageCandidates.Count -gt 1) { $errors += "multiple packaged Claude Desktop profiles found; target is ambiguous" }
if ($processError) { $errors += "could not inspect Agent Bridge processes: $processError" }
if ($activeProcesses.Count) { $errors += "refusing Apply while $($activeProcesses.Count) Agent Bridge process(es) use $install" }
$changes = @($plans | Where-Object { $_.ChangeRequired })
$report = [ordered]@{
    schemaVersion = 1
    operation = 'configure'
    apply = [bool]$Apply
    status = if ($Apply -and $errors.Count) { 'refused' } elseif ($Apply) { 'applied' } else { 'dry-run' }
    installRoot = $install
    shimPath = $shimPath
    configPath = $configPath
    nodePath = $node
    prerequisites = $prerequisites
    desktopPackageCandidates = @($packageCandidates | ForEach-Object { $_.FullName })
    activeProcesses = $activeProcesses
    backupPath = $null
    clients = @($plans | ForEach-Object { Convert-PlanForReport $_ })
    errors = $errors
}

if ($Apply -and $errors.Count) { return (Write-ReportAndExit $report 2) }
if ($Apply -and $changes.Count) {
    $lock = $null
    if ($MutationContextToken) {
        if (-not $InternalMutation) { throw 'Agent Bridge cutover context requires an in-process mutation invocation' }
        Assert-AgentBridgeMutationChildContext -InstallRoot $install -Token $MutationContextToken -OwnerPid $MutationOwnerPid
    }
    else { $lock = Enter-AgentBridgeMutationLock -InstallRoot $install }
    try {
        # Recheck under the shared lock immediately before any backup or write.
        Assert-AgentBridgeNoActiveProcesses -InstallRoot $install
        if (-not $InternalMutation) {
            Assert-AgentBridgeOperationalQuiescence -InstallRoot $install -Samples 2 -IntervalMilliseconds 1500 | Out-Null
        }
        if ($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG) { [IO.File]::AppendAllText($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG, "configure:$PID`n", [Text.UTF8Encoding]::new($false)) }
        $backupPath = Join-Path $backupBase ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        $manifestFiles = @()
        for ($index = 0; $index -lt $changes.Count; $index++) {
            $plan = $changes[$index]
            $currentExists = Test-Path -LiteralPath $plan.Path -PathType Leaf
            if ($currentExists -ne $plan.Exists -or ($currentExists -and [IO.File]::ReadAllText($plan.Path) -cne $plan.OriginalText)) {
                throw "client config changed during preflight: $($plan.Path)"
            }
            $backupFile = $null
            if ($plan.Exists) {
                $backupFile = Join-Path 'files' ('{0:D3}-{1}' -f $index, [IO.Path]::GetFileName($plan.Path))
                $backupTarget = Join-Path $backupPath $backupFile
                New-Item -ItemType Directory -Path (Split-Path -Parent $backupTarget) -Force | Out-Null
                Copy-Item -LiteralPath $plan.Path -Destination $backupTarget
            }
            $manifestFiles += [ordered]@{
                client = $plan.Client; originalPath = $plan.Path; existed = $plan.Exists
                originalSha256 = if ($plan.Exists) { Get-Sha256 $plan.Path } else { $null }
                backupFile = $backupFile
            }
        }
        $manifest = [ordered]@{
            schemaVersion = 1; createdAt = (Get-Date).ToUniversalTime().ToString('o')
            installRoot = $install; shimPath = $shimPath; configPath = $configPath; files = $manifestFiles
        }
        Write-Utf8Atomic (Join-Path $backupPath 'restore-manifest.json') (($manifest | ConvertTo-Json -Depth 10) + "`r`n")

        $written = @()
        try {
            foreach ($plan in $changes) {
                $written += $plan
                Write-Utf8Atomic $plan.Path $plan.NewText
            }
        } catch {
            foreach ($plan in @($written | Sort-Object { [array]::IndexOf($written, $_) } -Descending)) {
                $entry = @($manifestFiles | Where-Object { $_.originalPath -eq $plan.Path })[0]
                if ($entry.existed) { Copy-Item -LiteralPath (Join-Path $backupPath $entry.backupFile) -Destination $plan.Path -Force }
                elseif (Test-Path -LiteralPath $plan.Path -PathType Leaf) { Remove-Item -LiteralPath $plan.Path -Force }
            }
            throw
        }
        $report.backupPath = $backupPath
    } finally { if ($null -ne $lock) { Exit-AgentBridgeMutationLock $lock } }
}

return (Write-ReportAndExit $report 0)
