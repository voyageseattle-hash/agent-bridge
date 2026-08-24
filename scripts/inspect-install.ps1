[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:USERPROFILE '.codex\agent-bridge'),
    [string]$StateDir = (Join-Path $env:USERPROFILE '.agent-bridge'),
    [string]$UserProfile = $env:USERPROFILE,
    [string]$AppData = $env:APPDATA,
    [string]$LocalAppData = $env:LOCALAPPDATA,
    [string]$NodePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-DirectoryAcl([string]$Path) {
    $directory = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $directory.GetAccessControl() }
    return Get-Acl -LiteralPath $directory.FullName
}

function Test-PathValue([string]$Actual, [string]$Expected) {
    try {
        return [IO.Path]::GetFullPath($Actual).Equals([IO.Path]::GetFullPath($Expected), [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Test-ReleasePathValue([string]$Value, [string]$Root) {
    try {
        $full = [IO.Path]::GetFullPath($Value)
        $prefix = [IO.Path]::GetFullPath((Join-Path $Root 'releases')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        return $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Get-TomlSections([string]$Text) {
    $matches = [regex]::Matches($Text, '(?m)^[ \t]*\[([^\]\r\n]+)\][ \t]*(?:#[^\r\n]*)?\r?$')
    $sections = @()
    for ($index = 0; $index -lt $matches.Count; $index++) {
        $end = if ($index + 1 -lt $matches.Count) { $matches[$index + 1].Index } else { $Text.Length }
        $sections += [pscustomobject]@{
            Name = $matches[$index].Groups[1].Value.Trim()
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

function ConvertFrom-TomlStringValue([string]$Value) {
    if ($Value.Length -ge 2 -and $Value[0] -eq "'" -and $Value[$Value.Length - 1] -eq "'") {
        $literal = $Value.Substring(1, $Value.Length - 2)
        if ($literal.Contains("'") -or [regex]::IsMatch($literal, '[\x00-\x08\x0A-\x1F\x7F]')) {
            throw 'unsupported TOML literal string'
        }
        return $literal
    }
    $parsed = $Value | ConvertFrom-Json
    if ($parsed -isnot [string]) { throw 'TOML value must be a string' }
    return [string]$parsed
}

function Get-JsonObjectText([string]$Text, [int]$OpenBrace) {
    if ($OpenBrace -lt 0 -or $OpenBrace -ge $Text.Length -or $Text[$OpenBrace] -ne '{') { throw 'JSON object start is invalid' }
    $depth = 0
    $inString = $false
    $escaped = $false
    for ($index = $OpenBrace; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($inString) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') { $inString = $false }
            continue
        }
        if ($character -eq '"') { $inString = $true; continue }
        if ($character -eq '{') { $depth++ }
        elseif ($character -eq '}') {
            $depth--
            if ($depth -eq 0) { return $Text.Substring($OpenBrace, $index - $OpenBrace + 1) }
        }
    }
    throw 'JSON object is not balanced'
}

function Get-JsonTopLevelObjectProperties([string]$Text, [string[]]$Names) {
    $results = @()
    $curlyDepth = 0
    $squareDepth = 0
    $inString = $false
    $escaped = $false
    $stringStart = -1
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($inString) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -ne '"') { continue }
            $inString = $false
            if ($curlyDepth -ne 1 -or $squareDepth -ne 0) { continue }
            $name = $Text.Substring($stringStart + 1, $index - $stringStart - 1)
            if ($Names -inotcontains $name) { continue }
            $cursor = $index + 1
            while ($cursor -lt $Text.Length -and [char]::IsWhiteSpace($Text[$cursor])) { $cursor++ }
            if ($cursor -ge $Text.Length -or $Text[$cursor] -ne ':') { continue }
            $cursor++
            while ($cursor -lt $Text.Length -and [char]::IsWhiteSpace($Text[$cursor])) { $cursor++ }
            if ($cursor -lt $Text.Length -and $Text[$cursor] -eq '{') {
                $results += [pscustomobject]@{ Name = $name; Text = (Get-JsonObjectText $Text $cursor) }
            }
            continue
        }
        if ($character -eq '"') { $inString = $true; $stringStart = $index; continue }
        if ($character -eq '{') { $curlyDepth++ }
        elseif ($character -eq '}') { $curlyDepth-- }
        elseif ($character -eq '[') { $squareDepth++ }
        elseif ($character -eq ']') { $squareDepth-- }
    }
    return @($results)
}

function Get-TomlRegistrationEvidence([string]$Path, [string]$Shim, [string]$Config, [string]$Root, [string]$ExpectedNode) {
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    if (-not $exists) {
        return [ordered]@{ path = $Path; exists = $false; parseStatus = 'absent'; mentionsBridge = $false; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $text = [IO.File]::ReadAllText($Path)
    $allSections = @(Get-TomlSections $text)
    $sections = @($allSections | Where-Object { Test-AgentBridgeTomlName $_.Name })
    $envSections = @($allSections | Where-Object { Test-AgentBridgeTomlName $_.Name -Environment })
    if ($sections.Count -ne 1 -or $envSections.Count -gt 1) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = if ($sections.Count -eq 0 -and $envSections.Count -eq 0) { 'no-registration' } else { 'ambiguous' }; mentionsBridge = ($sections.Count -gt 0 -or $envSections.Count -gt 0); usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $commands = @(Get-TomlAssignmentValues $sections[0].Text 'command')
    $assignments = @(Get-TomlAssignmentValues $sections[0].Text 'args')
    if ($commands.Count -ne 1 -or $assignments.Count -ne 1) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = 'ambiguous'; mentionsBridge = $true; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $arguments = @()
    $configuredCommand = $null
    try {
        $configuredCommand = [string]($commands[0] | ConvertFrom-Json)
        # Windows PowerShell 5.1 unwraps a one-element top-level JSON array.
        # Parse it as an object property so the array shape is preserved.
        $argumentDocument = ('{"value":' + $assignments[0] + '}') | ConvertFrom-Json
        if ($argumentDocument -isnot [pscustomobject] -or $argumentDocument.value -isnot [array]) { throw 'args must be a JSON/TOML array' }
        $arguments = @($argumentDocument.value)
    } catch {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = 'unsupported-command-or-args'; mentionsBridge = $true; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $configAssignments = @(if ($envSections.Count -eq 1) { Get-TomlAssignmentValues $envSections[0].Text 'AGENT_BRIDGE_CONFIG' })
    $configuredPath = $null
    if ($configAssignments.Count -eq 1) {
        try { $configuredPath = ConvertFrom-TomlStringValue $configAssignments[0] } catch { $configuredPath = $null }
    }
    $usesStableShim = $arguments.Count -eq 1 -and (Test-PathValue ([string]$arguments[0]) $Shim)
    $usesSharedConfig = $null -ne $configuredPath -and (Test-PathValue $configuredPath $Config)
    $usesExpectedNode = $null -ne $configuredCommand -and (Test-PathValue $configuredCommand $ExpectedNode)
    return [ordered]@{
        path = $Path
        exists = $true
        parseStatus = 'parsed'
        mentionsBridge = $true
        usesExpectedNode = $usesExpectedNode
        usesStableShim = $usesStableShim
        usesSharedConfig = $usesSharedConfig
        registrationReady = ($usesExpectedNode -and $usesStableShim -and $usesSharedConfig)
        pinsReleaseDirectly = (@($arguments | Where-Object { Test-ReleasePathValue ([string]$_) $Root }).Count -gt 0)
    }
}

function Get-JsonRegistrationEvidence([string]$Path, [string]$Shim, [string]$Config, [string]$Root, [string]$ExpectedNode) {
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    if (-not $exists) {
        return [ordered]@{ path = $Path; exists = $false; parseStatus = 'absent'; mentionsBridge = $false; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $text = [IO.File]::ReadAllText($Path)
    try { $document = $text | ConvertFrom-Json } catch {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = 'invalid-json'; mentionsBridge = $false; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    if ($null -eq $document -or $document -isnot [pscustomobject]) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = 'invalid-root'; mentionsBridge = $false; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $servers = @($document.PSObject.Properties | Where-Object { $_.Name -ceq 'mcpServers' })
    if ($servers.Count -ne 1 -or $servers[0].Value -isnot [pscustomobject]) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = if ($servers.Count -eq 0) { 'no-registration' } else { 'ambiguous' }; mentionsBridge = $false; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $registrations = @($servers[0].Value.PSObject.Properties | Where-Object { $_.Name -match '^(?i:agent[-_]bridge)$' })
    if ($registrations.Count -ne 1 -or $registrations[0].Value -isnot [pscustomobject]) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = if ($registrations.Count -eq 0) { 'no-registration' } else { 'ambiguous' }; mentionsBridge = ($registrations.Count -gt 0); usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $registration = $registrations[0].Value
    $registrationText = $null
    $mcpObjects = @(Get-JsonTopLevelObjectProperties $text @('mcpServers'))
    if ($mcpObjects.Count -eq 1) {
        try {
            $aliasObjects = @(Get-JsonTopLevelObjectProperties $mcpObjects[0].Text @('agent-bridge', 'agent_bridge'))
            if ($aliasObjects.Count -eq 1) { $registrationText = $aliasObjects[0].Text }
        } catch { $registrationText = $null }
    }
    $registrationFields = @()
    if ($null -ne $registrationText) { $registrationFields = @(Get-JsonTopLevelObjectProperties $registrationText @('env')) }
    $commandCount = if ($null -ne $registrationText) { [regex]::Matches($registrationText, '(?i)"command"[ \t\r\n]*:').Count } else { 0 }
    $argsCount = if ($null -ne $registrationText) { [regex]::Matches($registrationText, '(?i)"args"[ \t\r\n]*:').Count } else { 0 }
    $envCount = if ($null -ne $registrationText) { [regex]::Matches($registrationText, '(?i)"env"[ \t\r\n]*:').Count } else { 0 }
    $configCount = if ($registrationFields.Count -eq 1) { [regex]::Matches($registrationFields[0].Text, '(?i)"AGENT_BRIDGE_CONFIG"[ \t\r\n]*:').Count } else { 0 }
    if ($null -eq $registrationText -or $commandCount -ne 1 -or $argsCount -ne 1 -or $envCount -ne 1 -or $registrationFields.Count -ne 1 -or $configCount -ne 1) {
        return [ordered]@{ path = $Path; exists = $true; parseStatus = 'ambiguous'; mentionsBridge = $true; usesExpectedNode = $false; usesStableShim = $false; usesSharedConfig = $false; registrationReady = $false; pinsReleaseDirectly = $false }
    }
    $arguments = @()
    $argumentsAreArray = $registration.PSObject.Properties.Name -contains 'args' -and $registration.args -is [array]
    if ($argumentsAreArray) { $arguments = @($registration.args) }
    $configuredCommand = if ($registration.PSObject.Properties.Name -contains 'command' -and $registration.command -is [string]) { [string]$registration.command } else { $null }
    $configuredPath = $null
    if ($registration.PSObject.Properties.Name -contains 'env' -and $registration.env -is [pscustomobject] -and $registration.env.PSObject.Properties.Name -contains 'AGENT_BRIDGE_CONFIG') {
        $configuredPath = [string]$registration.env.AGENT_BRIDGE_CONFIG
    }
    $usesStableShim = $arguments.Count -eq 1 -and (Test-PathValue ([string]$arguments[0]) $Shim)
    $usesSharedConfig = $null -ne $configuredPath -and (Test-PathValue $configuredPath $Config)
    $usesExpectedNode = $null -ne $configuredCommand -and (Test-PathValue $configuredCommand $ExpectedNode)
    return [ordered]@{
        path = $Path
        exists = $true
        parseStatus = 'parsed'
        mentionsBridge = $true
        usesExpectedNode = $usesExpectedNode
        usesStableShim = $usesStableShim
        usesSharedConfig = $usesSharedConfig
        registrationReady = ($usesExpectedNode -and $argumentsAreArray -and $usesStableShim -and $usesSharedConfig)
        pinsReleaseDirectly = (@($arguments | Where-Object { Test-ReleasePathValue ([string]$_) $Root }).Count -gt 0)
    }
}

function Get-RegistrationEvidence([string]$Path, [string]$Shim, [string]$Config, [string]$Root, [string]$ExpectedNode) {
    if ([IO.Path]::GetExtension($Path).Equals('.toml', [StringComparison]::OrdinalIgnoreCase)) {
        return Get-TomlRegistrationEvidence $Path $Shim $Config $Root $ExpectedNode
    }
    return Get-JsonRegistrationEvidence $Path $Shim $Config $Root $ExpectedNode
}

$root = [IO.Path]::GetFullPath($InstallRoot)
$shim = Join-Path $root 'agent-bridge.mjs'
$config = Join-Path $root 'config.json'
$current = Join-Path $root 'current-release.json'
$expectedNode = if ([string]::IsNullOrWhiteSpace($NodePath)) {
    $resolvedNode = @(Get-Command node.exe -CommandType Application -ErrorAction Stop)[0]
    [IO.Path]::GetFullPath([string]$resolvedNode.Source)
} else { [IO.Path]::GetFullPath($NodePath) }
$detectedProcesses = @()
try {
    # Fully qualify the built-in cmdlet and never reflect raw inventory errors or
    # command lines. Provider arguments can contain credentials and prompts.
    $detectedProcesses = @(CimCmdlets\Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction Stop | Where-Object {
        $_.CommandLine -and ($_.CommandLine -match '(?i)agent-bridge(?:\.mjs|\\releases\\|/releases/)')
    })
} catch { throw 'Agent Bridge install inspection could not capture the process inventory' }
$rootWindows = $root.TrimEnd('\', '/')
$rootForward = $rootWindows.Replace('\', '/')
$activeDetected = @($detectedProcesses | Where-Object {
    $forward = $_.CommandLine.Replace('\', '/')
    $_.CommandLine.IndexOf($rootWindows, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $forward.IndexOf($rootForward, [StringComparison]::OrdinalIgnoreCase) -ge 0
})
$allActive = @($detectedProcesses | ForEach-Object {
    [ordered]@{ pid = [int]$_.ProcessId; parentPid = [int]$_.ParentProcessId; commandLine = $null }
})
$active = @($activeDetected | ForEach-Object {
    [ordered]@{ pid = [int]$_.ProcessId; parentPid = [int]$_.ParentProcessId; commandLine = $null }
})

$aclReport = [ordered]@{ path = [IO.Path]::GetFullPath($StateDir); exists = $false; protected = $false; unexpectedAllowIdentities = @() }
if (Test-Path -LiteralPath $StateDir -PathType Container) {
    $stateAcl = Get-DirectoryAcl $StateDir
    $expected = @("$env:USERDOMAIN\$env:USERNAME", 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
    $aclReport.exists = $true
    $aclReport.protected = [bool]$stateAcl.AreAccessRulesProtected
    $aclReport.unexpectedAllowIdentities = @($stateAcl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $expected
    } | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
}

$registrations = [ordered]@{}
$registrationFiles = [ordered]@{
    codex = (Join-Path $UserProfile '.codex\config.toml')
    claudeCode = (Join-Path $UserProfile '.claude.json')
    claudeDesktopRoaming = (Join-Path $AppData 'Claude\claude_desktop_config.json')
}
$desktopPackages = @(Get-ChildItem -Path (Join-Path $LocalAppData 'Packages') -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue | ForEach-Object {
    Join-Path $_.FullName 'LocalCache\Roaming\Claude\claude_desktop_config.json'
} | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
foreach ($property in $registrationFiles.GetEnumerator()) {
    $path = [string]$property.Value
    $registrations[$property.Key] = Get-RegistrationEvidence $path $shim $config $root $expectedNode
}
$registrations.claudeDesktopPackages = @($desktopPackages | ForEach-Object {
    Get-RegistrationEvidence $_ $shim $config $root $expectedNode
})

$fallbackConfigPath = [IO.Path]::GetFullPath((Join-Path $StateDir 'config.json'))
$sharedConfigExists = Test-Path -LiteralPath $config -PathType Leaf
$fallbackConfigExists = Test-Path -LiteralPath $fallbackConfigPath -PathType Leaf
$sharedConfigSha = if ($sharedConfigExists) { Get-Sha256 $config } else { $null }
$fallbackConfigSha = if ($fallbackConfigExists) { Get-Sha256 $fallbackConfigPath } else { $null }
$fallbackDiffers = $sharedConfigExists -and $fallbackConfigExists -and $sharedConfigSha -ne $fallbackConfigSha
$unsharedRegistrationPaths = @()
if ($fallbackDiffers) {
    foreach ($name in @('codex', 'claudeCode', 'claudeDesktopRoaming')) {
        $entry = $registrations[$name]
        if ($entry.mentionsBridge -and -not $entry.usesSharedConfig) { $unsharedRegistrationPaths += [string]$entry.path }
    }
    foreach ($entry in @($registrations.claudeDesktopPackages)) {
        if ($entry.mentionsBridge -and -not $entry.usesSharedConfig) { $unsharedRegistrationPaths += [string]$entry.path }
    }
}

[ordered]@{
    schemaVersion = 1
    installRoot = $root
    expectedNodePath = $expectedNode
    shim = [ordered]@{ path = $shim; exists = (Test-Path -LiteralPath $shim -PathType Leaf); sha256 = if (Test-Path -LiteralPath $shim -PathType Leaf) { Get-Sha256 $shim } else { $null } }
    config = [ordered]@{ path = $config; exists = $sharedConfigExists; sha256 = $sharedConfigSha }
    fallbackConfig = [ordered]@{
        path = $fallbackConfigPath
        exists = $fallbackConfigExists
        sha256 = $fallbackConfigSha
        differsFromSharedConfig = $fallbackDiffers
        divergentRegistrationRisk = ($unsharedRegistrationPaths.Count -gt 0)
        affectedRegistrationPaths = @($unsharedRegistrationPaths | Sort-Object -Unique)
    }
    currentRelease = if (Test-Path -LiteralPath $current -PathType Leaf) { Get-Content -Raw -LiteralPath $current | ConvertFrom-Json } else { $null }
    activeProcessCount = $active.Count
    activeProcesses = $active
    globalActiveProcessCount = $allActive.Count
    stateAcl = $aclReport
    registrations = $registrations
} | ConvertTo-Json -Depth 8
