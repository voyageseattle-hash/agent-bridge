[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\+[0-9a-f]{7}$')]
    [string]$ReleaseId,
    [string]$InstallRoot = (Join-Path $env:USERPROFILE '.codex\agent-bridge'),
    [string]$StagedConfigPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedConfigSha256,
    [switch]$VerifyOnly,
    [string]$MutationContextToken,
    [int]$MutationOwnerPid,
    [switch]$InternalMutation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'cutover-lock.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'cutover-quiescence.psm1') -Force

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path); $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Get-Sha256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Get-Snapshot([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return [pscustomobject]@{ Exists = $true; Bytes = [IO.File]::ReadAllBytes($Path); Sha256 = Get-Sha256 $Path } }
    return [pscustomobject]@{ Exists = $false; Bytes = $null; Sha256 = $null }
}
function Write-SnapshotBackup([string]$Backup, [string]$Name, $Snapshot) {
    if ($Snapshot.Exists) { [IO.File]::WriteAllBytes((Join-Path $Backup $Name), $Snapshot.Bytes) }
}
function Get-ObjectPropertyValue($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Get-PromotionEvidence(
    [string]$ShimPath,
    [string]$ConfigPath,
    [string]$MarkerPath,
    [string]$RuntimePath,
    [string]$ExpectedReleaseId,
    [string]$ExpectedReleasePath,
    [string]$ExpectedRuntimeSha256,
    [string]$ExpectedShimSha256,
    [string]$ExpectedConfigSha256
) {
    $mismatches = @()
    $actualShimSha256 = if (Test-Path -LiteralPath $ShimPath -PathType Leaf) { Get-Sha256 $ShimPath } else { $null }
    $actualConfigSha256 = if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) { Get-Sha256 $ConfigPath } else { $null }
    $actualRuntimeSha256 = if (Test-Path -LiteralPath $RuntimePath -PathType Leaf) { Get-Sha256 $RuntimePath } else { $null }
    if ($actualShimSha256 -cne $ExpectedShimSha256) { $mismatches += 'shim-sha256' }
    if ($actualConfigSha256 -cne $ExpectedConfigSha256) { $mismatches += 'config-sha256' }
    if ($actualRuntimeSha256 -cne $ExpectedRuntimeSha256) { $mismatches += 'runtime-sha256' }
    $marker = $null
    if (Test-Path -LiteralPath $MarkerPath -PathType Leaf) {
        try { $marker = [IO.File]::ReadAllText($MarkerPath) | ConvertFrom-Json }
        catch { $mismatches += 'marker-json' }
    } else { $mismatches += 'marker-missing' }
    if ($null -ne $marker) {
        if ([int](Get-ObjectPropertyValue $marker 'schemaVersion') -ne 1) { $mismatches += 'marker-schema' }
        if ([string](Get-ObjectPropertyValue $marker 'releaseId') -cne $ExpectedReleaseId) { $mismatches += 'marker-release-id' }
        try {
            if (-not [IO.Path]::GetFullPath([string](Get-ObjectPropertyValue $marker 'releasePath')).Equals([IO.Path]::GetFullPath($ExpectedReleasePath), [StringComparison]::OrdinalIgnoreCase)) { $mismatches += 'marker-release-path' }
        } catch { $mismatches += 'marker-release-path' }
        if ([string](Get-ObjectPropertyValue $marker 'runtimeSha256') -cne $ExpectedRuntimeSha256) { $mismatches += 'marker-runtime-sha256' }
        if ([string](Get-ObjectPropertyValue $marker 'shimSha256') -cne $ExpectedShimSha256) { $mismatches += 'marker-shim-sha256' }
        if ([string](Get-ObjectPropertyValue $marker 'configSha256') -cne $ExpectedConfigSha256) { $mismatches += 'marker-config-sha256' }
    }
    return [pscustomobject][ordered]@{
        status = if ($mismatches.Count -eq 0) { 'current' } else { 'not-current' }
        current = ($mismatches.Count -eq 0)
        releaseId = $ExpectedReleaseId
        releasePath = $ExpectedReleasePath
        runtimeSha256 = $actualRuntimeSha256
        shimSha256 = $actualShimSha256
        configSha256 = $actualConfigSha256
        mismatches = @($mismatches | Sort-Object -Unique)
    }
}

$root = [IO.Path]::GetFullPath($InstallRoot)
$release = [IO.Path]::GetFullPath((Join-Path (Join-Path $root 'releases') $ReleaseId))
$releasePrefix = (Join-Path $root 'releases').TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $release.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'release path escaped the install root' }
if (-not (Test-Path -LiteralPath $release -PathType Container)) { throw "release is not installed: $release" }
$metadataPath = Join-Path $release 'release-metadata.json'; $runtimePath = Join-Path $release 'server\agent-bridge.mjs'
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or -not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) { throw 'release is incomplete' }
$metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
$expectedId = "$($metadata.version)+$(([string]$metadata.gitSha).Substring(0, 7).ToLowerInvariant())"
if ($expectedId -ne $ReleaseId) { throw "release directory identity mismatch: expected $expectedId" }
$runtimeMetadata = $metadata.files.PSObject.Properties | Where-Object Name -eq 'server/agent-bridge.mjs' | Select-Object -First 1
if (-not $runtimeMetadata -or (Get-Sha256 $runtimePath) -ne [string]$runtimeMetadata.Value.sha256) { throw 'installed runtime SHA-256 mismatch or metadata omission' }

$shimPath = Join-Path $root 'agent-bridge.mjs'; $configPath = Join-Path $root 'config.json'; $markerPath = Join-Path $root 'current-release.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "shared config is missing: $configPath" }
$desiredConfigBytes = [IO.File]::ReadAllBytes($configPath)
if ([string]::IsNullOrWhiteSpace($StagedConfigPath)) {
    if (-not [string]::IsNullOrWhiteSpace($ExpectedConfigSha256)) { throw 'ExpectedConfigSha256 requires StagedConfigPath' }
} else {
    if ([string]::IsNullOrWhiteSpace($ExpectedConfigSha256)) { throw 'StagedConfigPath requires ExpectedConfigSha256' }
    $stagedConfig = (Resolve-Path -LiteralPath $StagedConfigPath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $stagedConfig -PathType Leaf)) { throw "staged config is missing: $stagedConfig" }
    $desiredConfigBytes = [IO.File]::ReadAllBytes($stagedConfig)
    if ((Get-Sha256Bytes $desiredConfigBytes) -cne $ExpectedConfigSha256.ToLowerInvariant()) { throw 'staged config SHA-256 mismatch' }
    try { $stagedConfigDocument = [Text.UTF8Encoding]::new($false).GetString($desiredConfigBytes) | ConvertFrom-Json }
    catch { throw 'staged config is invalid JSON' }
    if ($null -eq $stagedConfigDocument -or $stagedConfigDocument -isnot [pscustomobject]) { throw 'staged config root must be a JSON object' }
}
$desiredConfigSha256 = Get-Sha256Bytes $desiredConfigBytes
$relativeRuntime = "./releases/$ReleaseId/server/agent-bridge.mjs"
$shim = (@"
#!/usr/bin/env node
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sharedConfig = fileURLToPath(new URL("./config.json", import.meta.url));
if (!process.env.AGENT_BRIDGE_CONFIG && existsSync(sharedConfig)) {
  process.env.AGENT_BRIDGE_CONFIG = sharedConfig;
}
await import(new URL("$relativeRuntime", import.meta.url).href);
"@).TrimStart()
$shimBytes = [Text.UTF8Encoding]::new($false).GetBytes($shim)
$shimSha256 = Get-Sha256Bytes $shimBytes
$maintenanceShimBytes = [Text.UTF8Encoding]::new($false).GetBytes((@'
#!/usr/bin/env node
process.stderr.write("Agent Bridge cutover is in progress; startup is temporarily refused.\n");
process.exitCode = 75;
'@).TrimStart())
$runtimeSha256 = Get-Sha256 $runtimePath
$marker = [ordered]@{ schemaVersion = 1; releaseId = $ReleaseId; releasePath = $release; runtimeSha256 = $runtimeSha256; shimSha256 = $shimSha256; configSha256 = $desiredConfigSha256; promotedAt = (Get-Date).ToUniversalTime().ToString('o'); backupPath = $null }

$lock = $null
if ($MutationContextToken) {
    if (-not $InternalMutation) { throw 'Agent Bridge cutover context requires an in-process mutation invocation' }
    Assert-AgentBridgeMutationChildContext -InstallRoot $root -Token $MutationContextToken -OwnerPid $MutationOwnerPid
}
elseif (-not $VerifyOnly) { $lock = Enter-AgentBridgeMutationLock -InstallRoot $root }
if ($VerifyOnly) {
    $verification = Get-PromotionEvidence $shimPath $configPath $markerPath $runtimePath $ReleaseId $release $runtimeSha256 $shimSha256 $desiredConfigSha256
    if ($InternalMutation) { return $verification }
    $verification | ConvertTo-Json -Depth 5
    return
}
try {
    # This is the final process check and is intentionally inside the shared
    # mutation lock. No lock is ever stale-reclaimed.
    Assert-AgentBridgeNoActiveProcesses -InstallRoot $root
    $preMutationQuiescence = @(Assert-AgentBridgeOperationalQuiescence -InstallRoot $root -Samples 2 -IntervalMilliseconds 250)
    if ($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG) { [IO.File]::AppendAllText($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG, "switch:$PID`n", [Text.UTF8Encoding]::new($false)) }
    $priorShim = Get-Snapshot $shimPath; $priorConfig = Get-Snapshot $configPath; $priorMarker = Get-Snapshot $markerPath
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $backup = Join-Path (Join-Path $root 'backups') "$timestamp-$([Guid]::NewGuid().ToString('N'))-before-$ReleaseId"
    New-Item -ItemType Directory -Path $backup -ErrorAction Stop | Out-Null
    Write-SnapshotBackup $backup 'agent-bridge.mjs' $priorShim
    Write-SnapshotBackup $backup 'config.json' $priorConfig
    Write-SnapshotBackup $backup 'current-release.json' $priorMarker
    $backupState = [ordered]@{ schemaVersion = 1; createdAt = (Get-Date).ToUniversalTime().ToString('o'); releaseId = $ReleaseId; files = @(
        @{ path = 'agent-bridge.mjs'; existed = $priorShim.Exists; sha256 = $priorShim.Sha256 },
        @{ path = 'config.json'; existed = $priorConfig.Exists; sha256 = $priorConfig.Sha256 },
        @{ path = 'current-release.json'; existed = $priorMarker.Exists; sha256 = $priorMarker.Sha256 }
    ) }
    [IO.File]::WriteAllText((Join-Path $backup 'rollback-state.json'), (($backupState | ConvertTo-Json -Depth 5) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    $marker.backupPath = $backup
    $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes(($marker | ConvertTo-Json -Depth 4) + [Environment]::NewLine)
    # Validate prepared bytes before the first mutation.
    if (-not ([Text.UTF8Encoding]::new($false).GetString($shimBytes) -match [regex]::Escape($relativeRuntime))) { throw 'prepared shim failed validation' }
    $preparedMarker = [Text.UTF8Encoding]::new($false).GetString($markerBytes) | ConvertFrom-Json
    if ($preparedMarker.releaseId -ne $ReleaseId -or $preparedMarker.runtimeSha256 -ne (Get-Sha256 $runtimePath) -or
        $preparedMarker.shimSha256 -ne $shimSha256 -or $preparedMarker.configSha256 -ne $desiredConfigSha256) { throw 'prepared promotion marker failed validation' }
    $mutated = $false
    try {
        # Establish a startup barrier before the final zero-host observation. A
        # host that began loading the old shim immediately before this atomic
        # replacement remains visible to the next process scan and aborts the
        # cutover; a host starting after it receives only the refusing shim.
        $preBarrierDelay = 0
        if ($env:AGENT_BRIDGE_TEST_PRE_BARRIER_DELAY_MS) { [void][int]::TryParse($env:AGENT_BRIDGE_TEST_PRE_BARRIER_DELAY_MS, [ref]$preBarrierDelay) }
        if ($env:AGENT_BRIDGE_TEST_PRE_BARRIER_READY_PATH) {
            [IO.File]::WriteAllText($env:AGENT_BRIDGE_TEST_PRE_BARRIER_READY_PATH, "ready`n", [Text.UTF8Encoding]::new($false))
        }
        if ($preBarrierDelay -gt 0) { Start-Sleep -Milliseconds $preBarrierDelay }
        $mutated = $true
        Write-AgentBridgeBytesAtomic -Path $shimPath -Bytes $maintenanceShimBytes
        $delay = 0
        if ($env:AGENT_BRIDGE_TEST_BARRIER_DELAY_MS) { [void][int]::TryParse($env:AGENT_BRIDGE_TEST_BARRIER_DELAY_MS, [ref]$delay) }
        if ($delay -gt 0) { Start-Sleep -Milliseconds $delay }
        Assert-AgentBridgeNoActiveProcesses -InstallRoot $root
        $barrierQuiescence = @(Assert-AgentBridgeOperationalQuiescence -InstallRoot $root -Samples 1 -IntervalMilliseconds 0)
        if (-not [string]::IsNullOrWhiteSpace($StagedConfigPath)) { Write-AgentBridgeBytesAtomic -Path $configPath -Bytes $desiredConfigBytes }
        if ($env:AGENT_BRIDGE_TEST_FAIL_CONFIG_WRITE -eq '1') { throw 'injected config write failure' }
        if ($env:AGENT_BRIDGE_TEST_FAIL_MARKER_WRITE -eq '1') { throw 'injected marker write failure' }
        Write-AgentBridgeBytesAtomic -Path $markerPath -Bytes $markerBytes
        $postMarkerDelay = 0
        if ($env:AGENT_BRIDGE_TEST_POST_MARKER_DELAY_MS) { [void][int]::TryParse($env:AGENT_BRIDGE_TEST_POST_MARKER_DELAY_MS, [ref]$postMarkerDelay) }
        if ($env:AGENT_BRIDGE_TEST_POST_MARKER_READY_PATH) {
            [IO.File]::WriteAllText($env:AGENT_BRIDGE_TEST_POST_MARKER_READY_PATH, "ready`n", [Text.UTF8Encoding]::new($false))
        }
        if ($postMarkerDelay -gt 0) { Start-Sleep -Milliseconds $postMarkerDelay }
        if ($env:AGENT_BRIDGE_TEST_FAIL_LIVE_SHIM_WRITE -eq '1') { throw 'injected live shim write failure' }
        # The marker becomes current while the maintenance shim still refuses
        # startup. Only once both identity files are prepared may a host load
        # the live runtime.
        Write-AgentBridgeBytesAtomic -Path $shimPath -Bytes $shimBytes
        $verification = Get-PromotionEvidence $shimPath $configPath $markerPath $runtimePath $ReleaseId $release $runtimeSha256 $shimSha256 $desiredConfigSha256
        if (-not $verification.current) { throw "promotion postcondition verification failed: $($verification.mismatches -join ', ')" }
    } catch {
        $failure = $_
        if ($mutated) {
            try {
                Restore-AgentBridgeFileSnapshot -Path $markerPath -Snapshot $priorMarker
                Restore-AgentBridgeFileSnapshot -Path $configPath -Snapshot $priorConfig
                Restore-AgentBridgeFileSnapshot -Path $shimPath -Snapshot $priorShim
                [IO.File]::WriteAllText((Join-Path $backup 'recovery.json'), ((@{ schemaVersion = 1; status = 'restored'; failedAt = (Get-Date).ToUniversalTime().ToString('o'); reason = $failure.Exception.Message } | ConvertTo-Json -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
            } catch { throw "promotion failed: $($failure.Exception.Message); automatic recovery also failed: $($_.Exception.Message)" }
        }
        throw "promotion failed and exact prior shim/config/marker state was restored: $($failure.Exception.Message)"
    }
    $result = [pscustomobject]@{
        schemaVersion = $marker.schemaVersion
        releaseId = $marker.releaseId
        releasePath = $marker.releasePath
        runtimeSha256 = $marker.runtimeSha256
        shimSha256 = $marker.shimSha256
        configSha256 = $marker.configSha256
        promotedAt = $marker.promotedAt
        backupPath = $marker.backupPath
        preMutationQuiescence = $preMutationQuiescence
        barrierQuiescence = $barrierQuiescence
        verification = $verification
    }
    if ($InternalMutation) { $result } else { $result | ConvertTo-Json -Depth 8 }
} finally { if ($null -ne $lock) { Exit-AgentBridgeMutationLock $lock } }
