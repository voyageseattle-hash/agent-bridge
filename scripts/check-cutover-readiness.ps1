[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:USERPROFILE '.codex\agent-bridge'),
    [ValidateRange(2, 10)][int]$Samples = 2,
    [ValidateRange(250, 30000)][int]$IntervalMilliseconds = 1500
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'cutover-quiescence.psm1') -Force

$root = [IO.Path]::GetFullPath($InstallRoot)
$captured = @()
$captureError = $null
try {
    for ($index = 0; $index -lt $Samples; $index++) {
        $captured += Get-AgentBridgeCutoverProcessSample -InstallRoot $root
        if ($index + 1 -lt $Samples) { Start-Sleep -Milliseconds $IntervalMilliseconds }
    }
} catch {
    # Do not reflect raw CIM errors because they can contain unrelated process
    # command lines. The structured result is sufficient for operator action.
    $captureError = 'process inventory failed closed'
}

$ready = $null -eq $captureError -and @($captured).Count -eq $Samples -and
    @($captured | Where-Object { $_.bridgeProcessCount -gt 0 -or $_.hostProcessCount -gt 0 }).Count -eq 0
$report = [ordered]@{
    schemaVersion = 1
    status = if ($ready) { 'ready' } elseif ($captureError) { 'error' } else { 'not-ready' }
    ready = $ready
    installRoot = $root
    requestedSamples = $Samples
    intervalMilliseconds = $IntervalMilliseconds
    samples = $captured
    error = $captureError
    operationalQuiescence = 'This read-only check reduces stale-registration launch risk by requiring bridge nodes and known Codex/Claude host families plus descendants to remain absent across samples. It cannot prevent an external user or service from launching a host after the final sample; unattended promotion remains unsafe without host-aware launch control.'
}
$report | ConvertTo-Json -Depth 8
if (-not $ready) { exit 2 }
