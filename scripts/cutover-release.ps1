[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\+[0-9a-f]{7}$')]
    [string]$ReleaseId,
    [string]$InstallRoot = (Join-Path $env:USERPROFILE '.codex\agent-bridge'),
    [string]$UserProfile = $env:USERPROFILE,
    [string]$AppData = $env:APPDATA,
    [string]$LocalAppData = $env:LOCALAPPDATA,
    [string]$StateDir = (Join-Path $env:USERPROFILE '.agent-bridge'),
    [string]$NodePath,
    [string]$StagedConfigPath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedConfigSha256,
    [switch]$ApplyStateAcl,
    [string]$StateAclBackupPath,
    [ValidateRange(2,10)][int]$QuiescenceSamples = 2,
    [ValidateRange(250,30000)][int]$QuiescenceIntervalMilliseconds = 1500
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'cutover-lock.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'cutover-quiescence.psm1') -Force

function ConvertFrom-OperationJson($Output, [string]$Label) {
    $text = @($Output) -join [Environment]::NewLine
    try { return $text | ConvertFrom-Json }
    catch { throw "$Label returned malformed JSON" }
}

function Assert-RegistrationPostconditions($Inspection) {
    if ([int]$Inspection.activeProcessCount -ne 0) { throw 'registration postcondition inspection observed an active Agent Bridge process' }
    $registrations = @(
        $Inspection.registrations.codex
        $Inspection.registrations.claudeCode
        $Inspection.registrations.claudeDesktopRoaming
    ) + @($Inspection.registrations.claudeDesktopPackages)
    foreach ($registration in $registrations) {
        if (-not [bool]$registration.registrationReady -or [bool]$registration.pinsReleaseDirectly) {
            $safeEvidence = [ordered]@{
                path = [string]$registration.path
                parseStatus = [string]$registration.parseStatus
                usesExpectedNode = [bool]$registration.usesExpectedNode
                usesStableShim = [bool]$registration.usesStableShim
                usesSharedConfig = [bool]$registration.usesSharedConfig
                pinsReleaseDirectly = [bool]$registration.pinsReleaseDirectly
            } | ConvertTo-Json -Compress
            throw "registration postcondition failed: $safeEvidence"
        }
    }
    Assert-NoDivergentFallbackConfig $Inspection
}

function Assert-NoDivergentFallbackConfig($Inspection) {
    if ([bool]$Inspection.fallbackConfig.exists) {
        $fallbackPathMatches = [string]$Inspection.fallbackConfig.path -ieq [string]$Inspection.config.path
        $fallbackSha = [string]$Inspection.fallbackConfig.sha256
        $sharedSha = [string]$Inspection.config.sha256
        $fallbackHashMatches = -not [string]::IsNullOrWhiteSpace($fallbackSha) -and
            -not [string]::IsNullOrWhiteSpace($sharedSha) -and
            $fallbackSha -ieq $sharedSha
        if (-not $fallbackPathMatches -or -not $fallbackHashMatches) {
            throw 'registration postcondition found a fallback config whose path or SHA-256 differs from the installed shared config'
        }
    }
}

function Assert-StateAclBackupPath([string]$Path, [string]$StatePath, [string]$InstallPath) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw 'StateAclBackupPath must be an absolute path when state ACL hardening is requested' }
    $backup = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $backup) { throw "StateAclBackupPath must not already exist: $backup" }
    $prefixes = @($StatePath, $InstallPath) | ForEach-Object { $_.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar }
    $insideProtectedRoot = @($prefixes | Where-Object { $backup.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    if ($backup -ieq $StatePath -or $backup -ieq $InstallPath -or $insideProtectedRoot) { throw "StateAclBackupPath must be outside StateDir and InstallRoot: $backup" }
    $parent = [IO.Path]::GetDirectoryName($backup)
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "StateAclBackupPath parent must already exist: $parent" }
    $cursor = $parent
    while ($true) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "StateAclBackupPath parent contains a reparse point: $($item.FullName)" }
        $next = [IO.Path]::GetDirectoryName($cursor); if ([string]::IsNullOrEmpty($next) -or $next -eq $cursor) { break }; $cursor = $next
    }
    return $backup
}

$root = [IO.Path]::GetFullPath($InstallRoot)
$state = [IO.Path]::GetFullPath($StateDir)
$lock = Enter-AgentBridgeMutationLock -InstallRoot $root
try {
    if ($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG) { [IO.File]::AppendAllText($env:AGENT_BRIDGE_TEST_MUTATION_PID_LOG, "cutover:$PID`n", [Text.UTF8Encoding]::new($false)) }
    # This is deliberately an outer-cutover gate. Lower-level switch-release
    # keeps its legacy rollback compatibility and must not be tightened here.
    $target = Get-AgentBridgeCutoverTargetEvidence -InstallRoot $root -ReleaseId $ReleaseId
    if ($null -eq $target.operations -or [string]$target.operations.contract.capability -cne 'immutable-release-operations-v2' -or [int]$target.operations.contract.schemaVersion -ne 2) {
        throw 'cutover requires immutable-release-operations-v2 with state protection'
    }
    $execution = Get-AgentBridgeExecutionProvenance -OperationDirectory $PSScriptRoot
    Assert-AgentBridgeNoActiveProcesses -InstallRoot $root
    $initialQuiescence = @(Assert-AgentBridgeOperationalQuiescence -InstallRoot $root -Samples $QuiescenceSamples -IntervalMilliseconds $QuiescenceIntervalMilliseconds)
    # This deliberately precedes ACL mutation: a known divergent fallback is a
    # release blocker, not a reason to leave a newly hardened ACL behind.
    $preflightInspectArgs = @{ InstallRoot = $root; StateDir = $state; UserProfile = $UserProfile; AppData = $AppData; LocalAppData = $LocalAppData }
    if ($NodePath) { $preflightInspectArgs.NodePath = $NodePath }
    $preflightInspection = ConvertFrom-OperationJson (& (Join-Path $PSScriptRoot 'inspect-install.ps1') @preflightInspectArgs) 'fallback preflight inspection'
    Assert-NoDivergentFallbackConfig $preflightInspection
    $protectScript = Join-Path $PSScriptRoot 'protect-state.ps1'
    $stateAuditBefore = ConvertFrom-OperationJson (& $protectScript -StateDir $state -AuditOnly) 'state ACL audit'
    $stateProtection = $null
    $stateProtectionInvoked = $false
    $configure = $null
    if (-not [bool]$stateAuditBefore.compliant) {
        if (-not $ApplyStateAcl) {
            throw 'state ACL is noncompliant; explicit -ApplyStateAcl authorization is required before cutover may change ACLs'
        }
        $stateAclBackup = Assert-StateAclBackupPath $StateAclBackupPath $state $root
        $stateProtectionInvoked = $true
        $stateProtection = ConvertFrom-OperationJson (& $protectScript -StateDir $state -BackupPath $stateAclBackup -Force -Confirm:$false) 'state ACL protection'
        if (-not [bool]$stateProtection.compliant -or [string]$stateProtection.status -cne 'protected') { throw 'state ACL protection did not establish a compliant tree' }
    }
    try {
        $stateAuditAfter = ConvertFrom-OperationJson (& $protectScript -StateDir $state -AuditOnly) 'state ACL postcondition audit'
        if (-not [bool]$stateAuditAfter.compliant) { throw 'state ACL postcondition failed' }
        $configureArgs = @{ Apply = $true; InternalMutation = $true; MutationContextToken = $lock.Token; MutationOwnerPid = $PID; InstallRoot = $root; UserProfile = $UserProfile; AppData = $AppData; LocalAppData = $LocalAppData }
        if ($NodePath) { $configureArgs.NodePath = $NodePath }
        $configure = & (Join-Path $PSScriptRoot 'configure-clients.ps1') @configureArgs
        if ($configure.status -ne 'applied') { throw "registration apply failed: $($configure | ConvertTo-Json -Depth 10 -Compress)" }
        $inspectArgs = @{ InstallRoot = $root; StateDir = $state; UserProfile = $UserProfile; AppData = $AppData; LocalAppData = $LocalAppData; NodePath = [string]$configure.nodePath }
        $inspection = ConvertFrom-OperationJson (& (Join-Path $PSScriptRoot 'inspect-install.ps1') @inspectArgs) 'registration postcondition inspection'
        Assert-RegistrationPostconditions $inspection
        $promotionArgs = @{ ReleaseId = $ReleaseId; InstallRoot = $root; InternalMutation = $true; MutationContextToken = $lock.Token; MutationOwnerPid = $PID }
        if (-not [string]::IsNullOrWhiteSpace($StagedConfigPath)) {
            $promotionArgs.StagedConfigPath = $StagedConfigPath
            $promotionArgs.ExpectedConfigSha256 = $ExpectedConfigSha256
        } elseif (-not [string]::IsNullOrWhiteSpace($ExpectedConfigSha256)) {
            throw 'ExpectedConfigSha256 requires StagedConfigPath'
        }
        $verifyArgs = @{} + $promotionArgs
        $verifyArgs.VerifyOnly = $true
        $current = & (Join-Path $PSScriptRoot 'switch-release.ps1') @verifyArgs
        if ([bool]$current.current) {
            [pscustomobject]@{
                status = 'already-current'
                target = $target
                execution = $execution
                registrationBackupPath = $configure.backupPath
                initialQuiescence = $initialQuiescence
                stateAcl = [ordered]@{
                    authorization = [ordered]@{ applyStateAcl = [bool]$ApplyStateAcl; protectionInvoked = $stateProtectionInvoked; rollbackPolicy = 'forward-only-security-hardening' }
                    before = $stateAuditBefore
                    protection = $stateProtection
                    after = $stateAuditAfter
                }
                registrationPostconditions = $inspection.registrations
                promotion = [ordered]@{ verification = $current; backupPath = $null }
                operationalQuiescence = 'Operator-run evidence only; unattended promotion remains prohibited because Windows does not provide a universal launch fence for cached direct-runtime commands.'
            } | ConvertTo-Json -Depth 10
            return
        }
        $preSwitchQuiescence = @(Assert-AgentBridgeOperationalQuiescence -InstallRoot $root -Samples $QuiescenceSamples -IntervalMilliseconds $QuiescenceIntervalMilliseconds)
        $promotion = & (Join-Path $PSScriptRoot 'switch-release.ps1') @promotionArgs
        [pscustomobject]@{
            status = 'cutover-complete'
            target = $target
            execution = $execution
            registrationBackupPath = $configure.backupPath
            initialQuiescence = $initialQuiescence
            preSwitchQuiescence = $preSwitchQuiescence
            stateAcl = [ordered]@{
                authorization = [ordered]@{ applyStateAcl = [bool]$ApplyStateAcl; protectionInvoked = $stateProtectionInvoked; rollbackPolicy = 'forward-only-security-hardening' }
                before = $stateAuditBefore
                protection = $stateProtection
                after = $stateAuditAfter
            }
            registrationPostconditions = $inspection.registrations
            promotion = $promotion
            operationalQuiescence = 'Operator-run evidence only; unattended promotion remains prohibited because Windows does not provide a universal launch fence for cached direct-runtime commands.'
        } | ConvertTo-Json -Depth 8
    } catch {
        $failure = $_
        $stateAclMessage = if ($stateProtectionInvoked -and $stateProtection.backupPath) { "; state ACL hardening remains committed by policy (forward-only-security-hardening); retained backup: $($stateProtection.backupPath) ($($stateProtection.backupSha256))" } else { '' }
        if ($null -ne $configure -and $configure.backupPath) {
            $restoreArgs = @{ RestoreFrom = $configure.backupPath; Apply = $true; InternalMutation = $true; MutationContextToken = $lock.Token; MutationOwnerPid = $PID; InstallRoot = $root; UserProfile = $UserProfile; AppData = $AppData; LocalAppData = $LocalAppData }
            $restore = & (Join-Path $PSScriptRoot 'configure-clients.ps1') @restoreArgs
            if ($restore.status -ne 'restored') { throw "cutover failed${stateAclMessage}: $failure; registration recovery failed: $($restore | ConvertTo-Json -Depth 10 -Compress)" }
        }
        if ($null -ne $configure -and $configure.backupPath) { throw "cutover failed and client registrations were restored${stateAclMessage}: $failure" }
        throw "cutover failed before promotion; no client registration restore was required${stateAclMessage}: $failure"
    }
} finally { Exit-AgentBridgeMutationLock $lock }
