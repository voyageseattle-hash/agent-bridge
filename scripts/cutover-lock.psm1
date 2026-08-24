Set-StrictMode -Version Latest

function Get-AgentBridgeCutoverIdentity {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)
    $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\', '/')
    $bytes = [Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant())
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    return [pscustomobject]@{ Root = $root; DiagnosticPath = (Join-Path $root '.agent-bridge-cutover.lock'); MutexName = "Local\AgentBridgeCutover-$digest" }
}

function Get-AgentBridgeFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-AgentBridgeReleaseMetadataFile {
    param(
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $filesProperty = $Metadata.PSObject.Properties['files']
    if ($null -eq $filesProperty -or $null -eq $filesProperty.Value) { throw 'release metadata is missing its file manifest' }
    $entry = @($filesProperty.Value.PSObject.Properties | Where-Object { $_.Name -ceq $Path } | Select-Object -First 1)
    if ($entry.Count -ne 1) { throw "release metadata omits required file: $Path" }
    return $entry[0].Value
}

function Assert-AgentBridgeReleaseFile {
    param(
        [Parameter(Mandatory = $true)][string]$ReleasePath,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $relativeNative = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $path = [IO.Path]::GetFullPath((Join-Path $ReleasePath $relativeNative))
    $prefix = $ReleasePath.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$Label is missing: $RelativePath"
    }
    $entry = Get-AgentBridgeReleaseMetadataFile -Metadata $Metadata -Path $RelativePath
    $expectedHash = [string]$entry.sha256
    if ($expectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw "$Label metadata hash is invalid: $RelativePath" }
    $actualHash = Get-AgentBridgeFileSha256 -Path $path
    if ($actualHash -cne $expectedHash.ToLowerInvariant()) { throw "$Label SHA-256 mismatch: $RelativePath" }
    if ($entry.PSObject.Properties['bytes'] -and $null -ne $entry.bytes -and [IO.FileInfo]::new($path).Length -ne [long]$entry.bytes) {
        throw "$Label byte-count mismatch: $RelativePath"
    }
    return [pscustomobject][ordered]@{ path = $path; sha256 = $actualHash; bytes = [IO.FileInfo]::new($path).Length }
}

function Get-AgentBridgeCutoverTargetEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseId
    )
    $root = [IO.Path]::GetFullPath($InstallRoot)
    $releasesRoot = [IO.Path]::GetFullPath((Join-Path $root 'releases'))
    $release = [IO.Path]::GetFullPath((Join-Path $releasesRoot $ReleaseId))
    $releasePrefix = $releasesRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $release.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'release path escaped the install root' }
    if (-not (Test-Path -LiteralPath $release -PathType Container)) { throw "release is not installed: $release" }
    $metadataPath = Join-Path $release 'release-metadata.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'release is incomplete: release metadata is missing' }
    try { $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json }
    catch { throw 'release metadata is unreadable' }
    if ([string]$metadata.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { throw 'release metadata has an invalid version' }
    if ([string]$metadata.gitSha -notmatch '^[0-9a-fA-F]{7,64}$') { throw 'release metadata has an invalid Git SHA' }
    $expectedId = "$($metadata.version)+$(([string]$metadata.gitSha).Substring(0, 7).ToLowerInvariant())"
    if ($expectedId -cne $ReleaseId) { throw "release directory identity mismatch: expected $expectedId" }

    $runtime = Assert-AgentBridgeReleaseFile -ReleasePath $release -RelativePath 'server/agent-bridge.mjs' -Metadata $metadata -Label 'installed runtime'
    $operationsProperty = $metadata.PSObject.Properties['operations']
    $operations = $null
    if ($null -ne $operationsProperty) {
        $contract = $operationsProperty.Value
        $legacyEntryPoints = [ordered]@{
            readiness = 'operations/check-cutover-readiness.ps1'
            cutover = 'operations/cutover-release.ps1'
            rollback = 'operations/switch-release.ps1'
            inspection = 'operations/inspect-install.ps1'
        }
        $capability = if ($null -ne $contract) { [string]$contract.capability } else { '' }
        $schemaVersion = if ($null -ne $contract) { [int]$contract.schemaVersion } else { -1 }
        if ($capability -ceq 'immutable-release-operations-v1' -and $schemaVersion -eq 1) {
            $requiredEntryPoints = $legacyEntryPoints
            $requiredFiles = @($legacyEntryPoints.Values + @('operations/configure-clients.ps1', 'operations/cutover-lock.psm1', 'operations/cutover-quiescence.psm1'))
        } elseif ($capability -ceq 'immutable-release-operations-v2' -and $schemaVersion -eq 2) {
            $requiredEntryPoints = [ordered]@{}
            foreach ($entry in $legacyEntryPoints.GetEnumerator()) { $requiredEntryPoints[$entry.Key] = $entry.Value }
            $requiredEntryPoints.stateProtection = 'operations/protect-state.ps1'
            $requiredFiles = @($legacyEntryPoints.Values + @('operations/protect-state.ps1', 'operations/configure-clients.ps1', 'operations/cutover-lock.psm1', 'operations/cutover-quiescence.psm1'))
        } else {
            throw 'unsupported immutable release operation contract'
        }
        $requiredPayloads = @('server/agent-bridge.mjs', 'server/agent-bridge.mjs.map') + $requiredFiles
        if ([string]$contract.platform -cne 'windows' -or $null -eq $contract.entryPoints) {
            throw 'unsupported immutable release operation contract'
        }
        $actualEntryPointNames = @($contract.entryPoints.PSObject.Properties.Name)
        if ($actualEntryPointNames.Count -ne $requiredEntryPoints.Count -or @(Compare-Object -CaseSensitive $actualEntryPointNames @($requiredEntryPoints.Keys) -SyncWindow 0).Count -gt 0) {
            throw 'immutable release operation entry point inventory mismatch'
        }
        foreach ($entryPoint in $requiredEntryPoints.GetEnumerator()) {
            $actual = $contract.entryPoints.PSObject.Properties[$entryPoint.Key]
            if ($null -eq $actual -or [string]$actual.Value -cne $entryPoint.Value) { throw "immutable release operation entry point mismatch: $($entryPoint.Key)" }
        }
        if ($contract.payloads -isnot [array]) { throw 'immutable release operation payload inventory is missing or invalid' }
        $declaredPayloads = @($contract.payloads | ForEach-Object { [string]$_ })
        if ($declaredPayloads.Count -ne $requiredPayloads.Count -or @(Compare-Object -CaseSensitive $declaredPayloads $requiredPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release operation payload inventory mismatch'
        }
        $expectedPayloads = @($requiredPayloads | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
        $metadataPayloads = @($metadata.files.PSObject.Properties | ForEach-Object { $_.Name.Replace('\', '/').ToLowerInvariant() } | Sort-Object)
        if ($metadataPayloads.Count -ne $expectedPayloads.Count -or @(Compare-Object -CaseSensitive $metadataPayloads $expectedPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release metadata payload inventory mismatch'
        }
        $installedPayloads = @(
            $releaseContentPrefix = $release.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
            Get-ChildItem -LiteralPath $release -File -Recurse | ForEach-Object {
                $_.FullName.Substring($releaseContentPrefix.Length).Replace('\', '/').ToLowerInvariant()
            } | Where-Object { $_ -notin @('manifest.json', 'release-metadata.json') } | Sort-Object
        )
        if ($installedPayloads.Count -ne $expectedPayloads.Count -or @(Compare-Object -CaseSensitive $installedPayloads $expectedPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release installed payload inventory mismatch'
        }
        $sourceMap = Assert-AgentBridgeReleaseFile -ReleasePath $release -RelativePath 'server/agent-bridge.mjs.map' -Metadata $metadata -Label 'installed source map'
        $operationEvidence = @()
        foreach ($relativePath in $requiredFiles) {
            $operationEvidence += Assert-AgentBridgeReleaseFile -ReleasePath $release -RelativePath $relativePath -Metadata $metadata -Label 'immutable release operation'
        }
        $operations = [pscustomobject][ordered]@{
            directory = Join-Path $release 'operations'
            contract = $contract
            sourceMap = $sourceMap
            files = $operationEvidence
        }
    }
    return [pscustomobject][ordered]@{
        releaseId = $ReleaseId
        releasePath = $release
        metadataPath = $metadataPath
        version = [string]$metadata.version
        gitSha = [string]$metadata.gitSha
        runtime = $runtime
        operations = $operations
    }
}

function Get-AgentBridgeExecutionProvenance {
    param([Parameter(Mandatory = $true)][string]$OperationDirectory)
    $directory = [IO.Path]::GetFullPath($OperationDirectory)
    $files = @()
    foreach ($name in @('cutover-release.ps1', 'configure-clients.ps1', 'switch-release.ps1', 'inspect-install.ps1', 'protect-state.ps1', 'cutover-lock.psm1', 'cutover-quiescence.psm1')) {
        $path = Join-Path $directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "executing operation file is missing: $path" }
        $files += [pscustomobject][ordered]@{ name = $name; path = $path; sha256 = Get-AgentBridgeFileSha256 -Path $path; bytes = [IO.FileInfo]::new($path).Length }
    }
    return [pscustomobject][ordered]@{ operationDirectory = $directory; files = $files }
}

function Enter-AgentBridgeMutationLock {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $identity = Get-AgentBridgeCutoverIdentity -InstallRoot $InstallRoot
    $token = [Guid]::NewGuid().ToString('N')
    $claimedDiagnostic = $false
    try {
        $claim = @{ schemaVersion = 1; status = 'active'; pid = $PID; token = $token; acquiredAt = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
        $claimBytes = [Text.UTF8Encoding]::new($false).GetBytes($claim + [Environment]::NewLine)
        $claimStream = [IO.File]::Open($identity.DiagnosticPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $claimStream.Write($claimBytes, 0, $claimBytes.Length); $claimStream.Flush($true) }
        finally { $claimStream.Dispose() }
        $claimedDiagnostic = $true
    } catch [IO.IOException] {
        throw "another Agent Bridge cutover mutation owns the install lock: $($identity.DiagnosticPath); do not delete or reclaim it automatically"
    }
    $mutex = [Threading.Mutex]::new($false, $identity.MutexName)
    $acquired = $false
    $preserveDiagnostic = $false
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] {
            # An abandoned owner can have left a half-written shim/config pair.
            # Do not inherit and continue. Our durable claim makes every later
            # invocation refuse even after the named mutex object disappears.
            $acquired = $true
            $preserveDiagnostic = $true
            $abandoned = @{ schemaVersion = 1; status = 'abandoned'; pid = $PID; token = $token; observedAt = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
            [IO.File]::WriteAllText($identity.DiagnosticPath, $abandoned + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
            throw "Agent Bridge cutover mutex was abandoned for $($identity.Root); inspect the install and diagnostic lock before retrying"
        }
        if (-not $acquired) { throw "another Agent Bridge cutover mutation owns the install mutex: $($identity.DiagnosticPath); do not delete or reclaim it automatically" }
        return [pscustomobject]@{ Path = $identity.DiagnosticPath; Token = $token; Mutex = $mutex; MutexName = $identity.MutexName; OwnerPid = $PID }
    } catch {
        if ($acquired) { try { $mutex.ReleaseMutex() } catch {} }
        $mutex.Dispose()
        if ($claimedDiagnostic -and -not $preserveDiagnostic) {
            try {
                $record = [IO.File]::ReadAllText($identity.DiagnosticPath) | ConvertFrom-Json
                if ($record.token -ceq $token -and [int]$record.pid -eq $PID) { Remove-Item -LiteralPath $identity.DiagnosticPath -Force }
            } catch {}
        }
        throw
    }
}

function Exit-AgentBridgeMutationLock {
    param([Parameter(Mandatory = $true)]$Lock)
    try {
        if (-not (Test-Path -LiteralPath $Lock.Path -PathType Leaf)) { throw "cutover diagnostic lock disappeared while its mutex remained owned: $($Lock.Path)" }
        $record = [IO.File]::ReadAllText($Lock.Path) | ConvertFrom-Json
        if ($record.token -cne $Lock.Token -or [int]$record.pid -ne [int]$Lock.OwnerPid) {
            throw "cutover diagnostic lock ownership mismatch: $($Lock.Path)"
        }
        # Delete while the named mutex is still owned. A contender cannot enter
        # between ownership verification and this removal.
        Remove-Item -LiteralPath $Lock.Path -Force
    } finally {
        try { $Lock.Mutex.ReleaseMutex() } finally { $Lock.Mutex.Dispose() }
    }
}

function Assert-AgentBridgeMutationChildContext {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][int]$OwnerPid
    )
    if ($Token -notmatch '^[0-9a-f]{32}$') { throw 'invalid Agent Bridge cutover child context token' }
    $identity = Get-AgentBridgeCutoverIdentity -InstallRoot $InstallRoot
    if (-not (Test-Path -LiteralPath $identity.DiagnosticPath -PathType Leaf)) { throw 'Agent Bridge cutover child context has no active owner diagnostic lock' }
    try { $record = [IO.File]::ReadAllText($identity.DiagnosticPath) | ConvertFrom-Json }
    catch { throw "invalid Agent Bridge cutover child context diagnostic lock: $($_.Exception.Message)" }
    if ($record.token -cne $Token -or [int]$record.pid -ne $OwnerPid) { throw 'Agent Bridge cutover child context does not match the active owner' }
    if ($PID -ne $OwnerPid) { throw 'Agent Bridge cutover internal mutation does not run in the lock-owning process' }
}

function Assert-AgentBridgeNoActiveProcesses {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)
    $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\', '/')
    $rootForward = $root.Replace('\', '/')
    try { $active = @(CimCmdlets\Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction Stop | Where-Object {
        if (-not $_.CommandLine -or $_.CommandLine -notmatch '(?i)agent-bridge') { return $false }
        $forward = $_.CommandLine.Replace('\', '/')
        return $_.CommandLine.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $forward.IndexOf($rootForward, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }) } catch { throw 'Agent Bridge cutover process precheck failed closed' }
    if ($active.Count) {
        $pids = (@($active | Select-Object -ExpandProperty ProcessId | Sort-Object -Unique | Select-Object -First 64) -join ', ')
        throw "refusing cutover mutation while $($active.Count) Agent Bridge process(es) are active (PIDs: $pids); command lines are redacted"
    }
}

function Write-AgentBridgeBytesAtomic {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    $directory = Split-Path -Parent $Path
    $temporary = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $replaceBackup = Join-Path $directory ('.agent-bridge-' + [Guid]::NewGuid().ToString('N') + '.replace-backup')
            try { [IO.File]::Replace($temporary, $Path, $replaceBackup, $true) }
            finally { if (Test-Path -LiteralPath $replaceBackup -PathType Leaf) { Remove-Item -LiteralPath $replaceBackup -Force } }
        } else {
            Move-Item -LiteralPath $temporary -Destination $Path
        }
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Restore-AgentBridgeFileSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Snapshot)
    if ($Snapshot.Exists) { Write-AgentBridgeBytesAtomic -Path $Path -Bytes $Snapshot.Bytes }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) { Remove-Item -LiteralPath $Path -Force }
}

Export-ModuleMember -Function Enter-AgentBridgeMutationLock, Exit-AgentBridgeMutationLock, Assert-AgentBridgeMutationChildContext, Assert-AgentBridgeNoActiveProcesses, Write-AgentBridgeBytesAtomic, Restore-AgentBridgeFileSnapshot, Get-AgentBridgeCutoverTargetEvidence, Get-AgentBridgeExecutionProvenance
