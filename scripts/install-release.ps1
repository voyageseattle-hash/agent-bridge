[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundlePath,

    [string]$InstallRoot = (Join-Path $env:USERPROFILE '.codex\agent-bridge'),

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBundleSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$MaxReleaseEntries = 32
$MaxReleaseFileBytes = 20MB
$MaxReleaseTotalBytes = 40MB
$ImmutableOperationsV1Capability = 'immutable-release-operations-v1'
$ImmutableOperationsV2Capability = 'immutable-release-operations-v2'

function Get-Sha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Read-ZipEntryBytes($Entry) {
    $stream = $Entry.Open()
    try {
        $memory = [IO.MemoryStream]::new()
        try { $stream.CopyTo($memory); return $memory.ToArray() }
        finally { $memory.Dispose() }
    } finally { $stream.Dispose() }
}

$bundle = (Resolve-Path -LiteralPath $BundlePath).Path
$bundleHash = Get-Sha256 ([IO.File]::ReadAllBytes($bundle))
if ($ExpectedBundleSha256 -and $bundleHash -ne $ExpectedBundleSha256.ToLowerInvariant()) {
    throw "bundle SHA-256 mismatch: expected $($ExpectedBundleSha256.ToLowerInvariant()), got $bundleHash"
}
$root = [IO.Path]::GetFullPath($InstallRoot)
$releasesRoot = Join-Path $root 'releases'
New-Item -ItemType Directory -Force -Path $releasesRoot | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($bundle)
$temporary = $null
try {
    if ($archive.Entries.Count -gt $MaxReleaseEntries) { throw "bundle exceeds the $MaxReleaseEntries-entry archive limit" }
    $entries = @{}
    $payloadBytes = [long]0
    foreach ($entry in $archive.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($name) -or $name.EndsWith('/')) { continue }
        if ($name.StartsWith('/') -or $name.Contains(':') -or $name.Split('/') -contains '..') {
            throw "unsafe bundle entry: $name"
        }
        $key = $name.ToLowerInvariant()
        if ($entries.ContainsKey($key)) { throw "duplicate bundle entry: $name" }
        if ([long]$entry.Length -gt $MaxReleaseFileBytes) { throw "bundle entry exceeds the $MaxReleaseFileBytes-byte size limit: $name" }
        $payloadBytes += [long]$entry.Length
        if ($payloadBytes -gt $MaxReleaseTotalBytes) { throw "bundle exceeds the $MaxReleaseTotalBytes-byte extracted-size limit" }
        $entries[$key] = $entry
    }

    foreach ($required in @('manifest.json', 'release-metadata.json', 'server/agent-bridge.mjs', 'server/agent-bridge.mjs.map')) {
        if (-not $entries.ContainsKey($required)) { throw "bundle is missing $required" }
    }

    $metadataBytes = Read-ZipEntryBytes $entries['release-metadata.json']
    $manifestBytes = Read-ZipEntryBytes $entries['manifest.json']
    $metadata = [Text.Encoding]::UTF8.GetString($metadataBytes) | ConvertFrom-Json
    $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    if ($metadata.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { throw 'release metadata has an invalid version' }
    if ($metadata.gitSha -notmatch '^[0-9a-fA-F]{7,64}$') { throw 'release metadata has an invalid Git SHA' }
    if ($manifest.version -ne $metadata.version) { throw 'manifest and release metadata versions differ' }
    $manifestMetaProperty = $manifest.PSObject.Properties['_meta']
    if ($null -ne $manifestMetaProperty) {
        if ($null -eq $manifestMetaProperty.Value -or $manifestMetaProperty.Value -isnot [pscustomobject]) {
            throw 'manifest release metadata is invalid'
        }
        $releaseIdentityProperty = $manifestMetaProperty.Value.PSObject.Properties['com.agentbridge.release']
        if ($null -eq $releaseIdentityProperty -or $null -eq $releaseIdentityProperty.Value -or $releaseIdentityProperty.Value -isnot [pscustomobject]) {
            throw 'manifest release identity is missing or invalid'
        }
        $releaseIdentity = $releaseIdentityProperty.Value
    } else {
        # The stable v0.2.1 bundle predates the namespaced MCPB `_meta`
        # identity. Accept only that exact, operation-free legacy contract and
        # preserve the same Git/runtime digest checks through manifest.metadata.
        $legacyIdentityProperty = $manifest.PSObject.Properties['metadata']
        $legacyManifestVersionProperty = $manifest.PSObject.Properties['manifest_version']
        $metadataOperationsProperty = $metadata.PSObject.Properties['operations']
        if ($null -eq $legacyManifestVersionProperty -or [string]$legacyManifestVersionProperty.Value -cne '0.1' -or
            [string]$metadata.version -cne '0.2.1' -or $null -ne $metadataOperationsProperty -or
            $null -eq $legacyIdentityProperty -or $null -eq $legacyIdentityProperty.Value -or
            $legacyIdentityProperty.Value -isnot [pscustomobject]) {
            throw 'manifest release identity is missing or invalid'
        }
        $releaseIdentity = $legacyIdentityProperty.Value
    }
    $sourceGitShaProperty = $releaseIdentity.PSObject.Properties['source_git_sha']
    $runtimeSha256Property = $releaseIdentity.PSObject.Properties['runtime_sha256']
    if ($null -eq $sourceGitShaProperty -or [string]$sourceGitShaProperty.Value -cnotmatch '^[0-9a-fA-F]{7,64}$') {
        throw 'manifest release identity Git SHA is missing or invalid'
    }
    if ($null -eq $runtimeSha256Property -or [string]$runtimeSha256Property.Value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'manifest release identity runtime SHA-256 is missing or invalid'
    }
    if ([string]$sourceGitShaProperty.Value -cne [string]$metadata.gitSha) { throw 'manifest and release metadata Git SHAs differ' }

    $metadataFiles = @{}
    $filesProperty = $metadata.PSObject.Properties['files']
    if ($null -eq $filesProperty -or $null -eq $filesProperty.Value -or $filesProperty.Value -isnot [pscustomobject]) {
        throw 'release metadata files inventory is missing or invalid'
    }
    foreach ($property in $metadata.files.PSObject.Properties) {
        $metadataName = $property.Name.Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($metadataName) -or $metadataName.StartsWith('/') -or $metadataName.Contains(':') -or $metadataName.Split('/') -contains '..') {
            throw "unsafe release metadata file path: $metadataName"
        }
        $metadataKey = $metadataName.ToLowerInvariant()
        if ($metadataFiles.ContainsKey($metadataKey)) { throw "duplicate release metadata file path: $metadataName" }
        $metadataFiles[$metadataKey] = $property
    }
    foreach ($entryKey in $entries.Keys) {
        if ($entryKey -in @('manifest.json', 'release-metadata.json')) { continue }
        if (-not $metadataFiles.ContainsKey($entryKey)) { throw "bundle contains an unhashed payload entry: $entryKey" }
    }

    $operationsContract = $null
    $operationsProperty = $metadata.PSObject.Properties['operations']
    if ($null -ne $operationsProperty) {
        $operationsContract = $operationsProperty.Value
        $legacyOperationEntryPoints = [ordered]@{
            readiness = 'operations/check-cutover-readiness.ps1'
            cutover = 'operations/cutover-release.ps1'
            rollback = 'operations/switch-release.ps1'
            inspection = 'operations/inspect-install.ps1'
        }
        $legacyOperationFiles = @(
            @($legacyOperationEntryPoints.Values)
            'operations/configure-clients.ps1'
            'operations/cutover-lock.psm1'
            'operations/cutover-quiescence.psm1'
        )
        $capabilityProperty = $operationsContract.PSObject.Properties['capability']
        $schemaProperty = $operationsContract.PSObject.Properties['schemaVersion']
        $platformProperty = $operationsContract.PSObject.Properties['platform']
        $capability = if ($null -ne $capabilityProperty) { [string]$capabilityProperty.Value } else { '' }
        $schemaVersion = if ($null -ne $schemaProperty) { [int]$schemaProperty.Value } else { -1 }
        if ($null -eq $platformProperty -or [string]$platformProperty.Value -cne 'windows') {
            throw 'unsupported immutable release operation contract'
        }
        if ($capability -ceq $ImmutableOperationsV1Capability -and $schemaVersion -eq 1) {
            $requiredOperationEntryPoints = $legacyOperationEntryPoints
            $requiredOperationFiles = $legacyOperationFiles
        } elseif ($capability -ceq $ImmutableOperationsV2Capability -and $schemaVersion -eq 2) {
            $requiredOperationEntryPoints = [ordered]@{}
            foreach ($entry in $legacyOperationEntryPoints.GetEnumerator()) { $requiredOperationEntryPoints[$entry.Key] = $entry.Value }
            $requiredOperationEntryPoints.stateProtection = 'operations/protect-state.ps1'
            $requiredOperationFiles = @(
                @($legacyOperationEntryPoints.Values)
                'operations/protect-state.ps1'
                'operations/configure-clients.ps1'
                'operations/cutover-lock.psm1'
                'operations/cutover-quiescence.psm1'
            )
        } else {
            throw 'unsupported immutable release operation contract'
        }
        $requiredPayloads = @('server/agent-bridge.mjs', 'server/agent-bridge.mjs.map') + $requiredOperationFiles
        $entryPointsProperty = $operationsContract.PSObject.Properties['entryPoints']
        if ($null -eq $entryPointsProperty -or $null -eq $entryPointsProperty.Value -or $entryPointsProperty.Value -isnot [pscustomobject]) {
            throw 'immutable release operation entry points are missing or invalid'
        }
        $actualEntryPointNames = @($entryPointsProperty.Value.PSObject.Properties.Name)
        if ($actualEntryPointNames.Count -ne $requiredOperationEntryPoints.Count -or @(Compare-Object -CaseSensitive $actualEntryPointNames @($requiredOperationEntryPoints.Keys) -SyncWindow 0).Count -gt 0) {
            throw 'immutable release operation entry point inventory mismatch'
        }
        foreach ($entryPoint in $requiredOperationEntryPoints.GetEnumerator()) {
            $actualEntryPoint = $entryPointsProperty.Value.PSObject.Properties[$entryPoint.Key]
            if ($null -eq $actualEntryPoint -or [string]$actualEntryPoint.Value -ne $entryPoint.Value) {
                throw "immutable release operation entry point mismatch: $($entryPoint.Key)"
            }
        }
        foreach ($operationPath in $requiredOperationFiles) {
            $operationKey = $operationPath.ToLowerInvariant()
            if (-not $entries.ContainsKey($operationKey) -or -not $metadataFiles.ContainsKey($operationKey)) {
                throw "immutable release operation is missing or unhashed: $operationPath"
            }
        }
        $payloadsProperty = $operationsContract.PSObject.Properties['payloads']
        if ($null -eq $payloadsProperty -or $null -eq $payloadsProperty.Value -or $payloadsProperty.Value -isnot [array]) {
            throw 'immutable release operation payload inventory is missing or invalid'
        }
        $declaredPayloads = @($payloadsProperty.Value | ForEach-Object { [string]$_ })
        if ($declaredPayloads.Count -ne $requiredPayloads.Count -or @(Compare-Object -CaseSensitive $declaredPayloads $requiredPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release operation payload inventory mismatch'
        }
        $actualPayloads = @($entries.Keys | Where-Object { $_ -notin @('manifest.json', 'release-metadata.json') } | Sort-Object)
        $expectedPayloads = @($requiredPayloads | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
        if ($actualPayloads.Count -ne $expectedPayloads.Count -or @(Compare-Object -CaseSensitive $actualPayloads $expectedPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release bundle payload inventory mismatch'
        }
        $actualMetadataPayloads = @($metadataFiles.Keys | Sort-Object)
        if ($actualMetadataPayloads.Count -ne $expectedPayloads.Count -or @(Compare-Object -CaseSensitive $actualMetadataPayloads $expectedPayloads -SyncWindow 0).Count -gt 0) {
            throw 'immutable release metadata payload inventory mismatch'
        }
        foreach ($payloadPath in $requiredPayloads) {
            $fileRecord = $metadataFiles[$payloadPath.ToLowerInvariant()].Value
            $recordProperties = @($fileRecord.PSObject.Properties.Name | Sort-Object)
            if ($recordProperties.Count -ne 2 -or $recordProperties[0] -ne 'bytes' -or $recordProperties[1] -ne 'sha256') {
                throw "immutable release metadata record must contain exactly sha256 and bytes: $payloadPath"
            }
            if ([string]$fileRecord.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw "immutable release metadata SHA-256 is invalid: $payloadPath" }
            if ($fileRecord.bytes -isnot [int] -and $fileRecord.bytes -isnot [long]) { throw "immutable release metadata byte count is not an integer: $payloadPath" }
            if ([long]$fileRecord.bytes -lt 0 -or [long]$fileRecord.bytes -gt $MaxReleaseFileBytes) { throw "immutable release metadata byte count is out of range: $payloadPath" }
        }
    } elseif (@($entries.Keys | Where-Object { $_.StartsWith('operations/') }).Count -gt 0) {
        throw 'bundle contains operation files without an immutable release operation contract'
    }

    $releaseId = "$($metadata.version)+$($metadata.gitSha.Substring(0, 7).ToLowerInvariant())"
    $destination = [IO.Path]::GetFullPath((Join-Path $releasesRoot $releaseId))
    $releasePrefix = $releasesRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $destination.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'release destination escaped the install root' }
    if (Test-Path -LiteralPath $destination) { throw "immutable release already exists: $destination" }

    $temporary = [IO.Path]::GetFullPath((Join-Path $releasesRoot ('.installing-' + [Guid]::NewGuid().ToString('N'))))
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $temporaryPrefix = $temporary.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    foreach ($entry in $entries.Values) {
        $relative = $entry.FullName.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $target = [IO.Path]::GetFullPath((Join-Path $temporary $relative))
        if (-not $target.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "bundle entry escaped staging: $relative" }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        $input = $entry.Open()
        try {
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output) } finally { $output.Dispose() }
        } finally { $input.Dispose() }
    }

    foreach ($property in $metadata.files.PSObject.Properties) {
        $relative = $property.Name.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $target = [IO.Path]::GetFullPath((Join-Path $temporary $relative))
        if (-not $target.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $target -PathType Leaf)) {
            throw "metadata references a missing or unsafe file: $($property.Name)"
        }
        $actual = Get-Sha256 ([IO.File]::ReadAllBytes($target))
        if ($actual -ne [string]$property.Value.sha256) { throw "SHA-256 mismatch for $($property.Name)" }
        $bytesProperty = $property.Value.PSObject.Properties['bytes']
        if ($null -ne $bytesProperty -and $null -ne $bytesProperty.Value -and
            [IO.FileInfo]::new($target).Length -ne [long]$bytesProperty.Value) {
            throw "byte-count mismatch for $($property.Name)"
        }
    }

    $runtimeHash = Get-Sha256 ([IO.File]::ReadAllBytes((Join-Path $temporary 'server\agent-bridge.mjs')))
    if ($runtimeHash -cne [string]$runtimeSha256Property.Value) { throw 'manifest runtime SHA-256 does not match the packaged runtime' }

    Move-Item -LiteralPath $temporary -Destination $destination
    $temporary = $null
    $operationsPath = if ($null -ne $operationsContract) { Join-Path $destination 'operations' } else { $null }
    [pscustomobject]@{
        status = 'installed'
        bundleSha256 = $bundleHash
        releaseId = $releaseId
        releasePath = $destination
        version = [string]$metadata.version
        gitSha = [string]$metadata.gitSha
        runtimeSha256 = $runtimeHash
        operationsPath = $operationsPath
        operationEntryPoints = if ($null -ne $operationsContract) { $operationsContract.entryPoints } else { $null }
    } | ConvertTo-Json -Depth 4
} finally {
    $archive.Dispose()
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
        $stagingRoot = [IO.Path]::GetFullPath($temporary)
        $expectedPrefix = $releasesRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar + '.installing-'
        if ($stagingRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }
}
