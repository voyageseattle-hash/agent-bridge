[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CandidateBundlePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCandidateBundleSha256,
    [Parameter(Mandatory = $true)][string]$PriorBundlePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPriorBundleSha256,
    [Parameter(Mandatory = $true)][string]$EvidenceDir,
    [string]$NodePath = 'node'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path); $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Assert-NewExternalEvidenceDirectory([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'EvidenceDir must be absolute' }
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) { throw 'EvidenceDir must not already exist' }
    $existing = $full
    $missing = [Collections.Generic.List[string]]::new()
    while (-not (Test-Path -LiteralPath $existing)) {
        $parent = Split-Path -Parent $existing
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existing) { throw 'EvidenceDir has no existing ancestor' }
        $missing.Insert(0, (Split-Path -Leaf $existing))
        $existing = $parent
    }
    $ancestor = Get-Item -Force -LiteralPath $existing
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'EvidenceDir ancestor must not be a reparse point' }
    $ancestorPath = $existing
    while ($true) {
        $ancestor = Get-Item -Force -LiteralPath $ancestorPath
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'EvidenceDir ancestor must not be a reparse point' }
        $parent = Split-Path -Parent $ancestorPath
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $ancestorPath) { break }
        $ancestorPath = $parent
    }
    $ancestor = Get-Item -Force -LiteralPath $existing
    if (-not $ancestor.PSIsContainer) { throw 'EvidenceDir ancestor must be a directory' }
    $canonicalTarget = (Resolve-Path -LiteralPath $existing -ErrorAction Stop).Path
    foreach ($segment in $missing) { $canonicalTarget = Join-Path $canonicalTarget $segment }
    $repoItem = Get-Item -Force -LiteralPath (Split-Path -Parent $PSScriptRoot)
    if (($repoItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'source repository root must not be a reparse point' }
    $canonicalRepoRoot = (Resolve-Path -LiteralPath $repoItem.FullName -ErrorAction Stop).Path.TrimEnd('\', '/')
    $repoPrefix = $canonicalRepoRoot + [IO.Path]::DirectorySeparatorChar
    if ($canonicalTarget.Equals($canonicalRepoRoot, [StringComparison]::OrdinalIgnoreCase) -or $canonicalTarget.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'EvidenceDir must be outside the source repository' }
    return $canonicalTarget
}
function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}
function Get-FileHashRecord([string]$Path) {
    return [ordered]@{ path = $Path; sha256 = if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-Sha256 $Path } else { $null } }
}
function Get-PointerHashes([string]$InstallRoot) {
    return [ordered]@{
        shim = Get-FileHashRecord (Join-Path $InstallRoot 'agent-bridge.mjs')
        config = Get-FileHashRecord (Join-Path $InstallRoot 'config.json')
        marker = Get-FileHashRecord (Join-Path $InstallRoot 'current-release.json')
    }
}
function Get-ArtifactManifest([string]$Root) {
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Name -notin @('artifact-manifest.json', 'rollback-rehearsal.json') } |
        ForEach-Object { [ordered]@{ path = $_.FullName.Substring($Root.Length).TrimStart('\', '/'); sha256 = Get-Sha256 $_.FullName; bytes = $_.Length } } | Sort-Object path)
}
function Complete-Result([string]$EvidenceRoot, $Result) {
    $manifestPath = Join-Path $EvidenceRoot 'artifact-manifest.json'
    Write-Json $manifestPath ([ordered]@{ schemaVersion = 1; files = Get-ArtifactManifest $EvidenceRoot })
    $Result.artifactManifestSha256 = Get-Sha256 $manifestPath
    Write-Json (Join-Path $EvidenceRoot 'rollback-rehearsal.json') $Result
}
function Invoke-Json([string]$Name, [scriptblock]$Command, [string]$OutputPath) {
    $global:LASTEXITCODE = 0
    $raw = @(& $Command 2>&1) -join [Environment]::NewLine
    $rawRecord = [ordered]@{ schemaVersion = 1; name = $Name; exitCode = $LASTEXITCODE; output = if ($raw.Length -le 65536) { $raw } else { $raw.Substring(0, 65536) + '…[truncated]' } }
    Write-Json ($OutputPath + '.raw.json') $rawRecord
    if ($LASTEXITCODE -ne 0) { throw "$Name exited with code $LASTEXITCODE" }
    try { $parsed = $raw | ConvertFrom-Json }
    catch { throw "$Name returned malformed JSON: $raw" }
    Write-Json $OutputPath $parsed
    return $parsed
}
function Get-ReleaseIdentity([string]$InstallRoot, [string]$ReleaseId) {
    $release = Join-Path (Join-Path $InstallRoot 'releases') $ReleaseId
    $metadata = Get-Content -Raw -LiteralPath (Join-Path $release 'release-metadata.json') | ConvertFrom-Json
    $runtime = Join-Path $release 'server\agent-bridge.mjs'
    $record = $metadata.files.PSObject.Properties['server/agent-bridge.mjs']
    if ($null -eq $record -or (Get-Sha256 $runtime) -cne [string]$record.Value.sha256) { throw "installed release runtime hash mismatch: $ReleaseId" }
    return [pscustomobject]@{ releaseId = $ReleaseId; releasePath = $release; version = [string]$metadata.version; runtimeSha256 = [string]$record.Value.sha256 }
}
function Assert-Current([string]$InstallRoot, $Identity) {
    $marker = Get-Content -Raw -LiteralPath (Join-Path $InstallRoot 'current-release.json') | ConvertFrom-Json
    if ([string]$marker.releaseId -cne $Identity.releaseId -or [string]$marker.runtimeSha256 -cne $Identity.runtimeSha256) { throw "fixture marker does not identify $($Identity.releaseId)" }
}

if ($env:OS -ne 'Windows_NT') { throw 'rehearse-rollback.ps1 requires Windows' }
$candidateBundle = (Resolve-Path -LiteralPath $CandidateBundlePath -ErrorAction Stop).Path
$priorBundle = (Resolve-Path -LiteralPath $PriorBundlePath -ErrorAction Stop).Path
if ([IO.Path]::GetFullPath($candidateBundle).Equals([IO.Path]::GetFullPath($priorBundle), [StringComparison]::OrdinalIgnoreCase)) { throw 'candidate and prior bundles must differ' }
if ((Get-Sha256 $candidateBundle) -cne $ExpectedCandidateBundleSha256.ToLowerInvariant()) { throw 'candidate bundle SHA-256 mismatch' }
if ((Get-Sha256 $priorBundle) -cne $ExpectedPriorBundleSha256.ToLowerInvariant()) { throw 'prior bundle SHA-256 mismatch' }
$evidence = Assert-NewExternalEvidenceDirectory $EvidenceDir
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
$fixture = Join-Path $evidence 'fixture'
$fixtureInstall = Join-Path $fixture 'install'
$stagedConfig = $null
$result = [ordered]@{ schemaVersion = 1; status = 'failed'; startedAt = (Get-Date).ToUniversalTime().ToString('o'); evidenceDir = $evidence; fixtureInstall = $fixtureInstall; candidateBundleSha256 = $ExpectedCandidateBundleSha256.ToLowerInvariant(); priorBundleSha256 = $ExpectedPriorBundleSha256.ToLowerInvariant(); steps = @() }
try {
    New-Item -ItemType Directory -Path $fixture -ErrorAction Stop | Out-Null
    $installer = Join-Path $PSScriptRoot 'install-release.ps1'
    $candidateInstall = Invoke-Json 'candidate install' { & $installer -BundlePath $candidateBundle -InstallRoot $fixtureInstall -ExpectedBundleSha256 $ExpectedCandidateBundleSha256 } (Join-Path $evidence 'install-candidate.json')
    $priorInstall = Invoke-Json 'prior install' { & $installer -BundlePath $priorBundle -InstallRoot $fixtureInstall -ExpectedBundleSha256 $ExpectedPriorBundleSha256 } (Join-Path $evidence 'install-prior.json')
    if ([string]$candidateInstall.releaseId -ceq [string]$priorInstall.releaseId) { throw 'candidate and prior installs resolved to the same release identity' }
    $candidate = Get-ReleaseIdentity $fixtureInstall $candidateInstall.releaseId
    $prior = Get-ReleaseIdentity $fixtureInstall $priorInstall.releaseId
    $stagedConfig = Join-Path $fixture 'rehearsal-config.json'
    $fixtureWork = Join-Path $fixture 'work'; $fixtureState = Join-Path $fixture 'state'
    New-Item -ItemType Directory -Path $fixtureWork, $fixtureState -ErrorAction Stop | Out-Null
    $minimalConfig = [ordered]@{
        agents = [ordered]@{ codex = [ordered]@{ enabled = $false }; claude = [ordered]@{ enabled = $false } }
        defaults = [ordered]@{ cwd = $fixtureWork; sandbox = 'read-only'; timeoutSec = 30 }
        allowedRoots = @($fixtureWork)
        handoffMaxChars = 24000
        stateDir = $fixtureState
    }
    [IO.File]::WriteAllText($stagedConfig, (($minimalConfig | ConvertTo-Json -Depth 6) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    $configSha256 = Get-Sha256 $stagedConfig
    $fixtureConfig = Join-Path $fixtureInstall 'config.json'
    if (Test-Path -LiteralPath $fixtureConfig) { throw "fixture shared config unexpectedly exists before rehearsal initialization: $fixtureConfig" }
    [IO.File]::WriteAllBytes($fixtureConfig, [IO.File]::ReadAllBytes($stagedConfig))
    if ((Get-Sha256 $fixtureConfig) -cne $configSha256) { throw 'fixture shared config hash mismatch after rehearsal initialization' }
    $result.initialSharedConfig = Get-FileHashRecord $fixtureConfig
    $switch = Join-Path $candidate.releasePath 'operations\switch-release.ps1'
    if (-not (Test-Path -LiteralPath $switch -PathType Leaf)) { throw 'candidate immutable switch-release operation is missing' }
    $canary = Join-Path $PSScriptRoot 'canary-release.mjs'
    $sequence = @(
        [pscustomobject]@{ name = 'candidate-first'; identity = $candidate; profile = 'strict' },
        [pscustomobject]@{ name = 'prior'; identity = $prior; profile = 'rollback-minimum' },
        [pscustomobject]@{ name = 'candidate-restored'; identity = $candidate; profile = 'strict' }
    )
    foreach ($step in $sequence) {
        $switchResult = Invoke-Json ($step.name + ' switch') { & $switch -ReleaseId $step.identity.releaseId -InstallRoot $fixtureInstall -StagedConfigPath $stagedConfig -ExpectedConfigSha256 $configSha256 } (Join-Path $evidence ($step.name + '-switch.json'))
        $verification = Invoke-Json ($step.name + ' verification') { & $switch -ReleaseId $step.identity.releaseId -InstallRoot $fixtureInstall -StagedConfigPath $stagedConfig -ExpectedConfigSha256 $configSha256 -VerifyOnly } (Join-Path $evidence ($step.name + '-verify.json'))
        if (-not [bool]$verification.current) { throw "$($step.name) VerifyOnly did not report current" }
        Assert-Current $fixtureInstall $step.identity
        $canaryDir = Join-Path $evidence ($step.name + '-canary')
        $canaryResult = Invoke-Json ($step.name + ' stable shim canary') { & $NodePath $canary --release-path $step.identity.releasePath --install-root $fixtureInstall --expected-version $step.identity.version --expected-runtime-sha256 $step.identity.runtimeSha256 --expected-stable-shim-sha256 $switchResult.shimSha256 --expected-stable-config-sha256 $configSha256 --evidence-dir $canaryDir --profile $step.profile --promotion current --entrypoint stable-shim } (Join-Path $evidence ($step.name + '-canary-result.json'))
        if ([string]$canaryResult.status -cne 'pass' -or [string]$canaryResult.promotionStatus -cne 'current') { throw "$($step.name) canary did not pass as current" }
        $result.steps += [ordered]@{ name = $step.name; releaseId = $step.identity.releaseId; runtimeSha256 = $step.identity.runtimeSha256; switchBackupPath = $switchResult.backupPath; canaryEvidencePath = $canaryResult.evidencePath; pointerHashes = Get-PointerHashes $fixtureInstall }
    }
    $result.status = 'pass'
    $result.completedAt = (Get-Date).ToUniversalTime().ToString('o')
    $result.stagedConfig = Get-FileHashRecord $stagedConfig
    Complete-Result $evidence $result
    $result | ConvertTo-Json -Depth 12
} catch {
    $result.error = $_.Exception.Message
    $result.completedAt = (Get-Date).ToUniversalTime().ToString('o')
    if ($null -ne $stagedConfig -and (Test-Path -LiteralPath $stagedConfig -PathType Leaf)) { $result.stagedConfig = Get-FileHashRecord $stagedConfig }
    Complete-Result $evidence $result
    throw
}
