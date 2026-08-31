[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$StateDir = (Join-Path $env:USERPROFILE '.agent-bridge'),
    [switch]$AuditOnly,
    [string]$BackupPath,
    [string]$RestoreFrom,
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedBackupSha256,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Force) { $ConfirmPreference = 'None' }

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ownerSid = $currentIdentity.User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$expectedSids = @($ownerSid.Value, $systemSid.Value, $administratorsSid.Value)
$fullControl = [long][Security.AccessControl.FileSystemRights]::FullControl

function Get-CanonicalPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw "$Label must be an absolute path" }
    return [IO.Path]::GetFullPath($Path)
}
function Test-PathInside([string]$Child, [string]$Parent) {
    $prefix = $Parent.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    return $Child.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}
function Assert-NoReparsePath([string]$Path, [string]$Label, [switch]$AllowLeafMissing) {
    $cursor = $Path
    if ($AllowLeafMissing) { $cursor = [IO.Path]::GetDirectoryName($cursor) }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label contains a reparse point: $($item.FullName)" }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

$target = Get-CanonicalPath $StateDir 'StateDir'
if ($target -eq [IO.Path]::GetPathRoot($target) -or $target -eq [IO.Path]::GetFullPath($env:USERPROFILE)) { throw "refusing to change or audit ACLs on broad path: $target" }

function Get-AclObject([IO.FileSystemInfo]$Item) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        if ($Item.PSIsContainer) { return [IO.DirectoryInfo]::new($Item.FullName).GetAccessControl() }
        return [IO.FileInfo]::new($Item.FullName).GetAccessControl()
    }
    return Get-Acl -LiteralPath $Item.FullName
}
function Set-AclObject([IO.FileSystemInfo]$Item, $Acl) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        if ($Item.PSIsContainer) { [IO.DirectoryInfo]::new($Item.FullName).SetAccessControl($Acl) }
        else { [IO.FileInfo]::new($Item.FullName).SetAccessControl($Acl) }
    } else { Set-Acl -LiteralPath $Item.FullName -AclObject $Acl }
}
function Get-SidValue($IdentityReference) {
    try { if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) { return $IdentityReference.Value }; return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return "unresolved:$($IdentityReference.Value)" }
}
function Get-RuleTuple($Rule) {
    $rights = [long]$Rule.FileSystemRights
    # NTFS can report GENERIC_ALL (0x10000000) even though the managed access
    # rule constructor accepts only the concrete FileSystemRights mask.
    if (($rights -band 0x10000000) -ne 0) { $rights = ($rights -band (-bnot 0x10000000)) -bor $fullControl }
    [ordered]@{
        sid = Get-SidValue $Rule.IdentityReference
        type = [string]$Rule.AccessControlType
        rights = [string]$rights
        inheritance = [string][int]$Rule.InheritanceFlags
        propagation = [string][int]$Rule.PropagationFlags
        inherited = [bool]$Rule.IsInherited
    }
}
function Get-NormalizedRules($Acl, [bool]$IncludeExplicit, [bool]$IncludeInherited) {
    $rules = @($Acl.GetAccessRules($IncludeExplicit, $IncludeInherited, [Security.Principal.SecurityIdentifier])) | ForEach-Object { Get-RuleTuple $_ }
    return @($rules | Sort-Object sid,type,rights,inheritance,propagation,inherited | ForEach-Object { [pscustomobject]$_ })
}
function Get-StateItems {
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { return @() }
    Assert-NoReparsePath $target 'state path'
    $rootItem = Get-Item -LiteralPath $target -Force
    $children = @(Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction Stop)
    $items = @($rootItem) + $children
    foreach ($item in $items) { if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing state ACL operation because the tree contains a reparse point: $($item.FullName)" } }
    return @($items | Sort-Object @{ Expression = { $_.FullName.Length } }, FullName)
}
function Get-RelativeStatePath([string]$FullName) {
    if ($FullName -ieq $target) { return '' }
    if (-not (Test-PathInside $FullName $target)) { throw "state inventory item escapes state path: $FullName" }
    return $FullName.Substring($target.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}
function Get-StateSnapshot {
    $records = @()
    foreach ($item in @(Get-StateItems)) {
        $acl = Get-AclObject $item
        try { $recordOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { throw "unable to resolve state item owner: $($item.FullName)" }
        if ($recordOwner -cne $ownerSid.Value) { throw "refusing ACL mutation because state item has a foreign owner: $($item.FullName) ($recordOwner)" }
        $records += [pscustomobject][ordered]@{
            relativePath = Get-RelativeStatePath $item.FullName
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            ownerSid = $recordOwner
            daclProtected = [bool]$acl.AreAccessRulesProtected
            explicitDacl = @(Get-NormalizedRules $acl $true $false)
            effectiveDacl = @(Get-NormalizedRules $acl $true $true)
        }
    }
    return @($records)
}
function Get-Sha256([string]$Path) { return Get-Sha256Bytes ([IO.File]::ReadAllBytes($Path)) }
function Get-Sha256Bytes([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function Assert-BackupDestination([string]$Path) {
    $backup = Get-CanonicalPath $Path 'BackupPath'
    if (Test-Path -LiteralPath $backup) { throw "BackupPath must not already exist: $backup" }
    if (Test-PathInside $backup $target -or $backup -ieq $target) { throw "BackupPath must be outside StateDir: $backup" }
    $parent = [IO.Path]::GetDirectoryName($backup)
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "BackupPath parent must already exist: $parent" }
    Assert-NoReparsePath $parent 'BackupPath parent'
    return $backup
}
function Publish-Backup($Records, [string]$Path) {
    $payload = [ordered]@{ schemaVersion = 1; kind = 'agent-bridge-state-acl-backup'; statePath = $target; createdUtc = [DateTime]::UtcNow.ToString('o'); itemCount = @($Records).Count; records = @($Records) }
    $temp = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.agent-bridge-state-acl-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temp, ($payload | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
        $backupFile = Get-Item -LiteralPath $temp -Force
        $privateAcl = [Security.AccessControl.FileSecurity]::new()
        $privateAcl.SetOwner($ownerSid); $privateAcl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($ownerSid, $systemSid, $administratorsSid)) { [void]$privateAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)) }
        Set-AclObject $backupFile $privateAcl
        [IO.File]::Move($temp, $Path)
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }
    return Get-Sha256 $Path
}
function Get-StateAclAudit {
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { return [pscustomobject][ordered]@{ schemaVersion = 2; status = 'audited'; path = $target; exists = $false; compliant = $false; protectedRoot = $false; expectedOwnerSid = $ownerSid.Value; scannedItemCount = 0; violationCount = 1; violations = [ordered]@{ rootInheritance = 1; owner = 0; requiredGrant = 0; unexpectedAllow = 0; deny = 0 }; unexpectedAllowSids = @() } }
    $items = @(Get-StateItems); $rootProtected = $false; $ownerViolations = 0; $grantViolations = 0; $unexpectedAllowViolations = 0; $denyViolations = 0; $unexpectedSids = @()
    for ($index = 0; $index -lt $items.Count; $index++) {
        $acl = Get-AclObject $items[$index]; if ($index -eq 0) { $rootProtected = [bool]$acl.AreAccessRulesProtected }
        try { $actualOwnerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $actualOwnerSid = 'unresolved-owner' }
        if ($actualOwnerSid -cne $ownerSid.Value) { $ownerViolations++ }
        $allowRights = @{}; foreach ($sid in $expectedSids) { $allowRights[$sid] = [long]0 }
        foreach ($rule in @($acl.Access)) { $sid = Get-SidValue $rule.IdentityReference; if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) { $denyViolations++; continue }; if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }; if ($sid -notin $expectedSids) { $unexpectedAllowViolations++; $unexpectedSids += $sid; continue }; $allowRights[$sid] = [long]$allowRights[$sid] -bor [long]$rule.FileSystemRights }
        foreach ($sid in $expectedSids) { if (([long]$allowRights[$sid] -band $fullControl) -ne $fullControl) { $grantViolations++ } }
    }
    $rootInheritanceViolations = if ($rootProtected) { 0 } else { 1 }; $violationCount = $rootInheritanceViolations + $ownerViolations + $grantViolations + $unexpectedAllowViolations + $denyViolations
    return [pscustomobject][ordered]@{ schemaVersion = 2; status = 'audited'; path = $target; exists = $true; compliant = ($violationCount -eq 0); protectedRoot = $rootProtected; expectedOwnerSid = $ownerSid.Value; scannedItemCount = $items.Count; violationCount = $violationCount; violations = [ordered]@{ rootInheritance = $rootInheritanceViolations; owner = $ownerViolations; requiredGrant = $grantViolations; unexpectedAllow = $unexpectedAllowViolations; deny = $denyViolations }; unexpectedAllowSids = @($unexpectedSids | Sort-Object -Unique) }
}
function Set-PrivateAcl([IO.FileSystemInfo]$Item) {
    $acl = if ($Item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner($ownerSid); $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($ownerSid, $systemSid, $administratorsSid)) { [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)) }
    Set-AclObject $Item $acl
}
function Convert-ToRule($Tuple) {
    $sid = [Security.Principal.SecurityIdentifier]::new([string]$Tuple.sid)
    $rights = [Enum]::ToObject([Security.AccessControl.FileSystemRights], [long]$Tuple.rights)
    $inheritance = [Enum]::ToObject([Security.AccessControl.InheritanceFlags], [int]$Tuple.inheritance)
    $propagation = [Enum]::ToObject([Security.AccessControl.PropagationFlags], [int]$Tuple.propagation)
    $accessType = [Enum]::Parse([Security.AccessControl.AccessControlType], [string]$Tuple.type, $true)
    return [Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inheritance, $propagation, $accessType)
}
function Assert-RecordsValid($Backup) {
    if ([int]$Backup.schemaVersion -ne 1 -or [string]$Backup.kind -cne 'agent-bridge-state-acl-backup' -or [string]$Backup.statePath -cne $target) { throw 'ACL backup schema or state path does not match this StateDir' }
    $records = @($Backup.records); if ($records.Count -ne [int]$Backup.itemCount -or $records.Count -eq 0) { throw 'ACL backup inventory is invalid' }
    $seen = @{}
    foreach ($record in $records) {
        $relative = [string]$record.relativePath
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.?(?:[\\/]|$)' -or $relative -match ':') { throw "ACL backup contains unsafe relative path: $relative" }
        $key = $relative.ToUpperInvariant(); if ($seen.ContainsKey($key)) { throw "ACL backup contains duplicate inventory path: $relative" }; $seen[$key] = $true
        if ([string]$record.ownerSid -cne $ownerSid.Value -or ([string]$record.kind -cne 'file' -and [string]$record.kind -cne 'directory')) { throw "ACL backup record is invalid: $relative" }
        foreach ($tuple in @($record.explicitDacl) + @($record.effectiveDacl)) { [void](Convert-ToRule $tuple) }
    }
    if (@($records | Where-Object { [string]$_.relativePath -eq '' }).Count -ne 1) { throw 'ACL backup inventory must contain the state root exactly once' }
    $current = @(Get-StateItems); if ($current.Count -ne $records.Count) { throw 'ACL backup inventory does not match the current state tree' }
    $currentPaths = @{}; foreach ($item in $current) { $currentPaths[(Get-RelativeStatePath $item.FullName).ToUpperInvariant()] = $true }
    foreach ($key in $seen.Keys) { if (-not $currentPaths.ContainsKey($key)) { throw 'ACL backup inventory does not match the current state tree' } }
    foreach ($record in $records) {
        $path = if ([string]::IsNullOrEmpty([string]$record.relativePath)) { $target } else { Join-Path $target ([string]$record.relativePath) }
        if (-not (Test-Path -LiteralPath $path)) { throw "ACL backup item is missing: $path" }
        $item = Get-Item -LiteralPath $path -Force
        $actualKind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
        if ($actualKind -cne [string]$record.kind) { throw "ACL backup item type does not match: $path" }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "ACL backup item is a reparse point: $path" }
    }
    return $records
}
function Restore-StateAcl([string]$BackupFile, [string]$ExpectedHash) {
    $restore = Get-CanonicalPath $BackupFile 'RestoreFrom'; if (-not (Test-Path -LiteralPath $restore -PathType Leaf)) { throw "ACL backup does not exist: $restore" }; Assert-NoReparsePath $restore 'RestoreFrom'
    if ($restore -ieq $target -or (Test-PathInside $restore $target)) { throw "RestoreFrom must be outside StateDir: $restore" }
    $backupBytes = [IO.File]::ReadAllBytes($restore)
    $actualHash = Get-Sha256Bytes $backupBytes; if ($actualHash -cne $ExpectedHash) { throw "ACL backup SHA-256 mismatch; refusing restore before mutation" }
    try { $backup = [Text.UTF8Encoding]::new($false).GetString($backupBytes) | ConvertFrom-Json } catch { throw 'ACL backup is not valid JSON' }
    $records = @(Assert-RecordsValid $backup)
    foreach ($record in $records | Sort-Object @{ Expression = { ([string]$_.relativePath).Length } }, relativePath) {
        $path = if ([string]::IsNullOrEmpty([string]$record.relativePath)) { $target } else { Join-Path $target ([string]$record.relativePath) }; $item = Get-Item -LiteralPath $path -Force; $acl = Get-AclObject $item
        foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) { [void]$acl.RemoveAccessRuleSpecific($rule) }
        $acl.SetAccessRuleProtection([bool]$record.daclProtected, $false); $acl.SetOwner($ownerSid)
        foreach ($tuple in @($record.explicitDacl)) { [void]$acl.AddAccessRule((Convert-ToRule $tuple)) }
        Set-AclObject $item $acl
    }
    foreach ($record in $records) {
        $path = if ([string]::IsNullOrEmpty([string]$record.relativePath)) { $target } else { Join-Path $target ([string]$record.relativePath) }; $acl = Get-AclObject (Get-Item -LiteralPath $path -Force)
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne [string]$record.ownerSid -or [bool]$acl.AreAccessRulesProtected -ne [bool]$record.daclProtected -or (@(Get-NormalizedRules $acl $true $false) | ConvertTo-Json -Compress) -cne (@($record.explicitDacl) | ConvertTo-Json -Compress) -or (@(Get-NormalizedRules $acl $true $true) | ConvertTo-Json -Compress) -cne (@($record.effectiveDacl) | ConvertTo-Json -Compress)) { throw "ACL restore verification failed: $path" }
    }
    return [pscustomobject]@{ backupPath = $restore; backupSha256 = $actualHash; itemCount = $records.Count }
}

if (($AuditOnly -and ($BackupPath -or $RestoreFrom -or $ExpectedBackupSha256)) -or ($RestoreFrom -and $BackupPath) -or (-not $RestoreFrom -and $ExpectedBackupSha256)) { throw 'AuditOnly, BackupPath, RestoreFrom, and ExpectedBackupSha256 specify conflicting operation modes' }
if ($AuditOnly) { Get-StateAclAudit | ConvertTo-Json -Depth 8; return }
if ($RestoreFrom) {
    if ([string]::IsNullOrWhiteSpace($ExpectedBackupSha256)) { throw 'ExpectedBackupSha256 is required for RestoreFrom' }
    if (-not $PSCmdlet.ShouldProcess($target, 'restore state owner and DACL semantics from the hash-verified ACL backup')) { return }
    $restored = Restore-StateAcl $RestoreFrom $ExpectedBackupSha256
    [pscustomobject][ordered]@{ schemaVersion = 2; status = 'restored'; compliant = (Get-StateAclAudit).compliant; backupPath = $restored.backupPath; backupSha256 = $restored.backupSha256; itemCount = $restored.itemCount } | ConvertTo-Json -Depth 8
    return
}
if ([string]::IsNullOrWhiteSpace($BackupPath)) { throw 'BackupPath is required for state ACL mutation' }
if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "state directory does not exist: $target" }
$backup = Assert-BackupDestination $BackupPath
if (-not $PSCmdlet.ShouldProcess($target, 'replace state ACLs recursively with current user, SYSTEM, and Administrators full control')) { return }
$records = @(Get-StateSnapshot)
$backupHash = Publish-Backup $records $backup
$stateMutationAttempted = $false
try {
    $publishedBytes = [IO.File]::ReadAllBytes($backup)
    if ((Get-Sha256Bytes $publishedBytes) -cne $backupHash) { throw 'persisted ACL backup changed before state ACL mutation' }
    $publishedBackup = [Text.UTF8Encoding]::new($false).GetString($publishedBytes) | ConvertFrom-Json
    [void](Assert-RecordsValid $publishedBackup)
    if ((@($records) | ConvertTo-Json -Depth 12 -Compress) -cne (@(Get-StateSnapshot) | ConvertTo-Json -Depth 12 -Compress)) { throw 'state ACL changed after backup capture; refusing mutation' }
    if ($env:AGENT_BRIDGE_TEST_FAIL_STATE_ACL_BEFORE_APPLY) { throw 'injected state ACL failure before first mutation' }
    $count = 0
    foreach ($item in @(Get-StateItems)) { $stateMutationAttempted = $true; Set-PrivateAcl $item; $count++; if ($env:AGENT_BRIDGE_TEST_FAIL_STATE_ACL_AFTER -and $count -eq [int]$env:AGENT_BRIDGE_TEST_FAIL_STATE_ACL_AFTER) { throw "injected state ACL failure after $count mutation(s)" } }
    $audit = Get-StateAclAudit; if (-not $audit.compliant) { throw "state ACL verification failed after protection: $($audit.violationCount) violation(s) across $($audit.scannedItemCount) item(s)" }
    $audit.status = 'protected'; $audit | Add-Member -NotePropertyName backupPath -NotePropertyValue $backup; $audit | Add-Member -NotePropertyName backupSha256 -NotePropertyValue $backupHash; $audit | Add-Member -NotePropertyName itemCount -NotePropertyValue $records.Count; $audit | ConvertTo-Json -Depth 8
} catch {
    $failure = $_
    if (-not $stateMutationAttempted) { throw "state ACL protection refused before ACL mutation; retained backup: $backup ($backupHash); failure: $failure" }
    try { [void](Restore-StateAcl $backup $backupHash) } catch { throw "state ACL protection failed: $failure; automatic ACL recovery failed verification: $($_.Exception.Message); retained backup: $backup ($backupHash)" }
    throw "state ACL protection failed and automatic ACL recovery restored the pre-image; retained backup: $backup ($backupHash); failure: $failure"
}
