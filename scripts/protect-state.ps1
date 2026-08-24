[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$StateDir = (Join-Path $env:USERPROFILE '.agent-bridge'),
    [switch]$AuditOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Force) { $ConfirmPreference = 'None' }

$target = [IO.Path]::GetFullPath($StateDir)
if ($target -eq [IO.Path]::GetPathRoot($target) -or $target -eq [IO.Path]::GetFullPath($env:USERPROFILE)) {
    throw "refusing to change or audit ACLs on broad path: $target"
}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ownerSid = $currentIdentity.User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$expectedSids = @($ownerSid.Value, $systemSid.Value, $administratorsSid.Value)
$fullControl = [long][Security.AccessControl.FileSystemRights]::FullControl

function Get-AclObject([IO.FileSystemInfo]$Item) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        if ($Item.PSIsContainer) { return [IO.DirectoryInfo]::new($Item.FullName).GetAccessControl() }
        return [IO.FileInfo]::new($Item.FullName).GetAccessControl()
    }
    return Get-Acl -LiteralPath $Item.FullName
}

function Get-SidValue($IdentityReference) {
    try {
        if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) { return $IdentityReference.Value }
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return "unresolved:$($IdentityReference.Value)"
    }
}

function Get-StateItems {
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { return @() }
    $rootItem = Get-Item -LiteralPath $target -Force
    $children = @(Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction Stop)
    $reparse = @($rootItem) + $children | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
    if (@($reparse).Count -gt 0) { throw "refusing state ACL operation because the tree contains a reparse point: $($reparse[0].FullName)" }
    return @($rootItem) + $children
}

function Get-StateAclAudit {
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        return [pscustomobject][ordered]@{
            schemaVersion = 1; status = 'audited'; path = $target; exists = $false; compliant = $false
            protectedRoot = $false; expectedOwnerSid = $ownerSid.Value; scannedItemCount = 0; violationCount = 1
            violations = [ordered]@{ rootInheritance = 1; owner = 0; requiredGrant = 0; unexpectedAllow = 0; deny = 0 }
            unexpectedAllowSids = @()
        }
    }
    $items = @(Get-StateItems)
    $rootProtected = $false
    $ownerViolations = 0
    $grantViolations = 0
    $unexpectedAllowViolations = 0
    $denyViolations = 0
    $unexpectedSids = @()
    for ($index = 0; $index -lt $items.Count; $index++) {
        $acl = Get-AclObject $items[$index]
        if ($index -eq 0) { $rootProtected = [bool]$acl.AreAccessRulesProtected }
        try { $actualOwnerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value }
        catch { $actualOwnerSid = 'unresolved-owner' }
        if ($actualOwnerSid -cne $ownerSid.Value) { $ownerViolations++ }
        $allowRights = @{}
        foreach ($sid in $expectedSids) { $allowRights[$sid] = [long]0 }
        foreach ($rule in @($acl.Access)) {
            $sid = Get-SidValue $rule.IdentityReference
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
                $denyViolations++
                continue
            }
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($sid -notin $expectedSids) {
                $unexpectedAllowViolations++
                $unexpectedSids += $sid
                continue
            }
            $allowRights[$sid] = [long]$allowRights[$sid] -bor [long]$rule.FileSystemRights
        }
        foreach ($sid in $expectedSids) {
            if (([long]$allowRights[$sid] -band $fullControl) -ne $fullControl) { $grantViolations++ }
        }
    }
    $rootInheritanceViolations = if ($rootProtected) { 0 } else { 1 }
    $violationCount = $rootInheritanceViolations + $ownerViolations + $grantViolations + $unexpectedAllowViolations + $denyViolations
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        status = 'audited'
        path = $target
        exists = $true
        compliant = ($violationCount -eq 0)
        protectedRoot = $rootProtected
        expectedOwnerSid = $ownerSid.Value
        scannedItemCount = $items.Count
        violationCount = $violationCount
        violations = [ordered]@{
            rootInheritance = $rootInheritanceViolations
            owner = $ownerViolations
            requiredGrant = $grantViolations
            unexpectedAllow = $unexpectedAllowViolations
            deny = $denyViolations
        }
        unexpectedAllowSids = @($unexpectedSids | Sort-Object -Unique)
    }
}

function Set-PrivateAcl([IO.FileSystemInfo]$Item) {
    $acl = if ($Item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($ownerSid, $systemSid, $administratorsSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        if ($Item.PSIsContainer) { [IO.DirectoryInfo]::new($Item.FullName).SetAccessControl($acl) }
        else { [IO.FileInfo]::new($Item.FullName).SetAccessControl($acl) }
    } else {
        Set-Acl -LiteralPath $Item.FullName -AclObject $acl
    }
}

if ($AuditOnly) {
    Get-StateAclAudit | ConvertTo-Json -Depth 5
    return
}

if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "state directory does not exist: $target" }
$items = @(Get-StateItems)
if (-not $PSCmdlet.ShouldProcess($target, 'replace state ACLs recursively with current user, SYSTEM, and Administrators full control')) { return }

foreach ($item in $items) { Set-PrivateAcl $item }
$audit = Get-StateAclAudit
if (-not $audit.compliant) {
    throw "state ACL verification failed after protection: $($audit.violationCount) violation(s) across $($audit.scannedItemCount) item(s)"
}
$audit.status = 'protected'
$audit | ConvertTo-Json -Depth 5
