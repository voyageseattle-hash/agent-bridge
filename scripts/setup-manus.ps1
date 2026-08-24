param(
    [string]$CredentialPath = (Join-Path $env:USERPROFILE '.agent-bridge\secrets\manus-api-key')
)

$ErrorActionPreference = 'Stop'
$secret = Read-Host 'Paste the Manus API key (input is hidden)' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No API key was entered.' }
    $directory = Split-Path -Parent $CredentialPath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [IO.File]::WriteAllText($CredentialPath, $plain.Trim(), [Text.UTF8Encoding]::new($false))
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner([Security.Principal.NTAccount]::new("$env:USERDOMAIN\$env:USERNAME"))
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        "$env:USERDOMAIN\$env:USERNAME",
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $CredentialPath -AclObject $acl
    Write-Host "Manus credential stored at $CredentialPath"
    Write-Host 'Restart Codex and Claude after enabling agents.manus in the bridge config.'
} finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $plain = $null
}
