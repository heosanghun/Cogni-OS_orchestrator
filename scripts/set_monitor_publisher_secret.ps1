[CmdletBinding(DefaultParameterSetName = "Prompt")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "SecureString")]
    [Security.SecureString]$Secret,

    [Parameter(Mandatory = $true, ParameterSetName = "Environment")]
    [switch]$FromEnvironment,

    [Parameter(Mandatory = $false)]
    [string]$SecretPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = Join-Path $repoRoot (
        ".runtime\cogni-monitor-secret.clixml"
    )
}
$environmentSecret = $null
try {
    if ($PSCmdlet.ParameterSetName -eq "Environment") {
        $environmentSecret = [string]$env:COGNI_MONITOR_INGEST_SECRET
        if ([string]::IsNullOrWhiteSpace($environmentSecret)) {
            throw "COGNI_MONITOR_INGEST_SECRET is empty."
        }
        $Secret = ConvertTo-SecureString $environmentSecret -AsPlainText -Force
    } elseif ($null -eq $Secret) {
        $Secret = Read-Host "Monitoring HMAC secret" -AsSecureString
    }

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        $length = ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)).Length
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    if ($length -lt 32 -or $length -gt 256) {
        throw "Monitoring HMAC secret must contain 32-256 characters."
    }

    $parent = Split-Path -Parent $SecretPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = Join-Path $parent (
        ".cogni-monitor-secret.{0}.tmp" -f ([Guid]::NewGuid().ToString("N"))
    )
    try {
        $Secret | Export-Clixml -LiteralPath $temporary -Force
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $identity.User
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($sid)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $temporary -AclObject $acl
        Move-Item -LiteralPath $temporary -Destination $SecretPath -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }

    $verified = Import-Clixml -LiteralPath $SecretPath
    if ($verified -isnot [Security.SecureString]) {
        throw "DPAPI verification failed after writing the secret."
    }
    $writtenAcl = Get-Acl -LiteralPath $SecretPath
    $writtenOwnerSid = (
        [Security.Principal.NTAccount]$writtenAcl.Owner
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($writtenOwnerSid -ne $sid.Value) {
        throw "DPAPI secret owner does not match the current Windows principal."
    }
    [pscustomobject]@{
        SecretPath = $SecretPath
        Protection = "CURRENT_USER_DPAPI"
        PrincipalSid = $sid.Value
        Verified = $true
    }
} finally {
    $environmentSecret = $null
    $Secret = $null
    if ($FromEnvironment) {
        Remove-Item Env:COGNI_MONITOR_INGEST_SECRET -ErrorAction SilentlyContinue
    }
}
