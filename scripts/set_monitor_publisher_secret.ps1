[CmdletBinding(DefaultParameterSetName = "Prompt")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "SecureString")]
    [Security.SecureString]$Secret,

    [Parameter(Mandatory = $true, ParameterSetName = "Environment")]
    [switch]$FromEnvironment,

    [Parameter(Mandatory = $false)]
    [string]$SecretPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$ValidationOnly
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$canonicalSecretPath = Join-Path $repoRoot '.runtime\cogni-monitor-secret.clixml'

function Assert-CogniSecretBootstrapFileTrust {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $allowedOwners = @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    $writeMask = (
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    $cursor = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Secret bootstrap path crosses a reparse point: $($cursor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $ownerSid = (
            [Security.Principal.NTAccount]$acl.Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedOwners) {
            throw "Secret bootstrap path is not administrator-owned: $($cursor.FullName)"
        }
        foreach ($rule in @($acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        ))) {
            $effectiveWriteMask = $writeMask
            if (
                [IO.Path]::GetFullPath($cursor.FullName) -eq
                [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($cursor.FullName))
            ) {
                $effectiveWriteMask = (
                    [Security.AccessControl.FileSystemRights]::Delete -bor
                    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                    [Security.AccessControl.FileSystemRights]::TakeOwnership
                )
            }
            if (
                $rule.AccessControlType -eq
                    [Security.AccessControl.AccessControlType]::Allow -and
                ($rule.PropagationFlags -band
                    [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                $rule.IdentityReference.Value -notin $allowedOwners -and
                ($rule.FileSystemRights -band $effectiveWriteMask) -ne 0
            ) {
                throw "Secret bootstrap path is writable by an untrusted principal: $($cursor.FullName)"
            }
        }
        $parent = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor.FullName) {
            break
        }
        $cursor = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0) {
        throw "Secret bootstrap file is not a bounded regular file: $fullPath"
    }
    return $item.FullName
}

function Get-CogniRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $target = [IO.Path]::GetFullPath($TargetPath)
    $getRelativePath = [IO.Path].GetMethod(
        'GetRelativePath',
        [type[]]@([string], [string])
    )
    if ($null -ne $getRelativePath) {
        return [string]$getRelativePath.Invoke($null, @($base, $target))
    }
    $baseUri = [Uri]::new($base)
    $targetUri = [Uri]::new($target)
    return [Uri]::UnescapeDataString(
        $baseUri.MakeRelativeUri($targetUri).ToString()
    ).Replace('/', [IO.Path]::DirectorySeparatorChar)
}

function Test-CogniPathContained {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $relative = Get-CogniRelativePath -BasePath $BasePath -TargetPath $TargetPath
    return (
        -not [string]::IsNullOrWhiteSpace($relative) -and
        -not [IO.Path]::IsPathRooted($relative) -and
        $relative -ne '..' -and
        -not $relative.StartsWith(
            '..' + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::Ordinal
        )
    )
}

if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = $canonicalSecretPath
}
$SecretPath = [IO.Path]::GetFullPath($SecretPath)
if ($ValidationOnly) {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (
        $FromEnvironment -or
        (Test-Path Env:COGNI_MONITOR_INGEST_SECRET) -or
        -not (Test-CogniPathContained `
            -BasePath $temporaryRoot `
            -TargetPath $SecretPath)
    ) {
        throw 'ValidationOnly secret path must remain inside the OS temporary root.'
    }
} else {
    if (-not [string]::Equals(
        $SecretPath,
        [IO.Path]::GetFullPath($canonicalSecretPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Production secret path is fixed and cannot be overridden.'
    }
    foreach ($path in @(
        $PSCommandPath,
        (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1')
    )) {
        $null = Assert-CogniSecretBootstrapFileTrust -LiteralPath $path
    }
}
. (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1')

function Get-CogniSecretParentWriteMask {
    param([Parameter(Mandatory = $false)][switch]$IsRoot)

    if ($IsRoot) {
        # Volume roots commonly grant create-directory/append-data rights to
        # ordinary users.  Those rights cannot replace an existing descendant.
        # Only destructive or ACL-takeover rights are unsafe at this boundary.
        return (
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        )
    }
    return (
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
}

function Assert-CogniSecretParent {
    param(
        [Parameter(Mandatory = $true)][string]$ParentPath,
        [Parameter(Mandatory = $false)][switch]$ProductionTrust
    )

    if (-not (Test-Path -LiteralPath $ParentPath -PathType Container)) {
        throw 'Secret parent must be provisioned before secret rotation.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $records = [Collections.Generic.List[string]]::new()
    $cursor = Get-Item -LiteralPath $ParentPath -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Secret parent chain crosses a reparse point: $($cursor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $ownerSid = (
            [Security.Principal.NTAccount]$acl.Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($ProductionTrust) {
            $cursorFullPath = [IO.Path]::GetFullPath($cursor.FullName)
            $isRoot = $cursorFullPath -eq [IO.Path]::GetPathRoot($cursorFullPath)
            $effectiveWriteMask = Get-CogniSecretParentWriteMask -IsRoot:$isRoot
            $allowedWriters = @(
                $ownerSid,
                'S-1-5-18',
                'S-1-5-32-544',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
            ) | Sort-Object -Unique
            foreach ($rule in @($acl.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            ))) {
                if (
                    $rule.AccessControlType -eq
                        [Security.AccessControl.AccessControlType]::Allow -and
                    ($rule.PropagationFlags -band
                        [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                    $rule.IdentityReference.Value -notin $allowedWriters -and
                    ($rule.FileSystemRights -band $effectiveWriteMask) -ne 0
                ) {
                    throw "Secret parent chain is writable by an untrusted principal: $($cursor.FullName)"
                }
            }
        }
        $records.Add((
            '{0}|{1}|{2}|{3}' -f
            [IO.Path]::GetFullPath($cursor.FullName),
            [int]$cursor.Attributes,
            $ownerSid,
            $acl.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::Access
            )
        ))
        $parent = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor.FullName) {
            break
        }
        $cursor = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
    $acl = Get-Acl -LiteralPath $ParentPath -ErrorAction Stop
    $ownerSid = (
        [Security.Principal.NTAccount]$acl.Owner
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -ne $identity.User.Value) {
        throw 'Secret parent is not owned by the current Windows principal.'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($records -join "`n"))
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return -join (
            $hasher.ComputeHash($bytes) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $hasher.Dispose()
    }
}

function Assert-CogniExistingSecretTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnerSid
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt 65536
    ) {
        throw 'Existing secret target is not a bounded regular non-reparse file.'
    }
    $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $observedOwner = (
        [Security.Principal.NTAccount]$acl.Owner
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    ))
    if (
        $observedOwner -ne $OwnerSid -or
        -not $acl.AreAccessRulesProtected -or
        $rules.Count -ne 1 -or
        $rules[0].IdentityReference.Value -ne $OwnerSid -or
        $rules[0].AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
        (($rules[0].FileSystemRights -band
            [Security.AccessControl.FileSystemRights]::FullControl) -ne
            [Security.AccessControl.FileSystemRights]::FullControl)
    ) {
        throw 'Existing secret target ownership or ACL is not exact.'
    }
    return $true
}

function Get-CogniSecretTargetTrustFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnerSid
    )

    $null = Assert-CogniExistingSecretTarget -Path $Path -OwnerSid $OwnerSid
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $value = '{0}|{1}|{2}|{3}' -f
        [IO.Path]::GetFullPath($item.FullName),
        [int]$item.Attributes,
        $OwnerSid,
        $acl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return -join (
            $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $hasher.Dispose()
    }
}

$parent = Split-Path -Parent $SecretPath
$parentFingerprint = Assert-CogniSecretParent `
    -ParentPath $parent `
    -ProductionTrust:(-not $ValidationOnly)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
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

    $targetExists = Test-Path -LiteralPath $SecretPath -PathType Leaf
    $targetFingerprint = $null
    if ($targetExists) {
        $targetFingerprint = Get-CogniSecretTargetTrustFingerprint `
            -Path $SecretPath `
            -OwnerSid $sid.Value
    } elseif (Test-Path -LiteralPath $SecretPath) {
        throw 'Secret target exists but is not a regular file.'
    }
    $temporary = Join-Path $parent (
        ".cogni-monitor-secret.{0}.tmp" -f ([Guid]::NewGuid().ToString("N"))
    )
    try {
        $Secret | Export-Clixml -LiteralPath $temporary
        $temporaryItem = Get-Item -LiteralPath $temporary -Force
        if (($temporaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Temporary secret unexpectedly resolved to a reparse point.'
        }
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
        $parentBeforeCommit = Assert-CogniSecretParent `
            -ParentPath $parent `
            -ProductionTrust:(-not $ValidationOnly)
        if ($parentBeforeCommit -cne $parentFingerprint) {
            throw 'Secret parent trust fingerprint changed before atomic commit.'
        }
        if ($targetExists) {
            $targetBeforeCommit = Get-CogniSecretTargetTrustFingerprint `
                -Path $SecretPath `
                -OwnerSid $sid.Value
            if ($targetBeforeCommit -cne $targetFingerprint) {
                throw 'Secret target trust fingerprint changed before atomic replace.'
            }
            [IO.File]::Replace($temporary, $SecretPath, $null)
        } else {
            [IO.File]::Move($temporary, $SecretPath)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }

    $parentAfterCommit = Assert-CogniSecretParent `
        -ParentPath $parent `
        -ProductionTrust:(-not $ValidationOnly)
    if ($parentAfterCommit -cne $parentFingerprint) {
        throw 'Secret parent trust fingerprint changed during atomic commit.'
    }
    $null = Get-CogniSecretTargetTrustFingerprint `
        -Path $SecretPath `
        -OwnerSid $sid.Value
    $verified = Import-Clixml -LiteralPath $SecretPath
    if ($verified -isnot [Security.SecureString]) {
        throw "DPAPI verification failed after writing the secret."
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
