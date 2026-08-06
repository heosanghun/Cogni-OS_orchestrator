Set-StrictMode -Version 3.0

$script:CogniTrustedInstallerSid = (
    'S-1-5-80-956008885-3418522649-1831038044-' +
    '1853292631-2271478464'
)
$script:CogniTrustedOwnerSids = @(
    'S-1-5-18',      # LocalSystem
    'S-1-5-32-544',  # BUILTIN\Administrators
    $script:CogniTrustedInstallerSid
)
function Get-CogniSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $stream = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return -join (
            $sha256.ComputeHash($stream) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Get-CogniPathChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    if (-not [IO.Path]::IsPathRooted($fullPath)) {
        throw 'Trusted executable path must be absolute.'
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    $chain = [Collections.Generic.List[string]]::new()
    $chain.Add($root)
    $relative = $fullPath.Substring($root.Length)
    $current = $root
    foreach ($component in $relative.Split(
        [char[]]@([IO.Path]::DirectorySeparatorChar),
        [StringSplitOptions]::RemoveEmptyEntries
    )) {
        $current = Join-Path $current $component
        $chain.Add($current)
    }
    return @($chain)
}

function Assert-CogniAdminOwnedPathChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $false)]
        [switch]$LeafMustBeFile
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

    $chain = @(Get-CogniPathChain -LiteralPath $LiteralPath)
    foreach ($component in $chain) {
        $item = Get-Item -LiteralPath $component -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Trusted path crosses a reparse point: $component"
        }
        $acl = Get-Acl -LiteralPath $component -ErrorAction Stop
        try {
            $ownerSid = (
                [Security.Principal.NTAccount]$acl.Owner
            ).Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            $ownerSid = [string]$acl.Owner
        }
        if ($ownerSid -notin $script:CogniTrustedOwnerSids) {
            throw "Trusted path is not admin-owned: $component"
        }
        $rules = @(
            $acl.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            )
        )
        $effectiveWriteMask = $writeMask
        if (
            [IO.Path]::GetFullPath($component) -eq
            [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($component))
        ) {
            # Windows volume roots commonly allow users to create unrelated
            # siblings. That cannot replace an already-existing trusted path;
            # deletion or ACL takeover of the root still remains forbidden.
            $effectiveWriteMask = (
                [Security.AccessControl.FileSystemRights]::Delete -bor
                [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            )
        }
        foreach ($rule in $rules) {
            if (
                $rule.AccessControlType -eq
                    [Security.AccessControl.AccessControlType]::Allow -and
                ($rule.PropagationFlags -band
                    [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                $rule.IdentityReference.Value -notin
                    $script:CogniTrustedOwnerSids -and
                (($rule.FileSystemRights -band $effectiveWriteMask) -ne 0)
            ) {
                throw "Trusted path is writable by an untrusted principal: $component"
            }
        }
    }
    $leaf = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if ($LeafMustBeFile -and $leaf.PSIsContainer) {
        throw "Trusted executable is not a file: $LiteralPath"
    }
    if ($LeafMustBeFile -and $leaf.Length -le 0) {
        throw "Trusted executable is empty: $LiteralPath"
    }
    return [IO.Path]::GetFullPath($leaf.FullName)
}

function Get-CogniTrustedExecutableRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z][a-z0-9_-]{1,31}$')]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $path = Assert-CogniAdminOwnedPathChain `
            -LiteralPath $candidate `
            -LeafMustBeFile
        return [pscustomobject]@{
            name = $Name
            path = $path
            sha256 = Get-CogniSha256 -LiteralPath $path
        }
    }
    throw "No trusted $Name executable exists in the fixed system allowlist."
}

function Assert-CogniTrustedExecutableRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Record
    )

    $path = Assert-CogniAdminOwnedPathChain `
        -LiteralPath ([string]$Record.path) `
        -LeafMustBeFile
    $sha256 = Get-CogniSha256 -LiteralPath $path
    if ($sha256 -ne [string]$Record.sha256) {
        throw "Trusted executable changed after attestation: $($Record.name)"
    }
    return $true
}

function ConvertTo-CogniBinaryManifestJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject[]]$Records
    )

    $manifest = [ordered]@{
        schema_version = 1
        executables = [ordered]@{}
    }
    foreach ($record in $Records) {
        if ($manifest.executables.Contains([string]$record.name)) {
            throw "Duplicate trusted executable record: $($record.name)"
        }
        $manifest.executables[[string]$record.name] = [ordered]@{
            path = [string]$record.path
            sha256 = [string]$record.sha256
        }
    }
    return $manifest | ConvertTo-Json -Compress -Depth 5
}
