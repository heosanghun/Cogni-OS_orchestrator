[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$WorkspaceRoot = "",

    [Parameter(Mandatory = $false)]
    [string]$Endpoint = "https://cogni-os-orchestrator.pages.dev/api/ingest",

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 3600)]
    [int]$IntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 3600)]
    [int]$MaxBackoffSeconds = 300,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGpu,

    [Parameter(Mandatory = $false)]
    [switch]$Once,

    [Parameter(Mandatory = $false)]
    [string]$SecretPath = "",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = "",

    [Parameter(Mandatory = $false)]
    [string]$PythonPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$ValidationOnly
)

$ErrorActionPreference = "Stop"
$scriptRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$canonicalSecretPath = Join-Path $scriptRepoRoot (
    '.runtime\cogni-monitor-secret.clixml'
)
$canonicalStateDir = Join-Path $scriptRepoRoot '.runtime\monitor-publisher'

function Assert-CogniBootstrapFileTrust {
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
            throw "Publisher bootstrap path crosses a reparse point: $($cursor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $ownerSid = (
            [Security.Principal.NTAccount]$acl.Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedOwners) {
            throw "Publisher bootstrap path is not administrator-owned: $($cursor.FullName)"
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
                throw "Publisher bootstrap path is writable by an untrusted principal: $($cursor.FullName)"
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
        throw "Publisher bootstrap file is not a bounded regular file: $fullPath"
    }
    return $item.FullName
}

function Test-CogniContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    if ([string]::IsNullOrWhiteSpace($BasePath) -or
        [string]::IsNullOrWhiteSpace($TargetPath)) {
        return $false
    }
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $target = [IO.Path]::GetFullPath($TargetPath)
    return $target.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)
}

if ($ValidationOnly) {
    # Validation paths are explicit and isolated; production defaults are never
    # inherited into this seam.
    if ([string]::IsNullOrWhiteSpace($WorkspaceRoot) -or
        [string]::IsNullOrWhiteSpace($SecretPath) -or
        [string]::IsNullOrWhiteSpace($StateDir) -or
        [string]::IsNullOrWhiteSpace($PythonPath)) {
        throw 'ValidationOnly requires explicit isolated paths.'
    }
} else {
    if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) {
        $WorkspaceRoot = $scriptRepoRoot
    }
    if ([string]::IsNullOrWhiteSpace($SecretPath)) {
        $SecretPath = $canonicalSecretPath
    }
    if ([string]::IsNullOrWhiteSpace($StateDir)) {
        $StateDir = $canonicalStateDir
    }
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($SecretPath),
        [IO.Path]::GetFullPath($canonicalSecretPath),
        [StringComparison]::OrdinalIgnoreCase
    ) -or -not [string]::Equals(
        [IO.Path]::GetFullPath($StateDir),
        [IO.Path]::GetFullPath($canonicalStateDir),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Production secret and state paths are fixed and cannot be overridden.'
    }
}

$bootstrapFiles = @(
    $PSCommandPath,
    (Join-Path $PSScriptRoot "publisher_production_preflight.ps1"),
    (Join-Path $PSScriptRoot "publisher_binary_trust.ps1")
)
if ($ValidationOnly) {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $validationRoot = [IO.Path]::GetFullPath($WorkspaceRoot)
    if (
        -not $Once -or
        $Endpoint -ne 'https://127.0.0.1:9/must-not-connect' -or
        -not (Test-CogniContainedPath `
            -BasePath $temporaryRoot -TargetPath $validationRoot) -or
        -not (Test-CogniContainedPath `
            -BasePath $validationRoot -TargetPath $SecretPath) -or
        -not (Test-CogniContainedPath `
            -BasePath $validationRoot -TargetPath $StateDir) -or
        -not (Test-CogniContainedPath `
            -BasePath $validationRoot -TargetPath $PythonPath) -or
        (Test-Path Env:COGNI_MONITOR_INGEST_SECRET)
    ) {
        throw 'ValidationOnly is restricted to an isolated, non-network test seam.'
    }
} else {
    foreach ($bootstrapFile in $bootstrapFiles) {
        $null = Assert-CogniBootstrapFileTrust -LiteralPath $bootstrapFile
    }
}
. (Join-Path $PSScriptRoot "publisher_production_preflight.ps1")
. (Join-Path $PSScriptRoot "publisher_binary_trust.ps1")
$canonicalOrigin = "https://cogni-os-orchestrator.pages.dev"
$canonicalIngestEndpoint = "$canonicalOrigin/api/ingest"
$canonicalHealthEndpoint = "$canonicalOrigin/api/health"

function Write-WrapperJournal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EventName,
        [Parameter(Mandatory = $false)]
        [string]$Message = ""
    )

    try {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        $safeMessage = ($Message -replace "[`r`n]+", " ").Trim()
        if ($safeMessage.Length -gt 512) {
            $safeMessage = $safeMessage.Substring(0, 512)
        }
        $entry = [ordered]@{
            schema_version = 1
            observed_at = [DateTime]::UtcNow.ToString("o")
            event = $EventName
            pid = $PID
            message = $safeMessage
        }
        $entry | ConvertTo-Json -Compress | Add-Content -LiteralPath (
            Join-Path $StateDir "monitor_publisher_wrapper_journal.jsonl"
        ) -Encoding UTF8
    } catch {
        # Journal failure must never trigger a plaintext-secret fallback.
    }
}

function Read-CurrentUserDpapiSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        throw "DPAPI secret path is a directory."
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "DPAPI secret path must not be a reparse point."
    }
    if ($item.Length -le 0 -or $item.Length -gt 65536) {
        throw "DPAPI secret file size is outside the safe range."
    }
    try {
        $ownerSid = (
            [Security.Principal.NTAccount](Get-Acl -LiteralPath $item.FullName).Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    } catch {
        throw "DPAPI secret ownership could not be verified."
    }
    if ($ownerSid -ne $currentSid) {
        throw (
            "DPAPI secret belongs to a different Windows principal. " +
            "Fail-closed key rotation is required."
        )
    }
    try {
        $secureSecret = Import-Clixml -LiteralPath $item.FullName
    } catch {
        throw (
            "Current-user DPAPI secret recovery failed. " +
            "The file may belong to another Windows user or PC."
        )
    }
    if ($secureSecret -isnot [Security.SecureString]) {
        throw "DPAPI secret file does not contain a SecureString."
    }

    $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $secureSecret
    )
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    }
}

function Invoke-CogniTrustedGit {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$GitRecord,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 10,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1024, 1048576)]
        [int]$MaxStdoutBytes = 262144,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1024, 262144)]
        [int]$MaxStderrBytes = 65536
    )

    $environmentNames = @(
        'PATH', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
        'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
        'GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_NOSYSTEM', 'GIT_CEILING_DIRECTORIES',
        'GIT_TERMINAL_PROMPT', 'GIT_OPTIONAL_LOCKS',
        'GIT_EXTERNAL_DIFF', 'GIT_SSH', 'GIT_SSH_COMMAND',
        'GIT_ASKPASS', 'SSH_ASKPASS'
    )
    $prior = @{}
    foreach ($name in $environmentNames) {
        $prior[$name] = if (Test-Path "Env:$name") {
            [pscustomobject]@{ Exists = $true; Value = [string](Get-Item "Env:$name").Value }
        } else {
            [pscustomobject]@{ Exists = $false; Value = '' }
        }
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    $captureRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'cogni-git-{0}' -f ([Guid]::NewGuid().ToString('N'))
    )
    $stdoutPath = Join-Path $captureRoot 'stdout.txt'
    $stderrPath = Join-Path $captureRoot 'stderr.txt'
    $process = $null
    try {
        New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null
        $env:PATH = (
            (Split-Path -Parent ([string]$GitRecord.path)) + ';' +
            (Join-Path $env:SystemRoot 'System32')
        )
        $env:GIT_CONFIG_NOSYSTEM = '1'
        $env:GIT_TERMINAL_PROMPT = '0'
        $env:GIT_OPTIONAL_LOCKS = '0'
        $nativeArguments = @(
            '-c', 'credential.helper=',
            '-c', 'core.fsmonitor=false',
            '-c', 'core.hooksPath=NUL',
            '-c', 'diff.external='
        )
        $nativeArguments += $Arguments
        $argumentLine = ($nativeArguments | ForEach-Object {
            $value = [string]$_
            if ($value.IndexOf([char]0) -ge 0 -or $value.Contains('"')) {
                throw 'Trusted Git argument contains a forbidden character.'
            }
            '"' + $value + '"'
        }) -join ' '
        $process = Start-Process `
            -FilePath ([string]$GitRecord.path) `
            -ArgumentList $argumentLine `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru `
            -NoNewWindow
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not $process.HasExited) {
            $stdoutSize = if (Test-Path -LiteralPath $stdoutPath) {
                (Get-Item -LiteralPath $stdoutPath -Force).Length
            } else { 0 }
            $stderrSize = if (Test-Path -LiteralPath $stderrPath) {
                (Get-Item -LiteralPath $stderrPath -Force).Length
            } else { 0 }
            if (
                $stdoutSize -gt $MaxStdoutBytes -or
                $stderrSize -gt $MaxStderrBytes
            ) {
                $process.Kill()
                throw 'Trusted Git output exceeded the bounded capture limit.'
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                $process.Kill()
                throw 'Trusted Git command exceeded its fixed timeout.'
            }
            Start-Sleep -Milliseconds 50
            $process.Refresh()
        }
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        foreach ($capture in @(
            @($stdoutPath, $MaxStdoutBytes),
            @($stderrPath, $MaxStderrBytes)
        )) {
            if (
                (Test-Path -LiteralPath $capture[0]) -and
                (Get-Item -LiteralPath $capture[0] -Force).Length -gt [int64]$capture[1]
            ) {
                throw 'Trusted Git output exceeded the bounded capture limit.'
            }
        }
        $result = if (Test-Path -LiteralPath $stdoutPath) {
            @(Get-Content -LiteralPath $stdoutPath -Encoding UTF8)
        } else { @() }
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            (Get-Content -LiteralPath $stderrPath -Raw -Encoding UTF8).Trim()
        } else { '' }
    } finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                $process.Kill()
            }
            $process.Dispose()
        }
        Remove-Item -LiteralPath $captureRoot -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($name in $environmentNames) {
            if ($prior[$name].Exists) {
                Set-Item "Env:$name" $prior[$name].Value
            } else {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            }
        }
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        Output = @($result)
        StandardError = $stderr
    }
}

function Get-CleanLocalSourceCommit {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$GitRecord
    )

    $resolved = Invoke-CogniTrustedGit -GitRecord $GitRecord -Arguments @(
        '-C', $scriptRepoRoot, 'rev-parse', '--verify', 'HEAD^{commit}'
    )
    $commit = @($resolved.Output)
    if ($resolved.ExitCode -ne 0 -or $commit.Count -ne 1) {
        throw "Publisher source commit could not be resolved."
    }
    $commit = ([string]$commit[0]).Trim().ToLowerInvariant()
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw "Publisher source commit is invalid."
    }
    $statusResult = Invoke-CogniTrustedGit -GitRecord $GitRecord -Arguments @(
        '-C', $scriptRepoRoot, 'status', '--porcelain=v1',
        '--untracked-files=all', '--ignore-submodules=none'
    )
    if ($statusResult.ExitCode -ne 0 -or @($statusResult.Output).Count -ne 0) {
        throw "Publisher source tree is not clean; startup is fail-closed."
    }
    $confirmed = Invoke-CogniTrustedGit -GitRecord $GitRecord -Arguments @(
        '-C', $scriptRepoRoot, 'rev-parse', '--verify', 'HEAD^{commit}'
    )
    if (
        $confirmed.ExitCode -ne 0 -or
        @($confirmed.Output).Count -ne 1 -or
        ([string]$confirmed.Output[0]).Trim().ToLowerInvariant() -ne $commit
    ) {
        throw "Publisher source ref changed during startup attestation."
    }
    return $commit
}

function Get-CollectorCodeManifest {
    $maxFiles = 4096
    $maxPathCharacters = 1048576
    $maxFileBytes = 67108864
    $maxTotalBytes = 536870912
    $pathCharacters = 0
    $totalBytes = [int64]0
    $paths = [Collections.Generic.List[string]]::new()
    foreach ($name in @(
        'publisher_binary_trust.ps1',
        'publisher_production_preflight.ps1',
        'run_monitor_publisher.ps1',
        'publish_monitor_snapshot.py'
    )) {
        $candidate = Join-Path $PSScriptRoot $name
        $pathCharacters += $candidate.Length
        if ($pathCharacters -gt $maxPathCharacters) {
            throw 'Collector code manifest path budget was exceeded.'
        }
        $paths.Add($candidate)
    }
    Get-ChildItem `
        -LiteralPath (Join-Path $scriptRepoRoot 'src\cogni_os') `
        -Recurse `
        -File `
        -Include '*.py' |
        ForEach-Object {
            if ($paths.Count -ge $maxFiles) {
                throw 'Collector code manifest file-count budget was exceeded.'
            }
            $pathCharacters += $_.FullName.Length
            if ($pathCharacters -gt $maxPathCharacters) {
                throw 'Collector code manifest path budget was exceeded.'
            }
            $paths.Add($_.FullName)
        }
    if ($paths.Count -gt $maxFiles) {
        throw 'Collector code manifest file-count budget was exceeded.'
    }
    $records = foreach ($path in @($paths | Sort-Object -Unique)) {
        $trustedPath = Assert-CogniAdminOwnedPathChain `
            -LiteralPath $path `
            -LeafMustBeFile
        $item = Get-Item -LiteralPath $trustedPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Collector code path is a reparse point: $path"
        }
        if ($item.Length -le 0 -or $item.Length -gt $maxFileBytes) {
            throw "Collector code file exceeds the per-file budget: $path"
        }
        $totalBytes += [int64]$item.Length
        if ($totalBytes -gt $maxTotalBytes) {
            throw 'Collector code manifest byte budget was exceeded.'
        }
        [ordered]@{
            path = $item.FullName.Substring($scriptRepoRoot.Length).TrimStart('\').Replace('\', '/')
            size = [int64]$item.Length
            sha256 = Get-CogniSha256 -LiteralPath $item.FullName
        }
    }
    $canonical = $records | ConvertTo-Json -Compress -Depth 4
    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join (
            $sha256.ComputeHash($bytes) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $sha256.Dispose()
    }
    return [pscustomobject]@{
        sha256 = $digest
        files = @($records).Count
    }
}

function Assert-CollectorCodeState {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$GitRecord,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedCommit,
        [Parameter(Mandatory = $true)]
        [psobject]$ExpectedManifest
    )

    $commit = Get-CleanLocalSourceCommit -GitRecord $GitRecord
    $manifest = Get-CollectorCodeManifest
    if (
        $commit -ne $ExpectedCommit -or
        $manifest.sha256 -ne $ExpectedManifest.sha256 -or
        $manifest.files -ne $ExpectedManifest.files
    ) {
        throw 'Collector source commit or code manifest changed after attestation.'
    }
    return $true
}

function Quote-CogniNativeArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.IndexOf([char]0) -ge 0 -or $Value.Contains('"')) {
        throw 'Publisher child argument contains a forbidden character.'
    }
    return '"' + $Value + '"'
}

function Invoke-CogniSanitizedPublisher {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$PythonRecord,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [hashtable]$Environment
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [string]$PythonRecord.path
    $start.Arguments = (($Arguments | ForEach-Object {
        Quote-CogniNativeArgument -Value ([string]$_)
    }) -join ' ')
    $start.WorkingDirectory = $scriptRepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $false
    $start.EnvironmentVariables.Clear()
    foreach ($name in @('SystemRoot', 'WINDIR', 'ComSpec', 'TEMP', 'TMP')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $start.EnvironmentVariables[$name] = $value
        }
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        $start.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'Trusted Python publisher process did not start.'
    }
    $process.WaitForExit()
    $code = $process.ExitCode
    $process.Dispose()
    return $code
}

function Invoke-ProductionReadinessPreflight {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSourceCommit
    )

    if ($Endpoint -ne $canonicalIngestEndpoint) {
        throw "Publisher endpoint must be the canonical production ingest endpoint."
    }
    $response = Invoke-WebRequest `
        -Uri $canonicalHealthEndpoint `
        -Method Get `
        -UseBasicParsing `
        -MaximumRedirection 0 `
        -TimeoutSec 15 `
        -Headers @{
            Accept = "application/json"
            "Cache-Control" = "no-cache"
            Pragma = "no-cache"
        }
    if ([int]$response.StatusCode -ne 200) {
        throw "Publisher preflight health endpoint did not return HTTP 200."
    }
    try {
        $health = $response.Content | ConvertFrom-Json
    } catch {
        throw "Publisher preflight health response is not valid JSON."
    }
    return Assert-CogniPublisherProductionHealth `
        -Health $health `
        -ExpectedSourceCommit $ExpectedSourceCommit
}

$exitCode = 1
$secret = $null

try {
    $keyId = if ($env:COGNI_MONITOR_KEY_ID) {
        [string]$env:COGNI_MONITOR_KEY_ID
    } else {
        "publisher-2026q3"
    }
    if (
        [string]::IsNullOrWhiteSpace($keyId) -or
        $keyId -notmatch '^[A-Za-z0-9._:-]{3,64}$'
    ) {
        throw "COGNI_MONITOR_KEY_ID must be a safe 3-64 character key id."
    }
    if (-not $Once -and $MaxBackoffSeconds -lt $IntervalSeconds) {
        throw "MaxBackoffSeconds cannot be lower than IntervalSeconds."
    }
    foreach ($name in @(
        'COGNI_PYTHON', 'PYTHONPATH', 'PYTHONHOME', 'GIT_DIR',
        'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
        'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG',
        'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT',
        'GIT_EXTERNAL_DIFF', 'GIT_SSH', 'GIT_SSH_COMMAND',
        'GIT_ASKPASS', 'SSH_ASKPASS', 'NODE_OPTIONS'
    )) {
        if (Test-Path "Env:$name") {
            throw "Production publisher rejects inherited runtime override: $name"
        }
    }

    if ($ValidationOnly) {
        $validationSecret = Read-CurrentUserDpapiSecret -Path $SecretPath
        try {
            if (
                [string]::IsNullOrWhiteSpace($validationSecret) -or
                $validationSecret.Length -lt 32 -or
                $validationSecret.Length -gt 256
            ) {
                throw 'ValidationOnly DPAPI secret must contain 32-256 characters.'
            }
        } finally {
            $validationSecret = $null
        }
        throw 'ValidationOnly completed the secret contract without invoking Python or network.'
    }
    $powerShellRecord = Get-CogniTrustedExecutableRecord `
        -Name 'powershell' `
        -Candidates @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    $currentPowerShell = [IO.Path]::GetFullPath((Get-Process -Id $PID).Path)
    if ($currentPowerShell -ne [IO.Path]::GetFullPath($powerShellRecord.path)) {
        throw 'Publisher wrapper is not running under the fixed trusted PowerShell.'
    }
    $gitRecord = Get-CogniTrustedExecutableRecord `
        -Name 'git' `
        -Candidates @(
            'C:\Program Files\Git\cmd\git.exe',
            'C:\Program Files\Git\bin\git.exe'
        )
    $fixedPythonCandidates = @(
        'C:\Program Files\Python312\python.exe',
        'C:\Program Files\Python310\python.exe'
    )
    if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
        $requestedPython = [IO.Path]::GetFullPath($PythonPath)
        if ($requestedPython -notin $fixedPythonCandidates) {
            throw 'PythonPath is not in the fixed system Python allowlist.'
        }
        $fixedPythonCandidates = @($requestedPython)
    }
    $pythonRecord = Get-CogniTrustedExecutableRecord `
        -Name 'python' `
        -Candidates $fixedPythonCandidates
    $binaryRecords = [Collections.Generic.List[object]]::new()
    foreach ($record in @($powerShellRecord, $gitRecord, $pythonRecord)) {
        $binaryRecords.Add($record)
    }
    if ($IncludeGpu) {
        $binaryRecords.Add((Get-CogniTrustedExecutableRecord `
            -Name 'nvidia-smi' `
            -Candidates @('C:\Windows\System32\nvidia-smi.exe')))
    }
    $sourceCommit = Get-CleanLocalSourceCommit -GitRecord $gitRecord
    $codeManifest = Get-CollectorCodeManifest
    $preflight = Invoke-ProductionReadinessPreflight `
        -ExpectedSourceCommit $sourceCommit
    $null = Assert-CollectorCodeState `
        -GitRecord $gitRecord `
        -ExpectedCommit $sourceCommit `
        -ExpectedManifest $codeManifest
    foreach ($record in $binaryRecords) {
        $null = Assert-CogniTrustedExecutableRecord -Record $record
    }
    $secret = [string]$env:COGNI_MONITOR_INGEST_SECRET
    if (
        [string]::IsNullOrWhiteSpace($secret) -and
        (Test-Path -LiteralPath $SecretPath)
    ) {
        $secret = Read-CurrentUserDpapiSecret -Path $SecretPath
    }
    if (
        [string]::IsNullOrWhiteSpace($secret) -or
        $secret.Length -lt 32 -or
        $secret.Length -gt 256
    ) {
        throw (
            "COGNI_MONITOR_INGEST_SECRET or the current-user DPAPI secret file " +
            "must contain the matching 32-256 character secret."
        )
    }
    Write-WrapperJournal -EventName "production_preflight_passed" -Message (
        "source_commit=$($preflight.source_commit) " +
        "minimum_release_snapshot_schema=" +
        $preflight.minimum_release_snapshot_schema
    )
    $effectiveInterval = if ($Once) { 0 } else { $IntervalSeconds }
    $arguments = @(
        "-B",
        (Join-Path $PSScriptRoot "publish_monitor_snapshot.py"),
        $WorkspaceRoot,
        "--key-id",
        $keyId,
        "--endpoint",
        $Endpoint,
        "--state-dir",
        $StateDir,
        "--interval-seconds",
        [string]$effectiveInterval,
        "--max-backoff-seconds",
        [string]$MaxBackoffSeconds
    )
    if ($IncludeGpu) {
        $arguments += "--include-gpu"
    }

    Write-WrapperJournal -EventName "wrapper_started" -Message (
        "GPU telemetry " + $(if ($IncludeGpu) { "ENABLED" } else { "DISABLED" })
    )
    $childEnvironment = @{
        PYTHONPATH = (Join-Path $scriptRepoRoot 'src')
        PYTHONNOUSERSITE = '1'
        PYTHONDONTWRITEBYTECODE = '1'
        PYTHONUTF8 = '1'
        COGNI_MONITOR_INGEST_SECRET = $secret
        COGNI_MONITOR_KEY_ID = $keyId
        COGNI_PUBLISHER_PRODUCTION = '1'
        COGNI_PUBLISHER_SOURCE_COMMIT = $sourceCommit
        COGNI_PUBLISHER_CODE_MANIFEST_SHA256 = $codeManifest.sha256
        COGNI_PUBLISHER_BINARY_MANIFEST = (
            ConvertTo-CogniBinaryManifestJson -Records @($binaryRecords)
        )
    }
    $exitCode = Invoke-CogniSanitizedPublisher `
        -PythonRecord $pythonRecord `
        -Arguments $arguments `
        -Environment $childEnvironment
    $null = Assert-CollectorCodeState `
        -GitRecord $gitRecord `
        -ExpectedCommit $sourceCommit `
        -ExpectedManifest $codeManifest
    foreach ($record in $binaryRecords) {
        $null = Assert-CogniTrustedExecutableRecord -Record $record
    }
    Write-WrapperJournal -EventName "python_exited" -Message (
        "exit_code=$exitCode"
    )
} catch {
    Write-WrapperJournal -EventName "wrapper_failed" -Message $_.Exception.Message
    Write-Error $_.Exception.Message
    $exitCode = 1
} finally {
    $secret = $null
}
exit $exitCode
