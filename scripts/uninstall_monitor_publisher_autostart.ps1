[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TaskName = "Cogni-OS Monitor Publisher",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$canonicalTaskName = 'Cogni-OS Monitor Publisher'
$canonicalEndpoint = 'https://cogni-os-orchestrator.pages.dev/api/ingest'
$canonicalSecretPath = Join-Path $repoRoot '.runtime\cogni-monitor-secret.clixml'
$canonicalStateDir = Join-Path $repoRoot '.runtime\monitor-publisher'
$runner = Join-Path $PSScriptRoot 'run_monitor_publisher.ps1'
$publisherScript = Join-Path $PSScriptRoot 'publish_monitor_snapshot.py'
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentIdentitySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Test-CogniUninstallIdentityBinding {
    param([Parameter(Mandatory = $true)][string]$ObservedIdentity)

    try {
        $observedSid = (
            [Security.Principal.NTAccount]$ObservedIdentity
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        return $observedSid -ceq $currentIdentitySid
    } catch {
        return $false
    }
}

function Assert-CogniUninstallBootstrapFileTrust {
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
            throw "Uninstaller bootstrap path crosses a reparse point: $($cursor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $ownerSid = (
            [Security.Principal.NTAccount]$acl.Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedOwners) {
            throw "Uninstaller bootstrap path is not administrator-owned: $($cursor.FullName)"
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
                throw "Uninstaller bootstrap path is writable by an untrusted principal: $($cursor.FullName)"
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
        throw "Uninstaller bootstrap file is not a bounded regular file: $fullPath"
    }
    return $item.FullName
}

foreach ($bootstrapFile in @(
    $PSCommandPath,
    (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1')
)) {
    $null = Assert-CogniUninstallBootstrapFileTrust `
        -LiteralPath $bootstrapFile
}
. (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1')

if ($TaskName -ne $canonicalTaskName) {
    throw 'Production publisher task name is fixed; arbitrary tasks are never removed.'
}
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = $canonicalStateDir
}
if (
    -not [string]::Equals(
        [IO.Path]::GetFullPath($StateDir),
        [IO.Path]::GetFullPath($canonicalStateDir),
        [StringComparison]::OrdinalIgnoreCase
    )
) {
    throw 'Production publisher state directory is fixed; arbitrary process scopes are rejected.'
}
foreach ($path in @(
    $PSCommandPath,
    (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1'),
    $runner,
    $publisherScript
)) {
    $null = Assert-CogniAdminOwnedPathChain -LiteralPath $path -LeafMustBeFile
}

$powershellRecord = Get-CogniTrustedExecutableRecord `
    -Name 'powershell' `
    -Candidates @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
$gitRecord = Get-CogniTrustedExecutableRecord `
    -Name 'git' `
    -Candidates @(
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files\Git\bin\git.exe'
    )
$pythonRecords = @(
    foreach ($candidate in @(
        'C:\Program Files\Python312\python.exe',
        'C:\Program Files\Python310\python.exe'
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Get-CogniTrustedExecutableRecord -Name 'python' -Candidates @($candidate)
        }
    }
)
if ($pythonRecords.Count -eq 0) {
    throw 'No trusted Python runtime exists; task ownership cannot be proven.'
}

function Get-CogniTaskMarker {
    param([Parameter(Mandatory = $true)][psobject]$PythonRecord)

    $markerInput = (
        "repo=$repoRoot`nrunner_sha256=" +
        (Get-CogniSha256 -LiteralPath $runner) +
        "`npython_sha256=$($PythonRecord.sha256)" +
        "`ngit_sha256=$($gitRecord.sha256)"
    )
    $bytes = [Text.Encoding]::UTF8.GetBytes($markerInput)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join (
            $hasher.ComputeHash($bytes) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $hasher.Dispose()
    }
    return "COGNI_PUBLISHER_TASK_V2:$digest"
}

function Get-CogniOwnedTaskIdentity {
    param([Parameter(Mandatory = $true)][psobject]$Task)

    $actions = @($Task.Actions)
    $triggers = @($Task.Triggers)
    if (
        [string]$Task.TaskName -cne $canonicalTaskName -or
        [string]$Task.TaskPath -cne '\' -or
        $actions.Count -ne 1 -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].Execute),
            [IO.Path]::GetFullPath([string]$powershellRecord.path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].WorkingDirectory),
            [IO.Path]::GetFullPath($repoRoot),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $triggers.Count -ne 1 -or
        [string]$triggers[0].CimClass.CimClassName -cne
            'MSFT_TaskLogonTrigger' -or
        -not [bool]$triggers[0].Enabled -or
        -not (Test-CogniUninstallIdentityBinding `
            -ObservedIdentity ([string]$triggers[0].UserId)) -or
        -not (Test-CogniUninstallIdentityBinding `
            -ObservedIdentity ([string]$Task.Principal.UserId)) -or
        [string]$Task.Principal.LogonType -cne 'Interactive' -or
        [string]$Task.Principal.RunLevel -cne 'Limited' -or
        [string]$Task.Settings.MultipleInstances -cne 'IgnoreNew' -or
        [int]$Task.Settings.RestartCount -ne 999 -or
        [string]$Task.Settings.RestartInterval -cne 'PT1M' -or
        [string]$Task.Settings.ExecutionTimeLimit -cne 'PT0S' -or
        -not [bool]$Task.Settings.StartWhenAvailable -or
        [bool]$Task.Settings.DisallowStartIfOnBatteries -or
        [bool]$Task.Settings.StopIfGoingOnBatteries
    ) {
        throw 'Scheduled task envelope is not the exact trusted publisher identity.'
    }
    $arguments = [string]$actions[0].Arguments
    foreach ($pythonRecord in $pythonRecords) {
        if ([string]$Task.Description -cne (Get-CogniTaskMarker -PythonRecord $pythonRecord)) {
            continue
        }
        $pattern = (
            '^-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
            '-File "' + [regex]::Escape($runner) + '" ' +
            '-WorkspaceRoot "(?<workspace>[^"\r\n]+)" ' +
            '-Endpoint "' + [regex]::Escape($canonicalEndpoint) + '" ' +
            '-IntervalSeconds (?<interval>[0-9]{1,4}) ' +
            '-MaxBackoffSeconds (?<backoff>[0-9]{1,4}) ' +
            '-SecretPath "' + [regex]::Escape($canonicalSecretPath) + '" ' +
            '-StateDir "' + [regex]::Escape($canonicalStateDir) + '" ' +
            '-PythonPath "' + [regex]::Escape([string]$pythonRecord.path) + '"' +
            '(?<gpu> -IncludeGpu)?$'
        )
        $match = [regex]::Match($arguments, $pattern)
        if (-not $match.Success) {
            continue
        }
        $interval = [int]$match.Groups['interval'].Value
        $backoff = [int]$match.Groups['backoff'].Value
        if (
            $interval -lt 5 -or $interval -gt 3600 -or
            $backoff -lt $interval -or $backoff -gt 3600
        ) {
            continue
        }
        return [pscustomobject]@{
            PythonPath = [string]$pythonRecord.path
            WorkspaceRoot = [IO.Path]::GetFullPath($match.Groups['workspace'].Value)
            IntervalSeconds = $interval
            MaxBackoffSeconds = $backoff
            IncludeGpu = $match.Groups['gpu'].Success
        }
    }
    throw 'Scheduled task ownership marker or canonical arguments are invalid.'
}

function Test-CogniOwnedTaskIdentityEqual {
    param(
        [Parameter(Mandatory = $true)][psobject]$Left,
        [Parameter(Mandatory = $true)][psobject]$Right
    )

    return (
        [string]$Left.PythonPath -ceq [string]$Right.PythonPath -and
        [string]$Left.WorkspaceRoot -ceq [string]$Right.WorkspaceRoot -and
        [int]$Left.IntervalSeconds -eq [int]$Right.IntervalSeconds -and
        [int]$Left.MaxBackoffSeconds -eq [int]$Right.MaxBackoffSeconds -and
        [bool]$Left.IncludeGpu -eq [bool]$Right.IncludeGpu
    )
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [pscustomobject]@{
        TaskName = $TaskName
        Removed = $false
        Reason = "NOT_INSTALLED"
        PublisherProcessesStopped = 0
    }
    exit 0
}
$owned = Get-CogniOwnedTaskIdentity -Task $task

# Re-read immediately before the destructive operation and require the same
# ownership identity. A task that changes during this window fails closed.
$latestTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$latestOwned = Get-CogniOwnedTaskIdentity -Task $latestTask
if (-not (Test-CogniOwnedTaskIdentityEqual -Left $owned -Right $latestOwned)) {
    throw 'Scheduled task ownership changed before uninstall; removal is fail-closed.'
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$unregisterTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$unregisterOwned = Get-CogniOwnedTaskIdentity -Task $unregisterTask
if (-not (Test-CogniOwnedTaskIdentityEqual -Left $owned -Right $unregisterOwned)) {
    throw 'Scheduled task changed after stop; unregister is fail-closed.'
}
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop

$stopped = 0
$receiptPath = Join-Path $StateDir 'monitor_publisher_runtime.json'
if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
    $receiptItem = Get-Item -LiteralPath $receiptPath -Force
    if (
        ($receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $receiptItem.Length -gt 0 -and
        $receiptItem.Length -le 65536
    ) {
        try {
            $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 |
                ConvertFrom-Json
            $publisherPid = [int]$receipt.pid
            if ($publisherPid -gt 0) {
                $process = Get-CimInstance Win32_Process `
                    -Filter "ProcessId = $publisherPid" `
                    -ErrorAction SilentlyContinue
                if ($null -ne $process) {
                    $expectedPrefix = (
                        '^"?' + [regex]::Escape($owned.PythonPath) + '"? ' +
                        '"-B" "' + [regex]::Escape($publisherScript) + '" "' +
                        [regex]::Escape($owned.WorkspaceRoot) + '" ' +
                        '"--key-id" "[A-Za-z0-9._:-]{3,64}" ' +
                        '"--endpoint" "' + [regex]::Escape($canonicalEndpoint) + '" ' +
                        '"--state-dir" "' + [regex]::Escape($canonicalStateDir) + '" ' +
                        '"--interval-seconds" "[0-9]{1,4}" ' +
                        '"--max-backoff-seconds" "[0-9]{1,4}"' +
                        $(if ($owned.IncludeGpu) { ' "--include-gpu"' } else { '' }) +
                        '$'
                    )
                    if (
                        [string]::Equals(
                            [IO.Path]::GetFullPath([string]$process.ExecutablePath),
                            [IO.Path]::GetFullPath($owned.PythonPath),
                            [StringComparison]::OrdinalIgnoreCase
                        ) -and
                        [string]$process.CommandLine -cmatch $expectedPrefix
                    ) {
                        Stop-Process -Id $publisherPid -Force -ErrorAction Stop
                        $stopped = 1
                    }
                }
            }
        } catch {
            # An untrusted or stale receipt never authorizes process termination.
            $stopped = 0
        }
    }
}

[pscustomobject]@{
    TaskName = $TaskName
    Removed = $true
    Reason = "REMOVED_EXACT_OWNERSHIP"
    PublisherProcessesStopped = $stopped
}
