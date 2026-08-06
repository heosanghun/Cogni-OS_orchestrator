[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$WorkspaceRoot = "C:\comunity",

    [Parameter(Mandatory = $false)]
    [string]$Endpoint = "https://cogni-os-orchestrator.pages.dev/api/ingest",

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 3600)]
    [int]$IntervalSeconds = 60,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 3600)]
    [int]$MaxBackoffSeconds = 300,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGpu,

    [Parameter(Mandatory = $false)]
    [string]$TaskName = "Cogni-OS Monitor Publisher",

    [Parameter(Mandatory = $false)]
    [string]$SecretPath = "",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = "",

    [Parameter(Mandatory = $false)]
    [string]$PythonPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$DoNotStart,

    [Parameter(Mandatory = $false)]
    [switch]$ValidationOnly
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$canonicalSecretPath = Join-Path $repoRoot '.runtime\cogni-monitor-secret.clixml'
$canonicalStateDir = Join-Path $repoRoot '.runtime\monitor-publisher'

function Assert-CogniInstallerBootstrapFileTrust {
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
            throw "Installer bootstrap path crosses a reparse point: $($cursor.FullName)"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop
        $ownerSid = (
            [Security.Principal.NTAccount]$acl.Owner
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $allowedOwners) {
            throw "Installer bootstrap path is not administrator-owned: $($cursor.FullName)"
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
                throw "Installer bootstrap path is writable by an untrusted principal: $($cursor.FullName)"
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
        throw "Installer bootstrap file is not a bounded regular file: $fullPath"
    }
    return $item.FullName
}

function Test-CogniInstallerContainedPath {
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
    return [IO.Path]::GetFullPath($TargetPath).StartsWith(
        $base,
        [StringComparison]::OrdinalIgnoreCase
    )
}

if (-not $ValidationOnly) {
    foreach ($bootstrapFile in @(
        $PSCommandPath,
        (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1')
    )) {
        $null = Assert-CogniInstallerBootstrapFileTrust `
            -LiteralPath $bootstrapFile
    }
}
. (Join-Path $PSScriptRoot "publisher_binary_trust.ps1")
if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = Join-Path $repoRoot (
        ".runtime\cogni-monitor-secret.clixml"
    )
}
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot ".runtime\monitor-publisher"
}
function Quote-TaskArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + ($Value -replace '"', '""') + '"'
}

if ($MaxBackoffSeconds -lt $IntervalSeconds) {
    throw "MaxBackoffSeconds cannot be lower than IntervalSeconds."
}

$runner = Join-Path $PSScriptRoot "run_monitor_publisher.ps1"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$identitySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$canonicalTaskName = 'Cogni-OS Monitor Publisher'
$canonicalEndpoint = 'https://cogni-os-orchestrator.pages.dev/api/ingest'

function Test-CogniTaskIdentityBinding {
    param([Parameter(Mandatory = $true)][string]$ObservedIdentity)

    try {
        $observedSid = (
            [Security.Principal.NTAccount]$ObservedIdentity
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        return $observedSid -ceq $identitySid
    } catch {
        return $false
    }
}

if ($ValidationOnly) {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $validationRoot = [IO.Path]::GetFullPath($WorkspaceRoot)
    if (
        -not $DoNotStart -or
        $TaskName -notmatch '^Cogni-OS P01 Validation [0-9a-f]{32}$' -or
        $Endpoint -ne 'https://127.0.0.1:9/must-not-connect' -or
        -not (Test-CogniInstallerContainedPath `
            -BasePath $temporaryRoot -TargetPath $validationRoot) -or
        -not (Test-CogniInstallerContainedPath `
            -BasePath $validationRoot -TargetPath $SecretPath) -or
        -not (Test-CogniInstallerContainedPath `
            -BasePath $validationRoot -TargetPath $StateDir) -or
        -not (Test-CogniInstallerContainedPath `
            -BasePath $validationRoot -TargetPath $PythonPath)
    ) {
        throw 'ValidationOnly is restricted to a non-started isolated P01 task.'
    }
    $powershell = Join-Path $PSHOME 'powershell.exe'
    $taskDescription = 'COGNI_PUBLISHER_VALIDATION_TASK_V1'
} else {
    if ($TaskName -ne $canonicalTaskName) {
        throw 'Production publisher task name is fixed and cannot be overridden.'
    }
    if ($Endpoint -ne $canonicalEndpoint) {
        throw 'Production publisher endpoint is fixed and cannot be overridden.'
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
    foreach ($name in @('COGNI_PYTHON', 'PYTHONPATH', 'PYTHONHOME', 'NODE_OPTIONS')) {
        if (Test-Path "Env:$name") {
            throw "Publisher installer rejects inherited runtime override: $name"
        }
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
    $pythonCandidates = @(
        'C:\Program Files\Python312\python.exe',
        'C:\Program Files\Python310\python.exe'
    )
    if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
        $requestedPython = [IO.Path]::GetFullPath($PythonPath)
        if ($requestedPython -notin $pythonCandidates) {
            throw 'PythonPath is not in the fixed system Python allowlist.'
        }
        $pythonCandidates = @($requestedPython)
    }
    $pythonRecord = Get-CogniTrustedExecutableRecord `
        -Name 'python' `
        -Candidates $pythonCandidates
    foreach ($path in @(
        $runner,
        (Join-Path $PSScriptRoot 'publisher_binary_trust.ps1'),
        (Join-Path $PSScriptRoot 'publisher_production_preflight.ps1'),
        (Join-Path $PSScriptRoot 'publish_monitor_snapshot.py')
    )) {
        $null = Assert-CogniAdminOwnedPathChain `
            -LiteralPath $path `
            -LeafMustBeFile
    }
    $powershell = [string]$powershellRecord.path
    $PythonPath = [string]$pythonRecord.path
    $markerInput = (
        "repo=$repoRoot`nrunner_sha256=" +
        (Get-CogniSha256 -LiteralPath $runner) +
        "`npython_sha256=$($pythonRecord.sha256)" +
        "`ngit_sha256=$($gitRecord.sha256)"
    )
    $markerBytes = [Text.Encoding]::UTF8.GetBytes($markerInput)
    $markerHash = [Security.Cryptography.SHA256]::Create()
    try {
        $markerDigest = -join (
            $markerHash.ComputeHash($markerBytes) |
                ForEach-Object { $_.ToString('x2') }
        )
    } finally {
        $markerHash.Dispose()
    }
    $taskDescription = "COGNI_PUBLISHER_TASK_V2:$markerDigest"
}

if (-not (Test-Path -LiteralPath $WorkspaceRoot -PathType Container)) {
    throw "WorkspaceRoot does not exist: $WorkspaceRoot"
}
if (-not (Test-Path -LiteralPath $SecretPath -PathType Leaf)) {
    throw (
        "Current-user DPAPI secret is missing. Autostart was not installed: " +
        $SecretPath
    )
}
if (
    [string]::IsNullOrWhiteSpace($PythonPath) -or
    -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)
) {
    throw "A concrete PythonPath is required for reboot-safe autostart."
}

$taskArguments = @(
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", (Quote-TaskArgument $runner),
    "-WorkspaceRoot", (Quote-TaskArgument $WorkspaceRoot),
    "-Endpoint", (Quote-TaskArgument $Endpoint),
    "-IntervalSeconds", [string]$IntervalSeconds,
    "-MaxBackoffSeconds", [string]$MaxBackoffSeconds,
    "-SecretPath", (Quote-TaskArgument $SecretPath),
    "-StateDir", (Quote-TaskArgument $StateDir),
    "-PythonPath", (Quote-TaskArgument $PythonPath)
)
if ($IncludeGpu) {
    $taskArguments += "-IncludeGpu"
}
$canonicalTaskArguments = $taskArguments -join " "

function Test-CogniOwnedTask {
    param([Parameter(Mandatory = $true)][psobject]$Task)

    $actions = @($Task.Actions)
    $triggers = @($Task.Triggers)
    return (
        [string]$Task.TaskName -ceq $TaskName -and
        [string]$Task.TaskPath -ceq '\' -and
        [string]$Task.Description -ceq $taskDescription -and
        $actions.Count -eq 1 -and
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].Execute),
            [IO.Path]::GetFullPath($powershell),
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].WorkingDirectory),
            [IO.Path]::GetFullPath($repoRoot),
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        [string]$actions[0].Arguments -ceq $canonicalTaskArguments -and
        $triggers.Count -eq 1 -and
        [string]$triggers[0].CimClass.CimClassName -ceq
            'MSFT_TaskLogonTrigger' -and
        [bool]$triggers[0].Enabled -and
        (Test-CogniTaskIdentityBinding `
            -ObservedIdentity ([string]$triggers[0].UserId)) -and
        (Test-CogniTaskIdentityBinding `
            -ObservedIdentity ([string]$Task.Principal.UserId)) -and
        [string]$Task.Principal.LogonType -ceq 'Interactive' -and
        [string]$Task.Principal.RunLevel -ceq 'Limited' -and
        [string]$Task.Settings.MultipleInstances -ceq 'IgnoreNew' -and
        [int]$Task.Settings.RestartCount -eq 999 -and
        [string]$Task.Settings.RestartInterval -ceq 'PT1M' -and
        [string]$Task.Settings.ExecutionTimeLimit -ceq 'PT0S' -and
        [bool]$Task.Settings.StartWhenAvailable -and
        -not [bool]$Task.Settings.DisallowStartIfOnBatteries -and
        -not [bool]$Task.Settings.StopIfGoingOnBatteries
    )
}

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$replaceOwnedTask = $false
if ($null -ne $existingTask) {
    if (-not (Test-CogniOwnedTask -Task $existingTask)) {
        throw 'Refusing to overwrite a scheduled task without the exact Cogni ownership identity.'
    }
    $replaceOwnedTask = $true
}

$action = New-ScheduledTaskAction `
    -Execute $powershell `
    -Argument $canonicalTaskArguments `
    -WorkingDirectory $repoRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal `
    -UserId $identity `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description $taskDescription
if ($replaceOwnedTask) {
    $latestTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $latestTask -or -not (Test-CogniOwnedTask -Task $latestTask)) {
        throw 'Scheduled task ownership changed before replacement; registration is fail-closed.'
    }
    Register-ScheduledTask `
        -TaskName $TaskName `
        -InputObject $task `
        -Force | Out-Null
} else {
    # Deliberately omit -Force. A same-name task created after the absence
    # check wins the race and makes registration fail instead of being erased.
    Register-ScheduledTask `
        -TaskName $TaskName `
        -InputObject $task | Out-Null
}

$registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if (-not (Test-CogniOwnedTask -Task $registered)) {
    throw 'Registered task failed exact post-registration ownership verification.'
}
if (-not $DoNotStart) {
    $startCandidate = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if (-not (Test-CogniOwnedTask -Task $startCandidate)) {
        throw 'Scheduled task changed before start; startup is fail-closed.'
    }
    Start-ScheduledTask -TaskName $TaskName
    $registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if (-not (Test-CogniOwnedTask -Task $registered)) {
        throw 'Scheduled task changed during start; ownership is untrusted.'
    }
}
[pscustomobject]@{
    TaskName = $registered.TaskName
    State = [string]$registered.State
    User = $identity
    WorkspaceRoot = $WorkspaceRoot
    IntervalSeconds = $IntervalSeconds
    MaxBackoffSeconds = $MaxBackoffSeconds
    PythonPath = $PythonPath
    GpuTelemetry = if ($IncludeGpu) { "ENABLED_0_TO_5_ONLY" } else { "DISABLED" }
    SecretStorage = "CURRENT_USER_DPAPI"
}
