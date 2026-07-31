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
    [switch]$DoNotStart
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = Join-Path $repoRoot (
        ".runtime\cogni-monitor-secret.clixml"
    )
}
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot ".runtime\monitor-publisher"
}
if ([string]::IsNullOrWhiteSpace($PythonPath)) {
    $bundledPython = Join-Path $env:USERPROFILE (
        ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    )
    if (Test-Path -LiteralPath $bundledPython -PathType Leaf) {
        $PythonPath = $bundledPython
    }
}

function Quote-TaskArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + ($Value -replace '"', '""') + '"'
}

if ($MaxBackoffSeconds -lt $IntervalSeconds) {
    throw "MaxBackoffSeconds cannot be lower than IntervalSeconds."
}

$runner = Join-Path $PSScriptRoot "run_monitor_publisher.ps1"
$powershell = Join-Path $PSHOME "powershell.exe"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

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

$action = New-ScheduledTaskAction `
    -Execute $powershell `
    -Argument ($taskArguments -join " ") `
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
    -Description (
        "Publishes signed, metadata-only Cogni-OS evidence snapshots. " +
        "GPU telemetry is disabled unless explicitly installed with -IncludeGpu."
    )
Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

if (-not $DoNotStart) {
    Start-ScheduledTask -TaskName $TaskName
}

$registered = Get-ScheduledTask -TaskName $TaskName
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
