[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TaskName = "Cogni-OS Monitor Publisher",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot ".runtime\monitor-publisher"
}
$publisherScript = Join-Path $PSScriptRoot "publish_monitor_snapshot.py"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [pscustomobject]@{
        TaskName = $TaskName
        Removed = $false
        Reason = "NOT_INSTALLED"
    }
    exit 0
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
$publishers = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "python.exe" -and
    $_.CommandLine -like "*$publisherScript*" -and
    $_.CommandLine -like "*$StateDir*"
}
foreach ($publisher in $publishers) {
    Stop-Process -Id $publisher.ProcessId -Force -ErrorAction Stop
}
[pscustomobject]@{
    TaskName = $TaskName
    Removed = $true
    Reason = "REMOVED"
    PublisherProcessesStopped = @($publishers).Count
}
