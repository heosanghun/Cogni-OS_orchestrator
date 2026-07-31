[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    [Parameter(Mandatory = $false)]
    [string]$Endpoint = "https://cogni-os-orchestrator.pages.dev/api/ingest",

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 3600)]
    [int]$IntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGpu
)

$ErrorActionPreference = "Stop"
$keyId = [string]$env:COGNI_MONITOR_KEY_ID
if (
    [string]::IsNullOrWhiteSpace($keyId) -or
    $keyId -notmatch '^[A-Za-z0-9._:-]{3,64}$'
) {
    throw "COGNI_MONITOR_KEY_ID must be set to a safe 3-64 character key id."
}
if (
    [string]::IsNullOrWhiteSpace($env:COGNI_MONITOR_INGEST_SECRET) -or
    $env:COGNI_MONITOR_INGEST_SECRET.Length -lt 32 -or
    $env:COGNI_MONITOR_INGEST_SECRET.Length -gt 256
) {
    throw "COGNI_MONITOR_INGEST_SECRET must contain the matching 32-256 character secret."
}

$python = if ($env:COGNI_PYTHON) { $env:COGNI_PYTHON } else { "python" }
$arguments = @(
    "-B",
    (Join-Path $PSScriptRoot "publish_monitor_snapshot.py"),
    $WorkspaceRoot,
    "--key-id",
    $keyId,
    "--endpoint",
    $Endpoint,
    "--interval-seconds",
    [string]$IntervalSeconds
)
if ($IncludeGpu) {
    $arguments += "--include-gpu"
}

$env:PYTHONPATH = (Join-Path $WorkspaceRoot "src")
& $python @arguments
exit $LASTEXITCODE
