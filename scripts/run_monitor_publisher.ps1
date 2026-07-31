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
    [switch]$IncludeGpu,

    [Parameter(Mandatory = $false)]
    [string]$SecretPath = (
        Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path `
            ".runtime\cogni-monitor-secret.clixml"
    ),

    [Parameter(Mandatory = $false)]
    [string]$StateDir = (
        Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path `
            ".runtime\monitor-publisher"
    )
)

$ErrorActionPreference = "Stop"
$keyId = if ($env:COGNI_MONITOR_KEY_ID) {
    [string]$env:COGNI_MONITOR_KEY_ID
} else {
    "publisher-2026q3"
}
if (
    [string]::IsNullOrWhiteSpace($keyId) -or
    $keyId -notmatch '^[A-Za-z0-9._:-]{3,64}$'
) {
    throw "COGNI_MONITOR_KEY_ID must be set to a safe 3-64 character key id."
}

$secret = [string]$env:COGNI_MONITOR_INGEST_SECRET
if ([string]::IsNullOrWhiteSpace($secret) -and (Test-Path -LiteralPath $SecretPath)) {
    $secureSecret = Import-Clixml -LiteralPath $SecretPath
    $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
    try {
        $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    }
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
$env:COGNI_MONITOR_INGEST_SECRET = $secret

$python = if ($env:COGNI_PYTHON) { $env:COGNI_PYTHON } else { "python" }
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
    [string]$IntervalSeconds
)
if ($IncludeGpu) {
    $arguments += "--include-gpu"
}

$env:PYTHONPATH = (Join-Path $WorkspaceRoot "src")
try {
    & $python @arguments
    exit $LASTEXITCODE
} finally {
    Remove-Item Env:COGNI_MONITOR_INGEST_SECRET -ErrorAction SilentlyContinue
}
