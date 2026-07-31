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
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"
$scriptRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) {
    $WorkspaceRoot = $scriptRepoRoot
}
if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = Join-Path $scriptRepoRoot (
        ".runtime\cogni-monitor-secret.clixml"
    )
}
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $scriptRepoRoot ".runtime\monitor-publisher"
}

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

$hadSecret = Test-Path Env:COGNI_MONITOR_INGEST_SECRET
$priorSecret = [string]$env:COGNI_MONITOR_INGEST_SECRET
$hadPythonPath = Test-Path Env:PYTHONPATH
$priorPythonPath = [string]$env:PYTHONPATH
$exitCode = 1

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
    $env:COGNI_MONITOR_INGEST_SECRET = $secret

    $python = if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
        $PythonPath
    } elseif ($env:COGNI_PYTHON) {
        $env:COGNI_PYTHON
    } else {
        "python"
    }
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

    $env:PYTHONPATH = (Join-Path $scriptRepoRoot "src")
    Write-WrapperJournal -EventName "wrapper_started" -Message (
        "GPU telemetry " + $(if ($IncludeGpu) { "ENABLED" } else { "DISABLED" })
    )
    & $python @arguments
    $exitCode = $LASTEXITCODE
    Write-WrapperJournal -EventName "python_exited" -Message (
        "exit_code=$exitCode"
    )
} catch {
    Write-WrapperJournal -EventName "wrapper_failed" -Message $_.Exception.Message
    Write-Error $_.Exception.Message
    $exitCode = 1
} finally {
    $secret = $null
    if ($hadSecret) {
        $env:COGNI_MONITOR_INGEST_SECRET = $priorSecret
    } else {
        Remove-Item Env:COGNI_MONITOR_INGEST_SECRET -ErrorAction SilentlyContinue
    }
    if ($hadPythonPath) {
        $env:PYTHONPATH = $priorPythonPath
    } else {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
}
exit $exitCode
