[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "",
    [ValidateRange(2, 60)][int]$PollSeconds = 5,
    [switch]$Once
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) {
    $WorkspaceRoot = Split-Path -Parent $scriptRoot
}
$coordinator = Join-Path $scriptRoot "ensemble.ps1"

do {
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $coordinator `
            advance -WorkspaceRoot $WorkspaceRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Coordinator child exited with code $LASTEXITCODE."
        }
    }
    catch {
        $stamp = [DateTime]::UtcNow.ToString("o")
        Write-Warning "[$stamp] Coordinator cycle skipped: $($_.Exception.Message)"
        if ($Once) {
            exit 1
        }
    }
    if (-not $Once) {
        Start-Sleep -Seconds $PollSeconds
    }
} while (-not $Once)
