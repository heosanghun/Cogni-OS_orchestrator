param(
    [Parameter(Mandatory = $true)]
    [string]$SpecPath,

    [Parameter(Mandatory = $true)]
    [string]$GatePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$utf8 = New-Object Text.UTF8Encoding($false)

function Write-TextCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $stream = New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $bytes = $utf8.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Write-JsonAtomicNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $temp = "{0}.partial.{1}.{2}" -f $Path, $PID, (
        [Guid]::NewGuid().ToString("N")
    )
    Write-TextCreateNew -Path $temp -Text (
        $Value | ConvertTo-Json -Depth 20
    )
    [IO.File]::Move($temp, $Path)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

$resolvedSpec = [IO.Path]::GetFullPath($SpecPath)
$resolvedGate = [IO.Path]::GetFullPath($GatePath)
$specRoot = [IO.Path]::GetDirectoryName($resolvedSpec)
$resultPath = Join-Path $specRoot "RESULT.json"
$runningPath = Join-Path $specRoot "RUNNING.json"
$logPath = Join-Path $specRoot "PROCESS.log"
$startedAt = [DateTime]::UtcNow.ToString("o")
$exitCode = 125
$outcome = "RUNNER_ERROR"
$errorMessage = ""
$spec = $null

try {
    $spec = Get-Content -LiteralPath $resolvedSpec -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([int]$spec.schema_version -ne 1) {
        throw "Unsupported process spec schema."
    }
    if (-not [IO.Path]::GetFullPath([string]$spec.gate_path).Equals(
        $resolvedGate,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runner gate path does not match the immutable spec."
    }
    if (-not [IO.Path]::GetFullPath([string]$spec.result_path).Equals(
        $resultPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runner result path does not match its attempt directory."
    }
    if (-not [IO.Path]::GetFullPath([string]$spec.log_path).Equals(
        $logPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runner log path does not match its attempt directory."
    }

    $gateDeadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $resolvedGate -PathType Leaf)) {
        if ([DateTime]::UtcNow -ge $gateDeadline) {
            throw "Runner gate was not opened within 60 seconds."
        }
        Start-Sleep -Milliseconds 50
    }

    $executable = [IO.Path]::GetFullPath([string]$spec.executable_path)
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Pinned executable is missing: $executable"
    }
    $actualSha = Get-Sha256 -Path $executable
    if ($actualSha -ne ([string]$spec.executable_sha256).ToLower()) {
        throw "Pinned executable SHA-256 mismatch: $executable"
    }

    Write-JsonAtomicNew -Path $runningPath -Value ([ordered]@{
        schema_version = 1
        invocation_id = [string]$spec.invocation_id
        task_id = [string]$spec.task_id
        stage = [string]$spec.stage
        runner_pid = $PID
        executable_path = $executable
        executable_sha256 = $actualSha
        started_at = $startedAt
    })

    $arguments = @($spec.arguments | ForEach-Object { [string]$_ })
    $stdinText = ""
    $hasStdin = -not [string]::IsNullOrWhiteSpace([string]$spec.stdin_path)
    if ($hasStdin) {
        $stdinPath = [IO.Path]::GetFullPath([string]$spec.stdin_path)
        if (-not $stdinPath.StartsWith(
            $specRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Runner stdin escaped its attempt directory."
        }
        $stdinText = [IO.File]::ReadAllText($stdinPath, $utf8)
    }

    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ([IO.Path]::GetExtension($executable) -eq ".ps1") {
            $output = @(
                & $executable @arguments -PromptText $stdinText 2>&1
            )
            $exitCode = if ($?) { 0 } else { 1 }
        }
        elseif ($hasStdin) {
            $output = @($stdinText | & $executable @arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        else {
            $output = @(& $executable @arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }

    Write-TextCreateNew -Path $logPath -Text (
        ($output | ForEach-Object { [string]$_ }) -join "`n"
    )
    $outcome = "EXITED"
}
catch {
    $errorMessage = $_.Exception.Message
    if (-not (Test-Path -LiteralPath $logPath)) {
        Write-TextCreateNew -Path $logPath -Text $errorMessage
    }
}
finally {
    $completedAt = [DateTime]::UtcNow.ToString("o")
    if (-not (Test-Path -LiteralPath $resultPath)) {
        Write-JsonAtomicNew -Path $resultPath -Value ([ordered]@{
            schema_version = 1
            invocation_id = if ($spec) {
                [string]$spec.invocation_id
            } else {
                ""
            }
            task_id = if ($spec) { [string]$spec.task_id } else { "" }
            stage = if ($spec) { [string]$spec.stage } else { "" }
            runner_pid = $PID
            started_at = $startedAt
            completed_at = $completedAt
            outcome = $outcome
            exit_code = [int]$exitCode
            error = $errorMessage
            log_path = $logPath
            log_sha256 = if (Test-Path -LiteralPath $logPath) {
                Get-Sha256 -Path $logPath
            } else {
                ""
            }
        })
    }
}

exit ([int]$exitCode)
