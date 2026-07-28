[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$coordinator = Join-Path $repoRoot "orchestrator\ensemble.ps1"
$tempRoot = Join-Path $env:TEMP (
    "four-agent-ensemble-selftest-" + [Guid]::NewGuid().ToString("N")
)
$targetRoot = Join-Path $tempRoot "target"
$staging = Join-Path $tempRoot "staging"
$utf8 = New-Object Text.UTF8Encoding($false)

function Write-TestFile {
    param([string]$Name, [string]$Text)
    $path = Join-Path $staging $Name
    [IO.File]::WriteAllText($path, $Text, $utf8)
    return $path
}

function Invoke-Coordinator {
    param([string[]]$Arguments)
    if ($Arguments.Count -gt 0 -and $Arguments[0] -eq "submit") {
        $taskIndex = [Array]::IndexOf($Arguments, "-TaskId")
        $agentIndex = [Array]::IndexOf($Arguments, "-Agent")
        $phaseIndex = [Array]::IndexOf($Arguments, "-Phase")
        $inputIndex = [Array]::IndexOf($Arguments, "-InputFile")
        if ($taskIndex -lt 0) { throw "submit test call lacks -TaskId." }
        $task = $Arguments[$taskIndex + 1]
        $statePath = Join-Path $tempRoot "ensemble\ledger\$task\STATE.json"
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $agentName = $Arguments[$agentIndex + 1]
        $phaseName = $Arguments[$phaseIndex + 1]
        $pending = @(
            Get-ChildItem -LiteralPath (
                Join-Path $tempRoot ".ensemble-runtime\messages\pending"
            ) -Filter "*.json" -File |
            ForEach-Object {
                Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 |
                    ConvertFrom-Json
            } |
            Where-Object {
                $_.task_id -eq $task -and
                $_.agent_id -eq $agentName -and
                $_.submit_phase -eq $phaseName -and
                [int]$_.state_version -eq [int]$state.state_version
            }
        ) | Select-Object -First 1
        if ($null -eq $pending) {
            throw "No pending envelope for $task/$agentName/$phaseName."
        }
        $source = $Arguments[$inputIndex + 1]
        $text = Get-Content -LiteralPath $source -Raw -Encoding UTF8
        [IO.File]::WriteAllText([string]$pending.output_path, $text, $utf8)
        $Arguments[$inputIndex + 1] = [string]$pending.output_path
        if ($Arguments -notcontains "-MessageStateVersion") {
            $Arguments += @("-MessageStateVersion", [string]$state.state_version)
        }
        if ($Arguments -notcontains "-MessageId") {
            $Arguments += @("-MessageId", [string]$pending.message_id)
        }
    }
    $output = & powershell -NoProfile -ExecutionPolicy Bypass `
        -File $coordinator @Arguments -WorkspaceRoot $tempRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Coordinator failed: $($Arguments -join ' ')"
    }
    return @($output)
}

function Get-State {
    param([string]$Task)
    $path = Join-Path $tempRoot "ensemble\ledger\$Task\STATE.json"
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
        ConvertFrom-Json)
}

function Assert-Phase {
    param([string]$Task, [string]$Expected)
    $state = Get-State $Task
    if ([string]$state.phase -ne $Expected) {
        throw "Expected phase $Expected, got $($state.phase)."
    }
}

[void](New-Item -ItemType Directory -Path $targetRoot -Force)
[void](New-Item -ItemType Directory -Path $staging -Force)
[IO.File]::WriteAllText(
    (Join-Path $targetRoot "baseline.txt"),
    "baseline`n",
    $utf8
)
& git -C $targetRoot init -q
& git -C $targetRoot config user.name "Ensemble Self Test"
& git -C $targetRoot config user.email "ensemble-selftest@example.invalid"
& git -C $targetRoot add baseline.txt
& git -C $targetRoot commit -q -m "self-test baseline"
if ($LASTEXITCODE -ne 0) { throw "Failed to create clean Git test target." }

try {
    Invoke-Coordinator @("init") | Out-Null
    $created = Invoke-Coordinator @(
        "new-task",
        "-Title", "State machine self test",
        "-Goal", "Reach READY_TO_COMMIT with three voices and passing tests.",
        "-TargetWorkspace", $targetRoot
    )
    $taskId = [string](@($created)[-1])
    $taskId = $taskId.Trim()
    if ($taskId -notmatch '^TASK-') {
        throw "Task id was not returned: $taskId"
    }
    Assert-Phase $taskId "R1_BLIND"

    $staleFile = Write-TestFile "stale-r1.md" "# Stale response`n"
    $cursorPending = @(
        Get-ChildItem -LiteralPath (
            Join-Path $tempRoot ".ensemble-runtime\messages\pending"
        ) -Filter "*.json" -File |
        ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 |
                ConvertFrom-Json
        } |
        Where-Object {
            $_.task_id -eq $taskId -and $_.agent_id -eq "cursor" -and
            $_.submit_phase -eq "r1"
        }
    ) | Select-Object -First 1
    [IO.File]::WriteAllText(
        [string]$cursorPending.output_path,
        (Get-Content -LiteralPath $staleFile -Raw -Encoding UTF8),
        $utf8
    )
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & powershell -NoProfile -ExecutionPolicy Bypass `
            -File $coordinator submit -WorkspaceRoot $tempRoot `
            -TaskId $taskId -Agent cursor -Phase r1 `
            -MessageId ([string]$cursorPending.message_id) `
            -MessageStateVersion 0 `
            -InputFile ([string]$cursorPending.output_path) 2>$null
        $staleExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($staleExitCode -eq 0) {
        throw "A stale response was accepted."
    }

    $r1Dir = Join-Path $tempRoot "ensemble\ledger\$taskId\ADVICE_R1"
    foreach ($n in 1..3) {
        [IO.File]::WriteAllText(
            (Join-Path $r1Dir "junk-$n.md"),
            "# Not an advisor receipt`n",
            $utf8
        )
    }
    Invoke-Coordinator @("advance", "-TaskId", $taskId) | Out-Null
    Assert-Phase $taskId "R1_BLIND"

    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        $file = Write-TestFile "r1-$advisor.md" @"
# Blind advice

Advisor: $advisor
Recommendation: proceed with a bounded synthetic test.
"@
        Invoke-Coordinator @(
            "submit", "-TaskId", $taskId, "-Agent", $advisor,
            "-Phase", "r1", "-InputFile", $file
        ) | Out-Null
    }
    Assert-Phase $taskId "R2_CRITIQUE"

    $r2Dir = Join-Path $tempRoot "ensemble\ledger\$taskId\CRITIQUE_R2"
    foreach ($n in 1..3) {
        [IO.File]::WriteAllText(
            (Join-Path $r2Dir "junk-$n.md"),
            "# Not an advisor receipt`n",
            $utf8
        )
    }
    Invoke-Coordinator @("advance", "-TaskId", $taskId) | Out-Null
    Assert-Phase $taskId "R2_CRITIQUE"

    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        $file = Write-TestFile "r2-$advisor.md" @"
# Cross critique

Advisor: $advisor
The plan must preserve files and prove the state transition.
"@
        Invoke-Coordinator @(
            "submit", "-TaskId", $taskId, "-Agent", $advisor,
            "-Phase", "r2", "-InputFile", $file
        ) | Out-Null
    }
    Assert-Phase $taskId "EXECUTOR_PLAN_OPEN"

    $plan = Write-TestFile "plan.md" @"
# Executor plan

Create no product change. Exercise the deterministic state machine and verify
the final decision artifact.
"@
    Invoke-Coordinator @(
        "submit", "-TaskId", $taskId, "-Agent", "codex-app",
        "-Phase", "plan", "-InputFile", $plan
    ) | Out-Null
    Assert-Phase $taskId "PLAN_REVIEW_OPEN"

    $planVotes = @{
        "antigravity" = "APPROVE"
        "cursor" = "APPROVE"
        "claude" = "REVISE"
    }
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        $file = Write-TestFile "plan-review-$advisor.md" @"
# Plan review

vote: $($planVotes[$advisor])
hard_stop: NONE
evidence: synthetic plan review by $advisor
"@
        Invoke-Coordinator @(
            "submit", "-TaskId", $taskId, "-Agent", $advisor,
            "-Phase", "plan-review", "-InputFile", $file
        ) | Out-Null
    }
    Assert-Phase $taskId "EXECUTION_AUTHORIZED"

    $testLog = Join-Path $targetRoot "self-test.log"
    [IO.File]::WriteAllText(
        $testLog,
        "command: synthetic-state-machine-test`nresult: PASS`nexit_code: 0`n",
        $utf8
    )
    $testLogSha = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $testLog
    ).Hash.ToLowerInvariant()
    $report = Write-TestFile "implementation.md" @"
# Implementation report

tests: PASS
test_log_path: $testLog
test_log_sha256: $testLogSha
evidence: state-machine self-test
"@
    Invoke-Coordinator @(
        "submit", "-TaskId", $taskId, "-Agent", "codex-app",
        "-Phase", "implementation", "-InputFile", $report
    ) | Out-Null
    Assert-Phase $taskId "POST_REVIEW_OPEN"

    $postVotes = @{
        "antigravity" = "APPROVE"
        "cursor" = "APPROVE"
        "claude" = "ABSTAIN"
    }
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        $file = Write-TestFile "post-review-$advisor.md" @"
# Post review

vote: $($postVotes[$advisor])
hard_stop: NONE
evidence: synthetic frozen result review by $advisor
"@
        Invoke-Coordinator @(
            "submit", "-TaskId", $taskId, "-Agent", $advisor,
            "-Phase", "post-review", "-InputFile", $file
        ) | Out-Null
    }
    Assert-Phase $taskId "READY_TO_COMMIT"

    $decision = Join-Path $tempRoot "ensemble\ledger\$taskId\DECISION.md"
    $minority = Join-Path $tempRoot "ensemble\ledger\$taskId\MINORITY_REPORT.md"
    $implementationEvidence = Join-Path $tempRoot `
        "ensemble\ledger\$taskId\implementation\EVIDENCE_v001.json"
    if (-not (Test-Path -LiteralPath $decision -PathType Leaf)) {
        throw "Decision artifact is missing."
    }
    if (-not (Test-Path -LiteralPath $minority -PathType Leaf)) {
        throw "Minority report is missing."
    }
    if (-not (Test-Path -LiteralPath $implementationEvidence -PathType Leaf)) {
        throw "Coordinator implementation evidence is missing."
    }

    $staleLock = Join-Path $tempRoot ".ensemble-runtime\locks\coordinator.lock"
    [IO.File]::WriteAllText($staleLock, '{"pid":-1}', $utf8)
    Invoke-Coordinator @("advance", "-TaskId", $taskId) | Out-Null
    Assert-Phase $taskId "READY_TO_COMMIT"

    $timeoutCreated = Invoke-Coordinator @(
        "new-task",
        "-Title", "Timeout retry self test",
        "-Goal", "Retry once with the same state version, then stop.",
        "-TargetWorkspace", $targetRoot
    )
    $timeoutTask = [string](@($timeoutCreated)[-1])
    $timeoutTask = $timeoutTask.Trim()
    $timeoutStatePath = Join-Path $tempRoot `
        "ensemble\ledger\$timeoutTask\STATE.json"
    $timeoutState = Get-Content -LiteralPath $timeoutStatePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    $timeoutState.phase_started_at = (
        [DateTime]::UtcNow.AddMinutes(-31)
    ).ToString("o")
    [IO.File]::WriteAllText(
        $timeoutStatePath,
        (($timeoutState | ConvertTo-Json -Depth 20) + "`n"),
        $utf8
    )
    Invoke-Coordinator @("advance", "-TaskId", $timeoutTask) | Out-Null
    $timeoutState = Get-Content -LiteralPath $timeoutStatePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$timeoutState.phase_retry -ne 1 -or
        [string]$timeoutState.phase -ne "R1_BLIND") {
        throw "Timeout retry was not recorded correctly."
    }
    $timeoutState.phase_started_at = (
        [DateTime]::UtcNow.AddMinutes(-31)
    ).ToString("o")
    [IO.File]::WriteAllText(
        $timeoutStatePath,
        (($timeoutState | ConvertTo-Json -Depth 20) + "`n"),
        $utf8
    )
    Invoke-Coordinator @("advance", "-TaskId", $timeoutTask) | Out-Null
    $timeoutState = Get-Content -LiteralPath $timeoutStatePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$timeoutState.phase -ne "WAITING_HUMAN") {
        throw "Timeout exhaustion did not stop the task."
    }

    $bypassCreated = Invoke-Coordinator @(
        "new-task",
        "-Title", "Receipt bypass self test",
        "-Goal", "Direct ledger files without receipts must not advance.",
        "-TargetWorkspace", $targetRoot
    )
    $bypassTask = [string](@($bypassCreated)[-1])
    $bypassTask = $bypassTask.Trim()
    $bypassR1 = Join-Path $tempRoot "ensemble\ledger\$bypassTask\ADVICE_R1"
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        [IO.File]::WriteAllText(
            (Join-Path $bypassR1 "$advisor.md"),
            "# Forged direct artifact without receipt`n",
            $utf8
        )
    }
    Invoke-Coordinator @("advance", "-TaskId", $bypassTask) | Out-Null
    $bypassState = Get-State $bypassTask
    if ([string]$bypassState.phase -ne "R1_BLIND") {
        throw "Direct artifacts bypassed coordinator receipts."
    }

    $lateCreated = Invoke-Coordinator @(
        "new-task",
        "-Title", "Late complete self test",
        "-Goal", "Completion must be evaluated before timeout.",
        "-TargetWorkspace", $targetRoot
    )
    $lateTask = [string](@($lateCreated)[-1])
    $lateTask = $lateTask.Trim()
    foreach ($advisor in @("antigravity", "cursor")) {
        $file = Write-TestFile "late-r1-$advisor.md" "# Timely R1`n"
        Invoke-Coordinator @(
            "submit", "-TaskId", $lateTask, "-Agent", $advisor,
            "-Phase", "r1", "-InputFile", $file
        ) | Out-Null
    }
    $lateStatePath = Join-Path $tempRoot `
        "ensemble\ledger\$lateTask\STATE.json"
    $lateState = Get-Content -LiteralPath $lateStatePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    $lateState.phase_retry = 1
    $lateState.phase_started_at = (
        [DateTime]::UtcNow.AddMinutes(-31)
    ).ToString("o")
    [IO.File]::WriteAllText(
        $lateStatePath,
        (($lateState | ConvertTo-Json -Depth 20) + "`n"),
        $utf8
    )
    $lateFile = Write-TestFile "late-r1-claude.md" "# Final valid R1`n"
    Invoke-Coordinator @(
        "submit", "-TaskId", $lateTask, "-Agent", "claude",
        "-Phase", "r1", "-InputFile", $lateFile
    ) | Out-Null
    $lateState = Get-State $lateTask
    if ([string]$lateState.phase -ne "R2_CRITIQUE") {
        throw "Timeout was evaluated before a complete valid phase."
    }

    $configPath = Join-Path $tempRoot "ensemble\agents.json"
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $config.advisor_approval_threshold = 0
    [IO.File]::WriteAllText(
        $configPath,
        (($config | ConvertTo-Json -Depth 20) + "`n"),
        $utf8
    )
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & powershell -NoProfile -ExecutionPolicy Bypass `
            -File $coordinator advance -WorkspaceRoot $tempRoot `
            -TaskId $taskId 2>$null
        $invalidPolicyExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($invalidPolicyExit -eq 0) {
        throw "An invalid zero-threshold policy was accepted."
    }

    [pscustomobject]@{
        result = "PASS"
        task_id = $taskId
        final_phase = "READY_TO_COMMIT"
        decision_exists = $true
        minority_report_exists = $true
        stale_response_rejected = $true
        junk_receipts_ignored = $true
        stale_lock_recovered = $true
        implementation_evidence_frozen = $true
        timeout_retry_and_stop = $true
        policy_invariants_enforced = $true
        direct_artifact_bypass_rejected = $true
        completion_precedes_timeout = $true
        temp_evidence = $tempRoot
    } | Format-List
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "Self-test evidence retained at: $tempRoot"
    exit 1
}
