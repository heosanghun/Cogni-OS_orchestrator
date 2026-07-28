[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$coordinator = Join-Path $repoRoot "orchestrator\ensemble.ps1"
$tempRoot = Join-Path $env:TEMP (
    "four-agent-hard-stop-test-" + [Guid]::NewGuid().ToString("N")
)
$targetRoot = Join-Path $tempRoot "target"
$staging = Join-Path $tempRoot "staging"
$utf8 = New-Object Text.UTF8Encoding($false)

function Put {
    param([string]$Name, [string]$Text)
    $path = Join-Path $staging $Name
    [IO.File]::WriteAllText($path, $Text, $utf8)
    return $path
}

function Run {
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
    $out = & powershell -NoProfile -ExecutionPolicy Bypass `
        -File $coordinator @Arguments -WorkspaceRoot $tempRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Coordinator failed: $($Arguments -join ' ')"
    }
    return @($out)
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
    Run @("init") | Out-Null
    $created = Run @(
        "new-task", "-Title", "Hard stop self test",
        "-Goal", "A valid hard stop must override a two-of-three majority.",
        "-TargetWorkspace", $targetRoot
    )
    $task = [string](@($created)[-1])
    $task = $task.Trim()

    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        Run @(
            "submit", "-TaskId", $task, "-Agent", $advisor, "-Phase", "r1",
            "-InputFile", (Put "r1-$advisor.md" "# R1`n")
        ) | Out-Null
    }
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        Run @(
            "submit", "-TaskId", $task, "-Agent", $advisor, "-Phase", "r2",
            "-InputFile", (Put "r2-$advisor.md" "# R2`n")
        ) | Out-Null
    }
    Run @(
        "submit", "-TaskId", $task, "-Agent", "codex-app", "-Phase", "plan",
        "-InputFile", (Put "plan.md" "# Plan`n")
    ) | Out-Null

    foreach ($advisor in @("antigravity", "cursor")) {
        Run @(
            "submit", "-TaskId", $task, "-Agent", $advisor,
            "-Phase", "plan-review",
            "-InputFile", (Put "review-$advisor.md" @"
vote: APPROVE
hard_stop: NONE
evidence: synthetic approval
"@)
        ) | Out-Null
    }
    Run @(
        "submit", "-TaskId", $task, "-Agent", "claude",
        "-Phase", "plan-review",
        "-InputFile", (Put "review-claude.md" @"
vote: VETO
hard_stop: SECRET_OR_PII
evidence: synthetic credential exposure
"@)
    ) | Out-Null

    $statePath = Join-Path $tempRoot "ensemble\ledger\$task\STATE.json"
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([string]$state.phase -ne "WAITING_HUMAN") {
        throw "Hard stop failed: expected WAITING_HUMAN, got $($state.phase)."
    }

    $createdUnknown = Run @(
        "new-task", "-Title", "Unknown hard stop self test",
        "-Goal", "Unknown hard-stop text must become REVISE, not a veto.",
        "-TargetWorkspace", $targetRoot
    )
    $unknownTask = [string](@($createdUnknown)[-1])
    $unknownTask = $unknownTask.Trim()
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        Run @(
            "submit", "-TaskId", $unknownTask, "-Agent", $advisor,
            "-Phase", "r1",
            "-InputFile", (Put "unknown-r1-$advisor.md" "# R1`n")
        ) | Out-Null
    }
    foreach ($advisor in @("antigravity", "cursor", "claude")) {
        Run @(
            "submit", "-TaskId", $unknownTask, "-Agent", $advisor,
            "-Phase", "r2",
            "-InputFile", (Put "unknown-r2-$advisor.md" "# R2`n")
        ) | Out-Null
    }
    Run @(
        "submit", "-TaskId", $unknownTask, "-Agent", "codex-app",
        "-Phase", "plan",
        "-InputFile", (Put "unknown-plan.md" "# Plan`n")
    ) | Out-Null
    foreach ($advisor in @("antigravity", "cursor")) {
        Run @(
            "submit", "-TaskId", $unknownTask, "-Agent", $advisor,
            "-Phase", "plan-review",
            "-InputFile", (Put "unknown-review-$advisor.md" @"
vote: APPROVE
hard_stop: NONE
evidence: synthetic approval
"@)
        ) | Out-Null
    }
    Run @(
        "submit", "-TaskId", $unknownTask, "-Agent", "claude",
        "-Phase", "plan-review",
        "-InputFile", (Put "unknown-review-claude.md" @"
vote: VETO
hard_stop: MADE_UP_CODE
evidence: this code is not in policy
"@)
    ) | Out-Null
    $unknownStatePath = Join-Path $tempRoot `
        "ensemble\ledger\$unknownTask\STATE.json"
    $unknownState = Get-Content -LiteralPath $unknownStatePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$unknownState.phase -ne "EXECUTION_AUTHORIZED") {
        throw "Unknown hard stop was treated as valid: $($unknownState.phase)."
    }

    [pscustomobject]@{
        result = "PASS"
        task_id = $task
        final_phase = $state.phase
        majority_overridden_by_hard_stop = $true
        unknown_hard_stop_rejected = $true
        temp_evidence = $tempRoot
    } | Format-List
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output "Hard-stop evidence retained at: $tempRoot"
    exit 1
}
