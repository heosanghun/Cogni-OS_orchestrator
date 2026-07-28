$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$tempRoot = Join-Path $env:SystemDrive (
    "pair-wb-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
)
$controlRoot = Join-Path $tempRoot "control"
$targetRoot = Join-Path $tempRoot "target"
$fakeRoot = Join-Path $tempRoot "fake"
$utf8 = New-Object Text.UTF8Encoding($false)

function Write-Utf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName($Path)
    ) | Out-Null
    [IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-State {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Id
    )
    return Get-Content -LiteralPath (
        Join-Path $Root ".ensemble-runtime\pair-workbench\tasks\$Id\STATE.json"
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-TestAgentRound {
    param(
        [Parameter(Mandatory = $true)]$State,
        [ValidateSet("R1", "R2")][string]$Round,
        [Parameter(Mandatory = $true)][string]$BodySuffix
    )

    $roundRoot = Join-Path ([string]$State.agent_outbox_root) $Round
    [IO.Directory]::CreateDirectory($roundRoot) | Out-Null
    $artifact = Join-Path $roundRoot "response.md"
    Write-Utf8 -Path $artifact -Text (
        "agent: antigravity`n" +
        "task_id: $($State.task_id)`n" +
        "recommendation: REVISE`n" +
        "hard_stop: NONE`n" +
        "$BodySuffix`n"
    )
    $done = [ordered]@{
        schema_version = 1
        task_id = [string]$State.task_id
        agent = "antigravity"
        artifact_path = $artifact
        sha256 = (
            Get-FileHash -LiteralPath $artifact -Algorithm SHA256
        ).Hash.ToLower()
        completed_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-Utf8 -Path (Join-Path $roundRoot "DONE.json") -Text (
        $done | ConvertTo-Json
    )
}

try {
    foreach ($path in @($controlRoot, $targetRoot, $fakeRoot)) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
    [IO.Directory]::CreateDirectory(
        (Join-Path $controlRoot "orchestrator")
    ) | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceRoot "orchestrator\pair.ps1") `
        -Destination (Join-Path $controlRoot "orchestrator\pair.ps1")
    Copy-Item -LiteralPath (
        Join-Path $sourceRoot "orchestrator\pair-sidecar.ps1"
    ) -Destination (
        Join-Path $controlRoot "orchestrator\pair-sidecar.ps1"
    )
    Copy-Item -LiteralPath (
        Join-Path $sourceRoot "orchestrator\pair-process-runner.ps1"
    ) -Destination (
        Join-Path $controlRoot "orchestrator\pair-process-runner.ps1"
    )

    & git -C $targetRoot init | Out-Null
    & git -C $targetRoot config user.name "Pair Workbench Test"
    & git -C $targetRoot config user.email "pair@test.invalid"
    Write-Utf8 -Path (Join-Path $targetRoot "baseline.txt") -Text "baseline`n"
    & git -C $targetRoot add baseline.txt
    & git -C $targetRoot commit -m "baseline" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create target fixture."
    }

    $fakeAgentApiPs1 = Join-Path $fakeRoot "fake-agentapi.ps1"
    $fakeAgentApiCmd = Join-Path $fakeRoot "agentapi.cmd"
    $fakeCodexPs1 = Join-Path $fakeRoot "fake-codex.ps1"
    $fakeCodexCmd = Join-Path $fakeRoot "codex.cmd"
    $fakeTreeChildPs1 = Join-Path $fakeRoot "fake-tree-child.ps1"
    $fakeHangAgentPs1 = Join-Path $fakeRoot "fake-hang-agent.ps1"

    Write-Utf8 -Path $fakeAgentApiPs1 -Text @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$ErrorActionPreference = "Stop"
$utf8 = New-Object Text.UTF8Encoding($false)
$root = $env:PAIR_TEST_TASK_ROOT
$state = Get-Content -LiteralPath (Join-Path $root "STATE.json") -Raw |
    ConvertFrom-Json
$taskId = [string]$state.task_id
$agentOutbox = [string]$state.agent_outbox_root
if ($Rest.Count -gt 0 -and [string]$Rest[0] -eq "agentapi") {
    $Rest = @($Rest | Select-Object -Skip 1)
}
$command = [string]$Rest[0]
$recommendation = if ($env:PAIR_TEST_RECOMMENDATION) {
    $env:PAIR_TEST_RECOMMENDATION
} else {
    "PROCEED"
}
[IO.File]::AppendAllText(
    (Join-Path $agentOutbox "fake-agentapi.calls"),
    (($Rest -join "|") + "`n"),
    $utf8
)
if ($command -eq "new-conversation") {
    $roundRoot = Join-Path $agentOutbox "R1"
    $artifact = Join-Path $roundRoot "response.md"
    $hardStop = if ($env:PAIR_TEST_HARDSTOP -eq "1") {
        "POLICY_BLOCK"
    } else {
        "NONE"
    }
    [IO.File]::WriteAllText(
        $artifact,
        (
            "agent: antigravity`ntask_id: $taskId`n" +
            "recommendation: $recommendation`nhard_stop: $hardStop`n`n" +
            "# Evidence body`nrecommendation: PROCEED`n" +
            "hard_stop: NONE"
        ),
        $utf8
    )
    $done = [ordered]@{
        schema_version = 1
        task_id = $taskId
        agent = "antigravity"
        artifact_path = $artifact
        sha256 = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLower()
        completed_at = [DateTime]::UtcNow.ToString("o")
    }
    [IO.File]::WriteAllText(
        (Join-Path $roundRoot "DONE.json"),
        ($done | ConvertTo-Json),
        $utf8
    )
    '{"response":{"newConversation":{"conversationId":"11111111-1111-1111-1111-111111111111"}}}'
    exit 0
}
if ($command -eq "send-message") {
    $roundRoot = Join-Path $agentOutbox "R2"
    $artifact = Join-Path $roundRoot "response.md"
    [IO.File]::WriteAllText(
        $artifact,
        (
            "agent: antigravity`ntask_id: $taskId`n" +
            "recommendation: $recommendation`nhard_stop: NONE`n`n" +
            "# Evidence body`nrecommendation: REVISE`n" +
            "hard_stop: NONE"
        ),
        $utf8
    )
    $done = [ordered]@{
        schema_version = 1
        task_id = $taskId
        agent = "antigravity"
        artifact_path = $artifact
        sha256 = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLower()
        completed_at = [DateTime]::UtcNow.ToString("o")
    }
    [IO.File]::WriteAllText(
        (Join-Path $roundRoot "DONE.json"),
        ($done | ConvertTo-Json),
        $utf8
    )
    '{"response":{"sendMessage":{"recipientId":"11111111-1111-1111-1111-111111111111"}}}'
    exit 0
}
exit 9
'@
    Write-Utf8 -Path $fakeAgentApiCmd -Text @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$fakeAgentApiPs1" %*
exit /b %ERRORLEVEL%
"@

    Write-Utf8 -Path $fakeCodexPs1 -Text @'
param(
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest,
    [string]$PromptText
)
$ErrorActionPreference = "Stop"
$utf8 = New-Object Text.UTF8Encoding($false)
$root = $env:PAIR_TEST_TASK_ROOT
$state = Get-Content -LiteralPath (Join-Path $root "STATE.json") -Raw |
    ConvertFrom-Json
$outputIndex = [Array]::IndexOf($Rest, "--output-last-message")
if ($outputIndex -lt 0) {
    throw "Missing --output-last-message."
}
$outputPath = $Rest[$outputIndex + 1]
[IO.File]::AppendAllText(
    (Join-Path $root "fake-codex.calls"),
    "$outputPath`n",
    $utf8
)
$label = if ([IO.Path]::GetFileName($outputPath) -eq "PAIR_CANDIDATE.md") {
    "PAIR_CANDIDATE"
} else {
    "DRAFT"
}
$recommendation = if ($env:PAIR_TEST_RECOMMENDATION) {
    $env:PAIR_TEST_RECOMMENDATION
} else {
    "PROCEED"
}
[IO.File]::WriteAllText(
    $outputPath,
    (
        "agent: codex`ntask_id: $($state.task_id)`n" +
        "recommendation: $recommendation`nhard_stop: NONE`n`n$label`n" +
        "recommendation: REVISE`nhard_stop: NONE"
    ),
    $utf8
)
$global:LASTEXITCODE = 0
return
'@
    Write-Utf8 -Path $fakeCodexCmd -Text @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$fakeCodexPs1" %*
exit /b %ERRORLEVEL%
"@

    Write-Utf8 -Path $fakeTreeChildPs1 -Text @'
param([Parameter(Mandatory = $true)][string]$MarkerPath)
$utf8 = New-Object Text.UTF8Encoding($false)
$grandchild = Start-Process powershell.exe -WindowStyle Hidden -PassThru `
    -ArgumentList @(
        "-NoProfile",
        "-Command",
        "Start-Sleep -Seconds 300"
    )
[IO.File]::WriteAllText(
    $MarkerPath,
    "$PID`n$($grandchild.Id)`n",
    $utf8
)
while ($true) {
    Start-Sleep -Seconds 5
}
'@
    Write-Utf8 -Path $fakeHangAgentPs1 -Text @"
param(
    [Parameter(ValueFromRemainingArguments = `$true)][string[]]`$Rest,
    [string]`$PromptText
)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', '$fakeTreeChildPs1',
    '-MarkerPath', `$env:PAIR_TEST_TREE_MARKER
) | Out-Null
while (`$true) {
    Start-Sleep -Seconds 5
}
"@

    $pair = Join-Path $controlRoot "orchestrator\pair.ps1"
    $sidecar = Join-Path $controlRoot "orchestrator\pair-sidecar.ps1"
    $runner = Join-Path $controlRoot "orchestrator\pair-process-runner.ps1"
    $gitPath = "C:\Program Files\Git\mingw64\bin\git.exe"
    $gitSha = (
        Get-FileHash -LiteralPath $gitPath -Algorithm SHA256
    ).Hash.ToLower()
    $agentApiSha = (
        Get-FileHash -LiteralPath $fakeAgentApiCmd -Algorithm SHA256
    ).Hash.ToLower()
    $codexSha = (
        Get-FileHash -LiteralPath $fakeCodexPs1 -Algorithm SHA256
    ).Hash.ToLower()
    $runnerSha = (
        Get-FileHash -LiteralPath $runner -Algorithm SHA256
    ).Hash.ToLower()
    function Invoke-FixtureReconcile {
        param(
            [Parameter(Mandatory = $true)][string]$TaskRoot,
            [int]$Count = 1
        )

        $env:PAIR_TEST_TASK_ROOT = $TaskRoot
        for ($index = 0; $index -lt $Count; $index++) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass `
                -File $sidecar -WorkspaceRoot $controlRoot `
                -LanguageServerPath $fakeAgentApiCmd `
                -LanguageServerSha256 $agentApiSha `
                -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
                -GitPath $gitPath -GitSha256 $gitSha `
                -RunnerPath $runner -RunnerSha256 $runnerSha `
                -AgentOutboxQuiescenceSeconds 0 `
                -AllowedTargetRoots $targetRoot
            if ($LASTEXITCODE -ne 0) {
                throw "Fixture sidecar reconcile failed."
            }
        }
    }
    $taskId = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Pair E2E" `
            -Goal "Exercise the bounded read-only pair flow." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    if ($LASTEXITCODE -ne 0 -or $taskId -notmatch '^PAIR-') {
        throw "Pair task creation failed."
    }
    $taskRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$taskId"
    )
    $env:PAIR_TEST_TASK_ROOT = $taskRoot
    $env:PAIR_TEST_RECOMMENDATION = "REVISE"

    for ($step = 1; $step -le 6; $step++) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $sidecar `
            -WorkspaceRoot $controlRoot `
            -LanguageServerPath $fakeAgentApiCmd `
            -LanguageServerSha256 $agentApiSha `
            -CodexPath $fakeCodexPs1 `
            -CodexSha256 $codexSha `
            -GitPath $gitPath -GitSha256 $gitSha `
            -RunnerPath $runner -RunnerSha256 $runnerSha `
            -AgentCallTimeoutSeconds 30 -CodexCallTimeoutSeconds 30 `
            -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Pair sidecar failed at step $step."
        }
    }
    $state = Get-State -Root $controlRoot -Id $taskId
    if ([string]$state.phase -ne "PAIR_CANDIDATE") {
        throw "Expected PAIR_CANDIDATE, got $($state.phase)."
    }
    if ([int]$state.schema_version -ne 6 -or
        [string]$state.recommendations.antigravity_r1 -ne "REVISE" -or
        [string]$state.recommendations.codex_r1 -ne "REVISE" -or
        [string]$state.recommendations.antigravity_r2 -ne "REVISE" -or
        [string]$state.recommendations.candidate -ne "REVISE") {
        throw "REVISE recommendations were not preserved through synthesis."
    }
    Remove-Item Env:\PAIR_TEST_RECOMMENDATION
    $agentCalls = Get-Content -LiteralPath (
        Join-Path ([string]$state.agent_outbox_root) "fake-agentapi.calls"
    ) -Raw -Encoding UTF8
    $r1Prompt = Get-Content -LiteralPath (
        Join-Path $taskRoot "R1_ANTIGRAVITY_PROMPT.md"
    ) -Raw -Encoding UTF8
    if ($agentCalls -notmatch "Read and execute the task prompt file" -or
        $r1Prompt -notmatch "After the Markdown is fully written") {
        throw "Antigravity dispatch did not bind the immutable prompt artifact."
    }
    foreach ($name in @(
        "R1_ANTIGRAVITY.md",
        "R1_ANTIGRAVITY.DONE.json",
        "R1_CODEX.md",
        "R1_CODEX.DONE.json",
        "R2_ANTIGRAVITY.md",
        "R2_ANTIGRAVITY.DONE.json",
        "PAIR_CANDIDATE.md",
        "PAIR_CANDIDATE.DONE.json",
        "PAIR_CANDIDATE_SEAL.json",
        "PAIR_CANDIDATE_SEAL.json.sha256"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $taskRoot $name))) {
            throw "Missing pair artifact: $name"
        }
    }
    foreach ($round in @("R1", "R2")) {
        $importRoot = Join-Path $taskRoot ".antigravity-imports\$round"
        $rawResponse = Join-Path $importRoot "response.md"
        $rawDonePath = Join-Path $importRoot "DONE.json"
        $importEvidencePath = Join-Path $importRoot "IMPORT_EVIDENCE.json"
        if (-not (Test-Path -LiteralPath $rawResponse -PathType Leaf) -or
            -not (Test-Path -LiteralPath $rawDonePath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $importEvidencePath -PathType Leaf) -or
            -not (Test-Path -LiteralPath "$importEvidencePath.sha256" -PathType Leaf)) {
            throw "Antigravity $round raw import evidence was not preserved."
        }
        $rawDone = Get-Content -LiteralPath $rawDonePath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $expectedRawPath = Join-Path (
            Join-Path ([string]$state.agent_outbox_root) $round
        ) "response.md"
        if (-not [IO.Path]::GetFullPath(
            [string]$rawDone.artifact_path
        ).Equals(
            [IO.Path]::GetFullPath($expectedRawPath),
            [StringComparison]::OrdinalIgnoreCase
        ) -or [string]$rawDone.sha256 -ne (
            Get-FileHash -LiteralPath $rawResponse -Algorithm SHA256
        ).Hash.ToLower()) {
            throw "Antigravity $round raw DONE provenance is invalid."
        }
        if (Test-Path -LiteralPath (
            Join-Path ([string]$state.agent_outbox_root) $round
        )) {
            throw "Antigravity $round was not quarantined out of writable staging."
        }
    }
    $invocationEvidenceFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $taskRoot ".attempts") `
            -Recurse -Filter "INVOCATION_EVIDENCE.json" -File
    )
    if ($invocationEvidenceFiles.Count -ne 4) {
        throw "Expected four immutable invocation evidence files."
    }
    foreach ($evidenceFile in $invocationEvidenceFiles) {
        $evidence = Get-Content -LiteralPath $evidenceFile.FullName -Raw `
            -Encoding UTF8 | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace(
            [string]$evidence.process_log_path
        ) -and -not (Test-Path -LiteralPath (
            [string]$evidence.process_log_path
        ) -PathType Leaf)) {
            throw "Invocation process log was moved out of its evidence path."
        }
        if (-not [string]::IsNullOrWhiteSpace(
            [string]$evidence.response_path
        ) -and -not (Test-Path -LiteralPath (
            [string]$evidence.response_path
        ) -PathType Leaf)) {
            throw "Invocation response was moved out of its evidence path."
        }
    }
    $targetStatus = @(& git -C $targetRoot status --porcelain=v1)
    if ($LASTEXITCODE -ne 0 -or $targetStatus.Count -ne 0) {
        throw "Read-only pair flow changed the target workspace."
    }
    $terminalVersion = [int]$state.state_version
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $state = Get-State -Root $controlRoot -Id $taskId
    if ([string]$state.phase -ne "PAIR_CANDIDATE" -or
        [int]$state.state_version -ne $terminalVersion) {
        throw "Benign terminal seal reconciliation changed the candidate."
    }
    Write-TestAgentRound -State $state -Round R2 `
        -BodySuffix "late async R2 rewrite"
    $env:PAIR_TEST_TASK_ROOT = $taskRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $lateR2State = Get-State -Root $controlRoot -Id $taskId
    $lateR2Evidence = @(
        Get-ChildItem -LiteralPath (
            Join-Path $taskRoot ".antigravity-late-results"
        ) -Filter "R2.*.evidence.json" -File
    )
    if ([string]$lateR2State.phase -ne "PAIR_SAFE_STOP" -or
        [string]$lateR2State.last_error -notmatch "R2 writable outbox" -or
        $lateR2Evidence.Count -ne 1) {
        throw "Late R2 rewrite did not invalidate the terminal candidate."
    }

    $candidateTamperTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task -WorkspaceRoot $controlRoot `
            -Title "Candidate seal tamper" `
            -Goal "Detect terminal candidate artifact tampering." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $candidateTamperRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$candidateTamperTask"
    )
    Invoke-FixtureReconcile -TaskRoot $candidateTamperRoot -Count 6
    Add-Content -LiteralPath (
        Join-Path $candidateTamperRoot "PAIR_CANDIDATE.md"
    ) -Value "tampered"
    Invoke-FixtureReconcile -TaskRoot $candidateTamperRoot
    $candidateTamperState = Get-State -Root $controlRoot `
        -Id $candidateTamperTask
    if ([string]$candidateTamperState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$candidateTamperState.last_error -notmatch
            "candidate sealed artifact changed") {
        throw "Terminal candidate artifact tampering was not detected."
    }

    $provenanceTamperTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task -WorkspaceRoot $controlRoot `
            -Title "Candidate provenance tamper" `
            -Goal "Detect terminal BRIEF provenance tampering." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $provenanceTamperRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$provenanceTamperTask"
    )
    Invoke-FixtureReconcile -TaskRoot $provenanceTamperRoot -Count 6
    Add-Content -LiteralPath (
        Join-Path $provenanceTamperRoot "BRIEF.md"
    ) -Value "tampered"
    Invoke-FixtureReconcile -TaskRoot $provenanceTamperRoot
    $provenanceTamperState = Get-State -Root $controlRoot `
        -Id $provenanceTamperTask
    if ([string]$provenanceTamperState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$provenanceTamperState.last_error -notmatch
            "provenance artifact changed") {
        throw "Terminal candidate provenance tampering was not detected."
    }

    $rawTamperTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task -WorkspaceRoot $controlRoot `
            -Title "Raw import seal tamper" `
            -Goal "Detect accepted raw import tampering." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $rawTamperRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$rawTamperTask"
    )
    Invoke-FixtureReconcile -TaskRoot $rawTamperRoot -Count 6
    Add-Content -LiteralPath (
        Join-Path $rawTamperRoot ".antigravity-imports\R1\response.md"
    ) -Value "tampered"
    Invoke-FixtureReconcile -TaskRoot $rawTamperRoot
    $rawTamperState = Get-State -Root $controlRoot -Id $rawTamperTask
    if ([string]$rawTamperState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$rawTamperState.last_error -notmatch
            "raw import evidence changed") {
        throw "Accepted raw import tampering was not detected."
    }

    $stopRaceTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task -WorkspaceRoot $controlRoot `
            -Title "Terminal stop race" `
            -Goal "Honor a stop request published during terminal transition." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $stopRaceRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$stopRaceTask"
    )
    Invoke-FixtureReconcile -TaskRoot $stopRaceRoot -Count 6
    $stopRequestPath = Join-Path $stopRaceRoot (
        "STOP_REQUEST.v1.20260101T000000Z.race0001.json"
    )
    Write-Utf8 -Path $stopRequestPath -Text (
        [ordered]@{
            schema_version = 1
            task_id = $stopRaceTask
            reason = "terminal race test"
            requested_at = [DateTime]::UtcNow.ToString("o")
        } | ConvertTo-Json
    )
    Invoke-FixtureReconcile -TaskRoot $stopRaceRoot
    $stopRaceState = Get-State -Root $controlRoot -Id $stopRaceTask
    if ([string]$stopRaceState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$stopRaceState.last_error -notmatch "terminal race test") {
        throw "Terminal-transition stop request was ignored."
    }

    $quiescenceTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Antigravity stable-window gate" `
            -Goal "Do not import a freshly written asynchronous DONE." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $quiescenceRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$quiescenceTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $quiescenceRoot
    foreach ($pass in 1..2) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $sidecar -WorkspaceRoot $controlRoot `
            -LanguageServerPath $fakeAgentApiCmd `
            -LanguageServerSha256 $agentApiSha `
            -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
            -GitPath $gitPath -GitSha256 $gitSha `
            -RunnerPath $runner -RunnerSha256 $runnerSha `
            -AgentOutboxQuiescenceSeconds 1 `
            -AllowedTargetRoots $targetRoot
    }
    $quiescenceState = Get-State -Root $controlRoot -Id $quiescenceTask
    if ([string]$quiescenceState.phase -ne "WAIT_ANTIGRAVITY_R1" -or
        (Test-Path -LiteralPath (
            Join-Path $quiescenceRoot "R1_ANTIGRAVITY.md"
        ))) {
        throw "Fresh Antigravity DONE bypassed the stability window."
    }
    $firstObservedSha = [string](
        $quiescenceState.pending_antigravity.stability_observation.
            response_sha256
    )
    $quiescenceResponse = Join-Path (
        [string]$quiescenceState.agent_outbox_root
    ) "R1\response.md"
    $quiescenceDone = Join-Path (
        [string]$quiescenceState.agent_outbox_root
    ) "R1\DONE.json"
    $changedText = (
        Get-Content -LiteralPath $quiescenceResponse -Raw -Encoding UTF8
    ).Replace("recommendation: PROCEED", "recommendation: REVISE")
    Write-Utf8 -Path $quiescenceResponse -Text $changedText
    $changedDone = Get-Content -LiteralPath $quiescenceDone -Raw `
        -Encoding UTF8 | ConvertFrom-Json
    $changedDone.sha256 = (
        Get-FileHash -LiteralPath $quiescenceResponse -Algorithm SHA256
    ).Hash.ToLower()
    Write-Utf8 -Path $quiescenceDone -Text (
        $changedDone | ConvertTo-Json
    )
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 1 `
        -AllowedTargetRoots $targetRoot
    $quiescenceState = Get-State -Root $controlRoot -Id $quiescenceTask
    if ([string]$quiescenceState.phase -ne "WAIT_ANTIGRAVITY_R1" -or
        [int]$quiescenceState.pending_antigravity.stability_observation.
            matching_reconcile_count -ne 1 -or
        [string]$quiescenceState.pending_antigravity.stability_observation.
            response_sha256 -eq $firstObservedSha) {
        throw "Changed Antigravity output did not reset broker observation."
    }
    $oldWrite = [DateTime]::UtcNow.AddSeconds(-31)
    foreach ($path in @(
        (Join-Path ([string]$quiescenceState.agent_outbox_root) "R1\response.md"),
        (Join-Path ([string]$quiescenceState.agent_outbox_root) "R1\DONE.json")
    )) {
        [IO.File]::SetLastWriteTimeUtc($path, $oldWrite)
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 1 `
        -AllowedTargetRoots $targetRoot
    $quiescenceState = Get-State -Root $controlRoot -Id $quiescenceTask
    if ([string]$quiescenceState.phase -ne "WAIT_ANTIGRAVITY_R1" -or
        (Test-Path -LiteralPath (
            Join-Path $quiescenceRoot ".antigravity-imports\R1\response.md"
        ))) {
        throw "Producer-controlled timestamps bypassed broker observation."
    }
    Start-Sleep -Milliseconds 1100
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 1 `
        -AllowedTargetRoots $targetRoot
    $quiescenceState = Get-State -Root $controlRoot -Id $quiescenceTask
    if ([string]$quiescenceState.phase -ne "CODEX_R1_DONE" -or
        -not (Test-Path -LiteralPath (
            Join-Path $quiescenceRoot ".antigravity-imports\R1\response.md"
        ))) {
        throw "Broker-observed stable Antigravity output was not promoted."
    }
    Write-TestAgentRound -State $quiescenceState -Round R1 `
        -BodySuffix "late async R1 rewrite"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $lateR1State = Get-State -Root $controlRoot -Id $quiescenceTask
    $lateR1Evidence = @(
        Get-ChildItem -LiteralPath (
            Join-Path $quiescenceRoot ".antigravity-late-results"
        ) -Filter "R1.*.evidence.json" -File
    )
    if ([string]$lateR1State.phase -ne "PAIR_SAFE_STOP" -or
        [string]$lateR1State.last_error -notmatch "R1 writable outbox" -or
        $lateR1Evidence.Count -ne 1 -or
        (Test-Path -LiteralPath (
            Join-Path $quiescenceRoot "R2_ANTIGRAVITY_PROMPT.md"
        ))) {
        throw "Late R1 rewrite did not stop the pair before R2."
    }

    $hardStopTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Pair hard stop" `
            -Goal "Verify that an advisor hard stop blocks Codex." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $hardStopRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$hardStopTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $hardStopRoot
    $env:PAIR_TEST_HARDSTOP = "1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    Remove-Item Env:\PAIR_TEST_HARDSTOP
    $hardStopState = Get-State -Root $controlRoot -Id $hardStopTask
    if ([string]$hardStopState.phase -ne "PAIR_SAFE_STOP") {
        throw "Advisor hard stop did not stop the pair flow."
    }
    if (Test-Path -LiteralPath (Join-Path $hardStopRoot "fake-codex.calls")) {
        throw "Codex ran after an advisor hard stop."
    }
    $oldSafeEvidencePath = [string]$hardStopState.safe_stop_evidence_path
    Add-Content -LiteralPath $oldSafeEvidencePath -Value "tampered"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $hardStopState = Get-State -Root $controlRoot -Id $hardStopTask
    if ([string]$hardStopState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$hardStopState.last_error -notmatch
            "evidence integrity failure" -or
        [string]$hardStopState.safe_stop_evidence_path -eq
            $oldSafeEvidencePath -or
        (Get-FileHash -LiteralPath (
            [string]$hardStopState.safe_stop_evidence_path
        ) -Algorithm SHA256).Hash.ToLower() -ne
            [string]$hardStopState.safe_stop_evidence_sha256) {
        throw "SAFE_STOP terminal evidence tampering was not rebound."
    }

    $revokedTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Async Antigravity acceptance revocation" `
            -Goal "A stop in WAIT must reject even a completed outbox result." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $revokedRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$revokedTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $revokedRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $pair stop -WorkspaceRoot $controlRoot `
        -TaskId $revokedTask -Reason "test acceptance revocation" | Out-Null
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $revokedState = Get-State -Root $controlRoot -Id $revokedTask
    if ([string]$revokedState.phase -ne "PAIR_SAFE_STOP" -or
        (Test-Path -LiteralPath (
            Join-Path $revokedRoot "R1_ANTIGRAVITY.md"
        )) -or -not (Test-Path -LiteralPath (
            Join-Path ([string]$revokedState.agent_outbox_root) "R1\response.md"
        ))) {
        throw "WAIT stop did not revoke Antigravity result acceptance."
    }
    $revokedEvidence = Get-Content -LiteralPath (
        [string]$revokedState.safe_stop_evidence_path
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([bool]$revokedEvidence.server_execution_cancelled -or
        $null -eq $revokedEvidence.pending_antigravity) {
        throw "SAFE_STOP incorrectly claimed asynchronous server cancellation."
    }

    $rogueTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Writable outbox quarantine" `
            -Goal "Reject an outbox round containing an undeclared extra file." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $rogueRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$rogueTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $rogueRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $rogueState = Get-State -Root $controlRoot -Id $rogueTask
    Write-Utf8 -Path (
        Join-Path ([string]$rogueState.agent_outbox_root) "R1\rogue.txt"
    ) -Text "unexpected`n"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $rogueState = Get-State -Root $controlRoot -Id $rogueTask
    if ([string]$rogueState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$rogueState.last_error -notmatch "exactly response.md" -or
        (Test-Path -LiteralPath (
            Join-Path $rogueRoot "R1_ANTIGRAVITY.md"
        ))) {
        throw "Outbox extra-file attack did not fail closed."
    }

    $quarantineRogueTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Post-quarantine manifest validation" `
            -Goal "Reject a file that raced into the directory before quarantine." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $quarantineRogueRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$quarantineRogueTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $quarantineRogueRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $quarantineRogueState = Get-State -Root $controlRoot `
        -Id $quarantineRogueTask
    $quarantineImportsRoot = Join-Path $quarantineRogueRoot (
        ".antigravity-imports"
    )
    [IO.Directory]::CreateDirectory($quarantineImportsRoot) | Out-Null
    [IO.Directory]::Move(
        (Join-Path ([string]$quarantineRogueState.agent_outbox_root) "R1"),
        (Join-Path $quarantineImportsRoot "R1")
    )
    Write-Utf8 -Path (
        Join-Path $quarantineImportsRoot "R1\raced.txt"
    ) -Text "raced`n"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $quarantineRogueState = Get-State -Root $controlRoot `
        -Id $quarantineRogueTask
    if ([string]$quarantineRogueState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$quarantineRogueState.last_error -notmatch
            "exact expected regular files" -or
        (Test-Path -LiteralPath (
            Join-Path $quarantineRogueRoot "R1_ANTIGRAVITY.md"
        ))) {
        throw "Post-quarantine manifest validation did not fail closed."
    }

    $publishCrashTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task -WorkspaceRoot $controlRoot `
            -Title "Import sidecar crash recovery" `
            -Goal "Recover a validated import JSON whose SHA sidecar was not published." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $publishCrashRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$publishCrashTask"
    )
    Invoke-FixtureReconcile -TaskRoot $publishCrashRoot -Count 2
    $publishCrashStatePath = Join-Path $publishCrashRoot "STATE.json"
    $publishCrashState = Get-State -Root $controlRoot -Id $publishCrashTask
    $publishCrashState.pending_antigravity.stability_observation.
        matching_reconcile_count = 2
    $publishCrashState.pending_antigravity.stability_observation.
        last_observed_at = [DateTime]::UtcNow.ToString("o")
    $publishCrashState.state_version = [int]$publishCrashState.state_version + 1
    [IO.File]::WriteAllText(
        $publishCrashStatePath,
        ($publishCrashState | ConvertTo-Json -Depth 30),
        $utf8
    )
    $publishCrashOutbox = Join-Path (
        [string]$publishCrashState.agent_outbox_root
    ) "R1"
    $publishCrashImportRoot = Join-Path $publishCrashRoot (
        ".antigravity-imports"
    )
    $publishCrashImport = Join-Path $publishCrashImportRoot "R1"
    [IO.Directory]::CreateDirectory($publishCrashImportRoot) | Out-Null
    [IO.Directory]::Move($publishCrashOutbox, $publishCrashImport)
    $publishCrashResponse = Join-Path $publishCrashImport "response.md"
    $publishCrashDonePath = Join-Path $publishCrashImport "DONE.json"
    $publishCrashDone = Get-Content -LiteralPath $publishCrashDonePath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    $publishCrashEvidence = [ordered]@{
        schema_version = 2
        task_id = $publishCrashTask
        round = "R1"
        source_round_path = $publishCrashOutbox
        imported_round_path = $publishCrashImport
        quarantined_entries = @("DONE.json", "response.md")
        response_sha256 = [string]$publishCrashDone.sha256
        response_bytes = [long](
            Get-Item -LiteralPath $publishCrashResponse
        ).Length
        done_sha256 = (
            Get-FileHash -LiteralPath $publishCrashDonePath -Algorithm SHA256
        ).Hash.ToLower()
        done_bytes = [long](
            Get-Item -LiteralPath $publishCrashDonePath
        ).Length
        broker_observation = (
            $publishCrashState.pending_antigravity.stability_observation
        )
        quiescence_seconds = 0
        imported_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-Utf8 -Path (
        Join-Path $publishCrashImport "IMPORT_EVIDENCE.json"
    ) -Text ($publishCrashEvidence | ConvertTo-Json -Depth 30)
    Invoke-FixtureReconcile -TaskRoot $publishCrashRoot
    $publishCrashState = Get-State -Root $controlRoot -Id $publishCrashTask
    if ([string]$publishCrashState.phase -ne "CODEX_R1_DONE" -or
        -not (Test-Path -LiteralPath (
            Join-Path $publishCrashImport "IMPORT_EVIDENCE.json.sha256"
        ) -PathType Leaf)) {
        throw "Valid import JSON sidecar crash boundary was not recovered."
    }

    $snapshotTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Snapshot mutation stop" `
            -Goal "Detect a same-namespace target mutation before dispatch." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $snapshotRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$snapshotTask"
    )
    Add-Content -LiteralPath (Join-Path $targetRoot "baseline.txt") `
        -Value "mutated"
    $env:PAIR_TEST_TASK_ROOT = $snapshotRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $snapshotState = Get-State -Root $controlRoot -Id $snapshotTask
    if ([string]$snapshotState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$snapshotState.last_error -notmatch "snapshot changed") {
        throw "Target snapshot mutation did not fail closed."
    }
    if (Test-Path -LiteralPath (
        Join-Path $snapshotRoot "fake-agentapi.calls"
    )) {
        throw "Antigravity ran after a target snapshot mismatch."
    }

    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair status -WorkspaceRoot $controlRoot `
            -TaskId "..\path-escape" 2>$null | Out-Null
        $escapeExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
    if ($escapeExit -eq 0) {
        throw "Path-traversal task ID was accepted."
    }

    $timeoutTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Bounded process timeout" `
            -Goal "Verify that a hung adapter tree is terminated and preserved." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $timeoutRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$timeoutTask"
    )
    $treeMarker = Join-Path $timeoutRoot "fake-tree-pids.txt"
    $env:PAIR_TEST_TASK_ROOT = $timeoutRoot
    $env:PAIR_TEST_TREE_MARKER = $treeMarker
    $hangSha = (
        Get-FileHash -LiteralPath $fakeHangAgentPs1 -Algorithm SHA256
    ).Hash.ToLower()
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeHangAgentPs1 `
        -LanguageServerSha256 $hangSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentCallTimeoutSeconds 5 -CodexCallTimeoutSeconds 30 `
        -ProcessTerminationGraceSeconds 5 `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $timeoutState = Get-State -Root $controlRoot -Id $timeoutTask
    if ([string]$timeoutState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$timeoutState.last_error -notmatch "timed out") {
        throw "Hung adapter did not reach a timeout SAFE_STOP."
    }
    $invocationEvidence = @(
        Get-ChildItem -LiteralPath (
            Join-Path $timeoutRoot ".attempts"
        ) -Recurse -Filter "INVOCATION_EVIDENCE.json" -File
    )
    if ($invocationEvidence.Count -ne 1) {
        throw "Timeout did not publish exactly one invocation evidence file."
    }
    $timeoutEvidence = Get-Content -LiteralPath (
        $invocationEvidence[0].FullName
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$timeoutEvidence.outcome -ne "TIMED_OUT" -or
        -not [bool]$timeoutEvidence.job_assigned -or
        -not [bool]$timeoutEvidence.terminated_job) {
        throw "Timeout evidence does not prove bounded Job termination."
    }
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $treeMarker) {
        foreach ($treePid in @(
            Get-Content -LiteralPath $treeMarker |
            ForEach-Object { [int]$_ }
        )) {
            if (Get-Process -Id $treePid -ErrorAction SilentlyContinue) {
                throw "Timed-out adapter descendant is still alive: $treePid"
            }
        }
    }
    Remove-Item Env:\PAIR_TEST_TREE_MARKER -ErrorAction SilentlyContinue

    $pinTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Runtime pin mismatch" `
            -Goal "Reject an adapter SHA mismatch before model dispatch." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $pinRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$pinTask"
    )
    $env:PAIR_TEST_TASK_ROOT = $pinRoot
    $badSha = "0" * 64
    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $sidecar -WorkspaceRoot $controlRoot `
            -LanguageServerPath $fakeAgentApiCmd `
            -LanguageServerSha256 $badSha `
            -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
            -GitPath $gitPath -GitSha256 $gitSha `
            -RunnerPath $runner -RunnerSha256 $runnerSha `
            -AgentOutboxQuiescenceSeconds 0 `
            -AllowedTargetRoots $targetRoot 2>$null
        $pinExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
    $pinState = Get-State -Root $controlRoot -Id $pinTask
    if ($pinExit -eq 0 -or [string]$pinState.phase -ne "NEW" -or
        (Test-Path -LiteralPath (Join-Path $pinRoot ".attempts"))) {
        throw "Adapter pin mismatch did not fail before dispatch."
    }

    $orphanTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Orphaned in-flight state" `
            -Goal "Never replay an adapter after a broker crash boundary." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $orphanRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$orphanTask"
    )
    $orphanStatePath = Join-Path $orphanRoot "STATE.json"
    $orphanState = Get-State -Root $controlRoot -Id $orphanTask
    $orphanState.phase = "RUNNING_CODEX_R1"
    $orphanState.state_version = [int]$orphanState.state_version + 1
    $orphanState.in_flight = [pscustomobject]@{
        stage = "CODEX_R1"
        invocation_id = "CODEX_R1-orphan"
        status = "RUNNING"
        created_at = [DateTime]::UtcNow.ToString("o")
    }
    [IO.File]::WriteAllText(
        $orphanStatePath,
        ($orphanState | ConvertTo-Json -Depth 30),
        $utf8
    )
    $env:PAIR_TEST_TASK_ROOT = $orphanRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $orphanState = Get-State -Root $controlRoot -Id $orphanTask
    if ([string]$orphanState.phase -ne "PAIR_SAFE_STOP" -or
        [string]$orphanState.last_error -notmatch "Orphaned in-flight") {
        throw "Orphaned in-flight state was replayed instead of stopped."
    }
    if (Test-Path -LiteralPath (Join-Path $orphanRoot ".attempts")) {
        throw "An orphaned in-flight task dispatched a new adapter attempt."
    }

    $staleTask = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $pair new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Stale lock PID reuse" `
            -Goal "An unlocked stale lease must not trust a reused PID." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    $staleRoot = Join-Path $controlRoot (
        ".ensemble-runtime\pair-workbench\tasks\$staleTask"
    )
    Write-Utf8 -Path (Join-Path $staleRoot ".broker.lock") -Text (
        [ordered]@{
            schema_version = 1
            task_id = $staleTask
            pid = $PID
            acquired_at = [DateTime]::UtcNow.ToString("o")
        } | ConvertTo-Json -Compress
    )
    $env:PAIR_TEST_TASK_ROOT = $staleRoot
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $sidecar -WorkspaceRoot $controlRoot `
        -LanguageServerPath $fakeAgentApiCmd `
        -LanguageServerSha256 $agentApiSha `
        -CodexPath $fakeCodexPs1 -CodexSha256 $codexSha `
        -GitPath $gitPath -GitSha256 $gitSha `
        -RunnerPath $runner -RunnerSha256 $runnerSha `
        -AgentOutboxQuiescenceSeconds 0 -AllowedTargetRoots $targetRoot
    $staleState = Get-State -Root $controlRoot -Id $staleTask
    $staleLocks = @(
        Get-ChildItem -LiteralPath $staleRoot -File `
            -Filter ".broker.lock.stale.*"
    )
    if ([string]$staleState.phase -ne "WAIT_ANTIGRAVITY_R1" -or
        $staleLocks.Count -ne 1) {
        throw "Unlocked stale lock with a live unrelated PID was not recovered."
    }

    Write-Output "PAIR_WORKBENCH_TEST_PASS task=$taskId"
}
finally {
    Remove-Item Env:\PAIR_TEST_TASK_ROOT -ErrorAction SilentlyContinue
    Remove-Item Env:\PAIR_TEST_HARDSTOP -ErrorAction SilentlyContinue
    Remove-Item Env:\PAIR_TEST_RECOMMENDATION -ErrorAction SilentlyContinue
    Remove-Item Env:\PAIR_TEST_TREE_MARKER -ErrorAction SilentlyContinue
    if ($env:PAIR_TEST_KEEP -ne "1" -and
        (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    elseif ($env:PAIR_TEST_KEEP -eq "1") {
        Write-Output "PAIR_TEST_PRESERVED=$tempRoot"
    }
}
