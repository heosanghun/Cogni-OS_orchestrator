$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "four-agent-room-helper-" + [Guid]::NewGuid().ToString("N")
)
$controlRoot = Join-Path $tempRoot "control"
$targetRoot = Join-Path $tempRoot "target"
$utf8 = New-Object Text.UTF8Encoding($false)

function Set-TaskStartInPast {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$TaskId
    )
    $statePath = Join-Path $Root "ensemble\ledger\$TaskId\STATE.json"
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $state.phase_started_at = [DateTime]::UtcNow.AddHours(-2).ToString("o")
    [IO.File]::WriteAllText(
        $statePath,
        ($state | ConvertTo-Json -Depth 30),
        $utf8
    )
}

function Get-PendingEnvelopeCount {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Agent
    )
    $count = 0
    $pendingRoot = Join-Path $Root ".ensemble-runtime\messages\pending"
    foreach ($file in @(
        Get-ChildItem -LiteralPath $pendingRoot -Filter "*.json" -File `
            -ErrorAction SilentlyContinue
    )) {
        $envelope = Get-Content -LiteralPath $file.FullName -Raw `
            -Encoding UTF8 | ConvertFrom-Json
        if ([string]$envelope.task_id -eq $TaskId -and
            [string]$envelope.agent_id -eq $Agent) {
            $count++
        }
    }
    return $count
}

try {
    foreach ($path in @(
        $controlRoot,
        (Join-Path $controlRoot "orchestrator"),
        (Join-Path $controlRoot "ensemble"),
        $targetRoot
    )) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }

    foreach ($relative in @(
        "orchestrator\ensemble.ps1",
        "orchestrator\room.ps1",
        "ensemble\agents.json",
        "ensemble\PROTOCOL.md",
        "ensemble\POLICY.md"
    )) {
        $destination = Join-Path $controlRoot $relative
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($destination)
        ) | Out-Null
        Copy-Item -LiteralPath (Join-Path $sourceRoot $relative) `
            -Destination $destination
    }

    & git -C $targetRoot init | Out-Null
    & git -C $targetRoot config user.name "Room Helper Test"
    & git -C $targetRoot config user.email "room-helper@test.invalid"
    [IO.File]::WriteAllText(
        (Join-Path $targetRoot "baseline.txt"),
        "baseline`n",
        $utf8
    )
    & git -C $targetRoot add baseline.txt
    & git -C $targetRoot commit -m "baseline" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create target fixture commit."
    }

    $coordinator = Join-Path $controlRoot "orchestrator\ensemble.ps1"
    $room = Join-Path $controlRoot "orchestrator\room.ps1"

    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $coordinator init -WorkspaceRoot $controlRoot | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Coordinator init failed."
    }

    $taskId = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $coordinator new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Room helper smoke" `
            -Goal "Accept one bound R1 response." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    if ($LASTEXITCODE -ne 0 -or $taskId -notmatch '^TASK-') {
        throw "Task creation failed."
    }

    Set-TaskStartInPast -Root $controlRoot -TaskId $taskId
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $coordinator advance `
        -WorkspaceRoot $controlRoot `
        -TaskId $taskId | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Coordinator retry advance failed."
    }
    $retryCount = Get-PendingEnvelopeCount -Root $controlRoot `
        -TaskId $taskId -Agent antigravity
    if ($retryCount -ne 2) {
        throw "Timeout retry did not leave two bound pending envelopes."
    }

    $next = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $room next `
            -WorkspaceRoot $controlRoot `
            -Agent antigravity
    )
    if ($LASTEXITCODE -ne 0) {
        throw "room next failed."
    }
    $messageLine = @(
        $next | Where-Object { $_ -like "ROOM_MESSAGE_PATH=*" }
    )
    if ($messageLine.Count -ne 1) {
        throw "room next did not return exactly one message path."
    }
    $messagePath = $messageLine[0].Substring(
        "ROOM_MESSAGE_PATH=".Length
    )
    $messageText = Get-Content -LiteralPath $messagePath -Raw -Encoding UTF8
    $outputMatch = [regex]::Match(
        $messageText,
        '(?m)^output_path:\s*(.+?)\s*$'
    )
    if (-not $outputMatch.Success) {
        throw "Message output_path is missing."
    }
    $outputPath = $outputMatch.Groups[1].Value.Trim()
    [IO.File]::WriteAllText(
        $outputPath,
        "# Antigravity advice`n`nBound R1 response.`n",
        $utf8
    )

    $submitted = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $room submit `
            -WorkspaceRoot $controlRoot `
            -Agent antigravity `
            -MessagePath $messagePath
    )
    if ($LASTEXITCODE -ne 0 -or
        -not ($submitted -match 'SUBMIT_OK agent=antigravity')) {
        throw "room submit failed."
    }

    $artifact = Join-Path $controlRoot (
        "ensemble\ledger\$taskId\ADVICE_R1\antigravity.md"
    )
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Coordinator did not promote the room response."
    }

    $empty = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $room next `
            -WorkspaceRoot $controlRoot `
            -Agent antigravity
    )
    if ($LASTEXITCODE -ne 0 -or
        -not ($empty -match 'QUEUE_EMPTY agent=antigravity')) {
        throw "Submitted retry duplicate was not filtered."
    }
    $duplicatePendingCount = Get-PendingEnvelopeCount -Root $controlRoot `
        -TaskId $taskId -Agent antigravity
    if ($duplicatePendingCount -ne 1) {
        throw "Retry duplicate fixture was not preserved for the filter test."
    }

    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $room submit `
        -WorkspaceRoot $controlRoot `
        -Agent antigravity `
        -MessagePath $messagePath 2>$null | Out-Null
    $duplicateExitCode = $LASTEXITCODE
    $ErrorActionPreference = $priorErrorAction
    if ($duplicateExitCode -eq 0) {
        throw "A consumed message was accepted twice."
    }

    Set-TaskStartInPast -Root $controlRoot -TaskId $taskId
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $coordinator advance `
        -WorkspaceRoot $controlRoot `
        -TaskId $taskId | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Coordinator timeout exhaustion failed."
    }
    $stoppedState = Get-Content -LiteralPath (
        Join-Path $controlRoot "ensemble\ledger\$taskId\STATE.json"
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$stoppedState.phase -ne "WAITING_HUMAN") {
        throw "Timeout fixture did not enter WAITING_HUMAN."
    }
    $stale = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $room next `
            -WorkspaceRoot $controlRoot `
            -Agent cursor
    )
    if ($LASTEXITCODE -ne 0 -or
        -not ($stale -match 'QUEUE_EMPTY agent=cursor')) {
        throw "Timeout-transition stale pending message was selected."
    }

    $secondTaskId = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $coordinator new-task `
            -WorkspaceRoot $controlRoot `
            -Title "Room helper starvation regression" `
            -Goal "Skip stale prior-task messages." `
            -TargetWorkspace $targetRoot
    )[-1].Trim()
    if ($LASTEXITCODE -ne 0 -or $secondTaskId -notmatch '^TASK-') {
        throw "Second task creation failed."
    }
    $newTaskMessage = @(
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $room next `
            -WorkspaceRoot $controlRoot `
            -Agent cursor
    )
    if ($LASTEXITCODE -ne 0) {
        throw "room next failed while stale prior-task messages existed."
    }
    $newTaskLine = @(
        $newTaskMessage | Where-Object { $_ -like "ROOM_MESSAGE_PATH=*" }
    )
    if ($newTaskLine.Count -ne 1) {
        throw "A current message was starved by stale prior-task messages."
    }
    $newTaskPath = $newTaskLine[0].Substring(
        "ROOM_MESSAGE_PATH=".Length
    )
    $newTaskText = Get-Content -LiteralPath $newTaskPath -Raw -Encoding UTF8
    if ($newTaskText -notmatch (
        '(?m)^task_id:\s*' + [regex]::Escape($secondTaskId) + '\s*$'
    )) {
        throw "room next selected a stale task instead of the new task."
    }

    [pscustomobject]@{
        result = "PASS"
        task_id = $taskId
        second_task_id = $secondTaskId
        pending_message_selected = $true
        exact_output_promoted = $true
        consumed_message_filtered = $true
        duplicate_submit_rejected = $true
        retry_duplicate_filtered = $true
        timeout_stale_filtered = $true
        new_task_not_starved = $true
        temp_evidence = $tempRoot
    } | Format-List
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
