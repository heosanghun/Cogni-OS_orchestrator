[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("next", "wait", "submit", "status")]
    [string]$Command = "next",

    [Parameter(Mandatory = $true)]
    [ValidateSet("antigravity", "cursor", "claude", "codex-app")]
    [string]$Agent,

    [string]$MessagePath = "",
    [string]$WorkspaceRoot = "",

    [ValidateRange(1, 300)]
    [int]$PollSeconds = 5,

    [ValidateRange(1, 86400)]
    [int]$TimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Root = if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) {
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}
else {
    [IO.Path]::GetFullPath($WorkspaceRoot)
}
$script:RuntimeRoot = Join-Path $script:Root ".ensemble-runtime"
$script:InboxRoot = Join-Path $script:RuntimeRoot "inbox\$Agent"
$script:PendingRoot = Join-Path $script:RuntimeRoot "messages\pending"
$script:Coordinator = Join-Path $script:Root "orchestrator\ensemble.ps1"

function Test-HasProperties {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    foreach ($name in $Names) {
        if ($Object.PSObject.Properties.Name -notcontains $name) {
            return $false
        }
    }
    return $true
}

function Get-HeaderValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $match = [regex]::Match(
        $Text,
        "(?m)^" + [regex]::Escape($Name) + ":\s*(.+?)\s*$"
    )
    if (-not $match.Success) {
        throw "Message header is missing '$Name'."
    }
    return $match.Groups[1].Value.Trim()
}

function Get-ExpectedStatePhase {
    param([Parameter(Mandatory = $true)][string]$MessagePhase)
    switch ($MessagePhase) {
        "R1_BLIND" { return "R1_BLIND" }
        "R2_CRITIQUE" { return "R2_CRITIQUE" }
        "EXECUTOR_PLAN" { return "EXECUTOR_PLAN_OPEN" }
        "PLAN_REVIEW" { return "PLAN_REVIEW_OPEN" }
        "IMPLEMENT" { return "EXECUTION_AUTHORIZED" }
        "POST_REVIEW" { return "POST_REVIEW_OPEN" }
        default { return "" }
    }
}

function Get-ValidatedRoomMessage {
    param(
        [Parameter(Mandatory = $true)][string]$PendingPath,
        [string]$ExpectedInboxPath = ""
    )
    try {
        $envelope = Get-Content -LiteralPath $PendingPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if (-not (Test-HasProperties -Object $envelope -Names @(
            "message_id",
            "task_id",
            "state_version",
            "agent_id",
            "message_phase",
            "submit_phase",
            "base_commit",
            "inbox_path",
            "output_path",
            "artifact_path",
            "created_at"
        ))) {
            return $null
        }

        $messageId = [string]$envelope.message_id
        $taskId = [string]$envelope.task_id
        if ($messageId -notmatch '^[a-fA-F0-9]{32}$' -or
            ([IO.Path]::GetFileNameWithoutExtension($PendingPath)) -ne
                $messageId -or
            $taskId -notmatch '^TASK-[A-Za-z0-9._-]+$' -or
            [string]$envelope.agent_id -ne $Agent) {
            return $null
        }

        $expectedStatePhase = Get-ExpectedStatePhase (
            [string]$envelope.message_phase
        )
        if ([string]::IsNullOrWhiteSpace($expectedStatePhase)) {
            return $null
        }

        $statePath = Join-Path $script:Root (
            "ensemble\ledger\$taskId\STATE.json"
        )
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            return $null
        }
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if (-not (Test-HasProperties -Object $state -Names @(
            "task_id", "state_version", "base_commit", "phase"
        ))) {
            return $null
        }
        if ([string]$state.task_id -ne $taskId -or
            [int]$state.state_version -ne [int]$envelope.state_version -or
            [string]$state.base_commit -ne [string]$envelope.base_commit -or
            [string]$state.phase -ne $expectedStatePhase) {
            return $null
        }

        $inboxPath = [IO.Path]::GetFullPath([string]$envelope.inbox_path)
        $inboxPrefix = [IO.Path]::GetFullPath($script:InboxRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar
        ) + [IO.Path]::DirectorySeparatorChar
        if (-not $inboxPath.StartsWith(
            $inboxPrefix,
            [StringComparison]::OrdinalIgnoreCase
        ) -or -not (Test-Path -LiteralPath $inboxPath -PathType Leaf)) {
            return $null
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedInboxPath) -and
            -not $inboxPath.Equals(
                [IO.Path]::GetFullPath($ExpectedInboxPath),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $null
        }

        $artifactPath = [IO.Path]::GetFullPath(
            [string]$envelope.artifact_path
        )
        $receiptPath = Join-Path $script:RuntimeRoot (
            "receipts\$taskId\$([string]$envelope.submit_phase)\" +
            "$Agent-v$([int]$envelope.state_version).json"
        )
        if ((Test-Path -LiteralPath $artifactPath -PathType Leaf) -or
            (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
            return $null
        }

        $text = Get-Content -LiteralPath $inboxPath -Raw -Encoding UTF8
        if ((Get-HeaderValue -Text $text -Name "message_id") -ne
            $messageId) {
            return $null
        }
        return [pscustomobject]@{
            Path = $inboxPath
            Text = $text
            MessageId = $messageId
            PendingPath = [IO.Path]::GetFullPath($PendingPath)
            Envelope = $envelope
            CreatedAt = [string]$envelope.created_at
        }
    }
    catch {
        return $null
    }
}

function Get-PendingRoomMessages {
    if (-not (Test-Path -LiteralPath $script:InboxRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $script:PendingRoot -PathType Container)) {
        return @()
    }

    $found = @()
    foreach ($file in @(
        Get-ChildItem -LiteralPath $script:PendingRoot -Filter "*.json" -File `
            -ErrorAction SilentlyContinue |
            Sort-Object Name
    )) {
        $message = Get-ValidatedRoomMessage -PendingPath $file.FullName
        if ($null -ne $message) {
            $found += $message
        }
    }
    return @($found | Sort-Object CreatedAt, Path)
}

function Show-RoomMessage {
    param([Parameter(Mandatory = $true)]$Message)
    Write-Output "ROOM_MESSAGE_PATH=$($Message.Path)"
    Write-Output "ROOM_PENDING_JSON=$($Message.PendingPath)"
    Write-Output "ROOM_MESSAGE_BEGIN"
    Write-Output $Message.Text
    Write-Output "ROOM_MESSAGE_END"
}

function Get-SelectedMessage {
    if ([string]::IsNullOrWhiteSpace($MessagePath)) {
        $pending = @(Get-PendingRoomMessages | Select-Object -First 1)
        if ($pending.Count -eq 0) {
            throw "No pending message exists for agent '$Agent'."
        }
        return $pending[0]
    }

    $full = [IO.Path]::GetFullPath($MessagePath)
    $inboxPrefix = [IO.Path]::GetFullPath($script:InboxRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith(
        $inboxPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "MessagePath must be inside this agent's inbox: $script:InboxRoot"
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Message file does not exist: $full"
    }
    $text = Get-Content -LiteralPath $full -Raw -Encoding UTF8
    $messageId = Get-HeaderValue -Text $text -Name "message_id"
    $pendingPath = Join-Path $script:PendingRoot "$messageId.json"
    if (-not (Test-Path -LiteralPath $pendingPath -PathType Leaf)) {
        throw "Message is stale or already consumed: $messageId"
    }
    $message = Get-ValidatedRoomMessage -PendingPath $pendingPath `
        -ExpectedInboxPath $full
    if ($null -eq $message) {
        throw "Message is stale, duplicated, or inconsistent: $messageId"
    }
    return $message
}

if (-not (Test-Path -LiteralPath $script:Coordinator -PathType Leaf)) {
    throw "Coordinator is missing: $script:Coordinator"
}

switch ($Command) {
    "next" {
        $message = @(Get-PendingRoomMessages | Select-Object -First 1)
        if ($message.Count -eq 0) {
            Write-Output "QUEUE_EMPTY agent=$Agent"
            break
        }
        Show-RoomMessage -Message $message[0]
    }

    "wait" {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            $message = @(Get-PendingRoomMessages | Select-Object -First 1)
            if ($message.Count -gt 0) {
                Show-RoomMessage -Message $message[0]
                return
            }
            Start-Sleep -Seconds $PollSeconds
        }
        Write-Output (
            "WAIT_TIMEOUT agent=$Agent timeout_seconds=$TimeoutSeconds"
        )
        exit 3
    }

    "submit" {
        $message = Get-SelectedMessage
        $envelope = $message.Envelope
        $taskId = [string]$envelope.task_id
        $stateVersion = [int]$envelope.state_version
        $submitPhase = [string]$envelope.submit_phase
        $outputPath = [string]$envelope.output_path

        if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
            throw "Agent output is missing: $outputPath"
        }

        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $script:Coordinator submit `
            -WorkspaceRoot $script:Root `
            -TaskId $taskId `
            -Agent $Agent `
            -Phase $submitPhase `
            -MessageId $message.MessageId `
            -MessageStateVersion $stateVersion `
            -InputFile $outputPath
        if ($LASTEXITCODE -ne 0) {
            throw "Coordinator submit failed with exit code $LASTEXITCODE."
        }
        Write-Output (
            "SUBMIT_OK agent=$Agent task_id=$taskId " +
            "message_id=$($message.MessageId)"
        )
    }

    "status" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $script:Coordinator status `
            -WorkspaceRoot $script:Root
        if ($LASTEXITCODE -ne 0) {
            throw "Coordinator status failed with exit code $LASTEXITCODE."
        }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $script:Coordinator queue `
            -WorkspaceRoot $script:Root `
            -Agent $Agent
        if ($LASTEXITCODE -ne 0) {
            throw "Coordinator queue failed with exit code $LASTEXITCODE."
        }
    }
}
