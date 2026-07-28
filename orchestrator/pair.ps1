param(
    [Parameter(Position = 0)]
    [ValidateSet("init", "new-task", "status", "list", "probe", "stop")]
    [string]$Command = "status",

    [string]$WorkspaceRoot = (
        [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    ),

    [string]$TaskId,
    [string]$Title,
    [string]$Goal,
    [string]$TargetWorkspace,
    [string]$Reason,
    [string]$AgentOutboxRoot = "",
    [string]$GitPath = "C:\Program Files\Git\mingw64\bin\git.exe",
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$GitSha256 = (
        "1a0043555d254618f2d56c936c3d9a1fbfb878bc878416a133c346bc7835eda9"
    ),
    [ValidateRange(1, 3)]
    [int]$MaxRounds = 2
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:Utf8 = New-Object Text.UTF8Encoding($false)
$script:WorkspaceRoot = [IO.Path]::GetFullPath($WorkspaceRoot)
$script:RuntimeRoot = Join-Path $script:WorkspaceRoot (
    ".ensemble-runtime\pair-workbench"
)
$script:TasksRoot = Join-Path $script:RuntimeRoot "tasks"
$script:AgentOutboxRoot = if ([string]::IsNullOrWhiteSpace(
    $AgentOutboxRoot
)) {
    Join-Path $script:WorkspaceRoot ".ensemble-runtime\pair-agent-outbox"
}
else {
    [IO.Path]::GetFullPath($AgentOutboxRoot)
}
$script:TaskIdPattern = '^PAIR-\d{8}T\d{6}Z-[0-9a-f]{8}$'
$script:ResolvedGit = $null

function Initialize-PairRuntime {
    foreach ($path in @(
        $script:RuntimeRoot,
        $script:TasksRoot,
        (Join-Path $script:RuntimeRoot "logs"),
        $script:AgentOutboxRoot
    )) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
}

function Write-Utf8NewFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to overwrite existing pair artifact: $Path"
    }
    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName($Path)
    ) | Out-Null
    [IO.File]::WriteAllText($Path, $Content, $script:Utf8)
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $script:Utf8.GetBytes($Text)
        return (
            [BitConverter]::ToString($sha.ComputeHash($bytes))
        ).Replace("-", "").ToLower()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Resolve-PinnedGit {
    $resolved = [IO.Path]::GetFullPath($GitPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Pinned Git executable does not exist: $resolved"
    }
    $actual = Get-Sha256 -Path $resolved
    if ($actual -ne $GitSha256.ToLower()) {
        throw "Pinned Git SHA-256 mismatch: $resolved"
    }
    return $resolved
}

function Assert-ValidTaskId {
    param([Parameter(Mandatory = $true)][string]$Id)

    if ($Id -notmatch $script:TaskIdPattern) {
        throw "Invalid pair task ID: $Id"
    }
}

function Get-TargetSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Target workspace does not exist: $resolved"
    }
    if ((Get-Item -LiteralPath $resolved).Attributes -band
        [IO.FileAttributes]::ReparsePoint) {
        throw "Target workspace cannot be a reparse point: $resolved"
    }

    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ((Get-Sha256 -Path $script:ResolvedGit) -ne
            $GitSha256.ToLower()) {
            throw "Pinned Git changed before target snapshot capture."
        }
        $headOutput = @(
            & $script:ResolvedGit -C $resolved rev-parse HEAD 2>$null
        )
        $headExit = $LASTEXITCODE
        if ($headExit -ne 0 -or $headOutput.Count -eq 0) {
            throw "Pair targets must be Git workspaces: $resolved"
        }
        $head = ([string]$headOutput[-1]).Trim()
        if ($head -notmatch '^[0-9a-fA-F]{40}$') {
            throw "Invalid Git HEAD for target workspace: $resolved"
        }

    $topOutput = @(
        & $script:ResolvedGit -C $resolved rev-parse --show-toplevel 2>$null
    )
    if ($LASTEXITCODE -ne 0 -or $topOutput.Count -eq 0) {
        throw "Unable to resolve Git root for target workspace: $resolved"
    }
    $gitRoot = [IO.Path]::GetFullPath(
        ([string]$topOutput[-1]).Trim()
    ).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if (-not $gitRoot.Equals(
        $resolved,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Target must be the Git root itself: $resolved"
    }

    $statusOutput = @(
        & $script:ResolvedGit -C $resolved -c core.quotePath=false status `
            --porcelain=v1 --untracked-files=all 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed for target workspace: $resolved"
    }
    $statusLines = @($statusOutput | ForEach-Object { [string]$_ })
    $statusText = $statusLines -join "`n"

    $diffOutput = @(
        & $script:ResolvedGit -C $resolved -c core.quotePath=false diff `
            --binary HEAD -- 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw "git diff failed for target workspace: $resolved"
    }
    $diffText = (@($diffOutput | ForEach-Object { [string]$_ })) -join "`n"

    $untrackedOutput = @(
        & $script:ResolvedGit -C $resolved -c core.quotePath=false ls-files `
            --others --exclude-standard 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw "git untracked-file listing failed: $resolved"
    }
    $rootPrefix = $resolved + [IO.Path]::DirectorySeparatorChar
    $untrackedManifest = @()
    foreach ($relative in @(
        $untrackedOutput | ForEach-Object { [string]$_ } | Sort-Object
    )) {
        $fullPath = [IO.Path]::GetFullPath((Join-Path $resolved $relative))
        if (-not $fullPath.StartsWith(
            $rootPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Untracked path escaped target workspace: $relative"
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Untracked entry is not a regular file: $relative"
        }
        $item = Get-Item -LiteralPath $fullPath
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Untracked reparse points are forbidden: $relative"
        }
        $untrackedManifest += [ordered]@{
            path = $relative.Replace(
                [IO.Path]::DirectorySeparatorChar,
                "/"
            )
            bytes = [long]$item.Length
            sha256 = (
                Get-FileHash -LiteralPath $fullPath -Algorithm SHA256
            ).Hash.ToLower()
        }
    }
    $manifestJson = ConvertTo-Json -InputObject @($untrackedManifest) `
        -Compress -Depth 8
    $statusSha = Get-TextSha256 -Text $statusText
    $diffSha = Get-TextSha256 -Text $diffText
    $manifestSha = Get-TextSha256 -Text $manifestJson
    $fingerprint = Get-TextSha256 -Text (
        @($resolved.ToLower(), $head.ToLower(), $statusSha, $diffSha, $manifestSha) `
            -join "`n"
    )

        return [ordered]@{
            path = $resolved
            is_git = $true
            base_commit = $head.ToLower()
            dirty_count = $statusLines.Count
            status_lines = $statusLines
            status_sha256 = $statusSha
            tracked_diff_sha256 = $diffSha
            untracked_manifest = @($untrackedManifest)
            untracked_manifest_sha256 = $manifestSha
            snapshot_fingerprint = $fingerprint
            git_path = $script:ResolvedGit
            git_sha256 = $GitSha256.ToLower()
        }
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
}

function New-PairTask {
    if ([string]::IsNullOrWhiteSpace($Title)) {
        throw "-Title is required for new-task."
    }
    if ([string]::IsNullOrWhiteSpace($Goal)) {
        throw "-Goal is required for new-task."
    }
    if ([string]::IsNullOrWhiteSpace($TargetWorkspace)) {
        throw "-TargetWorkspace is required for new-task."
    }

    Initialize-PairRuntime
    $snapshot = Get-TargetSnapshot -Path $TargetWorkspace
    $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $newTaskId = "PAIR-$stamp-$suffix"
    $taskRoot = Join-Path $script:TasksRoot $newTaskId
    [IO.Directory]::CreateDirectory($taskRoot) | Out-Null

    $briefPath = Join-Path $taskRoot "BRIEF.md"
    $brief = @"
# Pair workbench brief

- task_id: $newTaskId
- title: $Title
- target_workspace: $($snapshot.path)
- base_commit: $($snapshot.base_commit)
- target_dirty_count: $($snapshot.dirty_count)
- pinned_git_sha256: $($snapshot.git_sha256)
- max_rounds: $MaxRounds

## Goal

$Goal

## Safety boundary

- This is a reduced-assurance Antigravity + Codex planning workbench.
- Both agents are read-only. Product source edits, Git writes, push, deploy,
  release, and public claims are forbidden.
- Antigravity advises and critiques. Codex drafts and synthesizes.
- A pair candidate is not a four-agent council decision and cannot create
  `EXECUTION_AUTHORIZED`.
- Evidence and hard stops override either model's recommendation.
- Do not ask the user to relay messages between the two agents.
"@
    Write-Utf8NewFile -Path $briefPath -Content $brief

    $snapshotPath = Join-Path $taskRoot "TARGET_SNAPSHOT.json"
    $snapshotEnvelope = [ordered]@{
        schema_version = 2
        task_id = $newTaskId
        target = $snapshot
        brief_sha256 = (
            Get-FileHash -LiteralPath $briefPath -Algorithm SHA256
        ).Hash.ToLower()
        captured_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-Utf8NewFile -Path $snapshotPath -Content (
        $snapshotEnvelope | ConvertTo-Json -Depth 30
    )
    $snapshotFileSha = (
        Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256
    ).Hash.ToLower()

    $createdAt = [DateTime]::UtcNow.ToString("o")
    $state = [ordered]@{
        schema_version = 6
        mode = "PAIR_WORKBENCH"
        assurance = "reduced"
        task_id = $newTaskId
        title = $Title
        goal = $Goal
        phase = "NEW"
        state_version = 1
        max_rounds = $MaxRounds
        target = $snapshot
        brief_path = $briefPath
        brief_sha256 = $snapshotEnvelope.brief_sha256
        target_snapshot_path = $snapshotPath
        target_snapshot_sha256 = $snapshotFileSha
        agent_outbox_root = Join-Path $script:AgentOutboxRoot $newTaskId
        antigravity_conversation_id = ""
        dispatch_attempts = 0
        recommendations = [ordered]@{
            antigravity_r1 = ""
            codex_r1 = ""
            antigravity_r2 = ""
            candidate = ""
        }
        adapter_pins = $null
        in_flight = $null
        pending_antigravity = $null
        accepted_antigravity_rounds = [ordered]@{
            R1 = $null
            R2 = $null
        }
        candidate_seal = $null
        safe_stop_evidence_path = ""
        safe_stop_evidence_sha256 = ""
        last_error = ""
        phase_entered_at = $createdAt
        created_at = $createdAt
        updated_at = $createdAt
    }
    $statePath = Join-Path $taskRoot "STATE.json"
    Write-Utf8NewFile -Path $statePath -Content (
        $state | ConvertTo-Json -Depth 20
    )

    Write-Output $newTaskId
}

function Get-PairState {
    param([Parameter(Mandatory = $true)][string]$Id)

    Assert-ValidTaskId -Id $Id
    $statePath = Join-Path (Join-Path $script:TasksRoot $Id) "STATE.json"
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Pair task not found: $Id"
    }
    return Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
}

function Show-PairStatus {
    if ([string]::IsNullOrWhiteSpace($TaskId)) {
        $states = @(
            Get-ChildItem -LiteralPath $script:TasksRoot -Directory `
                -ErrorAction SilentlyContinue |
            ForEach-Object {
                $statePath = Join-Path $_.FullName "STATE.json"
                if (Test-Path -LiteralPath $statePath -PathType Leaf) {
                    Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
                        ConvertFrom-Json
                }
            }
        )
        if ($states.Count -eq 0) {
            Write-Output "No pair workbench tasks."
            return
        }
        $states |
            Sort-Object created_at |
            Select-Object task_id, phase, state_version, title, updated_at |
            Format-Table -AutoSize
        return
    }

    Get-PairState -Id $TaskId | ConvertTo-Json -Depth 20
}

function Stop-PairTask {
    if ([string]::IsNullOrWhiteSpace($TaskId)) {
        throw "-TaskId is required for stop."
    }
    if ([string]::IsNullOrWhiteSpace($Reason)) {
        throw "-Reason is required for stop."
    }
    Assert-ValidTaskId -Id $TaskId

    $taskRoot = Join-Path $script:TasksRoot $TaskId
    $statePath = Join-Path $taskRoot "STATE.json"
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Pair task not found: $TaskId"
    }
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([string]$state.phase -in @("PAIR_CANDIDATE", "PAIR_SAFE_STOP")) {
        throw "Pair task is already terminal: $($state.phase)"
    }
    $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $requestPath = Join-Path $taskRoot (
        "STOP_REQUEST.v1.$stamp.$suffix.json"
    )
    Write-Utf8NewFile -Path $requestPath -Content (
        [ordered]@{
            schema_version = 1
            task_id = $TaskId
            reason = $Reason
            requested_at = [DateTime]::UtcNow.ToString("o")
        } | ConvertTo-Json -Depth 10
    )
    Write-Output "PAIR_STOP_REQUESTED task=$TaskId path=$requestPath"
}

function Invoke-PairProbe {
    Initialize-PairRuntime
    $agentApi = Get-Command agentapi -ErrorAction SilentlyContinue
    if (-not $agentApi) {
        $bundled = Join-Path $env:USERPROFILE (
            ".gemini\antigravity\bin\agentapi.bat"
        )
        if (Test-Path -LiteralPath $bundled -PathType Leaf) {
            $agentApi = Get-Item -LiteralPath $bundled
        }
    }

    $codex = @(
        Get-ChildItem -LiteralPath (
            Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
        ) -Recurse -Filter "codex.exe" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    ) | Select-Object -First 1

    $agentApiResolved = ""
    if ($agentApi) {
        if ($agentApi.PSObject.Properties.Name -contains "Source") {
            $agentApiResolved = [string]$agentApi.Source
        }
        elseif ($agentApi.PSObject.Properties.Name -contains "FullName") {
            $agentApiResolved = [string]$agentApi.FullName
        }
    }

    [ordered]@{
        pair_mode = "PAIR_WORKBENCH"
        runtime_root = $script:RuntimeRoot
        agent_outbox_root = $script:AgentOutboxRoot
        agentapi_discovered = [bool]$agentApi
        agentapi_path = $agentApiResolved
        codex_discovered = [bool]$codex
        codex_path = if ($codex) { [string]$codex.FullName } else { "" }
        unattended_ready = $false
        note = "Run the authenticated end-to-end sidecar test before setting ready."
    } | ConvertTo-Json -Depth 10
}

Initialize-PairRuntime
$script:ResolvedGit = Resolve-PinnedGit
switch ($Command) {
    "init" {
        Write-Output "PAIR_INIT_OK root=$script:RuntimeRoot"
    }
    "new-task" {
        New-PairTask
    }
    "status" {
        Show-PairStatus
    }
    "list" {
        $TaskId = ""
        Show-PairStatus
    }
    "probe" {
        Invoke-PairProbe
    }
    "stop" {
        Stop-PairTask
    }
}
