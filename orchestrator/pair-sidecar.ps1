param(
    [string]$WorkspaceRoot = (
        [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    ),
    [string]$AgentOutboxRoot = "",
    [switch]$Loop,
    [ValidateRange(1, 30)]
    [int]$ReconcileSeconds = 3,
    [string]$AgentApiPath = "",
    [string]$CodexPath = "",
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$AgentApiSha256 = "",
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')]
    [string]$CodexSha256 = "",
    [string]$LanguageServerPath = (
        "C:\Users\wwwhu\AppData\Local\Programs\antigravity\" +
        "resources\bin\language_server.exe"
    ),
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$LanguageServerSha256 = (
        "dcfa776a77f4f4af6a603e984a0ce8cd0fe21019bd936c7163f60afb2951e963"
    ),
    [string]$GitPath = "C:\Program Files\Git\mingw64\bin\git.exe",
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$GitSha256 = (
        "1a0043555d254618f2d56c936c3d9a1fbfb878bc878416a133c346bc7835eda9"
    ),
    [string]$RunnerPath = (Join-Path $PSScriptRoot "pair-process-runner.ps1"),
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$RunnerSha256,
    [string[]]$AllowedTargetRoots = @(
        "C:\Project\System1.5",
        "C:\Project\CTS"
    ),
    [ValidateRange(1, 1440)]
    [int]$WaitTimeoutMinutes = 60,
    [ValidateRange(30, 3600)]
    [int]$LockLeaseSeconds = 300,
    [ValidateRange(5, 3600)]
    [int]$AgentCallTimeoutSeconds = 300,
    [ValidateRange(0, 300)]
    [int]$AgentOutboxQuiescenceSeconds = 30,
    [ValidateRange(5, 7200)]
    [int]$CodexCallTimeoutSeconds = 1800,
    [ValidateRange(1, 60)]
    [int]$ProcessTerminationGraceSeconds = 10
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
$script:BrokerLog = Join-Path $script:RuntimeRoot "logs\broker.log"
$script:ResolvedAgentApi = $null
$script:ResolvedLanguageServer = $null
$script:ResolvedCodex = $null
$script:ResolvedGit = $null
$script:ResolvedRunner = $null
$script:BrokerInstanceId = [Guid]::NewGuid().ToString("N")
$script:TaskIdPattern = '^PAIR-\d{8}T\d{6}Z-[0-9a-f]{8}$'
$script:MaxAgentResponseBytes = 1MB
$script:MaxAgentDoneBytes = 64KB
$script:AllowedPhases = @(
    "NEW",
    "RUNNING_ANTIGRAVITY_R1",
    "WAIT_ANTIGRAVITY_R1",
    "RUNNING_CODEX_R1",
    "CODEX_R1_DONE",
    "RUNNING_ANTIGRAVITY_R2",
    "WAIT_ANTIGRAVITY_R2",
    "RUNNING_CODEX_CANDIDATE",
    "PAIR_CANDIDATE",
    "PAIR_SAFE_STOP"
)
$script:AllowedTargetRoots = @(
    @(
        "C:\Project\System1.5",
        "C:\Project\CTS"
    ) + @($AllowedTargetRoots) | Sort-Object -Unique | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
    }
)

function Write-BrokerLog {
    param([Parameter(Mandatory = $true)][string]$Message)

    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName($script:BrokerLog)
    ) | Out-Null
    $line = "{0} {1}`n" -f [DateTime]::UtcNow.ToString("o"), $Message
    [IO.File]::AppendAllText($script:BrokerLog, $line, $script:Utf8)
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $directory = [IO.Path]::GetDirectoryName($Path)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temp = "{0}.partial.{1}.{2}" -f $Path, $PID, (
        [Guid]::NewGuid().ToString("N")
    )
    $json = $Value | ConvertTo-Json -Depth 30
    $stream = New-Object IO.FileStream(
        $temp,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $bytes = $script:Utf8.GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Write-TextImmutable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    $directory = [IO.Path]::GetDirectoryName($Path)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $stream = New-Object IO.FileStream(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $bytes = $script:Utf8.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Write-JsonImmutable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    Write-TextImmutable -Path $Path -Content (
        $Value | ConvertTo-Json -Depth 30
    )
}

function Set-State {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$Phase,
        [string]$ErrorMessage = ""
    )

    $phaseChanged = [string]$State.phase -ne $Phase
    $State.phase = $Phase
    $State.state_version = [int]$State.state_version + 1
    $now = [DateTime]::UtcNow.ToString("o")
    if ($phaseChanged) {
        $State.phase_entered_at = $now
    }
    $State.updated_at = $now
    $State.last_error = $ErrorMessage
    Write-JsonAtomic -Path $StatePath -Value $State
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
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

function Assert-PathsAbsent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)

    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) {
            throw "Refusing to overwrite existing pair evidence: $path"
        }
    }
}

function Assert-CanonicalChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Anchor,
        [switch]$MustExist,
        [ValidateSet("Any", "File", "Directory")]
        [string]$ExpectedType = "Any"
    )

    $anchorFull = [IO.Path]::GetFullPath($Anchor).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $pathFull = [IO.Path]::GetFullPath($Path)
    $anchorPrefix = $anchorFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.Equals(
        $anchorFull,
        [StringComparison]::OrdinalIgnoreCase
    ) -and -not $pathFull.StartsWith(
        $anchorPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Path escaped its canonical anchor: $pathFull"
    }
    if (-not (Test-Path -LiteralPath $anchorFull -PathType Container)) {
        throw "Canonical anchor is missing: $anchorFull"
    }

    $relative = $pathFull.Substring($anchorFull.Length).TrimStart(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $current = $anchorFull
    $parts = if ([string]::IsNullOrEmpty($relative)) {
        @()
    }
    else {
        @($relative -split '[\\/]')
    }
    foreach ($part in @("") + $parts) {
        if (-not [string]::IsNullOrEmpty($part)) {
            $current = Join-Path $current $part
        }
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse points are forbidden in pair paths: $current"
        }
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $pathFull)) {
        throw "Required canonical path is missing: $pathFull"
    }
    if ($MustExist -and $ExpectedType -eq "File" -and
        -not (Test-Path -LiteralPath $pathFull -PathType Leaf)) {
        throw "Expected a regular file: $pathFull"
    }
    if ($MustExist -and $ExpectedType -eq "Directory" -and
        -not (Test-Path -LiteralPath $pathFull -PathType Container)) {
        throw "Expected a directory: $pathFull"
    }
    return $pathFull
}

function Copy-ArtifactImmutable {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [string]$ExpectedSha256 = ""
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Source artifact is missing: $Source"
    }
    if ((Get-Item -LiteralPath $Source -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint) {
        throw "Source artifact cannot be a reparse point: $Source"
    }
    $sourceSha = Get-Sha256 -Path $Source
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
        $sourceSha -ne $ExpectedSha256.ToLower()) {
        throw "Source artifact SHA-256 mismatch: $Source"
    }
    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf) -or
            (Get-Sha256 -Path $Destination) -ne $sourceSha) {
            throw "Refusing to overwrite a different artifact: $Destination"
        }
        return $sourceSha
    }
    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName($Destination)
    ) | Out-Null
    [IO.File]::Copy($Source, $Destination, $false)
    $destinationSha = Get-Sha256 -Path $Destination
    if ($destinationSha -ne $sourceSha) {
        throw "Copied artifact SHA-256 mismatch: $Destination"
    }
    return $sourceSha
}

function Get-AgentOutboxRoundPaths {
    param(
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round
    )

    $taskOutbox = Join-Path $script:AgentOutboxRoot $TaskId
    $roundOutbox = Join-Path $taskOutbox $Round
    $importsRoot = Join-Path $TaskRoot ".antigravity-imports"
    $importRound = Join-Path $importsRoot $Round
    return [pscustomobject]@{
        task_outbox = $taskOutbox
        round_outbox = $roundOutbox
        response_outbox = Join-Path $roundOutbox "response.md"
        done_outbox = Join-Path $roundOutbox "DONE.json"
        imports_root = $importsRoot
        import_round = $importRound
        imported_response = Join-Path $importRound "response.md"
        imported_done = Join-Path $importRound "DONE.json"
        import_evidence = Join-Path $importRound "IMPORT_EVIDENCE.json"
        import_evidence_sidecar = Join-Path $importRound (
            "IMPORT_EVIDENCE.json.sha256"
        )
    }
}

function Get-AgentRoundObservation {
    param(
        [Parameter(Mandatory = $true)][string]$ResponsePath,
        [Parameter(Mandatory = $true)][string]$DonePath
    )

    try {
        $responseBefore = Get-Item -LiteralPath $ResponsePath -Force
        $doneBefore = Get-Item -LiteralPath $DonePath -Force
        $responseSha = Get-Sha256 -Path $ResponsePath
        $doneSha = Get-Sha256 -Path $DonePath
        $responseAfter = Get-Item -LiteralPath $ResponsePath -Force
        $doneAfter = Get-Item -LiteralPath $DonePath -Force
    }
    catch [IO.IOException] {
        return $null
    }
    if ([long]$responseBefore.Length -ne [long]$responseAfter.Length -or
        [long]$doneBefore.Length -ne [long]$doneAfter.Length) {
        return $null
    }
    return [ordered]@{
        response_sha256 = $responseSha
        response_bytes = [long]$responseAfter.Length
        done_sha256 = $doneSha
        done_bytes = [long]$doneAfter.Length
    }
}

function Test-AgentRoundObservationEqual {
    param(
        $Left,
        $Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    return (
        [string]$Left.response_sha256 -eq
            [string]$Right.response_sha256 -and
        [long]$Left.response_bytes -eq [long]$Right.response_bytes -and
        [string]$Left.done_sha256 -eq [string]$Right.done_sha256 -and
        [long]$Left.done_bytes -eq [long]$Right.done_bytes
    )
}

function Get-AgentRoundOutboxEntry {
    param(
        [Parameter(Mandatory = $true)]$State,
        [ValidateSet("R1", "R2")][string]$Round
    )

    $taskOutbox = Join-Path $script:AgentOutboxRoot ([string]$State.task_id)
    if (-not (Test-Path -LiteralPath $taskOutbox -PathType Container)) {
        return $null
    }
    $matches = @(
        Get-ChildItem -LiteralPath $taskOutbox -Force |
        Where-Object {
            $_.Name.Equals($Round, [StringComparison]::OrdinalIgnoreCase)
        }
    )
    if ($matches.Count -gt 1) {
        throw "Multiple case-equivalent Antigravity $Round outbox entries exist."
    }
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    return $null
}

function Quarantine-LateAgentRound {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round
    )

    $paths = Get-AgentOutboxRoundPaths -TaskId ([string]$State.task_id) `
        -TaskRoot $TaskRoot -Round $Round
    $sourceEntry = Get-AgentRoundOutboxEntry -State $State -Round $Round
    if ($null -eq $sourceEntry) {
        return $null
    }
    $sourcePath = $sourceEntry.FullName
    $null = Assert-CanonicalChildPath -Path $sourcePath `
        -Anchor $script:AgentOutboxRoot -MustExist
    $lateRoot = Join-Path $TaskRoot ".antigravity-late-results"
    [IO.Directory]::CreateDirectory($lateRoot) | Out-Null
    $null = Assert-CanonicalChildPath -Path $lateRoot `
        -Anchor $TaskRoot -MustExist -ExpectedType Directory
    $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $baseName = "$Round.$stamp.$suffix"
    $quarantinePath = Join-Path $lateRoot "$baseName.data"
    $moveError = ""
    $sourceIsReparse = [bool](
        $sourceEntry.Attributes -band [IO.FileAttributes]::ReparsePoint
    )
    if ($sourceIsReparse) {
        $moveError = "UNSAFE_REPARSE_NOT_MOVED"
        $quarantinePath = ""
    }
    else {
        try {
            if ($sourceEntry.PSIsContainer) {
                [IO.Directory]::Move($sourcePath, $quarantinePath)
            }
            else {
                [IO.File]::Move($sourcePath, $quarantinePath)
            }
        }
        catch {
            $moveError = $_.Exception.Message
            $quarantinePath = ""
        }
    }
    $inspectionPath = if ([string]::IsNullOrWhiteSpace($quarantinePath)) {
        $sourcePath
    }
    else {
        $quarantinePath
    }
    $entries = @()
    if (Test-Path -LiteralPath $inspectionPath -PathType Container) {
        $entries = @(
            Get-ChildItem -LiteralPath $inspectionPath -Force |
            Sort-Object Name |
            ForEach-Object {
                $isReparse = [bool](
                    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
                )
                $sha = ""
                if (-not $_.PSIsContainer -and -not $isReparse) {
                    try {
                        $sha = Get-Sha256 -Path $_.FullName
                    }
                    catch {
                        $sha = "UNREADABLE"
                    }
                }
                [ordered]@{
                    name = $_.Name
                    is_directory = [bool]$_.PSIsContainer
                    is_reparse = $isReparse
                    bytes = if ($_.PSIsContainer) {
                        $null
                    }
                    else {
                        [long]$_.Length
                    }
                    sha256 = $sha
                }
            }
        )
    }
    elseif (Test-Path -LiteralPath $inspectionPath -PathType Leaf) {
        $item = Get-Item -LiteralPath $inspectionPath -Force
        $isReparse = [bool](
            $item.Attributes -band [IO.FileAttributes]::ReparsePoint
        )
        $entries = @(
            [ordered]@{
                name = $item.Name
                is_directory = $false
                is_reparse = $isReparse
                bytes = [long]$item.Length
                sha256 = if ($isReparse) {
                    ""
                }
                else {
                    Get-Sha256 -Path $item.FullName
                }
            }
        )
    }
    $evidencePath = Join-Path $lateRoot "$baseName.evidence.json"
    Write-JsonImmutable -Path $evidencePath -Value ([ordered]@{
        schema_version = 1
        task_id = [string]$State.task_id
        round = $Round
        source_round_path = $sourcePath
        quarantine_path = $quarantinePath
        move_error = $moveError
        entries = $entries
        observed_at = [DateTime]::UtcNow.ToString("o")
    })
    $evidenceSha = Get-Sha256 -Path $evidencePath
    Write-TextImmutable -Path "$evidencePath.sha256" -Content (
        "$evidenceSha  $([IO.Path]::GetFileName($evidencePath))`n"
    )
    return [pscustomobject]@{
        path = $evidencePath
        sha256 = $evidenceSha
        quarantine_path = $quarantinePath
    }
}

function Register-AcceptedAgentRound {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round,
        [Parameter(Mandatory = $true)][string]$FinalResponsePath,
        [Parameter(Mandatory = $true)][string]$FinalDonePath,
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$Observation
    )

    $sealRoot = Join-Path $TaskRoot ".antigravity-seals"
    [IO.Directory]::CreateDirectory($sealRoot) | Out-Null
    $null = Assert-CanonicalChildPath -Path $sealRoot `
        -Anchor $TaskRoot -MustExist -ExpectedType Directory
    $sealPath = Join-Path $sealRoot "$Round.json"
    $sealSidecar = "$sealPath.sha256"
    $sealValue = [ordered]@{
        schema_version = 1
        task_id = [string]$State.task_id
        round = $Round
        canonical_response_path = [IO.Path]::GetFullPath($FinalResponsePath)
        canonical_response_sha256 = Get-Sha256 -Path $FinalResponsePath
        canonical_done_path = [IO.Path]::GetFullPath($FinalDonePath)
        canonical_done_sha256 = Get-Sha256 -Path $FinalDonePath
        imported_round_path = [IO.Path]::GetFullPath($Paths.import_round)
        import_evidence_path = [IO.Path]::GetFullPath(
            $Paths.import_evidence
        )
        import_evidence_sha256 = Get-Sha256 -Path $Paths.import_evidence
        broker_observation = $Observation
        quiescence_seconds = $AgentOutboxQuiescenceSeconds
    }
    if (Test-Path -LiteralPath $sealPath -PathType Leaf) {
        $existing = Get-Content -LiteralPath $sealPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        foreach ($name in @(
            "schema_version",
            "task_id",
            "round",
            "canonical_response_path",
            "canonical_response_sha256",
            "canonical_done_path",
            "canonical_done_sha256",
            "imported_round_path",
            "import_evidence_path",
            "import_evidence_sha256",
            "quiescence_seconds"
        )) {
            if ([string]$existing.$name -ne [string]$sealValue[$name]) {
                throw "Existing accepted-round seal mismatch for $Round."
            }
        }
    }
    else {
        Write-JsonImmutable -Path $sealPath -Value $sealValue
    }
    $sealSha = Get-Sha256 -Path $sealPath
    if (Test-Path -LiteralPath $sealSidecar -PathType Leaf) {
        $recordedSha = (
            Get-Content -LiteralPath $sealSidecar -Raw -Encoding UTF8
        ).Trim().Split(" ")[0]
        if ($recordedSha -ne $sealSha) {
            throw "Accepted-round seal sidecar mismatch for $Round."
        }
    }
    else {
        Write-TextImmutable -Path $sealSidecar -Content (
            "$sealSha  $([IO.Path]::GetFileName($sealPath))`n"
        )
    }
    $State.accepted_antigravity_rounds.$Round = [ordered]@{
        seal_path = $sealPath
        seal_sha256 = $sealSha
    }
}

function Assert-AcceptedAgentRoundSeals {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot
    )

    foreach ($round in @("R1", "R2")) {
        $accepted = $State.accepted_antigravity_rounds.$round
        if ($null -eq $accepted) {
            continue
        }
        $paths = Get-AgentOutboxRoundPaths `
            -TaskId ([string]$State.task_id) -TaskRoot $TaskRoot -Round $round
        if ($null -ne (Get-AgentRoundOutboxEntry `
            -State $State -Round $round)) {
            $late = Quarantine-LateAgentRound -State $State `
                -TaskRoot $TaskRoot -Round $round
            throw (
                "Accepted Antigravity $round writable outbox reappeared; " +
                "late result evidence=$($late.path)"
            )
        }
        $expectedSealPath = Join-Path (
            Join-Path $TaskRoot ".antigravity-seals"
        ) "$round.json"
        if (-not [IO.Path]::GetFullPath(
            [string]$accepted.seal_path
        ).Equals(
            [IO.Path]::GetFullPath($expectedSealPath),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Accepted-round seal path mismatch for $round."
        }
        $null = Assert-CanonicalChildPath -Path $expectedSealPath `
            -Anchor $TaskRoot -MustExist -ExpectedType File
        $actualSealSha = Get-Sha256 -Path $expectedSealPath
        if ($actualSealSha -ne [string]$accepted.seal_sha256) {
            throw "Accepted-round seal SHA mismatch for $round."
        }
        $sidecarSha = (
            Get-Content -LiteralPath "$expectedSealPath.sha256" -Raw `
                -Encoding UTF8
        ).Trim().Split(" ")[0]
        if ($sidecarSha -ne $actualSealSha) {
            throw "Accepted-round seal sidecar mismatch for $round."
        }
        $seal = Get-Content -LiteralPath $expectedSealPath -Raw `
            -Encoding UTF8 | ConvertFrom-Json
        if ([string]$seal.task_id -ne [string]$State.task_id -or
            [string]$seal.round -ne $round) {
            throw "Accepted-round seal identity mismatch for $round."
        }
        $expectedCanonicalResponse = Join-Path $TaskRoot (
            "${round}_ANTIGRAVITY.md"
        )
        $expectedCanonicalDone = Join-Path $TaskRoot (
            "${round}_ANTIGRAVITY.DONE.json"
        )
        foreach ($pathBinding in @(
            @("canonical_response_path", $expectedCanonicalResponse),
            @("canonical_done_path", $expectedCanonicalDone),
            @("imported_round_path", $paths.import_round),
            @("import_evidence_path", $paths.import_evidence)
        )) {
            if (-not [IO.Path]::GetFullPath(
                [string]$seal.($pathBinding[0])
            ).Equals(
                [IO.Path]::GetFullPath([string]$pathBinding[1]),
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Accepted-round sealed path mismatch for $round."
            }
        }
        foreach ($binding in @(
            @("canonical_response_path", "canonical_response_sha256"),
            @("canonical_done_path", "canonical_done_sha256"),
            @("import_evidence_path", "import_evidence_sha256")
        )) {
            $boundPath = [string]$seal.($binding[0])
            $null = Assert-CanonicalChildPath -Path $boundPath `
                -Anchor $TaskRoot -MustExist -ExpectedType File
            if ((Get-Sha256 -Path $boundPath) -ne
                [string]$seal.($binding[1])) {
                throw "Accepted-round sealed artifact changed for $round."
            }
        }
        $null = Assert-CanonicalChildPath `
            -Path ([string]$seal.imported_round_path) `
            -Anchor $TaskRoot -MustExist -ExpectedType Directory
        $importEntries = @(
            Get-ChildItem -LiteralPath $paths.import_round -Force
        )
        $importNames = @(
            $importEntries | Sort-Object Name | Select-Object -ExpandProperty Name
        )
        if (@($importEntries | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        }).Count -ne 0 -or
            ($importNames -join "`n") -ne (
                @(
                    "DONE.json",
                    "IMPORT_EVIDENCE.json",
                    "IMPORT_EVIDENCE.json.sha256",
                    "response.md"
                ) -join "`n"
            )) {
            throw "Accepted-round raw import manifest changed for $round."
        }
        $importEvidence = Get-Content -LiteralPath $paths.import_evidence `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        $rawResponse = Get-Item -LiteralPath $paths.imported_response -Force
        $rawDone = Get-Item -LiteralPath $paths.imported_done -Force
        if ([int]$importEvidence.schema_version -ne 2 -or
            [string]$importEvidence.task_id -ne [string]$State.task_id -or
            [string]$importEvidence.round -ne $round -or
            [string]$importEvidence.response_sha256 -ne (
                Get-Sha256 -Path $paths.imported_response
            ) -or
            [long]$importEvidence.response_bytes -ne
                [long]$rawResponse.Length -or
            [string]$importEvidence.done_sha256 -ne (
                Get-Sha256 -Path $paths.imported_done
            ) -or
            [long]$importEvidence.done_bytes -ne [long]$rawDone.Length) {
            throw "Accepted-round raw import evidence changed for $round."
        }
        $importSidecarSha = (
            Get-Content -LiteralPath $paths.import_evidence_sidecar -Raw `
                -Encoding UTF8
        ).Trim().Split(" ")[0]
        if ($importSidecarSha -ne (
            Get-Sha256 -Path $paths.import_evidence
        )) {
            throw "Accepted-round import sidecar changed for $round."
        }
    }
}

function Register-PairCandidateSeal {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string]$CandidateDonePath
    )

    if ($null -eq $State.accepted_antigravity_rounds.R1 -or
        $null -eq $State.accepted_antigravity_rounds.R2) {
        throw "Both Antigravity round seals are required for candidate sealing."
    }
    $artifactPaths = @(
        (Join-Path $TaskRoot "R1_CODEX.md"),
        (Join-Path $TaskRoot "R1_CODEX.DONE.json"),
        $CandidatePath,
        $CandidateDonePath
    )
    $artifacts = @(
        $artifactPaths | ForEach-Object {
            $null = Assert-CanonicalChildPath -Path $_ -Anchor $TaskRoot `
                -MustExist -ExpectedType File
            [ordered]@{
                path = [IO.Path]::GetFullPath($_)
                sha256 = Get-Sha256 -Path $_
            }
        }
    )
    $sealPath = Join-Path $TaskRoot "PAIR_CANDIDATE_SEAL.json"
    $sealSidecar = "$sealPath.sha256"
    $sealValue = [ordered]@{
        schema_version = 1
        task_id = [string]$State.task_id
        artifacts = $artifacts
        antigravity_r1_seal_sha256 = (
            [string]$State.accepted_antigravity_rounds.R1.seal_sha256
        )
        antigravity_r2_seal_sha256 = (
            [string]$State.accepted_antigravity_rounds.R2.seal_sha256
        )
        brief_sha256 = [string]$State.brief_sha256
        target_snapshot_sha256 = [string]$State.target_snapshot_sha256
        target_snapshot_fingerprint = (
            [string]$State.target.snapshot_fingerprint
        )
    }
    if (Test-Path -LiteralPath $sealPath -PathType Leaf) {
        $existingText = Get-Content -LiteralPath $sealPath -Raw -Encoding UTF8
        $expectedText = $sealValue | ConvertTo-Json -Depth 30
        if ((Get-TextSha256 -Text $existingText) -ne
            (Get-TextSha256 -Text $expectedText)) {
            throw "Existing pair candidate seal does not match."
        }
    }
    else {
        Write-JsonImmutable -Path $sealPath -Value $sealValue
    }
    $sealSha = Get-Sha256 -Path $sealPath
    if (Test-Path -LiteralPath $sealSidecar -PathType Leaf) {
        $recordedSha = (
            Get-Content -LiteralPath $sealSidecar -Raw -Encoding UTF8
        ).Trim().Split(" ")[0]
        if ($recordedSha -ne $sealSha) {
            throw "Pair candidate seal sidecar mismatch."
        }
    }
    else {
        Write-TextImmutable -Path $sealSidecar -Content (
            "$sealSha  PAIR_CANDIDATE_SEAL.json`n"
        )
    }
    $State.candidate_seal = [ordered]@{
        path = $sealPath
        sha256 = $sealSha
    }
}

function Assert-PairCandidateSeal {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot
    )

    if ($null -eq $State.candidate_seal) {
        throw "PAIR_CANDIDATE is missing its immutable seal."
    }
    $expectedSealPath = Join-Path $TaskRoot "PAIR_CANDIDATE_SEAL.json"
    if (-not [IO.Path]::GetFullPath(
        [string]$State.candidate_seal.path
    ).Equals(
        [IO.Path]::GetFullPath($expectedSealPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Pair candidate seal path mismatch."
    }
    $null = Assert-CanonicalChildPath -Path $expectedSealPath `
        -Anchor $TaskRoot -MustExist -ExpectedType File
    $sealSha = Get-Sha256 -Path $expectedSealPath
    if ($sealSha -ne [string]$State.candidate_seal.sha256) {
        throw "Pair candidate seal SHA mismatch."
    }
    $sidecarSha = (
        Get-Content -LiteralPath "$expectedSealPath.sha256" -Raw `
            -Encoding UTF8
    ).Trim().Split(" ")[0]
    if ($sidecarSha -ne $sealSha) {
        throw "Pair candidate seal sidecar mismatch."
    }
    $seal = Get-Content -LiteralPath $expectedSealPath -Raw `
        -Encoding UTF8 | ConvertFrom-Json
    if ([int]$seal.schema_version -ne 1 -or
        [string]$seal.task_id -ne [string]$State.task_id -or
        [string]$seal.antigravity_r1_seal_sha256 -ne
            [string]$State.accepted_antigravity_rounds.R1.seal_sha256 -or
        [string]$seal.antigravity_r2_seal_sha256 -ne
            [string]$State.accepted_antigravity_rounds.R2.seal_sha256 -or
        [string]$seal.brief_sha256 -ne [string]$State.brief_sha256 -or
        [string]$seal.target_snapshot_sha256 -ne
            [string]$State.target_snapshot_sha256 -or
        [string]$seal.target_snapshot_fingerprint -ne
            [string]$State.target.snapshot_fingerprint) {
        throw "Pair candidate seal provenance mismatch."
    }
    foreach ($provenanceBinding in @(
        @(
            [string]$State.brief_path,
            [string]$seal.brief_sha256,
            (Join-Path $TaskRoot "BRIEF.md")
        ),
        @(
            [string]$State.target_snapshot_path,
            [string]$seal.target_snapshot_sha256,
            (Join-Path $TaskRoot "TARGET_SNAPSHOT.json")
        )
    )) {
        if (-not [IO.Path]::GetFullPath(
            [string]$provenanceBinding[0]
        ).Equals(
            [IO.Path]::GetFullPath([string]$provenanceBinding[2]),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Pair candidate provenance path mismatch."
        }
        $null = Assert-CanonicalChildPath `
            -Path ([string]$provenanceBinding[0]) -Anchor $TaskRoot `
            -MustExist -ExpectedType File
        if ((Get-Sha256 -Path ([string]$provenanceBinding[0])) -ne
            [string]$provenanceBinding[1]) {
            throw "Pair candidate provenance artifact changed."
        }
    }
    $expectedArtifacts = @(
        (Join-Path $TaskRoot "R1_CODEX.md"),
        (Join-Path $TaskRoot "R1_CODEX.DONE.json"),
        (Join-Path $TaskRoot "PAIR_CANDIDATE.md"),
        (Join-Path $TaskRoot "PAIR_CANDIDATE.DONE.json")
    )
    if (@($seal.artifacts).Count -ne $expectedArtifacts.Count) {
        throw "Pair candidate seal artifact count mismatch."
    }
    for ($index = 0; $index -lt $expectedArtifacts.Count; $index++) {
        $expectedPath = [IO.Path]::GetFullPath($expectedArtifacts[$index])
        $binding = @($seal.artifacts)[$index]
        if (-not [IO.Path]::GetFullPath(
            [string]$binding.path
        ).Equals(
            $expectedPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Pair candidate sealed artifact path mismatch."
        }
        $null = Assert-CanonicalChildPath -Path $expectedPath `
            -Anchor $TaskRoot -MustExist -ExpectedType File
        if ((Get-Sha256 -Path $expectedPath) -ne [string]$binding.sha256) {
            throw "Pair candidate sealed artifact changed."
        }
    }
}

function Initialize-AgentOutboxRound {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round
    )

    $paths = Get-AgentOutboxRoundPaths -TaskId ([string]$State.task_id) `
        -TaskRoot $TaskRoot -Round $Round
    $null = Assert-CanonicalChildPath -Path $script:AgentOutboxRoot `
        -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType Directory
    if ($Round -eq "R1" -and
        (Test-Path -LiteralPath $paths.task_outbox)) {
        throw "Antigravity task outbox already exists: $($paths.task_outbox)"
    }
    if ($Round -eq "R2" -and
        -not (Test-Path -LiteralPath $paths.task_outbox -PathType Container)) {
        throw "Antigravity task outbox is missing before R2."
    }
    if ((Test-Path -LiteralPath $paths.round_outbox) -or
        (Test-Path -LiteralPath $paths.import_round)) {
        throw "Antigravity round outbox/import collision: $Round"
    }
    [IO.Directory]::CreateDirectory($paths.round_outbox) | Out-Null
    $null = Assert-CanonicalChildPath -Path $paths.round_outbox `
        -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType Directory
    return $paths
}

function Get-ImportedAgentEnvelope {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round,
        [Parameter(Mandatory = $true)][string]$FinalResponsePath,
        [Parameter(Mandatory = $true)][string]$FinalDonePath
    )

    $taskId = [string]$State.task_id
    $paths = Get-AgentOutboxRoundPaths -TaskId $taskId `
        -TaskRoot $TaskRoot -Round $Round
    $outboxExists = Test-Path -LiteralPath $paths.round_outbox
    $importExists = Test-Path -LiteralPath $paths.import_round
    if ($outboxExists -and $importExists) {
        $late = Quarantine-LateAgentRound -State $State `
            -TaskRoot $TaskRoot -Round $Round
        throw (
            "Both writable outbox and broker import exist for $Round; " +
            "late result evidence=$($late.path)"
        )
    }
    $stableObservation = $State.pending_antigravity.stability_observation
    if (-not $importExists) {
        if (-not $outboxExists) {
            return $null
        }
        $responseExists = Test-Path -LiteralPath $paths.response_outbox `
            -PathType Leaf
        $doneExists = Test-Path -LiteralPath $paths.done_outbox -PathType Leaf
        if (-not $doneExists) {
            return $null
        }
        if (-not $responseExists) {
            throw "Antigravity DONE exists without its response for $Round."
        }
        $null = Assert-CanonicalChildPath -Path $paths.round_outbox `
            -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType Directory
        $null = Assert-CanonicalChildPath -Path $paths.response_outbox `
            -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType File
        $null = Assert-CanonicalChildPath -Path $paths.done_outbox `
            -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType File
        $entries = @(
            Get-ChildItem -LiteralPath $paths.round_outbox -Force
        )
        if ($entries.Count -ne 2 -or
            @($entries | Where-Object { -not $_.PSIsContainer }).Count -ne 2) {
            throw "Antigravity outbox must contain exactly response.md and DONE.json."
        }
        $currentObservation = Get-AgentRoundObservation `
            -ResponsePath $paths.response_outbox -DonePath $paths.done_outbox
        if ($null -eq $currentObservation) {
            return $null
        }
        if ([long]$currentObservation.response_bytes -le 0 -or
            [long]$currentObservation.response_bytes -gt
                $script:MaxAgentResponseBytes -or
            [long]$currentObservation.done_bytes -le 0 -or
            [long]$currentObservation.done_bytes -gt
                $script:MaxAgentDoneBytes) {
            throw "Antigravity outbox size is outside the allowed range."
        }
        $priorObservation = (
            $State.pending_antigravity.stability_observation
        )
        $now = [DateTime]::UtcNow
        if (-not (Test-AgentRoundObservationEqual `
            -Left $priorObservation -Right $currentObservation)) {
            $currentObservation["first_observed_at"] = $now.ToString("o")
            $currentObservation["last_observed_at"] = $now.ToString("o")
            $currentObservation["matching_reconcile_count"] = 1
            $currentObservation["first_observed_state_version"] = (
                [int]$State.state_version
            )
            $State.pending_antigravity.stability_observation = (
                $currentObservation
            )
            Set-State -StatePath $StatePath -State $State `
                -Phase ([string]$State.phase)
            return $null
        }
        $observedAt = [DateTime]::MinValue
        if (-not [DateTime]::TryParse(
            [string]$priorObservation.first_observed_at,
            [ref]$observedAt
        )) {
            throw "Invalid broker observation timestamp for $Round."
        }
        $priorObservation.matching_reconcile_count = (
            [int]$priorObservation.matching_reconcile_count + 1
        )
        $priorObservation.last_observed_at = $now.ToString("o")
        $State.pending_antigravity.stability_observation = $priorObservation
        Set-State -StatePath $StatePath -State $State `
            -Phase ([string]$State.phase)
        $stableObservation = $priorObservation
        if ([int]$stableObservation.matching_reconcile_count -lt 2 -or
            ($now - $observedAt.ToUniversalTime()).TotalSeconds -lt
                $AgentOutboxQuiescenceSeconds) {
            return $null
        }
        [IO.Directory]::CreateDirectory($paths.imports_root) | Out-Null
        $null = Assert-CanonicalChildPath -Path $paths.imports_root `
            -Anchor $TaskRoot -MustExist -ExpectedType Directory
        [IO.Directory]::Move($paths.round_outbox, $paths.import_round)
    }

    $null = Assert-CanonicalChildPath -Path $paths.import_round `
        -Anchor $TaskRoot -MustExist -ExpectedType Directory
    $null = Assert-CanonicalChildPath -Path $paths.imported_response `
        -Anchor $TaskRoot -MustExist -ExpectedType File
    $null = Assert-CanonicalChildPath -Path $paths.imported_done `
        -Anchor $TaskRoot -MustExist -ExpectedType File
    $hasImportEvidence = Test-Path -LiteralPath $paths.import_evidence `
        -PathType Leaf
    $hasImportEvidenceSidecar = Test-Path `
        -LiteralPath $paths.import_evidence_sidecar -PathType Leaf
    $expectedImportNames = if ($hasImportEvidence) {
        if ($hasImportEvidenceSidecar) {
            @(
                "DONE.json",
                "IMPORT_EVIDENCE.json",
                "IMPORT_EVIDENCE.json.sha256",
                "response.md"
            )
        }
        else {
            @("DONE.json", "IMPORT_EVIDENCE.json", "response.md")
        }
    }
    else {
        @("DONE.json", "response.md")
    }
    $importEntries = @(
        Get-ChildItem -LiteralPath $paths.import_round -Force
    )
    $actualImportNames = @(
        $importEntries | Sort-Object Name | Select-Object -ExpandProperty Name
    )
    if (@($importEntries | Where-Object {
        $_.PSIsContainer -or
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }).Count -ne 0 -or
        ($actualImportNames -join "`n") -ne (
            @($expectedImportNames | Sort-Object) -join "`n"
        )) {
        throw (
            "Broker quarantine must contain only the exact expected regular " +
            "files for $Round."
        )
    }
    $responseItem = Get-Item -LiteralPath $paths.imported_response -Force
    $doneItem = Get-Item -LiteralPath $paths.imported_done -Force
    if ($responseItem.Length -le 0 -or
        $responseItem.Length -gt $script:MaxAgentResponseBytes) {
        throw "Antigravity response size is outside the allowed range."
    }
    if ($doneItem.Length -le 0 -or
        $doneItem.Length -gt $script:MaxAgentDoneBytes) {
        throw "Antigravity DONE size is outside the allowed range."
    }
    if ($null -ne $stableObservation) {
        $importedObservation = Get-AgentRoundObservation `
            -ResponsePath $paths.imported_response `
            -DonePath $paths.imported_done
        if (-not (Test-AgentRoundObservationEqual `
            -Left $stableObservation -Right $importedObservation)) {
            throw "Antigravity outbox changed during broker quarantine for $Round."
        }
    }
    $envelope = Test-AgentArtifact `
        -ResponsePath $paths.imported_response `
        -DonePath $paths.imported_done `
        -ExpectedArtifactPath $paths.response_outbox `
        -ExpectedAgent "antigravity" -ExpectedTaskId $taskId
    $rawDone = Get-Content -LiteralPath $paths.imported_done -Raw `
        -Encoding UTF8 | ConvertFrom-Json
    $responseSha = [string]$rawDone.sha256
    $doneSha = Get-Sha256 -Path $paths.imported_done

    if (-not (Test-Path -LiteralPath $paths.import_evidence)) {
        Write-JsonImmutable -Path $paths.import_evidence -Value ([ordered]@{
            schema_version = 2
            task_id = $taskId
            round = $Round
            source_round_path = $paths.round_outbox
            imported_round_path = $paths.import_round
            quarantined_entries = @("DONE.json", "response.md")
            response_sha256 = $responseSha
            response_bytes = [long]$responseItem.Length
            done_sha256 = $doneSha
            done_bytes = [long]$doneItem.Length
            broker_observation = $stableObservation
            quiescence_seconds = $AgentOutboxQuiescenceSeconds
            imported_at = [DateTime]::UtcNow.ToString("o")
        })
        $importEvidenceSha = Get-Sha256 -Path $paths.import_evidence
        Write-TextImmutable -Path $paths.import_evidence_sidecar -Content (
            "$importEvidenceSha  IMPORT_EVIDENCE.json`n"
        )
    }
    else {
        $importEvidence = Get-Content -LiteralPath $paths.import_evidence `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int]$importEvidence.schema_version -ne 2 -or
            [string]$importEvidence.task_id -ne $taskId -or
            [string]$importEvidence.round -ne $Round -or
            (@($importEvidence.quarantined_entries) -join "`n") -ne (
                @("DONE.json", "response.md") -join "`n"
            ) -or
            [string]$importEvidence.response_sha256 -ne $responseSha -or
            [long]$importEvidence.response_bytes -ne
                [long]$responseItem.Length -or
            [string]$importEvidence.done_sha256 -ne $doneSha -or
            [long]$importEvidence.done_bytes -ne [long]$doneItem.Length -or
            -not (Test-AgentRoundObservationEqual `
                -Left $importEvidence.broker_observation `
                -Right $stableObservation)) {
            throw "Antigravity import evidence mismatch for $Round."
        }
        $importEvidenceSha = Get-Sha256 -Path $paths.import_evidence
        if ($hasImportEvidenceSidecar) {
            $sidecarSha = (
                Get-Content -LiteralPath $paths.import_evidence_sidecar -Raw `
                    -Encoding UTF8
            ).Trim().Split(" ")[0]
            if ($sidecarSha -ne $importEvidenceSha) {
                throw "Antigravity import evidence sidecar mismatch for $Round."
            }
        }
        else {
            Write-TextImmutable -Path $paths.import_evidence_sidecar -Content (
                "$importEvidenceSha  IMPORT_EVIDENCE.json`n"
            )
        }
    }

    $expectedPhase = if ($Round -eq "R1") {
        "WAIT_ANTIGRAVITY_R1"
    }
    else {
        "WAIT_ANTIGRAVITY_R2"
    }
    if ([string]$State.phase -ne $expectedPhase) {
        throw "Antigravity result acceptance phase mismatch for $Round."
    }
    $stopRequest = Get-StopRequest -TaskRoot $TaskRoot -TaskId $taskId
    if ($stopRequest) {
        throw "Antigravity result acceptance revoked by manual stop: $($stopRequest.reason)"
    }
    if (Test-WaitExpired -State $State) {
        throw "Antigravity result acceptance window expired for $Round."
    }
    $null = Copy-ArtifactImmutable -Source $paths.imported_response `
        -Destination $FinalResponsePath -ExpectedSha256 $responseSha
    New-DoneSentinel -Path $FinalDonePath -TaskId $taskId `
        -Agent "antigravity" -ArtifactPath $FinalResponsePath
    Register-AcceptedAgentRound -State $State -TaskRoot $TaskRoot `
        -Round $Round -FinalResponsePath $FinalResponsePath `
        -FinalDonePath $FinalDonePath -Paths $paths `
        -Observation $stableObservation
    return $envelope
}

function Ensure-PromptArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ($existing -ne $Content) {
            throw "Refusing to overwrite a different prompt artifact: $Path"
        }
        return
    }
    Write-TextImmutable -Path $Path -Content $Content
}

function Read-StrictAgentEnvelope {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$ExpectedAgent,
        [Parameter(Mandatory = $true)][string]$ExpectedTaskId
    )

    $lines = @($Text -split "\r?\n")
    $nonBlank = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($nonBlank.Count -lt 4) {
        throw "Agent response is missing the four-line front matter."
    }
    $names = @("agent", "task_id", "recommendation", "hard_stop")
    $values = [ordered]@{}
    for ($index = 0; $index -lt $names.Count; $index++) {
        $name = $names[$index]
        $match = [regex]::Match(
            [string]$nonBlank[$index],
            "^\s*" + [regex]::Escape($name) + "\s*:\s*(\S(?:.*\S)?)\s*$"
        )
        if (-not $match.Success) {
            throw "Front matter line $($index + 1) must be '${name}: ...'."
        }
        $values[$name] = $match.Groups[1].Value.Trim()
    }
    if ([string]$values.agent -ne $ExpectedAgent) {
        throw "Agent response identity mismatch: $($values.agent)"
    }
    if ([string]$values.task_id -ne $ExpectedTaskId) {
        throw "Agent response task ID mismatch: $($values.task_id)"
    }
    if ([string]$values.recommendation -notin @(
        "PROCEED",
        "REVISE",
        "STOP"
    )) {
        throw "Invalid agent recommendation: $($values.recommendation)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$values.hard_stop) -or
        ([string]$values.hard_stop).Length -gt 256) {
        throw "Invalid hard_stop value."
    }
    return [pscustomobject]$values
}

function Resolve-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Pinned $Label does not exist: $resolved"
    }
    if ([string]::IsNullOrWhiteSpace($Sha256)) {
        throw "$Label SHA-256 pin is required."
    }
    $actual = Get-Sha256 -Path $resolved
    if ($actual -ne $Sha256.ToLower()) {
        throw "Pinned $Label SHA-256 mismatch: $resolved"
    }
    return $resolved
}

function Resolve-LanguageServer {
    return Resolve-PinnedFile -Path $LanguageServerPath `
        -Sha256 $LanguageServerSha256 -Label "Antigravity language server"
}

function Resolve-Git {
    return Resolve-PinnedFile -Path $GitPath -Sha256 $GitSha256 `
        -Label "Git runtime"
}

function Resolve-Runner {
    return Resolve-PinnedFile -Path $RunnerPath -Sha256 $RunnerSha256 `
        -Label "pair process runner"
}

function Resolve-Codex {
    $resolved = ""
    if (-not [string]::IsNullOrWhiteSpace($CodexPath)) {
        $resolved = [IO.Path]::GetFullPath($CodexPath)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:CODEX_PAIR_EXECUTABLE)) {
        $resolved = [IO.Path]::GetFullPath($env:CODEX_PAIR_EXECUTABLE)
    }
    else {
        throw "CodexPath or CODEX_PAIR_EXECUTABLE must be explicitly pinned."
    }
    return Resolve-PinnedFile -Path $resolved -Sha256 $CodexSha256 `
        -Label "Codex runtime"
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
            throw "Pinned Git changed before target snapshot verification."
        }
        $headOutput = @(
            & $script:ResolvedGit -C $resolved rev-parse HEAD 2>$null
        )
        if ($LASTEXITCODE -ne 0 -or $headOutput.Count -eq 0) {
            throw "Pair targets must be Git workspaces: $resolved"
        }
        $head = ([string]$headOutput[-1]).Trim().ToLower()

    $topOutput = @(
        & $script:ResolvedGit -C $resolved rev-parse --show-toplevel 2>$null
    )
    if ($LASTEXITCODE -ne 0 -or $topOutput.Count -eq 0) {
        throw "Unable to resolve Git root: $resolved"
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
        throw "git status failed: $resolved"
    }
    $statusLines = @($statusOutput | ForEach-Object { [string]$_ })
    $statusSha = Get-TextSha256 -Text ($statusLines -join "`n")

    $diffOutput = @(
        & $script:ResolvedGit -C $resolved -c core.quotePath=false diff `
            --binary HEAD -- 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw "git diff failed: $resolved"
    }
    $diffSha = Get-TextSha256 -Text (
        (@($diffOutput | ForEach-Object { [string]$_ })) -join "`n"
    )

    $untrackedOutput = @(
        & $script:ResolvedGit -C $resolved -c core.quotePath=false ls-files `
            --others --exclude-standard 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw "git untracked-file listing failed: $resolved"
    }
    $rootPrefix = $resolved + [IO.Path]::DirectorySeparatorChar
    $manifest = @()
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
        $manifest += [ordered]@{
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
    $manifestJson = ConvertTo-Json -InputObject @($manifest) `
        -Compress -Depth 8
    $manifestSha = Get-TextSha256 -Text $manifestJson
    $fingerprint = Get-TextSha256 -Text (
        @($resolved.ToLower(), $head, $statusSha, $diffSha, $manifestSha) `
            -join "`n"
    )
        return [ordered]@{
            path = $resolved
            is_git = $true
            base_commit = $head
            dirty_count = $statusLines.Count
            status_lines = $statusLines
            status_sha256 = $statusSha
            tracked_diff_sha256 = $diffSha
            untracked_manifest = @($manifest)
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

function Assert-TargetUnchanged {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot
    )

    $target = [IO.Path]::GetFullPath([string]$State.target.path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $allowed = $false
    foreach ($root in $script:AllowedTargetRoots) {
        if ($target.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
            $allowed = $true
            break
        }
    }
    if (-not $allowed) {
        throw "Target workspace is not allowlisted: $target"
    }

    $snapshotPath = [IO.Path]::GetFullPath(
        [string]$State.target_snapshot_path
    )
    $expectedSnapshotPath = Join-Path $TaskRoot "TARGET_SNAPSHOT.json"
    if (-not $snapshotPath.Equals(
        [IO.Path]::GetFullPath($expectedSnapshotPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Target snapshot path is outside its task envelope."
    }
    if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) {
        throw "Target snapshot is missing: $snapshotPath"
    }
    if ((Get-Sha256 -Path $snapshotPath) -ne
        [string]$State.target_snapshot_sha256) {
        throw "Immutable target snapshot SHA mismatch."
    }
    if ((Get-Sha256 -Path ([string]$State.brief_path)) -ne
        [string]$State.brief_sha256) {
        throw "Immutable pair brief SHA mismatch."
    }
    if ([string]$State.target.git_path -ne $script:ResolvedGit -or
        [string]$State.target.git_sha256 -ne $GitSha256.ToLower()) {
        throw "Task Git pin does not match the broker Git pin."
    }
    $current = Get-TargetSnapshot -Path $target
    if ([string]$current.snapshot_fingerprint -ne
        [string]$State.target.snapshot_fingerprint) {
        throw (
            "Target snapshot changed. expected=" +
            [string]$State.target.snapshot_fingerprint +
            " actual=" + [string]$current.snapshot_fingerprint +
            " status=" + [string]$current.status_sha256 +
            " diff=" + [string]$current.tracked_diff_sha256 +
            " untracked=" + [string]$current.untracked_manifest_sha256
        )
    }
}

function Get-ConversationId {
    param([Parameter(Mandatory = $true)][string]$JsonText)

    try {
        $parsed = $JsonText | ConvertFrom-Json
        $queue = New-Object Collections.Queue
        $queue.Enqueue($parsed)
        while ($queue.Count -gt 0) {
            $node = $queue.Dequeue()
            if ($null -eq $node) {
                continue
            }
            foreach ($property in @($node.PSObject.Properties)) {
                if ($property.Name -match '^(conversationId|recipientId)$' -and
                    [string]$property.Value -match (
                        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-' +
                        '[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                    )) {
                    return [string]$property.Value
                }
                if ($property.Value -is [Collections.IEnumerable] -and
                    -not ($property.Value -is [string])) {
                    foreach ($child in @($property.Value)) {
                        $queue.Enqueue($child)
                    }
                }
                elseif ($property.Value -is [psobject] -and
                    -not ($property.Value -is [string])) {
                    $queue.Enqueue($property.Value)
                }
            }
        }
    }
    catch {
        return ""
    }
    return ""
}

function Test-AgentArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$ResponsePath,
        [Parameter(Mandatory = $true)][string]$DonePath,
        [string]$ExpectedArtifactPath = "",
        [Parameter(Mandatory = $true)][string]$ExpectedAgent,
        [Parameter(Mandatory = $true)][string]$ExpectedTaskId
    )

    if (-not (Test-Path -LiteralPath $ResponsePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $DonePath -PathType Leaf)) {
        return $false
    }
    $text = Get-Content -LiteralPath $ResponsePath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Empty agent response: $ResponsePath"
    }
    $done = Get-Content -LiteralPath $DonePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([int]$done.schema_version -ne 1 -or
        [string]$done.task_id -ne $ExpectedTaskId -or
        [string]$done.agent -ne $ExpectedAgent) {
        throw "DONE sentinel identity mismatch: $DonePath"
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedArtifactPath)) {
        $ExpectedArtifactPath = $ResponsePath
    }
    if (-not [IO.Path]::GetFullPath([string]$done.artifact_path).Equals(
        [IO.Path]::GetFullPath($ExpectedArtifactPath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "DONE sentinel artifact path mismatch: $DonePath"
    }
    if ([string]$done.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "DONE sentinel SHA format is invalid: $DonePath"
    }
    $completedAt = [DateTime]::MinValue
    if (-not [DateTime]::TryParse(
        [string]$done.completed_at,
        [ref]$completedAt
    )) {
        throw "DONE sentinel timestamp is invalid: $DonePath"
    }
    $actualSha = Get-Sha256 -Path $ResponsePath
    if ([string]$done.sha256 -ne $actualSha) {
        throw "DONE sentinel SHA mismatch: $DonePath"
    }
    return Read-StrictAgentEnvelope -Text $text `
        -ExpectedAgent $ExpectedAgent -ExpectedTaskId $ExpectedTaskId
}

function Initialize-JobObjectInterop {
    if ("PairWorkbench.JobNative" -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PairWorkbench {
    public static class JobNative {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_COUNTERS {
            public UInt64 ReadOperationCount;
            public UInt64 WriteOperationCount;
            public UInt64 OtherOperationCount;
            public UInt64 ReadTransferCount;
            public UInt64 WriteTransferCount;
            public UInt64 OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public Int64 PerProcessUserTimeLimit;
            public Int64 PerJobUserTimeLimit;
            public UInt32 LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public UInt32 ActiveProcessLimit;
            public Int64 Affinity;
            public UInt32 PriorityClass;
            public UInt32 SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateJobObject(
            IntPtr lpJobAttributes,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetInformationJobObject(
            IntPtr hJob,
            int JobObjectInfoClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
            uint cbJobObjectInfoLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AssignProcessToJobObject(
            IntPtr hJob,
            IntPtr hProcess
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateJobObject(
            IntPtr hJob,
            uint uExitCode
        );

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
'@
}

function ConvertTo-WindowsArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ([regex]::Replace(
        $Value,
        '(\\*)"',
        '$1$1\"'
    ) -replace '(\\+)$', '$1$1') + '"'
}

function Get-StopRequest {
    param(
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId
    )

    $request = @(
        Get-ChildItem -LiteralPath $TaskRoot -File `
            -Filter "STOP_REQUEST.v1.*.json" -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -First 1
    )
    if ($request.Count -eq 0) {
        return $null
    }
    $payload = Get-Content -LiteralPath $request[0].FullName -Raw `
        -Encoding UTF8 | ConvertFrom-Json
    if ([int]$payload.schema_version -ne 1 -or
        [string]$payload.task_id -ne $TaskId -or
        [string]::IsNullOrWhiteSpace([string]$payload.reason)) {
        throw "Invalid stop request: $($request[0].FullName)"
    }
    return [pscustomobject]@{
        path = $request[0].FullName
        reason = [string]$payload.reason
    }
}

function Write-InvocationEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$AttemptRoot,
        [Parameter(Mandatory = $true)]$Evidence
    )

    $path = Join-Path $AttemptRoot "INVOCATION_EVIDENCE.json"
    Write-JsonImmutable -Path $path -Value $Evidence
    $sha = Get-Sha256 -Path $path
    $sidecar = "$path.sha256"
    Write-TextImmutable -Path $sidecar -Content (
        "$sha  $([IO.Path]::GetFileName($path))`n"
    )
    return [pscustomobject]@{ path = $path; sha256 = $sha }
}

function Invoke-BoundedAdapter {
    param(
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$AdapterKind,
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$ExecutableSha256,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowEmptyString()][string]$StdinText = "",
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$InvocationId
    )

    Initialize-JobObjectInterop
    if ((Get-Sha256 -Path $script:ResolvedRunner) -ne
        $RunnerSha256.ToLower()) {
        throw "Pair process runner changed before invocation."
    }
    if ((Get-Sha256 -Path $ExecutablePath) -ne
        $ExecutableSha256.ToLower()) {
        throw "Pinned $AdapterKind executable changed before invocation."
    }

    $attemptsRoot = Join-Path $TaskRoot ".attempts"
    [IO.Directory]::CreateDirectory($attemptsRoot) | Out-Null
    $attemptRoot = Join-Path $attemptsRoot $InvocationId
    if (Test-Path -LiteralPath $attemptRoot) {
        throw "Invocation attempt already exists: $InvocationId"
    }
    [IO.Directory]::CreateDirectory($attemptRoot) | Out-Null
    $gatePath = Join-Path $attemptRoot "START.gate"
    $specPath = Join-Path $attemptRoot "SPEC.json"
    $stdinPath = Join-Path $attemptRoot "STDIN.md"
    $processLogPath = Join-Path $attemptRoot "PROCESS.log"
    $resultPath = Join-Path $attemptRoot "RESULT.json"
    $responsePath = Join-Path $attemptRoot "response.ready"
    if (-not [string]::IsNullOrEmpty($StdinText)) {
        Write-TextImmutable -Path $stdinPath -Content $StdinText
    }
    else {
        $stdinPath = ""
    }
    $resolvedArguments = @(
        $Arguments | ForEach-Object {
            if ([string]$_ -eq "__PAIR_RESPONSE_PATH__") {
                $responsePath
            }
            else {
                [string]$_
            }
        }
    )
    $spec = [ordered]@{
        schema_version = 1
        invocation_id = $InvocationId
        task_id = $TaskId
        stage = $Stage
        adapter_kind = $AdapterKind
        executable_path = $ExecutablePath
        executable_sha256 = $ExecutableSha256.ToLower()
        arguments = $resolvedArguments
        stdin_path = $stdinPath
        gate_path = $gatePath
        log_path = $processLogPath
        result_path = $resultPath
        response_path = $responsePath
        created_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-JsonImmutable -Path $specPath -Value $spec

    $startedAt = [DateTime]::UtcNow
    $deadline = $startedAt.AddSeconds($TimeoutSeconds)
    $job = [IntPtr]::Zero
    $process = $null
    $jobAssigned = $false
    $terminated = $false
    $outcome = "LAUNCH_FAILED"
    $runnerExitCode = 125
    $stopRequest = $null
    $launchError = ""
    try {
        $job = [PairWorkbench.JobNative]::CreateJobObject(
            [IntPtr]::Zero,
            $null
        )
        if ($job -eq [IntPtr]::Zero) {
            throw "CreateJobObject failed."
        }
        $basic = New-Object (
            "PairWorkbench.JobNative+JOBOBJECT_BASIC_LIMIT_INFORMATION"
        )
        $basic.LimitFlags = [uint32]0x2000
        $extended = New-Object (
            "PairWorkbench.JobNative+JOBOBJECT_EXTENDED_LIMIT_INFORMATION"
        )
        $extended.BasicLimitInformation = $basic
        $size = [Runtime.InteropServices.Marshal]::SizeOf($extended)
        if (-not [PairWorkbench.JobNative]::SetInformationJobObject(
            $job,
            9,
            [ref]$extended,
            [uint32]$size
        )) {
            throw "SetInformationJobObject failed."
        }

        $powerShellPath = Join-Path $PSHOME "powershell.exe"
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $powerShellPath
        $startInfo.Arguments = (
            @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $script:ResolvedRunner,
                "-SpecPath", $specPath,
                "-GatePath", $gatePath
            ) | ForEach-Object {
                ConvertTo-WindowsArgument -Value ([string]$_)
            }
        ) -join " "
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Failed to start the gated pair runner."
        }
        if (-not [PairWorkbench.JobNative]::AssignProcessToJobObject(
            $job,
            $process.Handle
        )) {
            throw "AssignProcessToJobObject failed."
        }
        $jobAssigned = $true
        Write-TextImmutable -Path $gatePath -Content "start`n"

        while (-not $process.WaitForExit(250)) {
            $stopRequest = Get-StopRequest -TaskRoot $TaskRoot -TaskId $TaskId
            if ($stopRequest) {
                $outcome = "STOP_REQUESTED"
                break
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                $outcome = "TIMED_OUT"
                break
            }
        }
        if ($outcome -eq "LAUNCH_FAILED") {
            $stopRequest = Get-StopRequest -TaskRoot $TaskRoot -TaskId $TaskId
            if ($stopRequest) {
                $outcome = "STOP_REQUESTED"
            }
        }
        if ($outcome -in @("TIMED_OUT", "STOP_REQUESTED")) {
            if (-not $process.HasExited) {
                $terminationCode = if ($outcome -eq "TIMED_OUT") {
                    [uint32]124
                }
                else {
                    [uint32]130
                }
                $terminated = [PairWorkbench.JobNative]::TerminateJobObject(
                    $job,
                    $terminationCode
                )
                $null = $process.WaitForExit(
                    $ProcessTerminationGraceSeconds * 1000
                )
                if (-not $process.HasExited) {
                    throw "Job termination did not stop the runner tree."
                }
            }
        }
        else {
            $outcome = "EXITED"
        }
        if ($process.HasExited) {
            $runnerExitCode = [int]$process.ExitCode
        }
    }
    catch {
        $launchError = $_.Exception.Message
        if ($jobAssigned -and $process -and -not $process.HasExited) {
            $terminated = [PairWorkbench.JobNative]::TerminateJobObject(
                $job,
                [uint32]125
            )
            $null = $process.WaitForExit(
                $ProcessTerminationGraceSeconds * 1000
            )
        }
    }
    finally {
        if ($job -ne [IntPtr]::Zero) {
            [PairWorkbench.JobNative]::CloseHandle($job) | Out-Null
        }
        if ($process) {
            $process.Dispose()
        }
    }

    $result = $null
    if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([string]$result.invocation_id -ne $InvocationId -or
            [string]$result.task_id -ne $TaskId -or
            [string]$result.stage -ne $Stage) {
            throw "Runner result identity mismatch for $InvocationId."
        }
    }
    $evidence = [ordered]@{
        schema_version = 1
        invocation_id = $InvocationId
        task_id = $TaskId
        stage = $Stage
        adapter_kind = $AdapterKind
        executable_path = $ExecutablePath
        executable_sha256 = $ExecutableSha256.ToLower()
        runner_path = $script:ResolvedRunner
        runner_sha256 = $RunnerSha256.ToLower()
        job_assigned = $jobAssigned
        outcome = $outcome
        terminated_job = $terminated
        runner_exit_code = $runnerExitCode
        timeout_seconds = $TimeoutSeconds
        started_at = $startedAt.ToString("o")
        deadline = $deadline.ToString("o")
        completed_at = [DateTime]::UtcNow.ToString("o")
        launch_error = $launchError
        stop_request_path = if ($stopRequest) {
            [string]$stopRequest.path
        } else {
            ""
        }
        process_spec_path = $specPath
        process_spec_sha256 = Get-Sha256 -Path $specPath
        result_path = if (Test-Path -LiteralPath $resultPath) {
            $resultPath
        } else {
            ""
        }
        result_sha256 = if (Test-Path -LiteralPath $resultPath) {
            Get-Sha256 -Path $resultPath
        } else {
            ""
        }
        process_log_path = if (Test-Path -LiteralPath $processLogPath) {
            $processLogPath
        } else {
            ""
        }
        process_log_sha256 = if (Test-Path -LiteralPath $processLogPath) {
            Get-Sha256 -Path $processLogPath
        } else {
            ""
        }
        response_path = if (Test-Path -LiteralPath $responsePath) {
            $responsePath
        } else {
            ""
        }
        response_sha256 = if (Test-Path -LiteralPath $responsePath) {
            Get-Sha256 -Path $responsePath
        } else {
            ""
        }
    }
    $invocationEvidence = Write-InvocationEvidence `
        -AttemptRoot $attemptRoot -Evidence $evidence

    if ($outcome -eq "TIMED_OUT") {
        throw "$AdapterKind call timed out after $TimeoutSeconds seconds; evidence=$($invocationEvidence.path)"
    }
    if ($outcome -eq "STOP_REQUESTED") {
        throw "Stop requested during $AdapterKind call: $($stopRequest.reason); evidence=$($invocationEvidence.path)"
    }
    if ($outcome -eq "LAUNCH_FAILED") {
        throw "$AdapterKind launch failed: $launchError; evidence=$($invocationEvidence.path)"
    }
    if (-not $result) {
        throw "$AdapterKind runner did not publish RESULT.json; evidence=$($invocationEvidence.path)"
    }
    if ([int]$result.exit_code -ne 0 -or
        [string]$result.outcome -ne "EXITED") {
        throw "$AdapterKind failed with exit code $($result.exit_code); evidence=$($invocationEvidence.path)"
    }
    return [pscustomobject]@{
        invocation_id = $InvocationId
        attempt_root = $attemptRoot
        log_path = $processLogPath
        response_path = $responsePath
        evidence_path = $invocationEvidence.path
        evidence_sha256 = $invocationEvidence.sha256
    }
}

function Invoke-AgentApi {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$InvocationId
    )

    Assert-PathsAbsent -Paths @($LogPath)
    $cliArguments = @("agentapi") + @(
        $Arguments | ForEach-Object {
            [regex]::Replace([string]$_, "\s+", " ").Trim()
        }
    )
    $call = Invoke-BoundedAdapter -TaskRoot $TaskRoot -TaskId $TaskId `
        -Stage $Stage -AdapterKind "antigravity" `
        -ExecutablePath $script:ResolvedLanguageServer `
        -ExecutableSha256 $LanguageServerSha256 `
        -Arguments $cliArguments -TimeoutSeconds $AgentCallTimeoutSeconds `
        -InvocationId $InvocationId
    $null = Copy-ArtifactImmutable -Source $call.log_path `
        -Destination $LogPath
    return Get-Content -LiteralPath $LogPath -Raw -Encoding UTF8
}

function Invoke-CodexReadOnly {
    param(
        [Parameter(Mandatory = $true)][string]$TargetWorkspace,
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$InvocationId
    )

    Assert-PathsAbsent -Paths @($OutputPath, $LogPath)
    $arguments = @(
        "exec",
        "-c", 'approval_policy="never"',
        "-s", "read-only",
        "-C", $TargetWorkspace,
        "--output-last-message", "__PAIR_RESPONSE_PATH__",
        "-"
    )
    $call = Invoke-BoundedAdapter -TaskRoot $TaskRoot -TaskId $TaskId `
        -Stage $Stage -AdapterKind "codex" `
        -ExecutablePath $script:ResolvedCodex `
        -ExecutableSha256 $CodexSha256 -Arguments $arguments `
        -StdinText $Prompt -TimeoutSeconds $CodexCallTimeoutSeconds `
        -InvocationId $InvocationId
    if (-not (Test-Path -LiteralPath $call.response_path -PathType Leaf) -or
        (Get-Item -LiteralPath $call.response_path).Length -eq 0) {
        throw "Codex did not write a non-empty response; evidence=$($call.evidence_path)"
    }
    $null = Copy-ArtifactImmutable -Source $call.response_path `
        -Destination $OutputPath
    $null = Copy-ArtifactImmutable -Source $call.log_path `
        -Destination $LogPath
}

function New-DoneSentinel {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Agent,
        [Parameter(Mandatory = $true)][string]$ArtifactPath
    )

    $artifactFull = [IO.Path]::GetFullPath($ArtifactPath)
    $artifactSha = Get-Sha256 -Path $artifactFull
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([int]$existing.schema_version -ne 1 -or
            [string]$existing.task_id -ne $TaskId -or
            [string]$existing.agent -ne $Agent -or
            -not [IO.Path]::GetFullPath(
                [string]$existing.artifact_path
            ).Equals(
                $artifactFull,
                [StringComparison]::OrdinalIgnoreCase
            ) -or [string]$existing.sha256 -ne $artifactSha) {
            throw "Existing DONE sentinel does not match its artifact: $Path"
        }
        return
    }
    $value = [ordered]@{
        schema_version = 1
        task_id = $TaskId
        agent = $Agent
        artifact_path = $artifactFull
        sha256 = $artifactSha
        completed_at = [DateTime]::UtcNow.ToString("o")
    }
    Write-JsonImmutable -Path $Path -Value $value
}

function Get-AntigravityPrompt {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [ValidateSet("R1", "R2")][string]$Round
    )

    $briefPath = [string]$State.brief_path
    $outbox = Get-AgentOutboxRoundPaths -TaskId ([string]$State.task_id) `
        -TaskRoot $TaskRoot -Round $Round
    if ($Round -eq "R1") {
        $responsePath = $outbox.response_outbox
        $donePath = $outbox.done_outbox
        return @"
You are the Antigravity architecture advisor in a reduced-assurance,
read-only pair workbench. Read $briefPath and the applicable repository rules.
Perform genuine model reasoning; do not synthesize a vote and do not modify
 product source. Your only writable outputs are $responsePath and $donePath.
 Write your evidence-based advice to $responsePath. It must
contain:

agent: antigravity
task_id: $($State.task_id)
recommendation: PROCEED|REVISE|STOP
hard_stop: NONE|<reason>

These must be the first four nonblank lines and are the only machine-readable
envelope. You may repeat the words in later explanatory prose or code blocks;
later occurrences never override the four-line envelope.

After the Markdown is fully written, compute its SHA-256 and atomically write
$donePath as UTF-8 JSON with schema_version=1, task_id="$($State.task_id)",
 agent="antigravity", artifact_path="$responsePath", sha256="<lowercase hash>",
 and completed_at. If either output path already exists, do not overwrite it;
 stop and report the collision in the conversation. Do not add any other file
 or directory to the round outbox. Do not launch background processes,
 Start-Process, or nested shells. If hashing with PowerShell, use one direct
 Get-FileHash pipeline without shell variables, then stop running commands
 after DONE is published. Do not ask the user to relay anything.
"@
    }

    $codexPath = Join-Path $TaskRoot "R1_CODEX.md"
    $responsePath = $outbox.response_outbox
    $donePath = $outbox.done_outbox
    return @"
Continue the same read-only pair task $($State.task_id). Read $briefPath,
your prior advice, and the Codex draft at $codexPath. Critique factual gaps,
unsafe assumptions, and missing tests. Do not modify product source. Write the
critique to $responsePath with:

agent: antigravity
task_id: $($State.task_id)
recommendation: PROCEED|REVISE|STOP
hard_stop: NONE|<reason>

These must be the first four nonblank lines and are the only machine-readable
envelope. Later prose cannot override them.

 After the Markdown is fully written, compute its SHA-256 and atomically write
 $donePath with the same JSON contract used in round 1. If either output path
  already exists, do not overwrite it. Do not add any other file or directory
  to the round outbox. Do not launch background processes, Start-Process, or
  nested shells. If hashing with PowerShell, use one direct Get-FileHash
  pipeline without shell variables, then stop running commands after DONE is
  published. Do not ask the user to relay anything.
"@
}

function Assert-TaskEnvelope {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)]$State
    )

    $stateFull = [IO.Path]::GetFullPath($StatePath)
    $taskRoot = [IO.Path]::GetDirectoryName($stateFull)
    $taskId = Split-Path -Leaf $taskRoot
    $tasksPrefix = [IO.Path]::GetFullPath($script:TasksRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    if (-not $taskRoot.StartsWith(
        $tasksPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Task path escaped the pair runtime."
    }
    if ($taskId -notmatch $script:TaskIdPattern -or
        [string]$State.task_id -ne $taskId) {
        throw "Task directory and task_id do not match."
    }
    $expectedStatePath = Join-Path $taskRoot "STATE.json"
    if (-not $stateFull.Equals(
        [IO.Path]::GetFullPath($expectedStatePath),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "STATE.json must be directly under its task directory."
    }
    foreach ($path in @(
        $script:RuntimeRoot,
        $script:TasksRoot,
        $taskRoot,
        $stateFull,
        [string]$State.brief_path
    )) {
        $null = Assert-CanonicalChildPath -Path $path `
            -Anchor $script:RuntimeRoot -MustExist
    }
    if ([int]$State.schema_version -ne 6 -or
        [string]$State.mode -ne "PAIR_WORKBENCH") {
        throw "Unsupported pair task schema or mode."
    }
    if ($null -eq $State.accepted_antigravity_rounds -or
        $State.accepted_antigravity_rounds.PSObject.Properties.Name -notcontains
            "R1" -or
        $State.accepted_antigravity_rounds.PSObject.Properties.Name -notcontains
            "R2") {
        throw "Pair task is missing accepted-round seal state."
    }
    if ($State.PSObject.Properties.Name -notcontains "candidate_seal") {
        throw "Pair task is missing candidate seal state."
    }
    if ([string]$State.phase -notin $script:AllowedPhases) {
        throw "Unsupported pair task phase: $($State.phase)"
    }
    $briefExpected = Join-Path $taskRoot "BRIEF.md"
    if (-not [IO.Path]::GetFullPath([string]$State.brief_path).Equals(
        [IO.Path]::GetFullPath($briefExpected),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Brief path is outside its task envelope."
    }
    $expectedOutbox = Join-Path $script:AgentOutboxRoot $taskId
    if (-not [IO.Path]::GetFullPath(
        [string]$State.agent_outbox_root
    ).Equals(
        [IO.Path]::GetFullPath($expectedOutbox),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Agent outbox path is outside its task envelope."
    }
    $null = Assert-CanonicalChildPath -Path $script:AgentOutboxRoot `
        -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType Directory
    return $taskRoot
}

function Test-WaitExpired {
    param([Parameter(Mandatory = $true)]$State)

    if ([string]$State.phase -notlike "WAIT_*") {
        return $false
    }
    $entered = [DateTime]::MinValue
    if (-not [DateTime]::TryParse(
        [string]$State.phase_entered_at,
        [ref]$entered
    )) {
        throw "Invalid phase_entered_at timestamp."
    }
    return ([DateTime]::UtcNow - $entered.ToUniversalTime()).TotalMinutes `
        -gt $WaitTimeoutMinutes
}

function Acquire-TaskLock {
    param(
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId
    )

    $lockPath = Join-Path $TaskRoot ".broker.lock"
    if (Test-Path -LiteralPath $lockPath) {
        $probe = $null
        try {
            $probe = New-Object IO.FileStream(
                $lockPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch {
            return $null
        }
        finally {
            if ($probe) {
                $probe.Dispose()
            }
        }

        $stalePath = "{0}.stale.{1}.{2}" -f $lockPath, (
            [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        ), ([Guid]::NewGuid().ToString("N").Substring(0, 8))
        Move-Item -LiteralPath $lockPath -Destination $stalePath
        Write-BrokerLog "$TaskId preserved stale lock as $stalePath"
    }

    try {
        $lock = New-Object IO.FileStream -ArgumentList @(
            $lockPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::DeleteOnClose
        )
        $lockNonce = [Guid]::NewGuid().ToString("N")
        $leaseText = [ordered]@{
            schema_version = 2
            task_id = $TaskId
            broker_instance_id = $script:BrokerInstanceId
            lock_nonce = $lockNonce
            pid = $PID
            process_start_time_utc = (
                Get-Process -Id $PID
            ).StartTime.ToUniversalTime().ToString("o")
            script_path = $PSCommandPath
            script_sha256 = Get-Sha256 -Path $PSCommandPath
            acquired_at = [DateTime]::UtcNow.ToString("o")
        } | ConvertTo-Json -Compress
        $bytes = $script:Utf8.GetBytes($leaseText)
        $lock.Write($bytes, 0, $bytes.Length)
        $lock.Flush($true)
        return $lock
    }
    catch {
        return $null
    }
}

function Write-SafeStopEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][int]$StateVersion,
        $PendingAntigravity = $null
    )

    $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $path = Join-Path $TaskRoot (
        "PAIR_SAFE_STOP_EVIDENCE.v2.sv$StateVersion.$stamp.$suffix.json"
    )
    Write-JsonImmutable -Path $path -Value ([ordered]@{
        schema_version = 2
        task_id = $TaskId
        state_version = $StateVersion
        reason = $Reason
        pending_antigravity = $PendingAntigravity
        server_execution_cancelled = if ($null -ne $PendingAntigravity) {
            $false
        }
        else {
            $null
        }
        cancellation_note = if ($null -ne $PendingAntigravity) {
            "Public Antigravity agentapi has no cancellation command; result acceptance was revoked."
        }
        else {
            ""
        }
        broker_instance_id = $script:BrokerInstanceId
        recorded_at = [DateTime]::UtcNow.ToString("o")
    })
    $sha = Get-Sha256 -Path $path
    Write-TextImmutable -Path "$path.sha256" -Content (
        "$sha  $([IO.Path]::GetFileName($path))`n"
    )
    return [pscustomobject]@{ path = $path; sha256 = $sha }
}

function Assert-SafeStopEvidence {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot
    )

    $path = [string]$State.safe_stop_evidence_path
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw "PAIR_SAFE_STOP is missing its evidence path."
    }
    $null = Assert-CanonicalChildPath -Path $path -Anchor $TaskRoot `
        -MustExist -ExpectedType File
    $sha = Get-Sha256 -Path $path
    if ($sha -ne [string]$State.safe_stop_evidence_sha256) {
        throw "PAIR_SAFE_STOP evidence SHA mismatch."
    }
    $sidecarSha = (
        Get-Content -LiteralPath "$path.sha256" -Raw -Encoding UTF8
    ).Trim().Split(" ")[0]
    if ($sidecarSha -ne $sha) {
        throw "PAIR_SAFE_STOP evidence sidecar mismatch."
    }
    $evidence = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([int]$evidence.schema_version -ne 2 -or
        [string]$evidence.task_id -ne [string]$State.task_id -or
        [string]$evidence.reason -ne [string]$State.last_error) {
        throw "PAIR_SAFE_STOP evidence identity mismatch."
    }
}

function Set-PairSafeStop {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskRoot,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $evidence = Write-SafeStopEvidence -TaskRoot $TaskRoot `
        -TaskId $TaskId -Reason $Reason `
        -StateVersion ([int]$State.state_version) `
        -PendingAntigravity $State.pending_antigravity
    $State.safe_stop_evidence_path = $evidence.path
    $State.safe_stop_evidence_sha256 = $evidence.sha256
    Set-State -StatePath $StatePath -State $State `
        -Phase "PAIR_SAFE_STOP" -ErrorMessage $Reason
}

function Process-OneTask {
    param([Parameter(Mandatory = $true)][string]$StatePath)

    $state = $null
    $lock = $null
    $taskRoot = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath($StatePath)
    )
    $taskId = Split-Path -Leaf $taskRoot
    $lockPath = Join-Path $taskRoot ".broker.lock"
    try {
        $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([int]$state.schema_version -lt 6 -and
            [string]$state.phase -in @("PAIR_CANDIDATE", "PAIR_SAFE_STOP")) {
            return
        }
        if ([int]$state.schema_version -lt 6) {
            Write-BrokerLog (
                "$taskId skipped nonterminal legacy schema " +
                "$($state.schema_version); no same-namespace migration."
            )
            return
        }
        $taskRoot = Assert-TaskEnvelope -StatePath $StatePath -State $state
        $phase = [string]$state.phase
        $taskId = [string]$state.task_id
        $target = [string]$state.target.path
        $lock = Acquire-TaskLock -TaskRoot $taskRoot -TaskId $taskId
        if (-not $lock) {
            return
        }
        $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $null = Assert-TaskEnvelope -StatePath $StatePath -State $state
        $phase = [string]$state.phase
        if ($phase -eq "PAIR_SAFE_STOP") {
            try {
                Assert-SafeStopEvidence -State $state -TaskRoot $taskRoot
            }
            catch {
                Set-PairSafeStop -StatePath $StatePath -State $state `
                    -TaskRoot $taskRoot -TaskId $taskId -Reason (
                        "PAIR_SAFE_STOP evidence integrity failure: " +
                        $_.Exception.Message
                    )
            }
            return
        }
        Assert-AcceptedAgentRoundSeals -State $state -TaskRoot $taskRoot
        if ($phase -eq "PAIR_CANDIDATE") {
            Assert-PairCandidateSeal -State $state -TaskRoot $taskRoot
        }
        $stopRequest = Get-StopRequest -TaskRoot $taskRoot -TaskId $taskId
        if ($stopRequest) {
            Set-PairSafeStop -StatePath $StatePath -State $state `
                -TaskRoot $taskRoot -TaskId $taskId `
                -Reason ("Manual stop requested: " + $stopRequest.reason)
            return
        }
        if ($phase -eq "PAIR_CANDIDATE") {
            return
        }
        if ($phase -like "RUNNING_*") {
            Set-PairSafeStop -StatePath $StatePath -State $state `
                -TaskRoot $taskRoot -TaskId $taskId -Reason (
                    "Orphaned in-flight phase detected after broker restart: " +
                    $phase + ". Same-namespace adapter replay is forbidden."
                )
            return
        }
        if (Test-WaitExpired -State $state) {
            $reason = "Pair phase timed out after $WaitTimeoutMinutes minutes."
            Set-PairSafeStop -StatePath $StatePath -State $state `
                -TaskRoot $taskRoot -TaskId $taskId -Reason $reason
            return
        }
        Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
        $state.adapter_pins = [ordered]@{
            language_server_path = $script:ResolvedLanguageServer
            language_server_sha256 = $LanguageServerSha256.ToLower()
            codex_path = $script:ResolvedCodex
            codex_sha256 = $CodexSha256.ToLower()
            git_path = $script:ResolvedGit
            git_sha256 = $GitSha256.ToLower()
            runner_path = $script:ResolvedRunner
            runner_sha256 = $RunnerSha256.ToLower()
        }

        if ($phase -eq "NEW") {
            $responsePath = Join-Path $taskRoot "R1_ANTIGRAVITY.md"
            $donePath = Join-Path $taskRoot "R1_ANTIGRAVITY.DONE.json"
            $promptPath = Join-Path $taskRoot "R1_ANTIGRAVITY_PROMPT.md"
            $logPath = Join-Path $taskRoot "R1_ANTIGRAVITY_DISPATCH.log"
            Assert-PathsAbsent -Paths @(
                $responsePath,
                $donePath,
                $promptPath,
                $logPath
            )
            $outbox = Initialize-AgentOutboxRound -State $state `
                -TaskRoot $taskRoot -Round R1
            $prompt = Get-AntigravityPrompt -State $state `
                -TaskRoot $taskRoot -Round R1
            Ensure-PromptArtifact -Path $promptPath -Content $prompt
            $invocationId = "ANTIGRAVITY_R1-" + (
                [Guid]::NewGuid().ToString("N")
            )
            $state.in_flight = [ordered]@{
                stage = "ANTIGRAVITY_R1"
                invocation_id = $invocationId
                status = "RUNNING"
                created_at = [DateTime]::UtcNow.ToString("o")
            }
            $state.pending_antigravity = [ordered]@{
                stage = "ANTIGRAVITY_R1"
                round = "R1"
                invocation_id = $invocationId
                conversation_id = ""
                outbox_round_path = $outbox.round_outbox
                response_path = $outbox.response_outbox
                done_path = $outbox.done_outbox
                status = "DISPATCHING"
                dispatch_ack_at = ""
                stability_observation = $null
                server_execution_cancelled = $false
            }
            Set-State -StatePath $StatePath -State $state `
                -Phase "RUNNING_ANTIGRAVITY_R1"
            $apiOutput = Invoke-AgentApi -Arguments @(
                "new-conversation",
                "--title=Pair-$taskId",
                "Read and execute the task prompt file $promptPath"
            ) -LogPath $logPath -TaskRoot $taskRoot -TaskId $taskId `
                -Stage "ANTIGRAVITY_R1" -InvocationId $invocationId
            $conversationId = Get-ConversationId -JsonText $apiOutput
            if ([string]::IsNullOrWhiteSpace($conversationId)) {
                throw "agentapi did not return a conversation ID."
            }
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $state.antigravity_conversation_id = $conversationId
            $state.dispatch_attempts = [int]$state.dispatch_attempts + 1
            $state.in_flight = $null
            $state.pending_antigravity.conversation_id = $conversationId
            $state.pending_antigravity.status = "WAITING_FOR_RESULT"
            $state.pending_antigravity.dispatch_ack_at = (
                [DateTime]::UtcNow.ToString("o")
            )
            Set-State -StatePath $StatePath -State $state `
                -Phase "WAIT_ANTIGRAVITY_R1"
            Write-BrokerLog "$taskId dispatched to Antigravity R1."
            return
        }

        if ($phase -eq "WAIT_ANTIGRAVITY_R1") {
            $responsePath = Join-Path $taskRoot "R1_ANTIGRAVITY.md"
            $donePath = Join-Path $taskRoot "R1_ANTIGRAVITY.DONE.json"
            if ($null -eq $state.pending_antigravity -or
                [string]$state.pending_antigravity.stage -ne
                    "ANTIGRAVITY_R1" -or
                [string]$state.pending_antigravity.round -ne "R1") {
                throw "Missing or mismatched Antigravity R1 pending contract."
            }
            $envelope = Get-ImportedAgentEnvelope -State $state `
                -StatePath $StatePath -TaskRoot $taskRoot -Round R1 `
                -FinalResponsePath $responsePath -FinalDonePath $donePath
            if (-not $envelope) {
                return
            }
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $state.recommendations.antigravity_r1 = $envelope.recommendation
            $state.pending_antigravity = $null
            if ([string]$envelope.recommendation -eq "STOP" -or
                [string]$envelope.hard_stop -ne "NONE") {
                $reason = (
                    "Antigravity R1 stop: recommendation={0} hard_stop={1}" -f
                    $envelope.recommendation,
                    $envelope.hard_stop
                )
                Set-PairSafeStop -StatePath $StatePath -State $state `
                    -TaskRoot $taskRoot -TaskId $taskId -Reason $reason
                return
            }

            $outputPath = Join-Path $taskRoot "R1_CODEX.md"
            $logPath = Join-Path $taskRoot "R1_CODEX.log"
            $codexDonePath = Join-Path $taskRoot "R1_CODEX.DONE.json"
            Assert-PathsAbsent -Paths @(
                $outputPath,
                $logPath,
                $codexDonePath
            )
            $prompt = @"
You are Codex, the read-only drafting agent for pair task $taskId. Read the
brief at $($state.brief_path) and Antigravity advice at $responsePath.
Independently verify claims from available read-only evidence and write a
bounded candidate plan. Do not modify product source or Git. Your final answer
must contain:

agent: codex
task_id: $taskId
recommendation: PROCEED|REVISE|STOP
hard_stop: NONE|<reason>

These must be the first four nonblank lines and are the only machine-readable
envelope. Later prose cannot override them.

This is not formal council authorization.
"@
            $invocationId = "CODEX_R1-" + (
                [Guid]::NewGuid().ToString("N")
            )
            $state.in_flight = [ordered]@{
                stage = "CODEX_R1"
                invocation_id = $invocationId
                status = "RUNNING"
                created_at = [DateTime]::UtcNow.ToString("o")
            }
            Set-State -StatePath $StatePath -State $state `
                -Phase "RUNNING_CODEX_R1"
            Invoke-CodexReadOnly -TargetWorkspace $target -Prompt $prompt `
                -OutputPath $outputPath -LogPath $logPath `
                -TaskRoot $taskRoot -TaskId $taskId -Stage "CODEX_R1" `
                -InvocationId $invocationId
            Assert-AcceptedAgentRoundSeals -State $state -TaskRoot $taskRoot
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $codexText = Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8
            $codexEnvelope = Read-StrictAgentEnvelope -Text $codexText `
                -ExpectedAgent "codex" -ExpectedTaskId $taskId
            $state.recommendations.codex_r1 = $codexEnvelope.recommendation
            New-DoneSentinel -Path $codexDonePath -TaskId $taskId `
                -Agent "codex" -ArtifactPath $outputPath
            if ([string]$codexEnvelope.recommendation -eq "STOP" -or
                [string]$codexEnvelope.hard_stop -ne "NONE") {
                $reason = (
                    "Codex R1 stop: recommendation={0} hard_stop={1}" -f
                    $codexEnvelope.recommendation,
                    $codexEnvelope.hard_stop
                )
                Set-PairSafeStop -StatePath $StatePath -State $state `
                    -TaskRoot $taskRoot -TaskId $taskId -Reason $reason
                return
            }
            $state.in_flight = $null
            Set-State -StatePath $StatePath -State $state `
                -Phase "CODEX_R1_DONE"
            Write-BrokerLog "$taskId completed Codex R1."
            return
        }

        if ($phase -eq "CODEX_R1_DONE") {
            $r2PromptPath = Join-Path $taskRoot "R2_ANTIGRAVITY_PROMPT.md"
            $r2LogPath = Join-Path $taskRoot "R2_ANTIGRAVITY_DISPATCH.log"
            Assert-PathsAbsent -Paths @(
                $r2PromptPath,
                $r2LogPath,
                (Join-Path $taskRoot "R2_ANTIGRAVITY.md"),
                (Join-Path $taskRoot "R2_ANTIGRAVITY.DONE.json")
            )
            $outbox = Initialize-AgentOutboxRound -State $state `
                -TaskRoot $taskRoot -Round R2
            $r2Prompt = Get-AntigravityPrompt -State $state `
                -TaskRoot $taskRoot -Round R2
            Ensure-PromptArtifact -Path $r2PromptPath -Content $r2Prompt
            $invocationId = "ANTIGRAVITY_R2-" + (
                [Guid]::NewGuid().ToString("N")
            )
            $state.in_flight = [ordered]@{
                stage = "ANTIGRAVITY_R2"
                invocation_id = $invocationId
                status = "RUNNING"
                created_at = [DateTime]::UtcNow.ToString("o")
            }
            $state.pending_antigravity = [ordered]@{
                stage = "ANTIGRAVITY_R2"
                round = "R2"
                invocation_id = $invocationId
                conversation_id = [string]$state.antigravity_conversation_id
                outbox_round_path = $outbox.round_outbox
                response_path = $outbox.response_outbox
                done_path = $outbox.done_outbox
                status = "DISPATCHING"
                dispatch_ack_at = ""
                stability_observation = $null
                server_execution_cancelled = $false
            }
            Set-State -StatePath $StatePath -State $state `
                -Phase "RUNNING_ANTIGRAVITY_R2"
            Invoke-AgentApi -Arguments @(
                "send-message",
                [string]$state.antigravity_conversation_id,
                "Read and execute the task prompt file $r2PromptPath"
            ) -LogPath $r2LogPath -TaskRoot $taskRoot -TaskId $taskId `
                -Stage "ANTIGRAVITY_R2" -InvocationId $invocationId |
                Out-Null
            Assert-AcceptedAgentRoundSeals -State $state -TaskRoot $taskRoot
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $state.in_flight = $null
            $state.pending_antigravity.status = "WAITING_FOR_RESULT"
            $state.pending_antigravity.dispatch_ack_at = (
                [DateTime]::UtcNow.ToString("o")
            )
            Set-State -StatePath $StatePath -State $state `
                -Phase "WAIT_ANTIGRAVITY_R2"
            Write-BrokerLog "$taskId completed Codex R1 and sent R2."
            return
        }

        if ($phase -eq "WAIT_ANTIGRAVITY_R2") {
            $responsePath = Join-Path $taskRoot "R2_ANTIGRAVITY.md"
            $donePath = Join-Path $taskRoot "R2_ANTIGRAVITY.DONE.json"
            if ($null -eq $state.pending_antigravity -or
                [string]$state.pending_antigravity.stage -ne
                    "ANTIGRAVITY_R2" -or
                [string]$state.pending_antigravity.round -ne "R2") {
                throw "Missing or mismatched Antigravity R2 pending contract."
            }
            $envelope = Get-ImportedAgentEnvelope -State $state `
                -StatePath $StatePath -TaskRoot $taskRoot -Round R2 `
                -FinalResponsePath $responsePath -FinalDonePath $donePath
            if (-not $envelope) {
                return
            }
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $state.recommendations.antigravity_r2 = $envelope.recommendation
            $state.pending_antigravity = $null
            if ([string]$envelope.recommendation -eq "STOP" -or
                [string]$envelope.hard_stop -ne "NONE") {
                $reason = (
                    "Antigravity R2 stop: recommendation={0} hard_stop={1}" -f
                    $envelope.recommendation,
                    $envelope.hard_stop
                )
                Set-PairSafeStop -StatePath $StatePath -State $state `
                    -TaskRoot $taskRoot -TaskId $taskId -Reason $reason
                return
            }

            $candidatePath = Join-Path $taskRoot "PAIR_CANDIDATE.md"
            $logPath = Join-Path $taskRoot "PAIR_CANDIDATE.log"
            $candidateDonePath = Join-Path $taskRoot (
                "PAIR_CANDIDATE.DONE.json"
            )
            Assert-PathsAbsent -Paths @(
                $candidatePath,
                $logPath,
                $candidateDonePath
            )
            $prompt = @"
Synthesize the final read-only candidate for pair task $taskId. Read:
- $($state.brief_path)
- $(Join-Path $taskRoot "R1_ANTIGRAVITY.md")
- $(Join-Path $taskRoot "R1_CODEX.md")
- $responsePath

Reconcile disagreements using evidence. Do not edit product code or Git. State
remaining uncertainties, exact tests, and a stop condition. The first four
nonblank lines must be exactly one each of:

agent: codex
task_id: $taskId
recommendation: PROCEED|REVISE|STOP
hard_stop: NONE|<reason>

Then mark the result `PAIR_CANDIDATE` and explicitly say it is not four-agent
authorization.
"@
            $invocationId = "CODEX_CANDIDATE-" + (
                [Guid]::NewGuid().ToString("N")
            )
            $state.in_flight = [ordered]@{
                stage = "CODEX_CANDIDATE"
                invocation_id = $invocationId
                status = "RUNNING"
                created_at = [DateTime]::UtcNow.ToString("o")
            }
            Set-State -StatePath $StatePath -State $state `
                -Phase "RUNNING_CODEX_CANDIDATE"
            Invoke-CodexReadOnly -TargetWorkspace $target -Prompt $prompt `
                -OutputPath $candidatePath -LogPath $logPath `
                -TaskRoot $taskRoot -TaskId $taskId `
                -Stage "CODEX_CANDIDATE" -InvocationId $invocationId
            Assert-AcceptedAgentRoundSeals -State $state -TaskRoot $taskRoot
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            $candidateText = Get-Content -LiteralPath $candidatePath `
                -Raw -Encoding UTF8
            $candidateEnvelope = Read-StrictAgentEnvelope `
                -Text $candidateText -ExpectedAgent "codex" `
                -ExpectedTaskId $taskId
            $state.recommendations.candidate = (
                $candidateEnvelope.recommendation
            )
            New-DoneSentinel -Path $candidateDonePath -TaskId $taskId `
                -Agent "codex" -ArtifactPath $candidatePath
            Assert-AcceptedAgentRoundSeals -State $state -TaskRoot $taskRoot
            Assert-TargetUnchanged -State $state -TaskRoot $taskRoot
            Register-PairCandidateSeal -State $state -TaskRoot $taskRoot `
                -CandidatePath $candidatePath `
                -CandidateDonePath $candidateDonePath
            Assert-PairCandidateSeal -State $state -TaskRoot $taskRoot
            if ([string]$candidateEnvelope.recommendation -eq "STOP" -or
                [string]$candidateEnvelope.hard_stop -ne "NONE") {
                $reason = (
                    "Codex candidate stop: recommendation={0} hard_stop={1}" -f
                    $candidateEnvelope.recommendation,
                    $candidateEnvelope.hard_stop
                )
                Set-PairSafeStop -StatePath $StatePath -State $state `
                    -TaskRoot $taskRoot -TaskId $taskId -Reason $reason
                return
            }
            $state.in_flight = $null
            Set-State -StatePath $StatePath -State $state `
                -Phase "PAIR_CANDIDATE"
            Write-BrokerLog "$taskId reached PAIR_CANDIDATE."
            return
        }
    }
    catch {
        $reason = $_.Exception.Message
        Write-BrokerLog "Task processing error for ${StatePath}: $reason"
        if ($lock -and $state -and [int]$state.schema_version -eq 6 -and
            [string]$state.phase -ne "PAIR_SAFE_STOP") {
            try {
                $latestState = Get-Content -LiteralPath $StatePath -Raw `
                    -Encoding UTF8 | ConvertFrom-Json
                if ([string]$latestState.task_id -ne $taskId) {
                    throw "Task identity changed before safe stop."
                }
                if ([string]$latestState.phase -ne "PAIR_SAFE_STOP") {
                    Set-PairSafeStop -StatePath $StatePath `
                        -State $latestState -TaskRoot $taskRoot `
                        -TaskId $taskId -Reason $reason
                }
            }
            catch {
                Write-BrokerLog (
                    "Failed to persist safe stop for ${StatePath}: " +
                    $_.Exception.Message
                )
            }
        }
    }
    finally {
        if ($lock) {
            $lock.Dispose()
        }
    }
}

function Invoke-Reconcile {
    [IO.Directory]::CreateDirectory($script:TasksRoot) | Out-Null
    foreach ($taskDirectory in @(
        Get-ChildItem -LiteralPath $script:TasksRoot -Directory `
            -ErrorAction SilentlyContinue |
        Sort-Object FullName
    )) {
        if ($taskDirectory.Name -notmatch $script:TaskIdPattern -or
            ($taskDirectory.Attributes -band
                [IO.FileAttributes]::ReparsePoint)) {
            continue
        }
        $statePath = Join-Path $taskDirectory.FullName "STATE.json"
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            Process-OneTask -StatePath $statePath
        }
    }
}

foreach ($directory in @(
    $script:RuntimeRoot,
    $script:TasksRoot,
    $script:AgentOutboxRoot
)) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}
$null = Assert-CanonicalChildPath -Path $script:RuntimeRoot `
    -Anchor $script:RuntimeRoot -MustExist -ExpectedType Directory
$null = Assert-CanonicalChildPath -Path $script:TasksRoot `
    -Anchor $script:RuntimeRoot -MustExist -ExpectedType Directory
$null = Assert-CanonicalChildPath -Path $script:AgentOutboxRoot `
    -Anchor $script:AgentOutboxRoot -MustExist -ExpectedType Directory
$script:ResolvedLanguageServer = Resolve-LanguageServer
$script:ResolvedCodex = Resolve-Codex
$script:ResolvedGit = Resolve-Git
$script:ResolvedRunner = Resolve-Runner
Write-BrokerLog (
    "Adapter pins verified: language_server=$LanguageServerSha256 " +
    "codex=$CodexSha256 git=$GitSha256 runner=$RunnerSha256"
)
Invoke-Reconcile
if ($Loop) {
    $watcher = New-Object IO.FileSystemWatcher($script:TasksRoot)
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = (
        [IO.NotifyFilters]::FileName -bor
        [IO.NotifyFilters]::LastWrite -bor
        [IO.NotifyFilters]::DirectoryName
    )
    $watcher.EnableRaisingEvents = $true
    try {
        while ($true) {
            $watcher.WaitForChanged(
                [IO.WatcherChangeTypes]::All,
                $ReconcileSeconds * 1000
            ) | Out-Null
            Invoke-Reconcile
        }
    }
    finally {
        $watcher.Dispose()
    }
}
