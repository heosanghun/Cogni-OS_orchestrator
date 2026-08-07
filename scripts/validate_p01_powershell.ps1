$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$powershell = Join-Path $PSHOME 'powershell.exe'
$productionTaskName = 'Cogni-OS Monitor Publisher'
$productionSecretPath = Join-Path $repoRoot (
    '.runtime\cogni-monitor-secret.clixml'
)
$scripts = [ordered]@{
    binary_trust = Join-Path $PSScriptRoot 'publisher_binary_trust.ps1'
    installer = Join-Path $PSScriptRoot 'install_monitor_publisher_autostart.ps1'
    preflight = Join-Path $PSScriptRoot 'publisher_production_preflight.ps1'
    runner = Join-Path $PSScriptRoot 'run_monitor_publisher.ps1'
    secret = Join-Path $PSScriptRoot 'set_monitor_publisher_secret.ps1'
    uninstall = Join-Path $PSScriptRoot 'uninstall_monitor_publisher_autostart.ps1'
    validator = $PSCommandPath
}
$expectedCheckCount = 11
$expectedCheckInventorySha256 = (
    '916c5768baedf8aa257a8ad165477369edb2c06aec2241fb83a383454d1eb802'
)
$checks = [ordered]@{}
$failures = [Collections.Generic.List[string]]::new()
$context = [ordered]@{
    root = Join-Path ([IO.Path]::GetTempPath()) (
        'cogni-p01-powershell-{0}' -f ([Guid]::NewGuid().ToString('N'))
    )
    task_name = 'Cogni-OS P01 Validation {0}' -f (
        [Guid]::NewGuid().ToString('N')
    )
    task_registered = $false
}

function Invoke-RegressionCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    try {
        & $Action
        $checks[$Name] = $true
    } catch {
        $checks[$Name] = $false
        $message = ($_.Exception.Message -replace '[\r\n]+', ' ').Trim()
        if ($message.Length -gt 512) {
            $message = $message.Substring(0, 512)
        }
        $failures.Add(('{0}: {1}' -f $Name, $message))
    }
}

function Invoke-RunnerChild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecretPath,

        [Parameter(Mandatory = $true)]
        [string]$KeyId,

        [Parameter(Mandatory = $true)]
        [string]$StateDir
    )

    $hadKeyId = Test-Path Env:COGNI_MONITOR_KEY_ID
    $priorKeyId = [string]$env:COGNI_MONITOR_KEY_ID
    $hadSecret = Test-Path Env:COGNI_MONITOR_INGEST_SECRET
    $priorSecret = [string]$env:COGNI_MONITOR_INGEST_SECRET
    try {
        $env:COGNI_MONITOR_KEY_ID = $KeyId
        Remove-Item Env:COGNI_MONITOR_INGEST_SECRET -ErrorAction SilentlyContinue
        $captureId = [Guid]::NewGuid().ToString('N')
        $standardOutput = Join-Path $context.root (
            'runner-{0}.stdout.txt' -f $captureId
        )
        $standardError = Join-Path $context.root (
            'runner-{0}.stderr.txt' -f $captureId
        )
        $quote = {
            param([string]$Value)
            return '"' + ($Value -replace '"', '""') + '"'
        }
        $argumentLine = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-ExecutionPolicy Bypass'
            ('-File {0}' -f (& $quote $scripts.runner))
            ('-WorkspaceRoot {0}' -f (& $quote $context.root))
            '-Endpoint "https://127.0.0.1:9/must-not-connect"'
            '-Once'
            '-ValidationOnly'
            ('-SecretPath {0}' -f (& $quote $SecretPath))
            ('-StateDir {0}' -f (& $quote $StateDir))
            ('-PythonPath {0}' -f (& $quote $context.fake_python))
        ) -join ' '
        $process = Start-Process `
            -FilePath $powershell `
            -ArgumentList $argumentLine `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $standardOutput `
            -RedirectStandardError $standardError
        $output = @(
            if (Test-Path -LiteralPath $standardOutput) {
                Get-Content -LiteralPath $standardOutput
            }
            if (Test-Path -LiteralPath $standardError) {
                Get-Content -LiteralPath $standardError
            }
        )
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = (($output | ForEach-Object { [string]$_ }) -join "`n")
        }
    } finally {
        if ($hadKeyId) {
            $env:COGNI_MONITOR_KEY_ID = $priorKeyId
        } else {
            Remove-Item Env:COGNI_MONITOR_KEY_ID -ErrorAction SilentlyContinue
        }
        if ($hadSecret) {
            $env:COGNI_MONITOR_INGEST_SECRET = $priorSecret
        } else {
            Remove-Item Env:COGNI_MONITOR_INGEST_SECRET -ErrorAction SilentlyContinue
        }
    }
}

function Get-TaskConfigurationFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )

    $task = Get-ScheduledTask `
        -TaskName $TaskName `
        -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return [pscustomobject]@{
            Exists = $false
            Sha256 = $null
        }
    }
    $projection = [ordered]@{
        task_name = [string]$task.TaskName
        task_path = [string]$task.TaskPath
        description = [string]$task.Description
        actions = @(
            foreach ($action in @($task.Actions)) {
                [ordered]@{
                    execute = [string]$action.Execute
                    arguments = [string]$action.Arguments
                    working_directory = [string]$action.WorkingDirectory
                }
            }
        )
        triggers = @(
            foreach ($trigger in @($task.Triggers)) {
                [ordered]@{
                    type = [string]$trigger.CimClass.CimClassName
                    enabled = [bool]$trigger.Enabled
                    user_id = [string]$trigger.UserId
                    start_boundary = [string]$trigger.StartBoundary
                }
            }
        )
        principal = [ordered]@{
            user_id = [string]$task.Principal.UserId
            logon_type = [string]$task.Principal.LogonType
            run_level = [string]$task.Principal.RunLevel
        }
        settings = [ordered]@{
            multiple_instances = [string]$task.Settings.MultipleInstances
            restart_count = [int]$task.Settings.RestartCount
            restart_interval = [string]$task.Settings.RestartInterval
            execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
            start_when_available = [bool]$task.Settings.StartWhenAvailable
            allow_battery = [bool]$task.Settings.AllowStartIfOnBatteries
            keep_on_battery = [bool]$task.Settings.DontStopIfGoingOnBatteries
        }
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(
        ($projection | ConvertTo-Json -Compress -Depth 8)
    )
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($bytes)
        $hash = -join ($digest | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha256.Dispose()
    }
    return [pscustomobject]@{
        Exists = $true
        Sha256 = $hash
    }
}

$productionTaskBefore = Get-TaskConfigurationFingerprint `
    -TaskName $productionTaskName

try {
    New-Item -ItemType Directory -Path $context.root -Force | Out-Null
    # Hosted Windows runners can assign a newly-created TEMP child directory
    # to the local Administrators group.  Provision this test fixture with the
    # same current-principal-only boundary required by the production writer so
    # every subsequent regression reaches the behavior it is meant to test.
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $fixtureAcl = [Security.AccessControl.DirectorySecurity]::new()
    $fixtureAcl.SetOwner($currentSid)
    $fixtureAcl.SetAccessRuleProtection($true, $false)
    $fixtureRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        (
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        ),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $fixtureAcl.AddAccessRule($fixtureRule)
    Set-Acl -LiteralPath $context.root -AclObject $fixtureAcl
    $context.valid_secret = Join-Path $context.root 'valid-secret.clixml'
    $context.short_secret = Join-Path $context.root 'short-secret.clixml'
    $context.plaintext_secret = Join-Path $context.root 'plaintext-secret.clixml'
    $context.state_invalid_key = Join-Path $context.root 'state-invalid-key'
    $context.state_plaintext = Join-Path $context.root 'state-plaintext'
    $context.state_task = Join-Path $context.root 'state-scheduled-task'
    $context.fake_marker = Join-Path $context.root 'fake-python-invoked.txt'
    $context.fake_python = Join-Path $context.root 'fake-python.cmd'
    @(
        '@echo off'
        ('>"{0}" echo invoked' -f $context.fake_marker)
        'exit /b 97'
    ) | Set-Content -LiteralPath $context.fake_python -Encoding ASCII

    Invoke-RegressionCheck -Name 'isolated_resource_names' -Action {
        if ($context.task_name -notmatch '^Cogni-OS P01 Validation [0-9a-f]{32}$') {
            throw 'The validation task name is not a unique P01 test identity.'
        }
        if ($context.task_name -eq $productionTaskName) {
            throw 'The validation task name collides with the production task.'
        }
        if (
            [IO.Path]::GetFullPath($context.valid_secret) -eq
            [IO.Path]::GetFullPath($productionSecretPath)
        ) {
            throw 'The validation secret path collides with the production secret.'
        }
    }

    Invoke-RegressionCheck -Name 'syntax' -Action {
        foreach ($entry in $scripts.GetEnumerator()) {
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile(
                $entry.Value,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if ($parseErrors.Count -ne 0) {
                throw (
                    '{0} has {1} PowerShell parse error(s).' -f
                    $entry.Key,
                    $parseErrors.Count
                )
            }
        }

        $binaryTrustSource = Get-Content -LiteralPath $scripts.binary_trust -Raw
        $installerSource = Get-Content -LiteralPath $scripts.installer -Raw
        $runnerSource = Get-Content -LiteralPath $scripts.runner -Raw
        $uninstallSource = Get-Content -LiteralPath $scripts.uninstall -Raw
        $secretSource = Get-Content -LiteralPath $scripts.secret -Raw
        if (
            $binaryTrustSource.IndexOf('DeleteSubdirectoriesAndFiles') -lt 0 -or
            $binaryTrustSource.IndexOf(
                '$rule.IdentityReference.Value -notin'
            ) -lt 0 -or
            $binaryTrustSource.IndexOf('$script:CogniTrustedOwnerSids') -lt 0
        ) {
            throw 'Common binary trust omits exact destructive-ACE rejection.'
        }
        foreach ($inlineGuard in @(
            [pscustomobject]@{ Name = 'installer'; Source = $installerSource },
            [pscustomobject]@{ Name = 'runner'; Source = $runnerSource },
            [pscustomobject]@{ Name = 'secret'; Source = $secretSource },
            [pscustomobject]@{ Name = 'uninstaller'; Source = $uninstallSource }
        )) {
            if (
                $inlineGuard.Source.IndexOf(
                    'DeleteSubdirectoriesAndFiles'
                ) -lt 0 -or
                $inlineGuard.Source.IndexOf(
                    '$rule.IdentityReference.Value -notin $allowedOwners'
                ) -lt 0 -or
                $inlineGuard.Source -match
                    'CogniWritablePrincipalSids|forbiddenWriters|forbiddenSids'
            ) {
                throw (
                    '{0} bootstrap does not reject every untrusted destructive ACE.' -f
                    $inlineGuard.Name
                )
            }
        }
        foreach ($bootstrapContract in @(
            [pscustomobject]@{
                Name = 'installer'
                Source = $installerSource
                Guard = 'Assert-CogniInstallerBootstrapFileTrust'
                Load = '. (Join-Path $PSScriptRoot "publisher_binary_trust.ps1")'
            },
            [pscustomobject]@{
                Name = 'uninstaller'
                Source = $uninstallSource
                Guard = 'Assert-CogniUninstallBootstrapFileTrust'
                Load = ". (Join-Path `$PSScriptRoot 'publisher_binary_trust.ps1')"
            }
        )) {
            $guardCall = $bootstrapContract.Source.IndexOf(
                ('$null = {0}' -f $bootstrapContract.Guard)
            )
            $helperLoad = $bootstrapContract.Source.IndexOf($bootstrapContract.Load)
            if ($guardCall -lt 0 -or $helperLoad -lt 0 -or $guardCall -ge $helperLoad) {
                throw (
                    '{0} loads a mutable helper before bootstrap trust.' -f
                    $bootstrapContract.Name
                )
            }
        }
        foreach ($required in @(
            'Test-CogniOwnedTask',
            'Register-ScheduledTask',
            '$replaceOwnedTask = $false',
            '$latestTask = Get-ScheduledTask',
            '$canonicalSecretPath',
            '$canonicalStateDir',
            'Production secret and state paths are fixed',
            'Test-CogniInstallerContainedPath',
            '[string]$Task.TaskPath -ceq',
            '[string]$Task.Principal.UserId',
            'MSFT_TaskLogonTrigger',
            '[int]$Task.Settings.RestartCount -eq 999',
            "[string]`$Task.Settings.RestartInterval -ceq 'PT1M'",
            "[string]`$Task.Settings.ExecutionTimeLimit -ceq 'PT0S'",
            'Registered task failed exact post-registration',
            'Scheduled task changed before start'
        )) {
            if ($installerSource.IndexOf($required) -lt 0) {
                throw "Installer exact-ownership contract is missing: $required"
            }
        }
        $replacementBranch = $installerSource.IndexOf('if ($replaceOwnedTask) {')
        $absentBranch = $installerSource.IndexOf('} else {', $replacementBranch)
        $absentEnd = $installerSource.IndexOf(
            'if (-not $DoNotStart)',
            $absentBranch
        )
        if (
            $replacementBranch -lt 0 -or
            $absentBranch -le $replacementBranch -or
            $absentEnd -le $absentBranch
        ) {
            throw 'Installer absent/existing task ownership branches are ambiguous.'
        }
        $absentBlock = $installerSource.Substring(
            $absentBranch,
            $absentEnd - $absentBranch
        ) -replace '(?m)^\s*#.*$', ''
        if (
            $absentBlock.IndexOf('Register-ScheduledTask') -lt 0 -or
            $absentBlock.IndexOf('-Force') -ge 0
        ) {
            throw 'Installer absent-task registration is not a no-Force branch.'
        }
        foreach ($required in @(
            'Assert-CogniAdminOwnedPathChain',
            'Get-CogniOwnedTaskIdentity',
            'monitor_publisher_runtime.json',
            'ExecutablePath',
            '$expectedPrefix',
            'Unregister-ScheduledTask',
            '[string]$Task.TaskPath -cne',
            '[string]$Task.Principal.UserId',
            'MSFT_TaskLogonTrigger',
            'Test-CogniOwnedTaskIdentityEqual',
            'Scheduled task changed after stop'
        )) {
            if ($uninstallSource.IndexOf($required) -lt 0) {
                throw "Uninstaller exact-ownership contract is missing: $required"
            }
        }
        if ($uninstallSource -match '(?i)Get-CimInstance[^\r\n]+Win32_Process[^\r\n]+-like') {
            throw 'Uninstaller still performs substring-based process discovery.'
        }
        foreach ($required in @(
            '[switch]$ValidationOnly',
            'Assert-CogniSecretBootstrapFileTrust',
            '[IO.File]::Replace',
            '[IO.File]::Move',
            'AreAccessRulesProtected',
            'Assert-CogniSecretParent',
            'Assert-CogniExistingSecretTarget',
            'Get-CogniRelativePath',
            'Test-CogniPathContained',
            'ProductionTrust',
            'DeleteSubdirectoriesAndFiles',
            'Get-CogniSecretTargetTrustFingerprint',
            '$parentFingerprint',
            '$parentBeforeCommit',
            '$parentAfterCommit',
            '$targetBeforeCommit'
        )) {
            if ($secretSource.IndexOf($required) -lt 0) {
                throw "Secret writer atomic/path contract is missing: $required"
            }
        }
        if ($secretSource -match '(?im)^\s*Move-Item\b[^\r\n]*-Force') {
            throw 'Secret writer still uses overwrite-prone Move-Item -Force.'
        }
        if (
            $secretSource.IndexOf('Get-CogniSecretParentWriteMask') -lt 0 -or
            $secretSource.IndexOf(
                'Get-CogniSecretParentWriteMask -IsRoot:$isRoot'
            ) -lt 0
        ) {
            throw 'Secret parent does not use a root-specific destructive mask.'
        }
        $secretTokens = $null
        $secretParseErrors = $null
        $secretAst = [Management.Automation.Language.Parser]::ParseFile(
            $scripts.secret,
            [ref]$secretTokens,
            [ref]$secretParseErrors
        )
        $maskAst = $secretAst.Find(
            {
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Get-CogniSecretParentWriteMask'
            },
            $true
        )
        if ($null -eq $maskAst) {
            throw 'Secret parent root-mask function is not parseable.'
        }
        Invoke-Expression $maskAst.Extent.Text
        try {
            $rootMask = Get-CogniSecretParentWriteMask -IsRoot
            $strictMask = Get-CogniSecretParentWriteMask
            $normalRootRights = (
                [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
                [Security.AccessControl.FileSystemRights]::AppendData
            )
            $dangerousRootRights = (
                [Security.AccessControl.FileSystemRights]::Delete -bor
                [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            )
            if (
                ($rootMask -band $normalRootRights) -ne 0 -or
                ($rootMask -band $dangerousRootRights) -ne $dangerousRootRights -or
                ($rootMask -band [Security.AccessControl.FileSystemRights]::FullControl) -eq 0 -or
                ($strictMask -band $normalRootRights) -eq 0
            ) {
                throw 'Secret root/non-root ACL masks do not preserve strict boundaries.'
            }
            $rootPath = [IO.Path]::GetPathRoot($repoRoot)
            $rootAcl = Get-Acl -LiteralPath $rootPath -ErrorAction Stop
            $rootOwnerSid = (
                [Security.Principal.NTAccount]$rootAcl.Owner
            ).Translate([Security.Principal.SecurityIdentifier]).Value
            $trustedRootWriters = @(
                $rootOwnerSid,
                'S-1-5-18',
                'S-1-5-32-544',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
            ) | Sort-Object -Unique
            foreach ($rule in @($rootAcl.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            ))) {
                if (
                    $rule.AccessControlType -eq
                        [Security.AccessControl.AccessControlType]::Allow -and
                    ($rule.PropagationFlags -band
                        [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                    $rule.IdentityReference.Value -notin $trustedRootWriters -and
                    ($rule.FileSystemRights -band $rootMask) -ne 0
                ) {
                    throw 'The actual volume root grants an untrusted destructive ACE.'
                }
            }
            $dangerousRule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]'S-1-1-0',
                [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
                [Security.AccessControl.AccessControlType]::Allow
            )
            if (($dangerousRule.FileSystemRights -band $rootMask) -eq 0) {
                throw 'A synthetic dangerous volume-root ACE bypassed detection.'
            }
        } finally {
            Remove-Item Function:\Get-CogniSecretParentWriteMask `
                -Force `
                -ErrorAction SilentlyContinue
        }
        $secretBootstrap = $secretSource.IndexOf(
            'Assert-CogniSecretBootstrapFileTrust -LiteralPath $path'
        )
        $secretHelperLoad = $secretSource.IndexOf(
            ". (Join-Path `$PSScriptRoot 'publisher_binary_trust.ps1')"
        )
        if (
            $secretBootstrap -lt 0 -or
            $secretHelperLoad -lt 0 -or
            $secretBootstrap -ge $secretHelperLoad
        ) {
            throw 'Secret writer loads a mutable helper before bootstrap trust.'
        }
        foreach ($required in @(
            '$canonicalSecretPath',
            '$canonicalStateDir',
            'Production secret and state paths are fixed',
            'Test-CogniContainedPath'
        )) {
            if ($runnerSource.IndexOf($required) -lt 0) {
                throw "Runner canonical-path contract is missing: $required"
            }
        }
        if (
            $runnerSource.IndexOf("-Name 'docker'") -ge 0 -or
            $runnerSource.IndexOf('docker.exe') -ge 0 -or
            $runnerSource.IndexOf("-Name 'nvidia-smi'") -lt 0 -or
            $runnerSource.IndexOf(
                "-Candidates @('C:\Windows\System32\nvidia-smi.exe')"
            ) -lt 0
        ) {
            throw 'GPU publisher trust must require only fixed nvidia-smi, never Docker.'
        }
    }

    Invoke-RegressionCheck -Name 'publisher_production_preflight_contract' -Action {
        . $scripts.preflight
        $runnerSource = Get-Content -LiteralPath $scripts.runner -Raw
        $preflightCall = $runnerSource.IndexOf(
            '$preflight = Invoke-ProductionReadinessPreflight'
        )
        $binaryRecheck = $runnerSource.IndexOf(
            '$null = Assert-CogniTrustedExecutableRecord -Record $record',
            $preflightCall
        )
        $secretRead = $runnerSource.IndexOf(
            '$secret = [string]$env:COGNI_MONITOR_INGEST_SECRET'
        )
        $dpapiRead = $runnerSource.IndexOf(
            '$secret = Read-CurrentUserDpapiSecret -Path $SecretPath',
            $binaryRecheck
        )
        $pythonCall = $runnerSource.IndexOf(
            '$exitCode = Invoke-CogniSanitizedPublisher'
        )
        $bootstrapCheck = $runnerSource.IndexOf(
            'Assert-CogniBootstrapFileTrust -LiteralPath $bootstrapFile'
        )
        $helperLoad = $runnerSource.IndexOf(
            '. (Join-Path $PSScriptRoot "publisher_binary_trust.ps1")'
        )
        if (
            $preflightCall -lt 0 -or
            $binaryRecheck -lt 0 -or
            $secretRead -lt 0 -or
            $dpapiRead -lt 0 -or
            $pythonCall -lt 0 -or
            $bootstrapCheck -lt 0 -or
            $helperLoad -lt 0 -or
            $bootstrapCheck -ge $helperLoad -or
            $preflightCall -ge $binaryRecheck -or
            $binaryRecheck -ge $secretRead -or
            $binaryRecheck -ge $dpapiRead -or
            $secretRead -ge $pythonCall -or
            $dpapiRead -ge $pythonCall
        ) {
            throw 'Bootstrap, preflight, secret-read, and Python startup ordering is unsafe.'
        }
        foreach ($requiredBound in @(
            'MaxStdoutBytes',
            'MaxStderrBytes',
            'TimeoutSeconds',
            'maxFiles',
            'maxTotalBytes'
        )) {
            if ($runnerSource.IndexOf($requiredBound) -lt 0) {
                throw "Publisher runtime omits bounded resource control: $requiredBound"
            }
        }
        $commit = 'a' * 40
        $valid = [pscustomobject]@{
            ok = $true
            state = 'CONFIGURED'
            checks = [pscustomobject]@{
                runtime_configuration_ready = $true
                storage_state = 'READY'
                deployment_attribution = 'BUILD_BOUND'
                build_attribution_ready = $true
                operational_ingest_ready = $true
                release_attribution_ready = $false
                release_evidence_state = 'API_EVIDENCE_REQUIRED'
                minimum_release_snapshot_schema = '1.2'
            }
            deployment = [pscustomobject]@{
                attribution = 'BUILD_BOUND'
                source_commit = $commit
                branch = 'main'
                project = 'cogni-os-orchestrator'
                environment = 'production'
                url = 'https://cogni-os-orchestrator.pages.dev'
                deployment_url = (
                    'https://deployment-p01.cogni-os-orchestrator.pages.dev'
                )
            }
        }
        $result = Assert-CogniPublisherProductionHealth `
            -Health $valid `
            -ExpectedSourceCommit $commit
        if (
            $result.source_commit -ne $commit -or
            $result.minimum_release_snapshot_schema -ne '1.2' -or
            $result.operational_ingest -ne 'READY' -or
            $result.release_readiness -ne 'NO_GO_API_EVIDENCE_REQUIRED'
        ) {
            throw 'Valid production health was not normalized.'
        }

        foreach ($mutation in @(
            'schema', 'commit', 'attribution', 'operational', 'release'
        )) {
            $invalid = $valid | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            switch ($mutation) {
                'schema' {
                    $invalid.checks.minimum_release_snapshot_schema = '1.1'
                }
                'commit' {
                    $invalid.deployment.source_commit = 'b' * 40
                }
                'attribution' {
                    $invalid.deployment.attribution = 'UNAVAILABLE'
                }
                'operational' {
                    $invalid.checks.operational_ingest_ready = $false
                }
                'release' {
                    $invalid.checks.release_attribution_ready = $true
                }
            }
            $rejected = $false
            try {
                $null = Assert-CogniPublisherProductionHealth `
                    -Health $invalid `
                    -ExpectedSourceCommit $commit
            } catch {
                $rejected = $true
            }
            if (-not $rejected) {
                throw ('Publisher preflight accepted invalid {0}.' -f $mutation)
            }
        }
    }

    Invoke-RegressionCheck -Name 'dpapi_secret_and_acl' -Action {
        $plain = (
            [Guid]::NewGuid().ToString('N') +
            [Guid]::NewGuid().ToString('N')
        ).Substring(0, 48)
        try {
            $secure = ConvertTo-SecureString $plain -AsPlainText -Force
            & $scripts.secret `
                -Secret $secure `
                -SecretPath $context.valid_secret `
                -ValidationOnly | Out-Null
            if (-not (Test-Path -LiteralPath $context.valid_secret -PathType Leaf)) {
                throw 'The temporary DPAPI secret was not created.'
            }
            $raw = Get-Content -LiteralPath $context.valid_secret -Raw
            if ($raw.Contains($plain)) {
                throw 'The CLIXML file contains the plaintext test secret.'
            }
            $recovered = Import-Clixml -LiteralPath $context.valid_secret
            if ($recovered -isnot [Security.SecureString]) {
                throw 'The generated CLIXML payload is not a SecureString.'
            }

            $acl = Get-Acl -LiteralPath $context.valid_secret
            $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $ownerSid = (
                [Security.Principal.NTAccount]$acl.Owner
            ).Translate([Security.Principal.SecurityIdentifier])
            if ($ownerSid.Value -ne $currentSid.Value) {
                throw 'The DPAPI secret owner is not the current Windows principal.'
            }
            if (-not $acl.AreAccessRulesProtected) {
                throw 'The DPAPI secret ACL still inherits parent permissions.'
            }
            $rules = @(
                $acl.GetAccessRules(
                    $true,
                    $true,
                    [Security.Principal.SecurityIdentifier]
                )
            )
            if ($rules.Count -ne 1) {
                throw 'The DPAPI secret ACL must contain exactly one access rule.'
            }
            $rule = $rules[0]
            if (
                $rule.IdentityReference.Value -ne $currentSid.Value -or
                $rule.AccessControlType -ne
                    [Security.AccessControl.AccessControlType]::Allow -or
                (($rule.FileSystemRights -band
                    [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl)
            ) {
                throw 'The DPAPI secret ACL is not current-user FullControl only.'
            }
        } finally {
            $plain = $null
            $secure = $null
            $recovered = $null
        }
    }

    Invoke-RegressionCheck -Name 'short_secret_rejected' -Action {
        $short = ConvertTo-SecureString 'too-short' -AsPlainText -Force
        $rejected = $false
        try {
            & $scripts.secret `
                -Secret $short `
                -SecretPath $context.short_secret `
                -ValidationOnly | Out-Null
        } catch {
            $rejected = $_.Exception.Message -match '32-256'
        } finally {
            $short = $null
        }
        if (-not $rejected) {
            throw 'A short monitoring secret was not rejected.'
        }
        if (Test-Path -LiteralPath $context.short_secret) {
            throw 'A rejected short secret left a persistent CLIXML file.'
        }
    }

    Invoke-RegressionCheck -Name 'plaintext_clixml_rejected_before_python' -Action {
        'not-a-secure-string' | Export-Clixml `
            -LiteralPath $context.plaintext_secret `
            -Force
        # Match the already-validated secret file boundary so this regression
        # reaches the payload-type check instead of failing earlier on ACLs.
        $plaintextAcl = Get-Acl -LiteralPath $context.valid_secret
        Set-Acl -LiteralPath $context.plaintext_secret -AclObject $plaintextAcl
        Remove-Item -LiteralPath $context.fake_marker `
            -Force `
            -ErrorAction SilentlyContinue
        $result = Invoke-RunnerChild `
            -SecretPath $context.plaintext_secret `
            -KeyId 'publisher-p01-test' `
            -StateDir $context.state_plaintext
        if ($result.ExitCode -eq 0) {
            throw 'The runner accepted plaintext CLIXML.'
        }
        if ($result.Output -notmatch 'does not contain a SecureString') {
            throw 'The runner did not report the plaintext CLIXML type failure.'
        }
        if (Test-Path -LiteralPath $context.fake_marker) {
            throw 'Python was invoked after plaintext CLIXML rejection.'
        }
    }

    Invoke-RegressionCheck -Name 'invalid_key_rejected_before_python_or_network' -Action {
        Remove-Item -LiteralPath $context.fake_marker `
            -Force `
            -ErrorAction SilentlyContinue
        $siblingState = $context.root + '-sibling-state'
        Remove-Item -LiteralPath $siblingState `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
        $siblingResult = Invoke-RunnerChild `
            -SecretPath $context.valid_secret `
            -KeyId 'publisher-p01-test' `
            -StateDir $siblingState
        if (
            $siblingResult.ExitCode -eq 0 -or
            $siblingResult.Output -notmatch 'ValidationOnly is restricted' -or
            (Test-Path -LiteralPath $siblingState) -or
            (Test-Path -LiteralPath $context.fake_marker)
        ) {
            throw 'Runner accepted a sibling-prefix ValidationOnly state path.'
        }
        $result = Invoke-RunnerChild `
            -SecretPath $context.valid_secret `
            -KeyId 'invalid key!' `
            -StateDir $context.state_invalid_key
        if ($result.ExitCode -eq 0) {
            throw 'The runner accepted an invalid publisher key id.'
        }
        if ($result.Output -notmatch 'safe 3-64 character key id') {
            throw 'The runner did not report the key-id preflight failure.'
        }
        if (Test-Path -LiteralPath $context.fake_marker) {
            throw 'Python was invoked after invalid key-id rejection.'
        }
        $journal = Join-Path $context.state_invalid_key (
            'monitor_publisher_wrapper_journal.jsonl'
        )
        if (-not (Test-Path -LiteralPath $journal -PathType Leaf)) {
            throw 'The invalid key-id failure was not journaled.'
        }
        $lastEntry = Get-Content -LiteralPath $journal -Tail 1 |
            ConvertFrom-Json
        if ($lastEntry.event -ne 'wrapper_failed') {
            throw 'The invalid key-id path did not fail before wrapper startup.'
        }
    }

    Invoke-RegressionCheck -Name 'scheduled_task_do_not_start_configuration' -Action {
        $installerSiblingState = $context.root + '-installer-sibling-state'
        Remove-Item -LiteralPath $installerSiblingState `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
        $siblingRejected = $false
        try {
            & $scripts.installer `
                -WorkspaceRoot $context.root `
                -Endpoint 'https://127.0.0.1:9/must-not-connect' `
                -IntervalSeconds 5 `
                -MaxBackoffSeconds 5 `
                -TaskName $context.task_name `
                -SecretPath $context.valid_secret `
                -StateDir $installerSiblingState `
                -PythonPath $context.fake_python `
                -DoNotStart `
                -ValidationOnly
        } catch {
            $siblingRejected = $_.Exception.Message -match
                'ValidationOnly is restricted'
        }
        if (
            -not $siblingRejected -or
            (Get-ScheduledTask `
                -TaskName $context.task_name `
                -ErrorAction SilentlyContinue) -or
            (Test-Path -LiteralPath $installerSiblingState)
        ) {
            throw 'Installer accepted a sibling-prefix ValidationOnly state path.'
        }

        $spoofAction = New-ScheduledTaskAction `
            -Execute $powershell `
            -Argument '-NoProfile -NonInteractive -Command "exit 0"' `
            -WorkingDirectory $context.root
        $spoofTrigger = New-ScheduledTaskTrigger `
            -AtLogOn `
            -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
        $spoofTask = New-ScheduledTask `
            -Action $spoofAction `
            -Trigger $spoofTrigger `
            -Description 'COGNI_PUBLISHER_VALIDATION_TASK_V1'
        Register-ScheduledTask `
            -TaskName $context.task_name `
            -InputObject $spoofTask `
            -Force | Out-Null
        $context.task_registered = $true
        $spoofBefore = Get-TaskConfigurationFingerprint `
            -TaskName $context.task_name
        $spoofRejected = $false
        try {
            & $scripts.installer `
                -WorkspaceRoot $context.root `
                -Endpoint 'https://127.0.0.1:9/must-not-connect' `
                -IntervalSeconds 5 `
                -MaxBackoffSeconds 5 `
                -TaskName $context.task_name `
                -SecretPath $context.valid_secret `
                -StateDir $context.state_task `
                -PythonPath $context.fake_python `
                -DoNotStart `
                -ValidationOnly
        } catch {
            $spoofRejected = $_.Exception.Message -match 'exact Cogni ownership'
        }
        $spoofAfter = Get-TaskConfigurationFingerprint `
            -TaskName $context.task_name
        if (
            -not $spoofRejected -or
            $spoofBefore.Sha256 -ne $spoofAfter.Sha256
        ) {
            throw 'A same-marker task with a noncanonical action was overwritten.'
        }
        Unregister-ScheduledTask `
            -TaskName $context.task_name `
            -Confirm:$false `
            -ErrorAction Stop
        $context.task_registered = $false

        $installResult = & $scripts.installer `
            -WorkspaceRoot $context.root `
            -Endpoint 'https://127.0.0.1:9/must-not-connect' `
            -IntervalSeconds 5 `
            -MaxBackoffSeconds 5 `
            -TaskName $context.task_name `
            -SecretPath $context.valid_secret `
            -StateDir $context.state_task `
            -PythonPath $context.fake_python `
            -DoNotStart `
            -ValidationOnly
        $context.task_registered = $true
        $task = Get-ScheduledTask -TaskName $context.task_name -ErrorAction Stop
        if ([string]$task.State -eq 'Running') {
            throw 'The isolated validation task started despite -DoNotStart.'
        }
        if (@($task.Actions).Count -ne 1) {
            throw 'The validation task must contain exactly one action.'
        }
        if ($task.Description -ne 'COGNI_PUBLISHER_VALIDATION_TASK_V1') {
            throw 'The validation task does not carry the isolated ownership marker.'
        }
        $action = @($task.Actions)[0]
        if ($action.Execute -ne $powershell) {
            throw 'The validation task does not use Windows PowerShell.'
        }
        foreach ($expected in @(
            $scripts.runner,
            $context.root,
            $context.valid_secret,
            $context.state_task,
            $context.fake_python
        )) {
            if ($action.Arguments -notlike ('*{0}*' -f $expected)) {
                throw ('Scheduled task arguments omit {0}.' -f $expected)
            }
        }
        if (
            $action.Arguments -match '(?i)IncludeGpu' -or
            $action.Arguments -match '(?i)COGNI_MONITOR_INGEST_SECRET'
        ) {
            throw 'The scheduled task enables GPU telemetry or embeds a secret.'
        }
        if (@($task.Triggers).Count -ne 1 -or
            @($task.Triggers)[0].CimClass.CimClassName -ne
                'MSFT_TaskLogonTrigger') {
            throw 'The scheduled task does not have exactly one logon trigger.'
        }
        $trigger = @($task.Triggers)[0]
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $identitySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $triggerSid = (
            [Security.Principal.NTAccount]([string]$trigger.UserId)
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        $principalSid = (
            [Security.Principal.NTAccount]([string]$task.Principal.UserId)
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        if (
            [string]$task.TaskPath -cne '\' -or
            -not [bool]$trigger.Enabled -or
            $triggerSid -cne $identitySid -or
            $principalSid -cne $identitySid -or
            [string]$task.Principal.LogonType -cne 'Interactive' -or
            [string]$task.Principal.RunLevel -cne 'Limited'
        ) {
            throw 'The scheduled task principal or trigger is not exact.'
        }
        if ([string]$task.Settings.MultipleInstances -ne 'IgnoreNew') {
            throw 'The scheduled task duplicate-instance policy is not IgnoreNew.'
        }
        if (
            -not [bool]$task.Settings.StartWhenAvailable -or
            [int]$task.Settings.RestartCount -ne 999 -or
            [string]$task.Settings.RestartInterval -cne 'PT1M' -or
            [string]$task.Settings.ExecutionTimeLimit -cne 'PT0S' -or
            [bool]$task.Settings.DisallowStartIfOnBatteries -or
            [bool]$task.Settings.StopIfGoingOnBatteries
        ) {
            throw 'The scheduled task settings envelope is not exact.'
        }
        if ($installResult.SecretStorage -ne 'CURRENT_USER_DPAPI') {
            throw 'The installer did not report current-user DPAPI storage.'
        }
        if ($installResult.GpuTelemetry -ne 'DISABLED') {
            throw 'GPU telemetry must remain disabled in the validation task.'
        }
    }
} finally {
    $removed = $true
    try {
        $task = Get-ScheduledTask `
            -TaskName $context.task_name `
            -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Stop-ScheduledTask `
                -TaskName $context.task_name `
                -ErrorAction SilentlyContinue
            Unregister-ScheduledTask `
                -TaskName $context.task_name `
                -Confirm:$false `
                -ErrorAction Stop
        }
        $removed = $null -eq (
            Get-ScheduledTask `
                -TaskName $context.task_name `
                -ErrorAction SilentlyContinue
        )
    } catch {
        $removed = $false
        $message = ($_.Exception.Message -replace '[\r\n]+', ' ').Trim()
        $failures.Add(('scheduled_task_cleanup: {0}' -f $message))
    }
    $checks['scheduled_task_cleanup'] = $removed

    Remove-Item `
        -LiteralPath $context.root `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
    $checks['temporary_files_cleanup'] = -not (
        Test-Path -LiteralPath $context.root
    )
    if (-not $checks['temporary_files_cleanup']) {
        $failures.Add('temporary_files_cleanup: temporary root still exists')
    }

    try {
        $productionTaskAfter = Get-TaskConfigurationFingerprint `
            -TaskName $productionTaskName
        $productionUnchanged = (
            $productionTaskBefore.Exists -eq $productionTaskAfter.Exists -and
            $productionTaskBefore.Sha256 -eq $productionTaskAfter.Sha256
        )
        $checks['production_task_unchanged'] = $productionUnchanged
        if (-not $productionUnchanged) {
            $failures.Add(
                'production_task_unchanged: production task configuration changed'
            )
        }
    } catch {
        $checks['production_task_unchanged'] = $false
        $message = ($_.Exception.Message -replace '[\r\n]+', ' ').Trim()
        $failures.Add(('production_task_unchanged: {0}' -f $message))
    }
}

$observedCheckNames = @($checks.Keys | Sort-Object)
$inventoryBytes = [Text.Encoding]::UTF8.GetBytes(
    (($observedCheckNames -join "`n") + "`n")
)
$inventoryHasher = [Security.Cryptography.SHA256]::Create()
try {
    $observedCheckInventorySha256 = -join (
        $inventoryHasher.ComputeHash($inventoryBytes) |
            ForEach-Object { $_.ToString('x2') }
    )
} finally {
    $inventoryHasher.Dispose()
}
$inventoryValid = (
    $observedCheckNames.Count -eq $expectedCheckCount -and
    $observedCheckInventorySha256 -eq $expectedCheckInventorySha256
)
if (-not $inventoryValid) {
    $failures.Add('validation_inventory: PowerShell check inventory changed')
}
$failedChecks = @($checks.GetEnumerator() | Where-Object { -not $_.Value })
$record = [ordered]@{
    ok = (
        $failedChecks.Count -eq 0 -and
        $failures.Count -eq 0 -and
        $inventoryValid
    )
    checks = $checks
    passed = @($checks.GetEnumerator() | Where-Object { $_.Value }).Count
    total = $checks.Count
    failures = @($failures)
    validation_inventory = [ordered]@{
        expected = $expectedCheckCount
        observed = $observedCheckNames.Count
        expected_sha256 = $expectedCheckInventorySha256
        observed_sha256 = $observedCheckInventorySha256
        valid = $inventoryValid
    }
    isolation = [ordered]@{
        production_task_name_used = ($context.task_name -eq $productionTaskName)
        production_secret_path_used = (
            [IO.Path]::GetFullPath($context.valid_secret) -eq
            [IO.Path]::GetFullPath($productionSecretPath)
        )
        production_task_unchanged = [bool]$checks['production_task_unchanged']
        temporary_task_removed = [bool]$checks['scheduled_task_cleanup']
        temporary_files_removed = [bool]$checks['temporary_files_cleanup']
    }
}
$record | ConvertTo-Json -Compress -Depth 6
if (-not $record.ok) { exit 1 }
