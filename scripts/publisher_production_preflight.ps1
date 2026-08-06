function Assert-CogniPublisherProductionHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Health,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSourceCommit
    )

    $canonicalOrigin = 'https://cogni-os-orchestrator.pages.dev'
    $expectedProject = 'cogni-os-orchestrator'
    $commit = $ExpectedSourceCommit.ToLowerInvariant()
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw 'Publisher preflight expected source commit is invalid.'
    }
    if (
        $Health.ok -isnot [bool] -or
        $Health.ok -ne $true -or
        [string]$Health.state -ne 'CONFIGURED'
    ) {
        throw 'Publisher preflight health is not CONFIGURED.'
    }
    if ($null -eq $Health.checks) {
        throw 'Publisher preflight health checks are missing.'
    }
    if (
        $Health.checks.runtime_configuration_ready -isnot [bool] -or
        $Health.checks.runtime_configuration_ready -ne $true -or
        [string]$Health.checks.storage_state -ne 'READY' -or
        [string]$Health.checks.deployment_attribution -ne 'BUILD_BOUND' -or
        $Health.checks.build_attribution_ready -isnot [bool] -or
        $Health.checks.build_attribution_ready -ne $true -or
        $Health.checks.operational_ingest_ready -isnot [bool] -or
        $Health.checks.operational_ingest_ready -ne $true -or
        $Health.checks.release_attribution_ready -isnot [bool] -or
        $Health.checks.release_attribution_ready -ne $false -or
        [string]$Health.checks.release_evidence_state -ne
            'API_EVIDENCE_REQUIRED' -or
        [string]$Health.checks.minimum_release_snapshot_schema -ne '1.2'
    ) {
        throw 'Publisher preflight health trust checks are not release-ready.'
    }
    $deployment = $Health.deployment
    if (
        $null -eq $deployment -or
        [string]$deployment.attribution -ne 'BUILD_BOUND' -or
        [string]$deployment.source_commit -ne $commit -or
        [string]$deployment.branch -ne 'main' -or
        [string]$deployment.project -ne $expectedProject -or
        [string]$deployment.environment -ne 'production' -or
        [string]$deployment.url -ne $canonicalOrigin
    ) {
        throw 'Publisher preflight deployment attribution does not match local source.'
    }

    try {
        $direct = [Uri]([string]$deployment.deployment_url)
    } catch {
        throw 'Publisher preflight deployment URL is invalid.'
    }
    $directHost = $direct.DnsSafeHost.ToLowerInvariant()
    if (
        $direct.Scheme -ne 'https' -or
        -not [string]::IsNullOrEmpty($direct.UserInfo) -or
        -not $direct.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($direct.Query) -or
        -not [string]::IsNullOrEmpty($direct.Fragment) -or
        $direct.AbsolutePath -ne '/' -or
        $directHost -eq ($expectedProject + '.pages.dev') -or
        -not $directHost.EndsWith('.' + $expectedProject + '.pages.dev')
    ) {
        throw 'Publisher preflight deployment URL is not a unique project deployment.'
    }

    return [pscustomobject]@{
        source_commit = $commit
        deployment_url = $direct.AbsoluteUri.TrimEnd('/')
        minimum_release_snapshot_schema = '1.2'
        operational_ingest = 'READY'
        release_readiness = 'NO_GO_API_EVIDENCE_REQUIRED'
    }
}
