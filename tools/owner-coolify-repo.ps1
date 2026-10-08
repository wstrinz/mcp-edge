# OWNER-RUN ONLY. Never executed by an agent.
# Existing authentication is used only in memory for fixed-origin HTTPS calls.
# Inspect has no mutations. Setup creates only a new disabled/unstarted Git
# application; actual target verification precedes later auto-deploy activation.
[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Setup')][string]$Mode = 'Inspect',
    [ValidatePattern('^[A-Za-z0-9-]{8,64}$')][string]$ServerUuid,
    [ValidatePattern('^[A-Za-z0-9-]{8,64}$')][string]$DestinationUuid,
    [ValidateRange(1, 2147483647)][int]$GithubSourceId,
    [ValidatePattern('^[A-Za-z0-9-]{8,64}$')][string]$GithubSourceUuid,
    [ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedCommit,
    [string]$SecretsPath = 'C:\Users\wstri\.config\ship\secrets.env'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'PowerShell 7.4+ is required.' }
$name = 'mcp-edge'
$repository = 'wstrinz/mcp-edge'
$branch = 'main'
$apiBase = 'https://app.stri.nz/api/v1'
$script:token = $null
$script:ownerConfirmed = $false
function Field($Object, [string]$Key) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Key]
    if ($null -ne $property) { return $property.Value }
}
function Safe($Value) { return [regex]::Replace([string]$Value, '[^\x20-\x7e]', '?') }
function Api([string]$Method, [string]$Path, $Body = $null) {
    $id = '[A-Za-z0-9-]{8,64}'
    $read = $Method -eq 'GET' -and ($Path -match '^/(version|servers|projects|applications|github-apps)$' -or $Path -match "^/servers/$id/destinations$" -or $Path -match "^/projects/$id/production$" -or $Path -match '^/github-apps/[0-9]+/repositories(/wstrinz/mcp-edge/branches)?$' -or $Path -match "^/applications/$id$")
    $write = $script:ownerConfirmed -and $Method -eq 'POST' -and $Path -in @('/projects', '/applications/private-github-app')
    if (-not ($read -or $write)) { throw 'API action is outside this reviewed setup scope.' }
    $uri = [uri]($apiBase + $Path)
    if ($uri.Scheme -ne 'https' -or $uri.DnsSafeHost -ne 'app.stri.nz' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'API origin validation failed.' }
    $options = @{ Uri = $uri; Method = $Method; MaximumRedirection = 0; NoProxy = $true; TimeoutSec = 30; SkipHttpErrorCheck = $true; Headers = @{ Authorization = 'Bearer ' + $script:token; Accept = 'application/json' } }
    if ($null -ne $Body) { $options.ContentType = 'application/json'; $options.Body = $Body | ConvertTo-Json -Depth 20 -Compress }
    try { $reply = Invoke-WebRequest @options } catch { throw 'Coolify request failed; raw errors, headers and bodies are suppressed.' }
    if ([int]$reply.StatusCode -lt 200 -or [int]$reply.StatusCode -ge 300) { throw "Coolify HTTP $([int]$reply.StatusCode). Stop; no mutation retries or access changes occur." }
    if ($reply.Content.Length -gt 4MB) { throw 'API response exceeded the bounded inspection size.' }
    if ($Path -eq '/version') {
        $text = $reply.Content.Trim().Trim('"')
        if ($text -notmatch '^[A-Za-z0-9._-]{1,100}$') { throw 'Unexpected version response.' }
        return $text
    }
    try { return $reply.Content | ConvertFrom-Json -Depth 40 } catch { throw 'Unexpected API JSON; raw data is suppressed.' }
}
try {
    Write-Host 'Owner-run preview: fixed HTTPS app.stri.nz; existing token in memory; no redirects/proxies or credential output.'
    Write-Host 'GET version/servers/projects/applications/github-apps; selected destination and source repo/branch metadata if supplied.'
    $config = @{}
    foreach ($line in [IO.File]::ReadLines($SecretsPath)) {
        if ($line -match '^\s*(?:export\s+)?(COOLIFY_API_URL|COOLIFY_API_TOKEN)\s*=\s*(.*?)\s*$') {
            $key = $Matches[1]; $value = $Matches[2]
            if ($config.ContainsKey($key)) { throw 'Duplicate required configuration key.' }
            if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) { $value = $value.Substring(1, $value.Length - 2) }
            $config[$key] = $value
        }
    }
    try { $configuredUri = [uri]$config['COOLIFY_API_URL'] } catch { throw 'Configured API URL cannot be parsed; value is suppressed.' }
    if ($configuredUri.Scheme -ne 'https' -or $configuredUri.DnsSafeHost -ne 'app.stri.nz' -or $configuredUri.Port -ne 443 -or $configuredUri.UserInfo -or $configuredUri.Query -or $configuredUri.Fragment -or $configuredUri.AbsolutePath -notin @('/', '/api/v1', '/api/v1/')) { throw 'Configured API URL does not match the verified HTTPS origin.' }
    $script:token = $config['COOLIFY_API_TOKEN']
    if (-not $script:token -or $script:token.Length -gt 4096 -or $script:token -match '\s') { throw 'Existing API token format is unsupported.' }
    $config.Clear(); $line = $null; $value = $null
    $version = Api 'GET' '/version'
    $servers = @(Api 'GET' '/servers')
    $projects = @(Api 'GET' '/projects')
    $applications = @(Api 'GET' '/applications')
    $sources = @(Api 'GET' '/github-apps')
    [pscustomobject]@{
        Version = $version
        Servers = @($servers | ForEach-Object { [pscustomobject]@{ Uuid = (Field $_ 'uuid'); Name = (Safe (Field $_ 'name')); Reachable = (Field $_ 'is_reachable'); Usable = (Field $_ 'is_usable') } })
        Projects = @($projects | ForEach-Object { [pscustomobject]@{ Uuid = (Field $_ 'uuid'); Name = (Safe (Field $_ 'name')) } })
        GithubSources = @($sources | ForEach-Object { [pscustomobject]@{ Id = (Field $_ 'id'); Uuid = (Field $_ 'uuid'); Name = (Safe (Field $_ 'name')); Installed = [bool](Field $_ 'installation_id'); SystemWide = (Field $_ 'is_system_wide') } })
        ExistingEdge = @($applications | Where-Object { (Field $_ 'name') -eq $name } | ForEach-Object { [pscustomobject]@{ Uuid = (Field $_ 'uuid'); Status = (Safe (Field $_ 'status')) } })
    } | ConvertTo-Json -Depth 5 | Write-Host
    if ($ServerUuid) {
        $selectedServers = @($servers | Where-Object { (Field $_ 'uuid') -eq $ServerUuid })
        if ($selectedServers.Count -ne 1) { throw 'Server identifier is not unique in this account.' }
        $destinations = @(Api 'GET' "/servers/$ServerUuid/destinations")
        $eligible = @($destinations | Where-Object { (Field $_ 'type') -eq 'standalone' -and (Field $_ 'server_uuid') -eq $ServerUuid -and (-not $DestinationUuid -or (Field $_ 'uuid') -eq $DestinationUuid) })
        [pscustomobject]@{ ServerUuid = $ServerUuid; Destinations = @($eligible | ForEach-Object { [pscustomobject]@{ Uuid = (Field $_ 'uuid'); Network = (Safe (Field $_ 'network')) } }) } | ConvertTo-Json -Depth 4 | Write-Host
    }
    if ($GithubSourceId) {
        $selectedSources = @($sources | Where-Object { (Field $_ 'id') -eq $GithubSourceId })
        if ($selectedSources.Count -ne 1 -or -not (Field $selectedSources[0] 'installation_id')) { throw 'Existing installed GitHub source is not uniquely verified.' }
        $selectedSource = $selectedSources[0]
        $repos = Api 'GET' "/github-apps/$GithubSourceId/repositories"
        $matchingRepos = @((Field $repos 'repositories') | Where-Object { (Field $_ 'full_name') -eq $repository })
        if ($matchingRepos.Count -ne 1) { throw 'Proposed repository is absent or inaccessible to this existing GitHub App. Publish it/add only its approved installation access first.' }
        if ((Field $matchingRepos[0] 'private') -ne $true) { throw 'The proposed repository is not verified private. No visibility or access changes occur.' }
        $branches = Api 'GET' "/github-apps/$GithubSourceId/repositories/wstrinz/mcp-edge/branches"
        $matchingBranches = @((Field $branches 'branches') | Where-Object { (Field $_ 'name') -eq $branch })
        if ($matchingBranches.Count -ne 1) { throw 'Deployment branch was not uniquely returned. No fallback or new branch is created.' }
        $commit = [string](Field (Field $matchingBranches[0] 'commit') 'sha')
        if ($commit -notmatch '^[a-fA-F0-9]{40}$') { throw 'Published branch commit is not verified.' }
        [pscustomobject]@{ GithubSourceId = $GithubSourceId; GithubSourceUuid = (Field $selectedSource 'uuid'); Repository = $repository; Branch = $branch; Commit = $commit; RepositoryAccessible = $true } | ConvertTo-Json -Compress | Write-Host
    }
    if ($Mode -eq 'Inspect') { return }
    if (-not $ServerUuid -or -not $GithubSourceId -or -not $GithubSourceUuid -or -not $ExpectedCommit) { throw 'Setup requires verified server/source IDs and exact published commit. No mutation occurred.' }
    if ($eligible.Count -ne 1 -or (Field $selectedServers[0] 'is_reachable') -ne $true -or (Field $selectedServers[0] 'is_usable') -ne $true) { throw 'A usable server and unique standalone destination are required.' }
    if ((Field $selectedSource 'uuid') -ne $GithubSourceUuid -or $commit -ne $ExpectedCommit) { throw 'Source identity or published commit differs from the reviewed choice.' }
    if (@($applications | Where-Object { (Field $_ 'name') -eq $name }).Count -gt 0) { throw 'An application already has this name. This helper never updates or replaces it.' }
    $matchingProjects = @($projects | Where-Object { (Field $_ 'name') -eq $name })
    if ($matchingProjects.Count -gt 1) { throw 'Project name is ambiguous.' }
    $compose = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\compose.yaml'))
    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '..\compose.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Setup preview: optional new $name project; new GitHub App application; repo=$repository branch=$branch commit=$commit server=$ServerUuid destination=$((Field $eligible[0] 'uuid')) compose=$sourceHash."
    Write-Host 'No domains, deployment, preview deployments, shared-network connection or auto-deploy activation. Coolify may clone/reload Compose asynchronously.'
    Write-Host 'Creation tracks branch HEAD. Verify the actual cloned commit against the reviewed published commit before later activation.'
    $phrase = "SET UP PRIVATE $repository $ExpectedCommit ON $ServerUuid"
    if ((Read-Host "Owner confirmation: type $phrase") -cne $phrase) { throw 'Owner did not confirm these exact configuration mutations.' }
    $script:ownerConfirmed = $true
    if ($matchingProjects.Count -eq 0) {
        $createdProject = Api 'POST' '/projects' @{ name = $name; description = 'Optional Wiskit MCP edge, GitHub repository auto-deploy preparation' }
        $projectUuid = Field $createdProject 'uuid'
    } else { $projectUuid = Field $matchingProjects[0] 'uuid' }
    if ($projectUuid -notmatch '^[A-Za-z0-9-]{8,64}$') { throw 'Project identity is unsupported; no retry occurs.' }
    $production = Api 'GET' "/projects/$projectUuid/production"
    $environmentUuid = Field $production 'uuid'
    if ($environmentUuid -notmatch '^[A-Za-z0-9-]{8,64}$') { throw 'Production environment identity is not verified.' }
    $payload = @{
        name = $name; description = "Inert deny-all repo starter; Compose SHA256 $sourceHash";
        project_uuid = $projectUuid; environment_uuid = $environmentUuid;
        server_uuid = $ServerUuid; destination_uuid = (Field $eligible[0] 'uuid');
        github_app_uuid = $GithubSourceUuid; git_repository = $repository; git_branch = $branch;
        git_commit_sha = 'HEAD'; build_pack = 'dockercompose'; base_directory = '/';
        docker_compose_location = '/compose.yaml'; docker_compose_raw = $compose;
        docker_compose_domains = @(); autogenerate_domain = $false;
        connect_to_docker_network = $false; is_auto_deploy_enabled = $false;
        is_preview_deployments_enabled = $false; instant_deploy = $false; use_build_secrets = $false
    }
    $created = Api 'POST' '/applications/private-github-app' $payload
    $applicationUuid = Field $created 'uuid'
    if ($applicationUuid -notmatch '^[A-Za-z0-9-]{8,64}$') { throw 'Application identity response is unsupported. Inspect the account before retrying any mutation.' }
    [pscustomobject]@{ ApplicationUuid = $applicationUuid; ProjectUuid = $projectUuid; Repository = $repository; Branch = $branch; PublishedCommit = $commit; InstantDeployRequested = $false; AutoDeployRequested = $false; DeploymentVerified = $false; MCPForwarding = $false; Next = 'Verify actual cloned/rendered source and generated environment once; then finalize auto-deploy and first start on this new UUID' } | ConvertTo-Json -Compress | Write-Host
} finally {
    $script:token = $null
    $script:ownerConfirmed = $false
    if (Get-Variable config -ErrorAction SilentlyContinue) { $config.Clear() }
}
