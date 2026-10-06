# One-time repository auto-deploy setup

> **Phase 2 note (2026-10-05).** `compose.yaml` now describes the real edge: service
> `edge`, `EDGE_MODE=edge`, port 8080 exposed to the Coolify proxy network and a named
> volume `edge-data`. The inert-runtime statements below (no network, no domain, no
> mounts) describe the earlier package. The owner helper still creates the
> application with no domain; after creation set the `edge` service domain to
> `https://mcp.app.stri.nz:8080` and the `EDGE_ENROLL_CODE` secret, then follow the
> README's deployment steps. Verify the rendered Compose before enabling auto-deploy.

The preferred route is the owner's existing ordinary Coolify workflow:
GitHub repository -> existing Coolify GitHub App -> application -> Docker build
on the selected server -> automatic deployment on the selected branch.

The owner approved private `wstrinz/wiskit-mcp-edge`, branch `main`, for
publication on 2026-10-05. Recommended pending Coolify choices: dedicated
project/application `wiskit-mcp-edge`, production environment, base `/`,
Docker Compose build pack, Compose `/compose.yaml`, root Dockerfile. Select the
actual server and standalone destination from the owner's existing account;
none of their identifiers is known in this task.

## What was inspected

Current Wiskit main has root AGENTS.md and LF conventions. Its tree contains no
root Docker/Coolify deployment definition or `.agents/` directory. No Wulfram
repository or shared service was inspected. The connected GitHub repository
search did not return an existing `wiskit-mcp-edge` repository; this is not proof
that no inaccessible repository exists.

Coolify official documentation supports GitHub App auto-deploy and selected
repository access. Existing installation access must already include the new
repository. If it does not, the owner adds that one repository to the existing
installation after approval; the helper does not create an app, key, token or
installation, expand permissions, or edit webhook/DNS/firewall settings.

- [GitHub App auto-deploy](https://coolify.io/docs/applications/sources/github/auto-deploy)
- [GitHub App repository access](https://coolify.io/docs/applications/sources/github/app)
- [Docker Compose applications](https://coolify.io/docs/applications/builds/docker-compose)

## Minimal owner flow

1. Publish this reviewed package through the existing authorized GitHub
   connection using the approved private repository and `main` branch.
2. The owner runs `tools/owner-coolify-repo.ps1 -Mode Inspect`. It reads the
   existing Ship Coolify settings only in memory, validates the fixed HTTPS
   origin `app.stri.nz`, and reports sanitized server/project/source identifiers.
   No credential values or raw API bodies are printed. If necessary, repeat
   inspection with the exact server UUID and existing numeric GitHub source ID
   to verify the source's repository/branch access.
   The helper also requires GitHub to report the proposed repository as private.
3. After the repository is published, pass those identifiers, the exact source
   UUID and the verified published `main` commit to `-Mode Setup`. The helper
   previews and requires one typed owner confirmation, creates only this named
   project if absent and a new **unstarted** application with auto-deploy off.
4. Verify the actual cloned source/rendered Compose and generated environment
   once. Then finalize that new application's auto-deploy setting and queue the
   first build. The exact target-specific verification/finalization step is
   pending the inspection report; it must not be assumed to have passed.
5. Record application/project/source/server/destination IDs and deployed commit
   plus health. Authorized future pushes/merges to `main` deploy automatically.

First read-only command, run by the owner:

```powershell
pwsh -NoProfile -File .\tools\owner-coolify-repo.ps1 -Mode Inspect
```

Setup uses current official REST controller fields. GitHub source repository
and branch endpoints take the **numeric source ID**; application creation takes
the source's **UUID**. These are not the GitHub installation ID. The helper
verifies their relationship instead of substituting guessed identifiers.

## Reviewed application creation shape

One-time POST `/api/v1/applications/private-github-app`, with actual verified IDs:

```json
{
  "name": "wiskit-mcp-edge",
  "project_uuid": "<verified project UUID>",
  "environment_uuid": "<verified production environment UUID>",
  "server_uuid": "<verified server UUID>",
  "destination_uuid": "<verified standalone destination UUID>",
  "github_app_uuid": "<verified existing GitHub source UUID>",
  "git_repository": "wstrinz/wiskit-mcp-edge",
  "git_branch": "main",
  "git_commit_sha": "HEAD",
  "build_pack": "dockercompose",
  "base_directory": "/",
  "docker_compose_location": "/compose.yaml",
  "docker_compose_domains": [],
  "autogenerate_domain": false,
  "connect_to_docker_network": false,
  "is_auto_deploy_enabled": false,
  "is_preview_deployments_enabled": false,
  "instant_deploy": false,
  "use_build_secrets": false
}
```

The helper also supplies the reviewed `compose.yaml` as a plain
`docker_compose_raw` string. Applications use plain Compose here; the older
Compose **service** endpoint used base64. Coolify can asynchronously reload the
Compose file from Git even with instant deployment off. Treat creation as
configuration/clone activity, not proof of a running or healthy deployment.
The helper checks the current published branch commit, but creation tracks
`HEAD`; a later push can race cloning. Compare the actual cloned commit and
rendered files against the approved source before enabling auto-deploy.

After verification, the ordinary finalization is PATCH
`/api/v1/applications/<new UUID>` with `is_auto_deploy_enabled: true`, then POST
`/api/v1/applications/<new UUID>/start` for the initial deployment. No recurring
manual API operation is needed for subsequent branch pushes. Those writes are
not executed or implemented as an unchecked bypass in the prepared helper.

- [Current application API controller](https://github.com/coollabsio/coolify/blob/main/app/Http/Controllers/Api/ApplicationsController.php)
- [Current GitHub source API controller](https://github.com/coollabsio/coolify/blob/main/app/Http/Controllers/Api/GithubController.php)

## Remaining concrete verification

Actual Coolify/API version and configured GitHub source/webhook health are
unknown. Source access does not prove webhook delivery. Verify one real push to
the configured branch produces a deployment and that the expected commit starts.
Missing source access requires the owner's selected-repository adjustment, not
new persistent credentials or a guessed public-repository fallback.

Current official application and service parsers inject `env_file: [.env]`.
That file is not a mounted volume, but its generated contents still need proof
that only expected nonsecret metadata and deny-all mode reach this new runtime.
The earlier strict gate rejects unverified env files; do not bypass it blindly.
The actual target's rendered build/network/security settings, Linux compilation,
available build resources and effective runtime health are also unverified.

The root Compose omits an explicit image so current Coolify can supply a
resource-and-commit-specific image tag for Git-built Compose services. Verify
that behavior on the actual instance. Rollback changes an image, not persistent
data or configuration; this initial container has no mounts or application data.

Public hostname, TLS route, networking, persistent gateway identity, enrolled
origins, real Wiskit adapter and OAuth remain a later integration/activation
phase. Automatic deployment does not complete those features. The existing
`WiskitRelay` mailbox and all other projects stay outside this setup.
