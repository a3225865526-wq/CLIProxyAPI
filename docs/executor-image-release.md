# Executor image release

This workflow publishes an Executor image only. It has no SSH, VPS, Gateway,
Compose, database migration, or production deployment step.

## Inputs and source

Run `.github/workflows/release-executor.yml` manually after the reviewed workflow
is available on the repository default branch. Supply a full lowercase 40-digit
`source_commit` in the same repository and a version such as `pg03-rc1`.
The source Dockerfile and `.dockerignore` must match the reviewed workflow ref.
Source and workflow commits are recorded separately. Repository ownership is
restricted to `a3225865526-wq`; the proposed image repository is
`ghcr.io/a3225865526-wq/clearapi-executor`. Package access must be provisioned by
the repository owner before the first release. Registering or dispatching this
workflow is a separate authorized action.

## Build and verification

The workflow builds Linux amd64 once, loads that image, and verifies it before
GHCR login. It then pushes the same local image under a run-specific tag, resolves
the registry digest, pulls by digest, and repeats verification. No second build
occurs. SBOM and provenance are intentionally disabled for this initial release.
The image digest is a single-platform manifest digest, not its image/config ID
or its executable SHA256. Publication can succeed before a later verification
fails: a failed workflow's image must never be selected for deployment.

The Docker build context admits only module files and the cmd/internal/sdk source
trees, with runtime credentials and state excluded. The final application
directory contains only the executable, not a sample or live config. Runtime
configuration must be mounted at `/CLIProxyAPI/config.yaml`. The explicit
entrypoint is `/CLIProxyAPI/CLIProxyAPI`; the default command supplies that path.
Health checks require port 8317; a deployment choosing another port must override
the health check. Curl is provided by the runtime image.

Verification checks Linux amd64, OCI metadata, startup metadata, entrypoint,
command, healthcheck presence, application-directory contents, and the SHA256 of
the executable extracted from the final image. The disposable smoke container
uses synthetic empty configuration and `--network none`; it neither loads OAuth
credentials nor submits upstream requests. `/healthz` verifies liveness only.
This is not proof of PG03 policy, Pool readiness, billing, load capacity, or
compatibility with a particular Gateway release. Those remain separate gates.

Base images currently retain the existing Go 1.26/bookworm and Debian bookworm
tags. Exact base digests and dependency provenance are not claimed by this
initial release. Rollback must use the retained published digest, never rebuild
the old source to recreate an assumed identical image.

## Release artifact

A successful run uploads `executor-image-release.json` and places its contents
in the run summary. It records:

- image repository, registry digest, immutable image ref, platform manifest
  digest and local image/config ID;
- source repository, source commit, OCI revision, version and build date;
- final binary path and SHA256;
- workflow repository, path, commit, ref, run ID and attempt, and run URL;
- passed metadata, binary, platform and liveness checks;
- null SBOM and provenance fields.

The JSON is generated only from an actual verified publication. No sample JSON
with fabricated digest is committed. This artifact does not update the production
Release Manifest. A subsequent authorized deployment may consume it as the
Executor component identity in Manifest v2 after Gateway compatibility checks.
Retain both the artifact and referenced GHCR digest for rollback; the workflow
does not delete old images or state volumes.

## Local checks without building

Parse workflow YAML, inspect the dispatch-only trigger and pinned actions, run
`bash -n .github/scripts/verify-executor-image.sh`, and review `git diff --check`.
Do not run the verification script against production: it creates and removes
disposable containers. Runtime image checks require a separately authorized
build or a GitHub Actions run; passing static checks is not an image release.
