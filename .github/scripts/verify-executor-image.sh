#!/usr/bin/env bash
# Verify only disposable CI images/containers; never contacts production.
set -euo pipefail
image=${1:?Usage: verify-executor-image.sh IMAGE}
: "${SOURCE_COMMIT:?}" "${SOURCE_URL:?}" "${RELEASE_VERSION:?}" "${BUILD_DATE:?}"
work=$(mktemp -d)
container=
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT

docker image inspect "$image" > "$work/image.json"
python3 - "$work/image.json" <<'PY'
import json, os, sys
image = json.load(open(sys.argv[1]))[0]
assert image["Os"] == "linux" and image["Architecture"] == "amd64", "wrong platform"
config = image["Config"]
labels = config.get("Labels") or {}
for label, env in {
    "org.opencontainers.image.revision": "SOURCE_COMMIT",
    "org.opencontainers.image.source": "SOURCE_URL",
    "org.opencontainers.image.version": "RELEASE_VERSION",
    "org.opencontainers.image.created": "BUILD_DATE",
}.items():
    assert labels.get(label) == os.environ[env], "metadata mismatch: " + label
assert config["Entrypoint"] == ["/CLIProxyAPI/CLIProxyAPI"], "unexpected entrypoint"
assert config["Cmd"] == ["--config", "/CLIProxyAPI/config.yaml"], "unexpected command"
assert config.get("Healthcheck", {}).get("Test"), "missing healthcheck"
for value in config.get("Env", []):
    name = value.split("=", 1)[0]
    assert not any(s in name for s in ("SECRET", "TOKEN", "PASSWORD", "POLICY_KEY", "PROOF_KEY")), "embedded credential variable"
PY

# Extract the actual final-image binary without running it or mounting source.
container=$(docker create --network none "$image")
docker cp "$container:/CLIProxyAPI/CLIProxyAPI" "$work/CLIProxyAPI"
docker export "$container" > "$work/rootfs.tar"
python3 - "$work/rootfs.tar" <<'PY'
import tarfile, sys
with tarfile.open(sys.argv[1]) as archive:
    paths = {m.name.lstrip("./").rstrip("/") for m in archive.getmembers()}
assert "CLIProxyAPI/CLIProxyAPI" in paths
unexpected = {p for p in paths if p.startswith("CLIProxyAPI/") and p != "CLIProxyAPI/CLIProxyAPI"}
assert not unexpected, "unexpected application files: " + repr(sorted(unexpected))
PY
binary_sha=$(sha256sum "$work/CLIProxyAPI" | cut -d ' ' -f1)
image_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["Id"])' "$work/image.json")
docker rm "$container" >/dev/null
container=

# No OAuth data, Pool state, upstream request, or outbound network is used.
mkdir "$work/auths"
cat > "$work/config.yaml" <<'YAML'
config-version: 8
server:
  host: "127.0.0.1"
  port: 8317
oauth:
  auth-dir: /tmp/executor-auths
management:
  disable-control-panel: true
YAML
container=$(docker run -d --network none \
  --mount "type=bind,src=$work/config.yaml,dst=/CLIProxyAPI/config.yaml,readonly" \
  --mount "type=bind,src=$work/auths,dst=/tmp/executor-auths" \
  "$image" --config /CLIProxyAPI/config.yaml --local-model)
healthy=false
for attempt in {1..30}; do
  if docker exec "$container" curl --fail --silent --max-time 2 http://127.0.0.1:8317/healthz > "$work/health.json"; then
    healthy=true
    break
  fi
  [[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]] || break
  sleep 1
done
if [[ "$healthy" != true ]]; then
  docker logs "$container"
  echo 'Executor health verification failed' >&2
  exit 1
fi
python3 - "$work/health.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1])) == {"status": "ok"}, "unexpected health response"
PY
docker logs "$container" > "$work/startup.log" 2>&1
grep -F "CLIProxyAPI Version: $RELEASE_VERSION, Commit: $SOURCE_COMMIT, BuiltAt: $BUILD_DATE" "$work/startup.log" >/dev/null
printf '%s\n' "$binary_sha" > executor-binary.sha256
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'binary_sha256=%s\nimage_id=%s\n' "$binary_sha" "$image_id" >> "$GITHUB_OUTPUT"
fi
printf 'Verified %s; binary SHA256 %s\n' "$image" "$binary_sha"
