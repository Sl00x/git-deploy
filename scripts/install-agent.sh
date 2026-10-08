#!/usr/bin/env bash
# Idempotent installation of the udeploy agent + edge proxy on a Docker host (run as root).
#
#   scripts/install-agent.sh --control-plane https://deploy.example.com \
#     --token udenr_xxx --registries registry.example.com[,ghcr.io] --acme-email ops@example.com
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE=/var/lib/udeploy-agent
IMAGE="${UDEPLOY_AGENT_IMAGE:-udeploy/agent:0.1.0}"
CP="" TOKEN="${UDEPLOY_ENROLL_TOKEN:-}" REGISTRIES="" ACME_EMAIL="" CA_BUNDLE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --control-plane|--url) CP="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --registries|--allowed-registries) REGISTRIES="$2"; shift 2 ;;
    --acme-email) ACME_EMAIL="$2"; shift 2 ;;
    --ca-bundle) CA_BUNDLE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$CP" && -n "$REGISTRIES" && -n "$ACME_EMAIL" ]] || {
  echo "usage: $0 --control-plane URL --token TOKEN --registries R1[,R2] --acme-email EMAIL" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

install -d -m 0700 "$STATE" "$STATE/secrets" "$STATE/projects" "$STATE/identity" "$STATE/docker-config"
install -d -m 0755 "$STATE/traefik"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -f "$ROOT/infra/docker/agent.Dockerfile" -t "$IMAGE" "$ROOT"
fi

if [[ ! -f "$STATE/identity/identity.json" ]]; then
  [[ -n "$TOKEN" ]] || { echo "--token is required for the first enrolment" >&2; exit 2; }
  extra=()
  if [[ -n "$CA_BUNDLE" ]]; then extra=(-v "$CA_BUNDLE:/ca.pem:ro"); fi
  docker run --rm -v "$STATE:$STATE" -e UDEPLOY_AGENT_STATE_DIR="$STATE" -e UDEPLOY_ENROLL_TOKEN="$TOKEN" \
    "${extra[@]}" "$IMAGE" enroll --url "$CP" ${CA_BUNDLE:+--ca-bundle /ca.pem}
else
  echo "==> already enrolled ($(cat "$STATE/identity/identity.json"))"
fi

umask 077
cat > "$ROOT/agent.env" <<ENV
UDEPLOY_AGENT_ALLOWED_REGISTRIES=${REGISTRIES}
UDEPLOY_ACME_EMAIL=${ACME_EMAIL}
UDEPLOY_AGENT_IMAGE=${IMAGE}
ENV

docker compose -f "$ROOT/infra/agent.compose.yml" --env-file "$ROOT/agent.env" up -d
echo "agent running. Pull credentials (read-only) for private registries:"
echo "  DOCKER_CONFIG=$STATE/docker-config docker login <registry>"
