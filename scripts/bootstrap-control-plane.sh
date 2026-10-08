#!/usr/bin/env bash
# Idempotent bootstrap of the udeploy control plane on one Docker host.
# Safe to re-run: existing .env, CA, database and organization are kept.
#
#   scripts/bootstrap-control-plane.sh \
#     --public-url https://deploy.example.com \
#     --agent-api-name deploy.example.com \
#     --org acme --email ops@example.com --app-domain example.com
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infra/control-plane.compose.yml")
IMAGE="${UDEPLOY_CP_IMAGE:-udeploy/control-plane:0.1.0}"
PUBLIC_URL="" AGENT_API_NAME="" ORG="" EMAIL="" APP_DOMAINS=() AGENT_API_BIND="0.0.0.0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --agent-api-name) AGENT_API_NAME="$2"; shift 2 ;;
    --org) ORG="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --app-domain|--domain) APP_DOMAINS+=("$2"); shift 2 ;;
    --agent-api-bind) AGENT_API_BIND="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PUBLIC_URL" && -n "$AGENT_API_NAME" && -n "$ORG" && -n "$EMAIL" ]] || {
  echo "usage: $0 --public-url URL --agent-api-name DNS --org SLUG --email EMAIL [--app-domain D]..." >&2; exit 2; }

rand() { openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-40; }

echo "==> image ${IMAGE}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -f "$ROOT/infra/docker/control-plane.Dockerfile" -t "$IMAGE" "$ROOT"
fi

ENV_FILE="$ROOT/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> generating $ENV_FILE (secrets stay on this host; back it up offline)"
  umask 077
  public_host="$(echo "$PUBLIC_URL" | sed -E 's#^https?://##; s#/.*$##')"
  cat > "$ENV_FILE" <<ENV
POSTGRES_PASSWORD=$(rand)
REDIS_PASSWORD=$(rand)
UDEPLOY_MASTER_KEYS=$(docker run --rm "$IMAGE" udeploy-admin gen-master-key)
UDEPLOY_PUBLIC_BASE_URL=${PUBLIC_URL}
UDEPLOY_AGENT_API_URL=https://${AGENT_API_NAME}:8443
UDEPLOY_RESERVED_HOSTS=["${public_host}","${AGENT_API_NAME}"]
UDEPLOY_AGENT_API_BIND=${AGENT_API_BIND}
UDEPLOY_LOG_JSON=true
ENV
else
  echo "==> keeping existing $ENV_FILE"
fi
set -a; source "$ENV_FILE"; set +a

echo "==> database, cache and migrations"
"${COMPOSE[@]}" --env-file "$ENV_FILE" up -d postgres redis
"${COMPOSE[@]}" --env-file "$ENV_FILE" run --rm migrate

echo "==> internal PKI (agent mTLS)"
"${COMPOSE[@]}" --env-file "$ENV_FILE" run --rm --no-deps api \
  udeploy-admin init-pki --server-name "$AGENT_API_NAME"

echo "==> services"
"${COMPOSE[@]}" --env-file "$ENV_FILE" up -d

echo "==> organization ${ORG}"
args=(udeploy-admin bootstrap --org "$ORG" --email "$EMAIL")
for d in "${APP_DOMAINS[@]}"; do args+=(--domain "$d"); done
"${COMPOSE[@]}" --env-file "$ENV_FILE" run --rm --no-deps api "${args[@]}"

echo "==> waiting for readiness"
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" --env-file "$ENV_FILE" exec -T api python -c \
      "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/health/ready').status!=200)" \
      2>/dev/null; then
    echo "control plane ready. Next: route ${PUBLIC_URL} to the api (infra/traefik/dynamic/control-plane.yml)"
    exit 0
  fi
  sleep 2
done
echo "control plane did not become ready; inspect: docker compose -f infra/control-plane.compose.yml logs" >&2
exit 1
