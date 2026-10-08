#!/usr/bin/env bash
# Restore helpers (see docs/disaster-recovery.md). Each action is explicit; nothing is guessed.
#
#   infra/backup/restore.sh --pg FILE            restore the control plane DB (stop api/worker/beat first)
#   infra/backup/restore.sh --pki FILE           restore the PKI volume (CA + agent API certificate)
#   infra/backup/restore.sh --volume NAME FILE   restore one application volume (its containers must be stopped)
# Files ending in .age are decrypted with $AGE_IDENTITY (age -d -i).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
plain() {  # plain <file> -> path of a decrypted copy
  local f="$1"
  if [[ "$f" == *.age ]]; then
    [[ -n "${AGE_IDENTITY:-}" ]] || { echo "set AGE_IDENTITY to the age identity file" >&2; exit 2; }
    local out; out="$(mktemp)"; age -d -i "$AGE_IDENTITY" -o "$out" "$f"; echo "$out"
  else
    echo "$f"
  fi
}

case "${1:-}" in
  --pg)
    f="$(plain "$2")"
    CP=(docker compose -f "$ROOT/infra/control-plane.compose.yml" --env-file "$ROOT/.env")
    "${CP[@]}" stop api agent-api worker beat
    "${CP[@]}" exec -T postgres pg_restore -U udeploy -d udeploy --clean --if-exists --no-owner < "$f"
    "${CP[@]}" up -d
    ;;
  --pki)
    f="$(plain "$2")"
    docker volume create udeploy-cp_pki >/dev/null
    docker run --rm -i -v udeploy-cp_pki:/pki busybox:1.37 sh -c 'tar -C /pki -xzf - && chown -R 10001:10001 /pki' < "$f"
    ;;
  --volume)
    name="$2"; f="$(plain "$3")"
    if [[ -n "$(docker ps -q --filter volume="$name")" ]]; then
      echo "containers are using $name; stop them first (docker compose -p <project> stop)" >&2; exit 1
    fi
    docker volume inspect "$name" >/dev/null 2>&1 || docker volume create --label io.udeploy.managed=true "$name" >/dev/null
    docker run --rm -i -v "$name":/data busybox:1.37 sh -c 'tar -C /data -xzf -' < "$f"
    ;;
  *)
    sed -n '2,8p' "$0"; exit 2 ;;
esac
echo "restore done"
