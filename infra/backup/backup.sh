#!/usr/bin/env bash
# Backups for udeploy. Idempotent, timestamped, optionally encrypted with age.
#
#   infra/backup/backup.sh --out /srv/backups [--control-plane] [--volumes] [--age-recipient age1...]
#
# --control-plane  pg_dump of the control plane DB + archive of the PKI volume (CA private key!).
#                  Run on the control plane host. The .env (master keys) is NOT copied: store it
#                  separately offline — without it encrypted secrets in the dump are unreadable.
# --volumes        every Docker volume labelled io.udeploy.managed=true on this host (app data).
#                  Run on each agent host. Files are copied while applications run: for databases
#                  prefer an application-level dump (pg_dump, mysqldump...) scheduled by the app.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="" DO_CP=0 DO_VOL=0 AGE_RECIPIENT="${UDEPLOY_BACKUP_AGE_RECIPIENT:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --control-plane) DO_CP=1; shift ;;
    --volumes) DO_VOL=1; shift ;;
    --age-recipient) AGE_RECIPIENT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$OUT" && $((DO_CP + DO_VOL)) -gt 0 ]] || { echo "usage: $0 --out DIR [--control-plane] [--volumes]" >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$OUT/$STAMP"
umask 077
mkdir -p "$DEST"

seal() {  # seal <file>: encrypt with age when a recipient is configured, then checksum
  local f="$1"
  if [[ -n "$AGE_RECIPIENT" ]]; then
    age -r "$AGE_RECIPIENT" -o "$f.age" "$f" && rm -f "$f" && f="$f.age"
  fi
  sha256sum "$f" >> "$DEST/SHA256SUMS"
}

if [[ $DO_CP -eq 1 ]]; then
  CP=(docker compose -f "$ROOT/infra/control-plane.compose.yml" --env-file "$ROOT/.env")
  echo "==> control plane database"
  "${CP[@]}" exec -T postgres pg_dump -U udeploy -d udeploy -Fc > "$DEST/controlplane.pgdump"
  seal "$DEST/controlplane.pgdump"
  echo "==> PKI volume (contains the CA private key)"
  docker run --rm -v udeploy-cp_pki:/pki:ro busybox:1.37 tar -C /pki -czf - . > "$DEST/pki.tgz"
  seal "$DEST/pki.tgz"
fi

if [[ $DO_VOL -eq 1 ]]; then
  echo "==> application volumes"
  for vol in $(docker volume ls -q --filter label=io.udeploy.managed=true); do
    docker volume inspect "$vol" --format '{{json .Labels}}' > "$DEST/volume-$vol.labels.json"
    docker run --rm -v "$vol":/data:ro busybox:1.37 tar -C /data -czf - . > "$DEST/volume-$vol.tgz"
    seal "$DEST/volume-$vol.tgz"
    echo "    $vol"
  done
fi

echo "backup written to $DEST"
