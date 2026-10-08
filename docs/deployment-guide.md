# Guide de déploiement — VPS Debian/Ubuntu

Cible Phase 1 : **un VPS** portant le control plane et l'agent (les deux peuvent être séparés : l'agent
n'a besoin que d'un accès sortant HTTPS vers le control plane). Appliquer d'abord le durcissement de
`docs/runbook.md`.

## 1. Prérequis

- Debian 12 / Ubuntu 24.04, Docker Engine ≥ 24 avec le plugin Compose V2 (`docker compose version`).
- Un nom DNS pour le control plane (ex. `deploy.example.com`) et, pour les agents distants, un nom joignable
  sur le port 8443 (ex. `agents.deploy.example.com`).
- Pare-feu : 80/443 publics, 8443 ouvert aux IP des hôtes agents uniquement.

## 2. Control plane

Fichiers : `infra/control-plane.compose.yml`, `scripts/bootstrap-control-plane.sh`.

```bash
git clone <ce dépôt> /opt/udeploy && cd /opt/udeploy
sudo ./scripts/bootstrap-control-plane.sh \
  --public-url https://deploy.example.com \
  --agent-api-name agents.deploy.example.com \
  --org acme --email ops@example.com --domain example.com
```

Le script est idempotent ; il effectue, dans l'ordre :

1. construction de l'image `udeploy/control-plane:0.1.0` si absente ;
2. génération de `.env` (mode 0600) s'il n'existe pas : mots de passe PostgreSQL/Redis aléatoires,
   `UDEPLOY_MASTER_KEYS` produit par `udeploy-admin gen-master-key`, URLs publiques et `UDEPLOY_RESERVED_HOSTS`
   (`.env.example` documente ces clés sans valeur sensible) ;
3. démarrage de postgres/redis puis `udeploy-admin migrate` (service one-shot `migrate`, Alembic) ;
4. `udeploy-admin init-pki --server-name agents.deploy.example.com` : CA interne + certificat serveur du
   listener agent dans le volume `udeploy-cp_pki` (monté sur `/var/lib/udeploy-pki`) ;
5. `docker compose -f infra/control-plane.compose.yml --env-file .env up -d` (api, agent-api mTLS, worker, beat) ;
6. `udeploy-admin bootstrap --org acme --email ops@example.com --domain example.com` : organisation,
   propriétaire, jeton API **affiché une seule fois** (`api_token=udp_…`) ;
7. attente de `/health/ready`.

Ré-exécuter le script conserve `.env`, la CA, la base et l'organisation (vérifié : la seconde exécution
affiche `keeping existing .env`, `CA already present`, `an active token already exists`).

Variables principales (`apps/api/udeploy_api/settings.py`, préfixe `UDEPLOY_`) :

| Variable | Rôle |
|---|---|
| `UDEPLOY_DATABASE_URL` | `postgresql+asyncpg://…` |
| `UDEPLOY_REDIS_URL` | broker Celery + rate limiting |
| `UDEPLOY_MASTER_KEYS` | keyring `kid:base64,…` (premier = actif) — **à sauvegarder hors serveur** |
| `UDEPLOY_PUBLIC_BASE_URL` | URL publique (URLs de webhooks) |
| `UDEPLOY_AGENT_API_URL` | URL mTLS communiquée aux agents |
| `UDEPLOY_PKI_DIR` | CA + certificat serveur agent |
| `UDEPLOY_RESERVED_HOSTS` | JSON, ex. `["deploy.example.com"]` : hôtes interdits aux applications |
| `UDEPLOY_DOCS_ENABLED` | `/docs` et `/openapi.json` |
| `UDEPLOY_AGENT_LEASE_SECONDS`, `UDEPLOY_TASK_MAX_ATTEMPTS`, `UDEPLOY_DEPLOYMENT_STUCK_AFTER_SECONDS` | réconciliation |
| `UDEPLOY_RELEASE_VERIFY_MAX_RETRIES`, `UDEPLOY_RELEASE_VERIFY_BACKOFF_SECONDS` | vérification registre |

Contrôle : `curl https://deploy.example.com/health/ready` → `{"status":"ready"}`.

## 3. Agent sur l'hôte Docker

Fichiers : `infra/agent.compose.yml` (agent + Traefik edge), `scripts/install-agent.sh`.

```bash
export UDEPLOY=https://deploy.example.com TOKEN=udp_…   # jeton admin
ORG=$(curl -s -H "Authorization: Bearer $TOKEN" $UDEPLOY/v1/organizations | jq -r '.items[0].id')
curl -s -X POST $UDEPLOY/v1/hosts/enroll-token -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG\",\"host_name\":\"vps-1\",\"pool\":\"production-docker\"}"
# → {"token":"udenr_…","expires_at":…}   (usage unique, 1 h)

# sur l'hôte Docker
# identifiants PULL-ONLY, dans la config Docker propre à l'agent (DOCKER_CONFIG de infra/agent.compose.yml)
sudo DOCKER_CONFIG=/var/lib/udeploy-agent/docker-config docker login registry.example.com
sudo ./scripts/install-agent.sh --url $UDEPLOY --token udenr_… \
  --allowed-registries registry.example.com --acme-email ops@example.com
```

`install-agent.sh` lance `udeploy-agent enroll --url … --token …` (clé générée localement, seul le CSR
est envoyé), puis démarre `infra/agent.compose.yml`.

Variables de l'agent (`agent/udeploy_agent/config.py`) :

| Variable | Défaut | Rôle |
|---|---|---|
| `UDEPLOY_AGENT_ALLOWED_REGISTRIES` | (obligatoire) | registres autorisés **localement** |
| `UDEPLOY_AGENT_STATE_DIR` | `/var/lib/udeploy-agent` | identité, releases, secrets |
| `UDEPLOY_AGENT_SECRETS_DIR` | `<state>/secrets` | fichiers de secrets montés dans les conteneurs |
| `UDEPLOY_AGENT_TRAEFIK_CONTAINER` | `udeploy-traefik` | conteneur proxy à connecter aux réseaux `_edge` |
| `UDEPLOY_AGENT_TRAEFIK_DYNAMIC_DIR` | `<state>/traefik` | répertoire du file provider |
| `UDEPLOY_AGENT_CERT_RESOLVER` | `letsencrypt` | resolver ACME des routes TLS |
| `UDEPLOY_AGENT_PROBE_IMAGE` | `busybox:1.37` | image des sondes HTTP (épingler par digest en prod) |
| `UDEPLOY_AGENT_KEEP_RELEASES` | `5` | releases (et secrets) conservées pour rollback |
| `UDEPLOY_AGENT_API_URL` | issu de l'enrôlement | surcharge de l'URL mTLS |

**Important** : `/var/lib/udeploy-agent` doit être monté **au même chemin** sur l'hôte et dans le
conteneur agent : le démon Docker résout les chemins `secrets.file` du Compose sur l'hôte. Prévoir un
`stop_grace_period` long pour l'agent (un déploiement en cours n'est pas interrompu proprement sinon).

Contrôle : `GET /v1/hosts?organization_id=$ORG` → `"online": true`.

## 4. Exemple complet : trois services (`templates/manifests/inkerflow.udeploy.yaml`)

```bash
H="Authorization: Bearer $TOKEN"; J='Content-Type: application/json'
# registre (identifiants de lecture pour la vérification des digests)
curl -s -X POST $UDEPLOY/v1/registries -H "$H" -H "$J" -d "{\"organization_id\":\"$ORG\",
  \"name\":\"registry-production\",\"host\":\"registry.example.com\",\"namespace\":\"prod\",
  \"username\":\"udeploy-read\",\"password\":\"…\"}"
# projet
P=$(curl -s -X POST $UDEPLOY/v1/projects -H "$H" -H "$J" -d "{\"organization_id\":\"$ORG\",
  \"slug\":\"inkerflow\",\"name\":\"Inkerflow\",\"source_provider\":\"gitlab\",
  \"repository\":\"group/inkerflow\"}" | jq -r .id)
# manifeste approuvé (YAML accepté) ; essai à blanc : POST /v1/projects/$P/manifest/validate
curl -s -X PUT $UDEPLOY/v1/projects/$P/manifest -H "$H" -H 'Content-Type: application/yaml' \
  --data-binary @templates/manifests/inkerflow.udeploy.yaml
# secrets (écriture seule)
curl -s -X PUT $UDEPLOY/v1/projects/$P/environments/production/secrets/inkerflow/prod/database-url \
  -H "$H" -H "$J" -d '{"value":"postgres://…"}'
# webhook (secret affiché une fois) et jeton CI (affiché une fois)
curl -s -X POST $UDEPLOY/v1/projects/$P/webhook-endpoints -H "$H" -H "$J" -d '{"provider":"gitlab"}'
curl -s -X POST $UDEPLOY/v1/projects/$P/ci-tokens -H "$H" -H "$J" -d '{"name":"gitlab-ci"}'
```

Configurer le webhook dans GitHub (URL + secret, content type `application/json`) ou GitLab (URL +
« Secret token » ; ajouter un signing token si disponible, transmis via `signing_secret`).

### CI

- GitHub Actions : copier `templates/github-actions/udeploy-release.yml` dans `.github/workflows/`.
- GitLab CI : inclure `templates/gitlab-ci/udeploy-release.gitlab-ci.yml`.

Droits requis :

| Secret / variable | Portée |
|---|---|
| `UDEPLOY_URL` | URL publique du control plane |
| `UDEPLOY_CI_TOKEN` | jeton `udci_…` : un projet, publication de releases **uniquement** |
| `REGISTRY_USERNAME` / `REGISTRY_PASSWORD` | compte **push-only** sur le namespace du projet |
| Permissions GitHub | `contents: read`, `packages: write`, `id-token: write` (cosign keyless) |
| GitLab | variables **masquées et protégées** (disponibles seulement sur tags/branches protégés) |

Aucun identifiant de production (secrets applicatifs, accès hôte) ne va dans le dépôt ni dans la CI.

## 5. Opérations courantes

```bash
REL=$(curl -s "$UDEPLOY/v1/releases?project_id=$P&limit=1" -H "$H" | jq -r '.items[0].id')
# déployer (Idempotency-Key recommandé pour les retries client)
D=$(curl -s -X POST $UDEPLOY/v1/deployments -H "$H" -H "$J" -H 'Idempotency-Key: rel-1.5.0-prod' \
  -d "{\"project_id\":\"$P\",\"environment\":\"production\",\"release_id\":\"$REL\"}" | jq -r .id)
# approbation par une AUTRE personne (rôle deployer/admin/owner)
curl -s -X POST $UDEPLOY/v1/deployments/$D/approve -H "Authorization: Bearer $OTHER_TOKEN"
# suivi
curl -s "$UDEPLOY/v1/deployments/$D/events?after_id=0" -H "$H"
curl -s $UDEPLOY/v1/deployments/$D/logs -H "$H"
curl -s $UDEPLOY/v1/deployments/$D -H "$H" | jq '{state,error,running_digests}'
# annuler (avant exécution : cancelled ; pendant : rollback par l'agent)
curl -s -X POST $UDEPLOY/v1/deployments/$D/cancel -H "$H"
# rollback : redéploie la release réussie précédente, par digest, sans approbation
curl -s -X POST $UDEPLOY/v1/deployments/$D/rollback -H "$H"
# historique
curl -s "$UDEPLOY/v1/projects/$P/history?environment=production" -H "$H"
```

Promotion staging → production : déployer le **même** `release_id` en production (mêmes digests, aucun
rebuild) ; la release doit satisfaire les règles de tags de l'environnement.
