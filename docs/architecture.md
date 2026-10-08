# Architecture technique — udeploy (Phase 1)

udeploy est un moteur CI/CD auto-hébergé qui déploie des images OCI **par digest** sur des hôtes
Docker Engine + Compose V2, sans Kubernetes, Swarm ni Helm. Le code est découpé en trois plans
strictement séparés : **control plane**, **agent** (execution plane) et **runtime** applicatif.

## 1. Vue d'ensemble

```text
                          Internet
                             │ HTTPS (edge proxy du control plane)
        ┌────────────────────┼──────────────────────────────────────────┐
        │  CONTROL PLANE     ▼                                          │
        │  ┌──────────────────────────────┐   ┌───────────────────────┐ │
GitHub ─┼─►│ API publique (FastAPI)       │   │ Worker Celery + beat  │ │
GitLab ─┼─►│  /v1/webhooks/*  /v1/ci/*    │   │  relay_outbox (2 s)   │ │
CI     ─┼─►│  /v1/projects …  /v1/agent/  │   │  verify_release       │ │
Admin  ─┼─►│  enroll                      │   │  start_deployment     │ │
        │  └──────────┬───────────────────┘   │  reconcile (15 s)     │ │
        │             │ SQL (transactions)    └──────────┬────────────┘ │
        │      ┌──────▼──────┐   outbox    ┌──────────┐  │              │
        │      │ PostgreSQL  │◄───────────►│  Redis   │◄─┘              │
        │      └──────▲──────┘             └──────────┘                 │
        │             │                                                 │
        │  ┌──────────┴───────────────────┐                             │
        │  │ API agent (uvicorn mTLS 8443)│  CERT_REQUIRED, CA interne  │
        │  └──────────▲───────────────────┘                             │
        └─────────────┼─────────────────────────────────────────────────┘
                      │ mTLS sortant (long poll) — aucun port entrant sur l'hôte Docker
        ┌─────────────┼─────────────────────────────────────────────────┐
        │  HÔTE DOCKER│ (execution plane)                               │
        │  ┌──────────┴──────────┐  docker CLI (allow-list)  ┌────────┐  │
        │  │ udeploy-agent       │──────────────────────────►│ dockerd│  │
        │  │ (docker.sock monté) │                           └───┬────┘  │
        │  └─────────┬───────────┘                               │       │
        │            │ fichiers dynamiques (rename atomique)     │       │
        │  ┌─────────▼─────────┐  80/443   ┌─────────────────────▼─────┐ │
        │  │ Traefik (file     │◄─────────►│ RUNTIME : projet Compose  │ │
        │  │ provider)         │  réseau   │ <org>-<proj>-<env>-<h6>   │ │
        │  └───────────────────┘  _edge    │  réseaux _backend / _edge │ │
        │                                  │  volumes external         │ │
        │                                  │  secrets en fichiers RO   │ │
        │                                  └───────────────────────────┘ │
        └────────────────────────────────────────────────────────────────┘
```

| Composant | Code | Rôle |
|---|---|---|
| API publique | `apps/api/udeploy_api/main.py:create_app` | admin, webhooks, notifications CI, enrôlement |
| API agent | `apps/api/udeploy_api/main.py:create_agent_app`, `mtls.py` | protocole agent, servi **uniquement** par le listener mTLS |
| Worker | `apps/worker/udeploy_worker/` | relais outbox, vérification de releases, planification, réconciliation |
| Agent | `agent/udeploy_agent/` | exécute un `DeploymentPlan` typé, rien d'autre |
| Domaine | `packages/domain/` | manifeste, plan, nommage, machine à états |
| Planner | `packages/planner/` | politiques (`policy.py`) et construction de plan (`builder.py`) |
| Renderer | `packages/compose_renderer/` | Compose V2 durci + configuration Traefik |
| Sécurité | `packages/security/` | HMAC webhooks, AES-GCM, PKI, tokens, masquage |
| Providers | `packages/providers/` | client OCI Distribution, normalisation Git |

## 2. Flux de bout en bout

```text
git tag v1.5.0
 └► CI (templates/github-actions | templates/gitlab-ci)
     build multi-stage → tests → scan (Trivy) → SBOM → push registre → récupération des digests
 └► POST /v1/ci/artifacts/published      (Bearer udci_…, scope projet)
     • service connu, registre de l'organisation, image == <namespace>/<image du service>
     • version immuable : même contenu → 200 idempotent ; contenu différent → 409 (anti re-tag)
     • Release(pending_verification) + Artifacts + outbox "release.verify" (même transaction)
 └► worker verify_release  (OCIRegistryClient, services/releases.py)
     • GET manifest par digest : contenu re-hashé == digest demandé (DigestMismatch sinon)
     • index multi-arch → manifeste de la plateforme demandée → blob de config re-hashé
     • label org.opencontainers.image.revision == commit_sha (s'il est présent)
     • le tag pointe toujours vers ce digest (sinon « tag moved » → échec)
     • ManifestNotFound / RegistryUnavailable → retries bornés avec backoff, puis verification_failed
     • verified → déploiement auto des environnements autoDeploy dont les règles tag/branche matchent
       (jamais par-dessus une release plus récente : protection hors ordre)
 └► POST /v1/deployments  (ou auto)  services/deployments.py:request_deployment
     • gates : release vérifiée, règles d'environnement, scan « passed », signature (fail closed)
     • requireApproval → awaiting_approval ; approbation par une autre personne (4 yeux)
     • queued + outbox "deployment.start"
 └► worker start_deployment
     • verrou ligne Environment FOR UPDATE + index unique partiel (1 déploiement actif / env)
     • arbitrage : un auto-déploiement plus ancien est annulé (superseded)
     • choix d'hôte : hôte épinglé (volumes) sinon hôte en ligne du pool
     • DeploymentPlan immuable (JSON canonique + sha256) persisté, AgentTask pending
 └► agent : POST /v1/agent/tasks/claim (mTLS, long poll ≤ 25 s)
     • enveloppe = plan + sha256 + valeurs des secrets référencés (uniquement cet environnement)
     • re-validation locale (sha256, AgentPolicy) avant tout appel Docker
     preparing   : secrets écrits (fichiers), volumes external créés, compose.yml rendu
     pulling     : docker pull <registry>/<path>@sha256:… (3 essais) — la release saine tourne encore
     verifying   : RepoDigests local contient le digest
     starting    : docker compose -p <projet> -f releases/<deployment>/compose.yml up -d --remove-orphans
     healthchecking : conteneurs running, healthcheck Docker, puis sonde HTTP depuis un conteneur
                   jetable confiné (busybox wget) sur le réseau <projet>_backend
     switching   : Traefik connecté à <projet>_edge, fichier dynamique écrit (tmp + fsync + rename)
     succeeded   │ échec/cancel après starting → rollback_pending → compose up de la release
                 │ précédente (compose.yml + secrets de son répertoire) → routes restaurées → rolled_back
```

## 3. Décisions d'architecture (ADR courts)

**ADR-1 — Agent sortant en mTLS, CA interne.** L'agent initie toutes les connexions ; aucun port Docker
n'est exposé. Enrôlement : jeton à usage unique (`POST /v1/hosts/enroll-token`, TTL 1 h), l'agent génère
sa clé EC P-256 localement et n'envoie qu'un CSR ; le control plane impose le sujet (SAN
`urn:udeploy:host:<id>`), certificat 90 jours. Identité = empreinte SHA-256 du certificat stockée dans
`docker_hosts.cert_fingerprint` ; révocation = `POST /v1/hosts/{id}/disable` (empreinte effacée), effet
immédiat sans CRL. Renouvellement automatique à < 30 jours via `/v1/agent/renew`.

**ADR-2 — Exposer le certificat pair sans en-tête HTTP.** Uvicorn vérifie le certificat client
(`CERT_REQUIRED`) mais ne l'expose pas à l'application. `MTLSH11Protocol` (`apps/api/udeploy_api/mtls.py`)
copie le certificat DER vérifié dans l'état ASGI *par connexion* (`request.state.tls_peer_cert_der`).
Aucun en-tête (p. ex. `X-Forwarded-Tls-Client-Cert`) n'est jamais lu : impossible à usurper depuis le réseau.

**ADR-3 — Compose généré depuis un schéma.** Le `docker-compose.yml` d'un dépôt n'est jamais exécuté.
`udeploy_compose.renderer` produit un Compose déterministe avec un socle non désactivable :
`cap_drop: [ALL]`, `no-new-privileges`, `read_only` (désactivable si la politique l'autorise), `init`,
limites mémoire/CPU/PIDs, `ulimits`, tmpfs `noexec,nosuid,nodev`, rotation des logs, `pull_policy: never`,
image par digest, aucun `ports:`.

**ADR-4 — Le manifeste est une demande.** Validation serveur en trois couches
(`packages/planner/udeploy_planner/policy.py`) : `scan_hostile` (messages explicites pour `privileged`,
`network_mode`, `cap_add`, `docker.sock`, `ports`…), schéma Pydantic `extra="forbid"` partout,
`PlatformPolicy` (stratégies supportées, plafonds de ressources, uid 0 interdit, domaines autorisés de
l'organisation, hôtes réservés). L'agent revalide le plan (`AgentPolicy` : hôte cible, registres autorisés
**localement**, digest cohérent, nom de projet Compose recalculé) : une base du control plane compromise
ne suffit pas à lancer un conteneur privilégié.

**ADR-5 — Secrets.** Stockage AES-256-GCM (`udeploy_security/crypto.py`), AAD =
`udeploy:secret:v1:<org>:<projet>:<env>:<path>` : un chiffré copié vers un autre projet échoue à
l'authentification. Keyring `kid:base64,…` (premier = actif) ; `udeploy-admin rotate-master-key`
re-chiffre tout. Les valeurs ne sortent qu'à travers l'enveloppe de tâche de l'agent : `AgentTask.secrets`
est un `SecretStr` masqué par défaut, révélé uniquement par `AgentTask.wire_json()` dans la réponse
mTLS de claim. Dans le conteneur : fichiers `/run/secrets/<var>` et variable `<VAR>_FILE`, jamais la valeur
en variable d'environnement. Sur l'hôte : `<secrets_dir>/<projet>/<deployment_id>/<service>/<fichier>`,
répertoires 0700, fichiers 0400 (chown uid du service) ou 0444. Un répertoire par déploiement permet un
rollback avec les secrets exacts de la release restaurée.

**ADR-6 — Données persistantes.** Volumes nommés `<projet>_<nom>`, déclarés `external: true`, créés par
l'agent avec labels `io.udeploy.*`. Compose ne peut pas les supprimer et l'agent n'exécute jamais
`down -v`. Un environnement déployé est épinglé à son hôte (`environments.pinned_host_id`).

**ADR-7 — Fiabilité asynchrone.** Outbox transactionnelle (`outbox`) : l'intention de travail est écrite
dans la même transaction que le changement d'état ; `relay_outbox` la publie vers Celery
(at-least-once). Tâches idempotentes, `task_acks_late`, `reject_on_worker_lost`, retries avec backoff ;
après épuisement, le payload part dans `dead_letters`. `reconcile` : leases d'agent expirées → tâche
re-pending (ou échec après `task_max_attempts`), déploiements `queued` perdus → re-dispatch, déploiements
actifs sans progrès → `failed`, releases bloquées en vérification → re-vérification.

**ADR-8 — Réseaux par projet.** `<projet>_backend` (tous les services) et `<projet>_edge` (services
routés uniquement). Traefik rejoint chaque `_edge` (`docker network connect`) : pas de réseau partagé
entre projets, donc pas d'accès inter-projets par défaut. Traefik n'a pas accès à `docker.sock` (file
provider, pas de provider Docker).

**ADR-9 — Nommage.** `compose_project_name = <org>-<projet>-<env>-<hash6>` où le hash porte sur le
tuple non ambigu : `("a-b","c")` et `("a","b-c")` ne collisionnent pas ; longueur ≤ 63.
Images : `<registry>/<namespace>/<repo>_<service>`, tags normalisés, déploiement par digest uniquement.

## 4. Modèle de données (PostgreSQL, `apps/api/udeploy_api/models.py`)

| Table | Contenu |
|---|---|
| `organizations` | slug, `allowed_domains` |
| `users`, `memberships`, `api_tokens` | identités, rôle par organisation ou par projet, jetons hachés SHA-256 |
| `projects` | dépôt (provider + chemin, unique par org), manifeste approuvé + version |
| `services` | spec validée, nom d'image |
| `environments` | pool d'hôtes, règles branches/tags, autoDeploy, requireApproval, hôte épinglé, déploiement courant |
| `routes` | host + pathPrefix **uniques sur toute la plateforme** |
| `registries` | hôte, namespace, identifiants chiffrés |
| `secrets` | chiffrés AES-GCM, versionnés |
| `webhook_endpoints`, `webhook_deliveries` | secrets chiffrés ; livraisons avec clé d'idempotence unique |
| `ci_tokens` | jetons CI par projet (hachés) |
| `releases`, `artifacts` | version immuable, commit, digests, scan, vérification, label de révision |
| `docker_hosts`, `host_enroll_tokens` | empreinte de certificat, pool, last_seen, faits |
| `deployments`, `deployment_events` | état, plan + sha256, digests en cours ; journal masqué |
| `agent_tasks` | lease, tentatives, résultat (index unique partiel : une tâche ouverte par déploiement) |
| `audit_events` | actions auditées (détails nettoyés), correlation id |
| `outbox`, `dead_letters` | file transactionnelle et DLQ |

Index unique partiel `uq_deployment_active_env` sur `deployments(environment_id)` pour les états actifs :
garantie matérielle de sérialisation par environnement.

## 5. Machine à états (`packages/domain/udeploy_domain/states.py`)

```text
received → validated → (awaiting_approval →) queued → preparing → pulling → verifying
         → starting → healthchecking → switching → succeeded
            │ à partir de preparing : → rollback_pending → rolled_back | failed
            │ hors exécution : cancelled, blocked_by_policy, failed
```

États actifs : `preparing … switching`, `rollback_pending`. États terminaux : `succeeded`, `rolled_back`,
`failed`, `cancelled`, `blocked_by_policy`. Les transitions arrière sont interdites ; un agent qui rejoue
des étapes après redémarrage est journalisé sans faire reculer l'état.

## 6. Découpage par phases

- **Phase 1 (livrée)** : modèles + migrations, API, webhooks GitHub/GitLab, notifications CI, vérification
  OCI, RBAC, secrets chiffrés, agent mTLS, Compose durci, Traefik, stratégie `recreate` avec rollback
  automatique, réconciliation, tests unitaires/intégration/sécurité/e2e Docker réels.
- **Phase 2** : blue/green vérifiable, vérification cosign/provenance, promotion dédiée, freeze windows,
  sauvegardes orchestrées, observabilité (OpenTelemetry/Prometheus).
- **Phase 3** : génération CI, `managed_build` isolé, UI, environnements de preview, multi-hôtes avec
  ordonnancement explicite, providers SOPS/Vault, OIDC/MFA.

Voir `docs/limitations.md` pour le détail de ce qui n'est pas implémenté.
