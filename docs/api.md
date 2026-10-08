# API REST — v1

OpenAPI : `GET /openapi.json` (et `/docs`) si `UDEPLOY_DOCS_ENABLED=true`. L'API agent n'est pas
publiée dans l'OpenAPI public.

## 1. Authentification

| Type | En-tête | Usage |
|---|---|---|
| Jeton utilisateur | `Authorization: Bearer udp_…` | administration, déploiements |
| Jeton CI | `Authorization: Bearer udci_…` | `POST /v1/ci/artifacts/published` uniquement, un projet |
| Webhooks | signature/jeton du provider | `/v1/webhooks/*` |
| Jeton d'enrôlement | corps de `POST /v1/agent/enroll` | usage unique, 1 h |
| mTLS | certificat client signé par la CA interne | API agent (listener 8443) |

Jetons opaques (256 bits), stockés uniquement hachés (SHA-256), affichés une seule fois.

## 2. RBAC (`apps/api/udeploy_api/auth.py`)

Rôle par organisation (`project_id` nul) ou limité à un projet.

| Permission | viewer | auditor | developer | deployer | admin | owner |
|---|---|---|---|---|---|---|
| `read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `audit.read` | | ✓ | | | ✓ | ✓ |
| `release.create` | | | ✓ | | ✓ | ✓ |
| `deploy` | | | ✓ | ✓ | ✓ | ✓ |
| `deploy.protected` (env. `requireApproval`) | | | | ✓ | ✓ | ✓ |
| `deploy.approve` | | | | ✓ | ✓ | ✓ |
| `project.write`, `secret.write`, `registry.write`, `host.write` | | | | | ✓ | ✓ |
| `org.admin` | | | | | | ✓ |

Règle des 4 yeux : le demandeur d'un déploiement ne peut pas l'approuver.
Une ressource non visible renvoie 404 (pas de distinction avec « inexistant »).

## 3. Conventions

- Erreurs : `{"error": {"code", "message", "details", "correlation_id"}}`. Codes : `unauthorized`,
  `forbidden`, `not_found`, `conflict`, `policy_violation`, `validation_error`, `payload_too_large`,
  `unsupported_media_type`, `rate_limited`, `internal_error` (jamais de texte d'exception interne).
- `X-Request-ID` : accepté s'il est valide (`[A-Za-z0-9._-]{8,64}`), sinon généré ; renvoyé et enregistré
  dans l'audit.
- Pagination : `limit` (1–200, défaut 50), `offset`, `order=asc|desc` ; réponse
  `{"items", "limit", "offset", "count"}`.
- `Idempotency-Key` sur `POST /v1/deployments` (portée : utilisateur).
- Corps JSON (`Content-Type: application/json`) ; manifeste aussi en YAML sur `PUT …/manifest`.

## 4. Routes

### Santé
| Méthode | Chemin | |
|---|---|---|
| GET | `/health/live` | processus vivant |
| GET | `/health/ready` | PostgreSQL + Redis, 503 sinon |

### Ingestion
| Méthode | Chemin | Auth | Notes |
|---|---|---|---|
| POST | `/v1/webhooks/github/{endpoint_id}` | `X-Hub-Signature-256` | 202 `accepted`/`ignored`/`rejected`/`duplicate` ; aucun déploiement |
| POST | `/v1/webhooks/gitlab/{endpoint_id}` | `X-Gitlab-Token` (+ `webhook-signature` si signing token) | idem ; idempotence via `Idempotency-Key` / `X-Gitlab-Event-UUID` |
| POST | `/v1/ci/artifacts/published` | `udci_` | 202 création, 200 répétition identique, 409 version réutilisée |

Corps de `/v1/ci/artifacts/published` :
```json
{"version": "1.5.0", "commit_sha": "<40 hex>", "tag": "v1.5.0", "branch": null,
 "build_id": "123", "build_url": "https://…",
 "artifacts": [{"service": "api", "registry": "registry-production", "image": "prod/inkerflow_api",
                "tag": "1.5.0", "digest": "sha256:…", "platform": "linux/amd64",
                "scan": {"status": "passed", "report_url": null}, "signed": true}]}
```

### Organisations, registres
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/v1/organizations` | membre |
| PATCH | `/v1/organizations/{org_id}` | `org.admin` (`allowed_domains`, `name`) |
| POST | `/v1/organizations/{org_id}/members` | `org.admin` |
| POST | `/v1/registries` | `registry.write` (mot de passe chiffré, jamais renvoyé) |
| GET | `/v1/registries?organization_id=` | `read` |

### Projets
| Méthode | Chemin | Permission |
|---|---|---|
| POST | `/v1/projects` | `project.write` (manifeste optionnel) |
| GET | `/v1/projects` | `read` |
| GET | `/v1/projects/{id}` | `read` (services, environnements) |
| PATCH | `/v1/projects/{id}` | `project.write` |
| PUT | `/v1/projects/{id}/manifest` | `project.write` — 422 `policy_violation` avec la liste des erreurs |
| POST | `/v1/projects/{id}/manifest/validate` | `read` — essai à blanc |
| POST | `/v1/projects/{id}/services` | `project.write` (fusionné dans le manifeste, même validation) |
| POST | `/v1/projects/{id}/environments` | `project.write` |
| GET | `/v1/projects/{id}/history?environment=` | `read` |
| PUT | `/v1/projects/{id}/environments/{env}/secrets/{path}` | `secret.write` — 204, écriture seule, 64 KiB max |
| GET | `/v1/projects/{id}/environments/{env}/secrets` | `read` — chemins et versions, jamais les valeurs |
| DELETE | `/v1/projects/{id}/environments/{env}/secrets/{path}` | `secret.write` |
| POST | `/v1/projects/{id}/webhook-endpoints` | `project.write` — URL + secret affiché une fois |
| POST | `/v1/projects/{id}/ci-tokens` | `project.write` — jeton affiché une fois |
| DELETE | `/v1/projects/{id}/ci-tokens/{token_id}` | `project.write` — révocation |

### Releases et déploiements
| Méthode | Chemin | Permission |
|---|---|---|
| POST | `/v1/releases` | `release.create` (même vérification registre que la CI) |
| GET | `/v1/releases?project_id=` · `/v1/releases/{id}` | `read` |
| POST | `/v1/deployments` | `deploy` (+ `deploy.protected`) ; corps `{project_id, environment, release_id}` |
| GET | `/v1/deployments/{id}` | `read` (inclut le plan, sans secrets) |
| POST | `/v1/deployments/{id}/approve` | `deploy.approve`, ≠ demandeur |
| POST | `/v1/deployments/{id}/cancel` | `deploy` |
| POST | `/v1/deployments/{id}/rollback` | `deploy` — nouvelle demande vers la release réussie précédente |
| GET | `/v1/deployments/{id}/events?after_id=` | `read` |
| GET | `/v1/deployments/{id}/logs` | `read` (sorties masquées) |

### Hôtes, audit
| Méthode | Chemin | Permission |
|---|---|---|
| POST | `/v1/hosts/enroll-token` | `host.write` |
| GET | `/v1/hosts?organization_id=` | `read` |
| GET | `/v1/hosts/{id}/health` | `read` |
| POST | `/v1/hosts/{id}/disable` | `host.write` — révocation immédiate du certificat |
| GET | `/v1/audit-events?organization_id=&action=&target_id=` | `audit.read` |

### Agent
| Méthode | Chemin | Listener |
|---|---|---|
| POST | `/v1/agent/enroll` | public — `{token, csr_pem}` → certificat, CA, `host_id`, `agent_api_url` |
| POST | `/v1/agent/heartbeat` | mTLS — faits de l'hôte |
| POST | `/v1/agent/tasks/claim?wait=` | mTLS — long poll ; `{"task": AgentTask | null}` |
| POST | `/v1/agent/tasks/{id}/events` | mTLS — `{state, message, log}` ; renvoie `cancel_requested` |
| POST | `/v1/agent/tasks/{id}/complete` | mTLS — `{outcome: succeeded|failed|rolled_back, running_digests, error}` (idempotent) |
| POST | `/v1/agent/renew` | mTLS — `{csr_pem}` |

Aucune route n'exécute de commande Docker arbitraire.
