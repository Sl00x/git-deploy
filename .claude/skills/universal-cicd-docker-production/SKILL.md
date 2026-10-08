---
name: universal-cicd-docker-production
version: 1.0.0
description: Concevoir et implémenter un moteur CI/CD universel self-hosted avec FastAPI, GitHub/GitLab, registres OCI, et déploiements Docker/Compose sécurisés pour la production, sans Kubernetes.
---

# SKILL — Universal CI/CD Engine : Docker Production Only

## 0. Rôle et mission

Tu es architecte logiciel principal, expert DevSecOps, Python/FastAPI, Docker Engine, Docker Compose, OCI, réseaux Linux, Zero Trust et CI/CD. Construis un **produit fonctionnel**, pas une démonstration ni une interface factice. Objectif : une plateforme auto-hébergée, multi-organisations, multi-projets et multi-services, où des événements GitHub/GitLab déclenchent des builds OCI puis des déploiements sécurisés sur des **serveurs Docker en production**. **Interdiction d'utiliser Kubernetes**, ses ressources ou Helm. La plateforme doit rester portable et modulaire.

Toute automatisation doit être explicite, traçable, idempotente, testée, sécurisée par défaut et configurable par projet. Ne jamais demander à l'utilisateur de placer des identifiants de production dans les dépôts sources. Ne jamais exposer le socket Docker à Internet ni monter `/var/run/docker.sock` dans l'API publique ou un conteneur applicatif.

## 1. Fonctionnement cible

```text
GitHub / GitLab (push, tag, release, pipeline)
  └─► HTTPS Webhook Ingress (signature + auth + anti-rejeu)
       └─► Event Normalizer / Policy Engine / Queue
            ├─► CI externe (GitHub Actions / GitLab CI) ─► OCI Registry
            └─► Build Worker isolé (optionnel; BuildKit rootless)
                          └─► OCI Registry
                                 └─► Digest verification / security gates
                                      └─► Deployment Planner
                                           └─► Agent mTLS sortant sur chaque hôte Docker
                                                └─► Docker Compose Project isolé
                                                     ├─► reverse proxy HTTPS
                                                     ├─► réseaux privés
                                                     ├─► secrets montés
                                                     └─► health checks / metrics / rollback
```

**Deux modes supportés :**
- `external_ci` (MVP conseillé) : GitHub Actions ou GitLab CI construit, teste, scanne, pousse les images et appelle l'API de notification **après confirmation du push**. Ne jamais déployer simplement parce qu'un événement `push` est arrivé dans Git.
- `managed_build` : des workers de build non privilégiés construisent les images dans une zone séparée des machines de production, publient et attestent les images. Ne pas compiler du code arbitraire sur les hôtes de production.

## 2. Stack technique obligatoire

- Python 3.13+, FastAPI, Pydantic v2, SQLAlchemy 2.x async, Alembic.
- PostgreSQL : métadonnées, audit, versions, plan d'exécution, locks de déploiement.
- Redis + Celery : traitement asynchrone avec tâches rejouables, backoff et DLQ.
- Docker Engine + Docker Compose V2 pour les applications et le runtime. Adapter version/compatibilité aux serveurs gérés.
- API HTTP REST documentée en OpenAPI, webhooks distincts des endpoints administratifs.
- Agent déployé par hôte Docker, authentification mutuelle mTLS, canal sortant vers control plane recommandé (polling long ou WebSocket sécurisé). Pas de SSH root automatique ni exposition du daemon TCP sans garanties.
- Traefik (ou Caddy interchangeable via interface) pour routage DNS, TLS ACME, middlewares; ne pas rendre l'UI ou les API internes publiques par défaut.
- OpenTelemetry, Prometheus, Grafana et Loki en modules optionnels.
- SOPS + age / Vault comme providers de secrets, avec backend local chiffré uniquement si correctement conçu.
- Ruff, mypy/pyright, pytest, testcontainers, Docker Compose pour tests intégration.

## 3. Modèle de configuration universelle

Concepts : `Organization`, `User`, `Role`, `ProviderConnection`, `Repository`, `Project`, `Service`, `BuildDefinition`, `Registry`, `Environment`, `DockerHost`, `DeploymentTarget`, `Route`, `SecretReference`, `WebhookEndpoint`, `Release`, `Artifact`, `Deployment`, `DeploymentStep`, `AuditEvent`.

Un repository peut contenir plusieurs services, et un service peut produire plusieurs artefacts. Plusieurs dépôts peuvent partager un environnement, **sans** partager directement leurs réseaux, volumes ou secrets. Un même artefact immutable peut être promu de staging à production sans rebuild.

Convention d'image par défaut, configurable :

```text
<registry>/<namespace>/<repo>_<service>:<tag>
```

Exemples :

```text
registry.example.com/prod/inkerflow_api:1.5.0
registry.example.com/prod/inkerflow_worker:1.5.0
registry.example.com/prod/inkerflow_frontend:1.5.0
```

En interne déployer **uniquement par digest** : `registry.example.com/prod/inkerflow_api@sha256:...`. Conserver `tag`, `branch`, `commit_sha`, `build_id`, `registry` et `digest` en base pour audit. Une branche n'est pas un identifiant immuable : normaliser les caractères de tag, enregistrer le SHA de commit et **ne pas** utiliser une branche mouvante pour identifier une release. Noms OCI et noms de projets Compose doivent être normalisés, dédupliqués et vérifiés.

### Exemple de manifeste déclaratif

```yaml
apiVersion: deploy.example.io/v1
kind: Application
project: inkerflow
source:
  provider: gitlab
  repository: group/inkerflow
  defaultBranch: main
build:
  mode: external_ci
  tagTemplate: "{semver}"   # pour branches: "{branch}-{sha_short}"
  registryRef: registry-production
release:
  trigger: pipeline_success
  requireRegistryDigest: true
  requireSignedArtifact: true
  requireScanPass: true
  environments:
    staging:
      branches: [develop]
      autoDeploy: true
    production:
      tags: ["v*"]
      autoDeploy: false
      requireApproval: true
services:
  api:
    imageName: "{repository}_{service}"
    internalPort: 8000
    replicas: 2
    healthcheck:
      path: /health/ready
      intervalSeconds: 15
    resources:
      memory: 1g
      cpus: 1.0
      pids: 200
    env:
      APP_ENV: production
    secretRefs:
      DATABASE_URL: inkerflow/prod/database-url
    routes:
      - host: api.inkerflow.com
        pathPrefix: /
        tls: true
    deploy:
      strategy: blue_green
      healthTimeoutSeconds: 120
      drainTimeoutSeconds: 30
  worker:
    imageName: "{repository}_{service}"
    command: ["celery", "-A", "app", "worker", "-l", "info"]
    replicas: 1
    routes: []
    deploy:
      strategy: recreate
  frontend:
    imageName: "{repository}_{service}"
    internalPort: 80
    replicas: 2
    routes:
      - host: inkerflow.com
        tls: true
    deploy:
      strategy: blue_green
targets:
  staging:
    hostPool: staging-docker
  production:
    hostPool: production-docker
```

Les champs sont validés avec schémas versionnés, valeurs par défaut et erreurs explicites. Le manifeste est une **demande** : politiques et secrets de production sont imposés côté serveur, pas par une PR non approuvée. Un projet ne peut pas choisir librement un réseau `host`, un montage du filesystem hôte, des capacités ou une image privilégiée.

## 4. Ingestion des événements Git

Implémenter :
- `POST /v1/webhooks/github/{endpoint_id}` : valider `X-Hub-Signature-256` HMAC SHA-256 sur les **octets bruts** du body en temps constant; vérifier l'événement, la configuration du dépôt et l'ID de livraison.
- `POST /v1/webhooks/gitlab/{endpoint_id}` : prendre en charge les tokens de webhook GitLab et leurs mécanismes de signature disponibles selon la version et la configuration; vérifier les en-têtes attendus et le dépôt enregistré, éviter de traiter `X-Gitlab-Token` comme une signature cryptographique du corps. Authentifier et autoriser le flux de notification CI de façon indépendante lorsque nécessaire.
- Événements normalisés : `push`, `tag`, `release`, `pipeline_success`, `pipeline_failure`, `artifact_published`, `manual_deploy`.
- Répondre rapidement en `202`, après validation et insertion durable en base/queue via outbox transactionnelle; la construction/déploiement se fait hors requête.
- Idempotency key par provider + delivery ID + event type; TTL et protection anti-rejeu; filtrage organisation/repo/branche/tag/environnement; protection contre les notifications en double et hors ordre.
- Validation des signatures **avant parsing JSON**; limites de taille, content-type, schema, timeout, rate limiting, audit sans journaliser les secrets.
- Lier l'événement au commit réellement construit et aux artefacts attestés ; rejeter les déploiements déclenchés par simple payload manipulable.

## 5. Construction OCI et publication

Providers `GitHubActionsBuild`, `GitLabCIBuild`, `RootlessBuildKitBuild` derrière `BuildProvider` :
- Pipeline : checkout à SHA fixé, dépendances verrouillées, lint, tests, SAST/SCA (configurable), multi-stage Docker builds, SBOM (Syft ou équivalent), scan Trivy/Grype, provenance / signature Cosign, push OCI, récupération des digests, publication de manifest de release signé.
- Politique de fail closed pour production : aucune release si build/test/scan/signature échoue selon seuils.
- GitHub Actions et GitLab CI générables automatiquement par templates versionnés, mais personnalisables.
- Multiplateforme facultatif (`linux/amd64`, `linux/arm64`), cache BuildKit non confidentiel, labels OCI, logs structurés.
- Credentials du registry limités au périmètre et au sens push/pull; TTL courts lorsque possible; ne jamais les loguer.
- Abstraction `RegistryProvider` : Docker Hub, GitHub Container Registry, GitLab Container Registry, Harbor, AWS ECR, Azure ACR et registre Docker V2/OCI compatible.
- Les workers `managed_build` sont isolés, non privilégiés, sans accès aux secrets applicatifs ni aux réseaux de production; considérer les Dockerfiles comme du code non fiable.

## 6. Architecture Docker adaptée à la production

### 6.1 Control plane et execution plane

- Control plane : API, base, queue, règles, authentification, dashboards; exposition réseau strictement contrôlée.
- Execution plane : `deploy-agent` par machine, permissions Docker élevées **inévitables et reconnues**; traiter l'agent comme un composant de confiance critique. L'agent authentifie chaque instruction, vérifie le scope organisation/projet/hôte/environnement, et n'accepte qu'un plan typé sur liste blanche (pas de commande shell arbitraire).
- Sur une machine mutualisée non fiable, Docker Engine n'offre pas une isolation équivalente à une VM. Pour séparer de vrais locataires adverses, déployer dans des **VM ou hôtes dédiés**. Le mode rootless améliore la posture mais n'est ni universel ni une barrière absolue.
- Dans le modèle à agent sortant, l'agent récupère les tâches autorisées via connexion mTLS et renvoie statut et journaux ; aucun port Docker n'est exposé publiquement.
- Ne pas donner à l'agent Docker l'accès aux secrets du control plane; limiter par hôte, chiffrer, auditer les actions.

### 6.2 Compose isolé par projet et environnement

- Générer un Compose V2 déterministe **à partir d'un schéma sûr**, pas exécuter aveuglément le `docker-compose.yml` fourni par un dépôt.
- Convention `project_name = <org>-<project>-<environment>` avec collision-proof slug; labels ownership/version.
- Réseaux bridge dédiés : backend interne par application, réseau d'edge séparé pour le reverse proxy, pas d'accès interprojet par défaut.
- Ports internes non publiés; seuls les ports nécessaires du reverse proxy (`80`/`443`) sont exposés.
- Volumes nommés par organisation/projet/env, procédures de sauvegarde/restauration, UID/GID et permissions appropriés.
- Secrets injectés via fichiers montés en lecture seule à la durée d'exécution ; attention : `secrets:` en Docker Compose (non-Swarm) ne fournit **pas** le même service de secrets chiffrés au repos qu'un orchestrateur dédié. Prévoir chiffrement et protections de l'hôte en amont.
- Aucun conteneur applicatif ne monte docker.sock ni des chemins sensibles de l'hôte.
- Sur les hôtes, activer log rotation / collecte, limites de ressources et politique de récupération des disques.

### 6.3 Politique de sécurité runtime (deny by default)

Rejeter ou imposer :
- `privileged: true`, `pid: host`, `network_mode: host`, `ipc: host`, `userns_mode: host`, `devices`, `cap_add`, mounts arbitraires de l'hôte, host ports applicatifs, `security_opt: seccomp=unconfined`, `apparmor=unconfined`.
- `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true` par défaut, `tmpfs` pour les zones d'écriture nécessaires, utilisateur non-root dans l'image (UID explicite) lorsque possible.
- Seccomp et AppArmor/SELinux activés selon hôte, limitation CPU/RAM/PIDs, `ulimits` adaptées, `init: true`, log rotation.
- Scan des images, registre approuvé, pull par digest, signatures/provenance selon politique, validation architecture et compatibilité.
- Réduire les privilèges de l'hôte et maintenir Docker/OS corrigés ; surveiller les CVE, protéger l'agent et le registre.
- La politique réseau Compose seule **ne garantit pas** l'interdiction des sorties Internet (egress). Appliquer des règles de pare-feu hôte / VM ou une solution réseau dédiée pour l'egress si nécessaire.

### 6.4 Déploiement production et absence d'interruption

Moteur de stratégies `recreate`, `rolling`, `blue_green` :
- `recreate` : mise à jour simple avec interruption possible.
- `blue_green` : démarrer la nouvelle version dans un stack **distinct**, vérifier sa disponibilité, basculer Traefik via configuration dynamique atomique ou autre mécanisme fiable, drainer connexions puis arrêter l'ancienne version.
- `rolling` : avec Docker Engine + Compose seul, la mise à jour roulante automatique multi-réplicas n'est **pas native comme sur un orchestrateur**. L'implémenter explicitement par gestion des pools/instances et du routage, ou déclarer `unsupported` pour les topologies incompatibles. Ne jamais annoncer du zero downtime sans réplicas sains, capacité suffisante et proxy configuré.
- La bascule d'un proxy ne fournit pas de transactions distribuées : stratégies de migration de schéma compatibles avant/après (expand/contract), sessions partagées, files de tâches et locks métiers, idempotence.
- `healthcheck` de conteneur + readiness HTTP spécifiques, warm-up, délais de démarrage, grace period, validation fonctionnelle optionnelle.
- Rollback immédiat des **images et routes** sur échec, en conservant l'ancienne release; **ne pas** promettre un rollback automatique de migration de base (restauration contrôlée + sauvegarde/test).
- Garantie limitée au domaine et à l'hôte : sans cluster ou redondance entre machines, une panne matérielle d'hôte provoquera une interruption même avec blue/green.

## 7. Cycle de vie d'un déploiement

États : `received → validated → queued → preparing → pulling → verifying → starting → healthchecking → switching → succeeded`, puis `rollback_pending → rolled_back` ou `failed`, avec états `cancelled`, `awaiting_approval` et `blocked_by_policy`.

Procédure :
1. Vérifier identité, rôle, autorisation d'environnement, événement et provenance CI.
2. Vérifier registry, artefact, tag/digest, scan, signature et compatibilité plateforme.
3. Obtenir un verrou transactionnel `(project, environment)`, planifier et réserver capacité CPU/RAM/ports/routes.
4. Produire et persister un `DeploymentPlan` immuable contenant l'ancien et le nouveau digest, secret references et actions.
5. Préparer le réseau, routes et secrets sans remplacer la version existante.
6. Pull de l'image **par digest** via l'agent, puis démarrage avec configuration durcie.
7. Attendre readiness/health checks ; vérifier que les replicas demandés sont prêts.
8. Appliquer la bascule de trafic si stratégie compatible; enregistrer le nouvel état et les métriques.
9. En cas d'échec, garder/restaurer l'ancien routage, stopper les nouveaux conteneurs, enregistrer erreurs et audit.
10. Effectuer GC contrôlé des images, releases, logs et volumes selon politiques; ne jamais supprimer données persistantes lors d'un rollback.

Tous les steps doivent supporter retry sûr, checkpoints, crash recovery, timeouts, cancellation contrôlée. Les déploiements concurrents sur un même environnement doivent être sérialisés ou explicitement arbitrés (annulation d'une release obsolète). Les déploiements partiels sur plusieurs hôtes doivent être détectés et compensés.

## 8. Multi-hôtes sans Kubernetes

Prendre en charge :
- `single-host` : Compose sur un serveur, idéal pour petits projets; haute disponibilité d'hôte non garantie.
- `multi-host-managed` : pool d'agents sur plusieurs VPS/VM; l'API décide où placer les services et maintient son propre état; **Docker Compose ne fournit pas un ordonnanceur multi-hôtes**. Prévoir placement, capacité, service discovery/routage, panne et rebascule si demandé.
- `dedicated-host` : par client/projet à exigences d'isolation élevées.
- `preview` : environnement temporaire par pull/merge request, DNS auto et expiration TTL, quotas stricts.

Ne pas simuler une HA qu'on ne possède pas : PostgreSQL, Redis, reverse proxy, certificats, stockage de volumes, DNS et control plane doivent avoir leur propre stratégie de redondance/sauvegarde. La v1 peut cibler **production mono-hôte robuste** avec sauvegardes et restauration documentée; implémenter le multi-hôtes dans une phase distincte.

## 9. Domaines, TLS et reverse proxy

- Supporter des domaines personnalisés, sous-domaines par environnement et routage host/path.
- Provisionner TLS ACME via DNS-01/HTTP-01 selon réseau; renouvellement automatique et stockage protégé des clés.
- Séparer edge proxy de tous les réseaux privés, limiter dashboard et endpoint admin.
- ACL des hôtes autorisés, protection contre host header poisoning, collision de domaines, attaques SSRF par URL de health check.
- Bascule blue/green via fichiers/labels dynamiques vérifiés ; configuration atomique et rollback des routes, timeout/drain/WebSockets documentés.
- Option middlewares : rate limiting, auth, IP allowlist, headers sécurité, compression, sticky sessions si besoin.

## 10. Authentification et autorisation

- OIDC/OAuth2 conseillé (Keycloak ou provider externe), sessions/tokens courts, MFA pour la production.
- RBAC minimal : `owner`, `admin`, `developer`, `deployer`, `viewer`, `auditor`; autorisation au niveau organisation, projet, environnement, registry et host pool.
- Secrets des intégrations et credentials chiffrés, rotation, audit sans exposer valeurs ; `read-only` pour accès non nécessaires.
- Approval gates (règle de 4 yeux pour prod), freeze windows, listes d'images/registries autorisées et branch/tag protections.
- Aucune action de production à partir d'un webhook non vérifié; protections contre confusion de projets et substitution d'artefact.

## 11. API REST minimale (à documenter intégralement)

```text
POST   /v1/webhooks/github/{endpoint_id}
POST   /v1/webhooks/gitlab/{endpoint_id}
POST   /v1/ci/artifacts/published
GET    /v1/organizations
POST   /v1/projects
GET    /v1/projects/{id}
PATCH  /v1/projects/{id}
POST   /v1/projects/{id}/services
POST   /v1/projects/{id}/environments
POST   /v1/registries
POST   /v1/hosts/enroll-token
GET    /v1/hosts
GET    /v1/hosts/{id}/health
POST   /v1/releases
GET    /v1/releases/{id}
POST   /v1/deployments
POST   /v1/deployments/{id}/approve
POST   /v1/deployments/{id}/cancel
POST   /v1/deployments/{id}/rollback
GET    /v1/deployments/{id}
GET    /v1/deployments/{id}/events
GET    /v1/deployments/{id}/logs
GET    /v1/projects/{id}/history
GET    /v1/audit-events
GET    /health/live
GET    /health/ready
```

CRUD sécurisé pour connexions providers, webhooks, secrets, policies, routes, registres et déploiements. Pagination, filtres, tri, erreurs JSON normalisées, correlation IDs, idempotency keys, OpenAPI versionné. Ne pas exposer une API « execute arbitrary docker command ».

## 12. Interface d'administration (option mais fortement recommandée)

React + Vite + TypeScript + Tailwind + shadcn/ui : overview, environnements, graphes des services, registres, connexions Git, hôtes Docker, déploiements en temps réel, comparaison des releases, logs masqués, alertes, approbations, secrets référencés (jamais affichés en clair). UI accessible et robuste; montrer les erreurs et résultats réels. L'API reste entièrement fonctionnelle sans UI.

## 13. Tests d'acceptation non négociables

- Webhook GitHub signature valide/invalide; GitLab token et/ou signature selon version; payloads dupliqués / hors ordre.
- Une notification pipeline success **avant publication réelle** n'entraîne aucun déploiement.
- Trois services d'un même repo peuvent être livrés avec tags identiques et digests différents.
- Un tag force-push/re-tag ne remplace pas silencieusement le digest d'une release.
- Un dépôt hostile tente `privileged`, `hostNetwork`, docker.sock, bind `/`, cap_add : refus automatique.
- Un service de projet A ne peut ni voir ni lire les secrets du projet B via l'API ou les montages.
- Registry temporairement indisponible : retries bornés, état clair, pas de remplacement de la release saine.
- Health check échoue sur la nouvelle version : ancien trafic intact, rollback de routes/instances.
- Déploiement concurrent / worker crash / agent hors ligne : reprise sûre et idempotente.
- Le déploiement ne détruit jamais les volumes de production; backups/restores testés.
- Les secrets ne sont jamais inclus dans logs, erreurs, manifestes publics ou templates CI.
- La sécurité et les garanties déclarées ont des tests d'intégration, pas seulement des tests mockés.

## 14. Structure de dépôt attendue

```text
universal-deployer/
├── apps/
│   ├── api/                  # FastAPI et OpenAPI
│   ├── worker/               # Celery: dispatch et workflows
│   └── dashboard/            # UI optionnelle
├── agent/                    # Agent de déploiement Docker par serveur
├── packages/
│   ├── domain/               # Modèles et règles de domaine
│   ├── providers/            # Git / CI / registry / DNS / secrets
│   ├── planner/              # Plans et politiques
│   ├── compose_renderer/     # Compose sécurisé généré
│   └── security/             # auth, signatures, OPA/policies optionnelles
├── templates/
│   ├── github-actions/
│   ├── gitlab-ci/
│   └── manifests/
├── infra/
│   ├── control-plane.compose.yml
│   ├── agent.compose.yml
│   ├── traefik/
│   └── backup/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── e2e/
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── deployment-guide.md
│   ├── disaster-recovery.md
│   └── api.md
├── .env.example             # valeurs non sensibles uniquement
└── README.md
```

## 15. Phases d'implémentation (livrer réellement à chaque phase)

**Phase 1 — socle fiable mono-hôte** : modèles, FastAPI, Postgres, queue, GitHub/GitLab webhooks, RBAC, registries OCI, réception de manifeste CI, agent Docker, Compose généré, secrets, healthchecks, Traefik et stratégie `recreate`. Tests end-to-end réels.

**Phase 2 — production avancée** : blue/green vérifiable, rollbacks de routes, approbations, audits, scan/signature, promotion staging → production par digest, sauvegarde et observabilité.

**Phase 3 — expérience universelle** : génération CI GitHub/GitLab, build-managed isolé, UI, previews, multi-hôtes et pools avec ordonnancement explicite, API publique documentée, providers extensibles.

Pour chaque phase : migrations DB, tests unitaires/intégration/sécurité, docs de déploiement, compose d'exploitation, scripts de bootstrap idempotents, exemples GitHub et GitLab. Ne pas remplacer une fonctionnalité par un TODO silencieux.

## 16. Livrables demandés à l'agent de code

1. Fournir d'abord l'architecture technique, diagramme, modèle de menaces, décisions majeures et découpage MVP.
2. Implémenter **le code exécutable complet** de la phase actuelle, migrations et tests inclus.
3. Donner une stack Docker Compose pour le control plane, une installation de l'agent et un exemple de déploiement de trois services.
4. Générer des templates CI GitHub/GitLab utilisables et documenter les droits/tokens requis.
5. Démontrer le chemin `git tag → build → scan → registry push → verify digest → API deploy → healthcheck → route switch/rollback`.
6. Fournir runbook production : durcissement Debian/Ubuntu, pare-feu, TLS, rotations de clés, alertes, sauvegardes, restauration, mises à niveau et diagnostic.
7. Signaler honnêtement les fonctionnalités non implémentées et les limites des garanties Docker-only (en particulier HA, multi-hôte, rollback de bases et isolation de locataires adverses).

## 17. Règles architecturales impératives

- **Pas de Kubernetes, Helm, Docker Swarm ou dépendance à un orchestrateur tiers.** Docker Compose V2 et Docker Engine seulement pour le runtime; ne jamais prétendre que Compose possède des capacités qu'il n'a pas.
- **Pas de daemon Docker public, pas de `docker.sock` dans l'API**, pas d'exécution shell arbitraire via webhook.
- Build de code non fiable uniquement hors production et dans un environnement isolé.
- Registry, Git provider, proxy, DNS, auth et secrets sont des interfaces remplaçables.
- Déploiement par digest, pas confiance aveugle dans les tags ou dans le contenu du webhook.
- Sécurité par défaut et refus des options Docker dangereuses même lorsque le manifeste source les réclame.
- Fiabilité : idempotence, locks, audit, sauvegardes, readiness, rollback prudent.
- Si une exigence ne peut pas être satisfaite de manière sûre sur Docker Compose, expliquer précisément la limite et fournir une alternative utilisant VM/hôtes dédiés ou changer explicitement la garantie; ne pas inventer un mécanisme.

**Instruction finale :** commence par implémenter une v1 exploitable en production sur un VPS Docker, extensible à plusieurs serveurs sans refonte majeure. Ne livre ni pseudocode ni mockups comme résultat final. Écris du code maintenable, typé, testé, documenté, avec configuration multi-projets et séparation claire control plane / agent / runtime.
