# udeploy

Moteur CI/CD auto-hébergé qui déploie des images OCI vérifiées par digest sur des hôtes Docker Engine +
Compose V2 — sans Kubernetes, Swarm ni Helm.

**Statut : Phase 1** — production mono-hôte robuste, stratégie `recreate` avec rollback automatique.
Voir [docs/limitations.md](docs/limitations.md).

## Principe

```text
git tag → CI (build, scan, push) → POST /v1/ci/artifacts/published
       → vérification des digests dans le registre → politique / approbation 4 yeux
       → plan immuable → agent mTLS sur l'hôte → pull par digest → Compose durci
       → readiness HTTP → route Traefik → succeeded | rollback automatique
```

Un webhook Git ne déploie jamais rien à lui seul ; seules des releases dont chaque digest a été vérifié
dans le registre peuvent l'être.

## Démarrage rapide

```bash
# control plane (VPS Debian/Ubuntu)
sudo ./scripts/bootstrap-control-plane.sh --public-url https://deploy.example.com \
  --agent-api-name agents.deploy.example.com --org acme --email ops@example.com --domain example.com
# agent sur l'hôte Docker (jeton issu de POST /v1/hosts/enroll-token)
sudo ./scripts/install-agent.sh --url https://deploy.example.com --token udenr_… \
  --allowed-registries registry.example.com --acme-email ops@example.com
```

Ensuite : registre, projet, manifeste (`templates/manifests/inkerflow.udeploy.yaml`), secrets, jeton CI,
template CI (`templates/github-actions/` ou `templates/gitlab-ci/`) — détail dans
[docs/deployment-guide.md](docs/deployment-guide.md).

## Structure du dépôt

```text
apps/api/            FastAPI : API publique, API agent (mTLS), CLI udeploy-admin
apps/worker/         Celery : relais outbox, vérification, planification, réconciliation
agent/               udeploy-agent : exécution des plans sur un hôte Docker
packages/domain/     manifeste, plan, nommage, machine à états
packages/providers/  client OCI Distribution, normalisation GitHub/GitLab
packages/planner/    politiques (deny by default) et construction de plan
packages/compose_renderer/  Compose V2 durci + configuration Traefik
packages/security/   HMAC webhooks, AES-GCM, PKI interne, jetons, masquage
templates/           CI GitHub Actions / GitLab CI, manifestes d'exemple
infra/               compose control plane et agent, Traefik, sauvegardes
migrations/          Alembic
tests/               unit, integration (Postgres/Redis réels), security, e2e (Docker réel)
docs/                architecture, menaces, déploiement, reprise, API, runbook, limites
```

## Développement

Python 3.13+, [uv](https://docs.astral.sh/uv/), Docker (tests d'intégration et e2e).

```bash
uv sync --extra control-plane
uv run pytest                          # toute la suite
uv run pytest tests/unit tests/security
uv run pytest -m integration           # PostgreSQL + Redis via testcontainers
uv run pytest -m e2e                   # registre, agent, Traefik et conteneurs réels
uv run ruff check . && uv run ruff format --check .
uv run mypy apps agent packages        # mode strict
```

## Documentation

- [Architecture](docs/architecture.md)
- [Modèle de menaces](docs/threat-model.md)
- [Guide de déploiement](docs/deployment-guide.md)
- [Reprise après sinistre](docs/disaster-recovery.md)
- [API](docs/api.md)
- [Runbook de production](docs/runbook.md)
- [Limites](docs/limitations.md)
