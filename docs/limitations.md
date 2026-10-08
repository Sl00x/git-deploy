# Limites connues et fonctionnalités non implémentées (Phase 1)

Ce document est volontairement explicite : rien de ce qui suit n'est simulé par le code.

## 1. Non implémenté en Phase 1

| Fonctionnalité | Comportement actuel |
|---|---|
| Stratégies `blue_green` et `rolling` | acceptées par le schéma, **refusées par la politique** (`not available in this release`) ; seule `recreate` existe |
| Vérification de signature / provenance (cosign) | non vérifiée ; `requireSignedArtifact: true` **bloque** le déploiement (`blocked_by_policy`, fail closed) |
| Statut de scan | déclaré par la CI (jeton CI de confiance), pas re-scanné par le control plane |
| Promotion staging → production dédiée | pas d'endpoint ; faisable en déployant le même `release_id` (mêmes digests, aucun rebuild) |
| Freeze windows | absentes |
| OIDC / OAuth2 / MFA | absents ; jetons opaques uniquement (`udp_`, `udci_`) |
| Dashboard (React) | absent ; l'API est complète sans UI |
| `managed_build` (BuildKit rootless) | absent ; seul `external_ci` est opérationnel |
| Multi-hôtes, ordonnancement, capacité | un environnement s'exécute sur un hôte (premier hôte en ligne du pool, puis épinglé) |
| Environnements de preview (PR/MR) | absents |
| Providers de secrets SOPS / Vault | interface `SecretProvider` seulement ; backend local chiffré AES-GCM |
| Observabilité OpenTelemetry / Prometheus / Loki | absente ; logs JSON structurés + audit en base |
| Rate limiting | basique (fenêtre fixe Redis), fail-open si Redis indisponible |
| Allowlist IP des providers Git | absente (à faire au proxy d'entrée) |
| Identifiants de pull poussés vers les hôtes | non : `docker login` pull-only configuré localement sur chaque hôte |
| Middlewares Traefik par route (auth, IP allowlist, rate limit, sticky) | seul un middleware d'en-têtes de sécurité est généré |
| Gestion de l'egress | non : pare-feu hôte requis |
| GC des images Docker | non automatique (seuls répertoires de releases/secrets sont élagués) |

## 2. Limites inhérentes à Docker Engine + Compose

- **Haute disponibilité** : aucune. Une panne d'hôte interrompt ses applications, même en blue/green
  (Phase 2). PostgreSQL, Redis, le proxy et le control plane n'ont pas de redondance fournie.
- **Multi-hôtes** : Compose n'ordonnance rien entre machines. Le multi-hôtes (Phase 3) sera un
  ordonnancement explicite du control plane, pas une capacité de Compose.
- **`recreate`** : interruption brève pendant le remplacement des conteneurs ; le **zero downtime n'est pas
  garanti** et n'est jamais annoncé.
- **Rollback** : restaure images, secrets et routes ; **jamais** les données ni les migrations de schéma
  (expand/contract + sauvegardes, voir `docs/disaster-recovery.md`).
- **Isolation des locataires** : les conteneurs partagent le noyau de l'hôte. Pour des locataires
  adverses, utiliser des hôtes ou VM dédiés (un pool par locataire).
- **Secrets Compose hors Swarm** : bind mounts de fichiers en clair sur l'hôte ; protection = permissions
  + chiffrement disque.
- **Agent** : root-équivalent sur son hôte (accès au socket Docker), composant de confiance critique.
- **Replicas** : `deploy.replicas` de Compose sur un seul hôte ; la répartition se fait par Traefik entre
  conteneurs du même hôte.
