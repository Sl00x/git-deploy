# Reprise après sinistre

Rappel : la Phase 1 cible un **hôte unique robuste**. Il n'y a pas de haute disponibilité : la perte
d'un hôte interrompt les applications qu'il porte, quelle que soit la stratégie de déploiement.

## 1. Ce qu'il faut sauvegarder

| Élément | Emplacement | Méthode |
|---|---|---|
| Base du control plane | conteneur PostgreSQL | `pg_dump -Fc` |
| PKI interne (CA + certificat serveur agent) | volume `udeploy-cp_pki` (`UDEPLOY_PKI_DIR=/var/lib/udeploy-pki` dans le conteneur) | archive chiffrée |
| Master keys | `UDEPLOY_MASTER_KEYS` (`.env`) | coffre hors serveur (gestionnaire de secrets, papier scellé) |
| Volumes applicatifs | volumes Docker labellisés `io.udeploy.managed=true` | `tar` via conteneur busybox |
| Identité de l'agent | `/var/lib/udeploy-agent/identity` | facultatif (ré-enrôlement possible) |

Sans les master keys, la base est inutilisable pour les secrets : **les sauvegarder séparément de la base**.

## 2. Sauvegarde

`infra/backup/backup.sh` (à planifier via cron/systemd timer) :

1. `pg_dump -Fc` du control plane ;
2. archive de `UDEPLOY_PKI_DIR` ;
3. pour chaque volume `docker volume ls --filter label=io.udeploy.managed=true` :
   `docker run --rm -v <volume>:/data:ro -v <dest>:/backup busybox:1.37 tar czf /backup/<volume>.tgz -C /data .`
4. rotation des archives et copie hors site (chiffrée).

Cohérence : `tar` d'un volume de base de données en cours d'écriture n'est pas cohérent. Pour une base
applicative, utiliser son outil natif (`pg_dump`, `mysqldump`…) avant ou à la place du `tar`.

## 3. Restauration (à tester régulièrement)

`infra/backup/restore.sh` :

1. arrêter api/worker/beat ; restaurer `pg_restore --clean --if-exists` ;
2. restaurer `UDEPLOY_PKI_DIR` et `.env` (master keys) ;
3. redémarrer ; `udeploy-admin migrate` ; vérifier `/health/ready` ;
4. pour un volume : arrêter le projet Compose concerné, extraire l'archive dans le volume, relancer.

Test minimal recommandé (mensuel) : restaurer sur une VM jetable, vérifier qu'un `GET /v1/projects`
répond, qu'un déploiement de la release courante aboutit (les secrets se déchiffrent), et qu'un volume
restauré contient les données attendues.

## 4. Perte d'un hôte Docker

Effet : interruption des applications de l'hôte. Le control plane marque l'hôte hors ligne
(`agent_offline_after_seconds`) ; les déploiements en cours expirent puis passent en `failed`.

Procédure :

1. provisionner un nouvel hôte, appliquer `docs/runbook.md` ;
2. créer un jeton d'enrôlement (`POST /v1/hosts/enroll-token`, même pool) et installer l'agent ;
3. désactiver l'ancien hôte : `POST /v1/hosts/{id}/disable` (son certificat cesse de fonctionner) ;
4. restaurer les volumes sur le nouvel hôte (noms identiques : `<org>-<projet>-<env>-<hash6>_<volume>`) ;
5. libérer l'épinglage de l'environnement (l'environnement reste épinglé à l'ancien hôte pour ne pas
   déplacer silencieusement des données) :
   ```sql
   UPDATE environments SET pinned_host_id = NULL WHERE pinned_host_id = '<ancien host id>';
   ```
6. redéployer la release courante **par digest** : `POST /v1/deployments` avec le `release_id` du
   déploiement courant (ou `POST /v1/deployments/{id}/rollback` selon le cas).

## 5. Perte du control plane

Les applications **continuent de tourner** : l'agent ne fait rien sans tâche, Traefik garde sa
configuration de fichiers. Aucun déploiement n'est possible jusqu'à la restauration.

1. restaurer la base, la PKI et les master keys (section 3) ;
2. si l'URL ou la CA change, ré-enrôler chaque agent ;
3. les tâches réclamées avant l'incident sont re-pending ou échouées par la réconciliation ; vérifier
   l'état réel sur l'hôte (`docker compose -p <projet> ps`) avant de redéployer.

## 6. Rotation des clés

- **Master key** : ajouter une nouvelle entrée en tête de `UDEPLOY_MASTER_KEYS`
  (`udeploy-admin gen-master-key`), redémarrer, exécuter `udeploy-admin rotate-master-key`, puis retirer
  l'ancienne entrée et redémarrer.
- **CA interne** : générer une nouvelle CA dans un nouveau `UDEPLOY_PKI_DIR`
  (`udeploy-admin init-pki --server-name …`), basculer le listener, ré-enrôler chaque agent (jeton
  d'enrôlement), désactiver les anciens hôtes. Pas de double-CA en Phase 1 : prévoir une fenêtre.
- **Certificats d'agent** : 90 jours, renouvelés automatiquement à moins de 30 jours.

## 7. Rollback de schéma de base applicative

Le rollback d'udeploy restaure **images, secrets et routes** — jamais les données. Une migration de base
applicative n'est pas annulée automatiquement :

- concevoir les migrations en **expand/contract** (la version N-1 doit fonctionner avec le schéma N) ;
- sauvegarder la base applicative avant toute release contenant une migration destructive ;
- en cas de migration incompatible ratée : restauration contrôlée depuis la sauvegarde, puis rollback
  de l'application.
