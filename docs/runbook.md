# Runbook de production

## 1. Durcissement de l'hôte (Debian 12 / Ubuntu 24.04)

```bash
apt-get update && apt-get -y full-upgrade
apt-get -y install unattended-upgrades ufw fail2ban
dpkg-reconfigure -plow unattended-upgrades
```

SSH (`/etc/ssh/sshd_config.d/hardening.conf`) :
```text
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AllowUsers ops
```

Pare-feu :
```bash
ufw default deny incoming && ufw default allow outgoing
ufw allow from <IP admin>/32 to any port 22 proto tcp
ufw allow 80/tcp && ufw allow 443/tcp
ufw allow from <IP des hôtes agents> to any port 8443 proto tcp   # hôte control plane seulement
ufw enable
```
Attention : les ports publiés par Docker contournent les règles `ufw` (chaînes iptables propres à
Docker). Seul Traefik publie des ports ; pour filtrer l'egress des conteneurs, utiliser la chaîne
`DOCKER-USER`.

`/etc/docker/daemon.json` :
```json
{
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "no-new-privileges": true,
  "userland-proxy": false,
  "icc": true
}
```
- `live-restore` : les conteneurs survivent à un redémarrage du démon (mise à jour Docker).
- `icc` : la communication inter-conteneurs reste nécessaire **dans** un réseau de projet ; l'isolation
  inter-projets vient des réseaux dédiés `<projet>_backend` / `_edge`, pas du bridge par défaut.
- `userns-remap` améliore l'isolation mais change les uid vus sur l'hôte (propriété des fichiers de
  secrets) : à valider avant activation.
- Chiffrer le disque (LUKS) : les fichiers de secrets montés sont en clair sur l'hôte.

## 2. TLS / ACME

- Edge Traefik (`infra/agent.compose.yml`) : resolver `letsencrypt`, HTTP-01 par défaut ; DNS-01 si
  l'hôte n'est pas joignable sur 80. Le stockage `acme.json` doit être en 0600.
- Routes `tls: true` → entrypoint `websecure` + `certResolver` ; redirection HTTP→HTTPS globale dans la
  configuration statique Traefik (`infra/traefik/`).
- Listener agent (8443) : certificat émis par la CA interne (`udeploy-admin init-pki`), **pas** par ACME.

## 3. Rotation des clés et jetons

| Élément | Fréquence | Procédure |
|---|---|---|
| Master keys | annuelle ou sur incident | nouvelle entrée en tête de `UDEPLOY_MASTER_KEYS`, restart, `udeploy-admin rotate-master-key`, retrait de l'ancienne |
| Certificats agents | 90 j, automatique | renouvelés à < 30 j (`/v1/agent/renew`) ; surveiller `cert_not_after` |
| CA interne | 10 ans / sur incident | voir `docs/disaster-recovery.md` §6 |
| Jetons CI | sur départ / incident | `POST …/ci-tokens` puis `DELETE …/ci-tokens/{id}` |
| Jetons API | sur départ | `udeploy-admin bootstrap --new-token` (owner) ; révocation `api_tokens.revoked_at` |
| Secrets de webhook | sur incident | nouvel endpoint (`POST …/webhook-endpoints`), mise à jour chez le provider, désactivation de l'ancien (`webhook_endpoints.active=false`) |
| Hôte compromis | immédiat | `POST /v1/hosts/{id}/disable` puis rotation des secrets livrés à cet hôte |

## 4. Alertes recommandées (requêtes SQL)

```sql
-- DLQ non vide
SELECT count(*) FROM dead_letters WHERE created_at > now() - interval '1 day';
-- hôtes hors ligne
SELECT name, pool, last_seen_at FROM docker_hosts
 WHERE status = 'active' AND last_seen_at < now() - interval '2 minutes';
-- déploiements en échec / rollback récents
SELECT id, state, error FROM deployments
 WHERE state IN ('failed','rolled_back') AND finished_at > now() - interval '1 hour';
-- certificats proches de l'expiration (le renouvellement automatique a échoué)
SELECT name, cert_not_after FROM docker_hosts WHERE cert_not_after < now() + interval '15 days';
-- releases en échec de vérification
SELECT version, status_detail FROM releases WHERE status = 'verification_failed'
 AND created_at > now() - interval '1 day';
```
Plus : espace disque hôte (`docker system df`), `/health/ready` du control plane, taille de l'outbox
non dispatchée (`SELECT count(*) FROM outbox WHERE dispatched_at IS NULL`).

## 5. Sauvegardes

`infra/backup/backup.sh` quotidien + copie hors site ; test de restauration mensuel
(`docs/disaster-recovery.md`).

## 6. Mises à niveau

**Control plane** :
1. sauvegarde (base + PKI) ;
2. `docker compose -f infra/control-plane.compose.yml pull` (ou build) ;
3. `udeploy-admin migrate` (migrations Alembic, compatibles avec la version précédente) ;
4. redémarrage service par service : worker/beat, puis api, puis agent-api. Les agents réessaient
   automatiquement pendant l'indisponibilité ; aucune application n'est affectée.

**Agent** : attendre qu'aucun déploiement ne soit actif sur l'hôte, puis
`docker compose -f infra/agent.compose.yml pull && … up -d`. Une tâche interrompue est re-réclamée et
rejouée (étapes idempotentes).

**Docker Engine** : avec `live-restore`, les conteneurs continuent de tourner pendant la mise à jour.

## 7. Diagnostic

```bash
# état d'un déploiement
curl -s $UDEPLOY/v1/deployments/$D -H "$H" | jq '{state,error,host_id,plan_sha256}'
curl -s "$UDEPLOY/v1/deployments/$D/events" -H "$H" | jq -r '.items[] | "\(.at) \(.state) \(.message)"'

# sur l'hôte
docker compose -p <org>-<projet>-<env>-<hash6> ps
ls /var/lib/udeploy-agent/projects/<projet compose>/releases/<deployment_id>/   # compose.yml, plan.json
cat /var/lib/udeploy-agent/projects/<projet compose>/current.json
ls /var/lib/udeploy-agent/traefik/                       # routes publiées
docker logs udeploy-agent --since 30m
docker logs udeploy-traefik --since 30m
```

```sql
-- tâches agent bloquées
SELECT t.id, t.status, t.attempt, t.lease_expires_at, h.name
  FROM agent_tasks t JOIN docker_hosts h ON h.id = t.host_id
 WHERE t.status IN ('pending','claimed');
-- environnement verrouillé par un déploiement actif
SELECT id, state, updated_at FROM deployments
 WHERE state IN ('preparing','pulling','verifying','starting','healthchecking','switching','rollback_pending');
```

Symptômes fréquents :
- `waiting for an online host in pool …` : aucun agent du pool n'a envoyé de heartbeat récent.
- `plan rejected by host policy: registry … not allowed` : compléter `UDEPLOY_AGENT_ALLOWED_REGISTRIES`.
- `pull failed` : identifiants `docker login` de l'hôte (pull-only) ou registre indisponible ; la release
  en cours n'a pas été touchée.
- `<service> not ready before timeout` : readiness HTTP en échec → rollback automatique ; consulter
  `/v1/deployments/{id}/logs` et `docker logs` des conteneurs (conservés arrêtés si première release).
