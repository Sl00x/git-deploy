# Modèle de menaces — udeploy (Phase 1)

## 1. Actifs

| Actif | Où | Impact si compromis |
|---|---|---|
| Master keys (`UDEPLOY_MASTER_KEYS`) | env du control plane | déchiffrement de tous les secrets, identifiants de registre, secrets de webhook |
| Clé de la CA interne (`<pki_dir>/ca.key`) | control plane | émission de certificats d'agent arbitraires |
| Secrets applicatifs | `secrets` (chiffré), enveloppe de tâche, fichiers sur l'hôte | fuite de données métier |
| Jetons API / CI / enrôlement | client ; base (hash SHA-256 seulement) | actions au nom d'un utilisateur / d'un projet |
| Clé privée de l'agent | `/var/lib/udeploy-agent/identity/agent.key` | usurpation de l'hôte auprès du control plane |
| `docker.sock` de l'hôte | conteneur agent | root sur l'hôte |
| Intégrité des releases (digests) | `artifacts` | déploiement d'un code non construit par la CI |
| Volumes de production | hôte Docker | perte de données |

## 2. Frontières de confiance

1. Internet → API publique (webhooks, CI, admin) — TLS terminé par le proxy d'entrée.
2. Internet → listener agent 8443 — mTLS obligatoire au handshake.
3. Control plane ↔ PostgreSQL/Redis — réseau privé.
4. Agent ↔ Docker Engine — confiance totale (socket).
5. Conteneurs applicatifs ↔ hôte / autres projets — isolation noyau Docker uniquement.
6. Dépôt Git / manifeste → control plane — entrée non fiable.

## 3. Acteurs

- **Attaquant Internet** : forge de webhooks, rejeu, énumération, déni de service applicatif.
- **Développeur malveillant avec accès au dépôt** : manifeste hostile, Dockerfile malveillant, tentative de
  détourner un domaine ou les secrets d'un autre projet.
- **CI compromise** : jeton `udci_` volé, publication de digests arbitraires, statut de scan mensonger.
- **Hôte / agent compromis** : vol des secrets livrés à cet hôte, rapport d'état falsifié.
- **Base du control plane compromise** (lecture/écriture SQL) : altération de plans.
- **Locataire adverse** sur un hôte partagé : évasion de conteneur, accès voisin.

## 4. STRIDE par composant et mitigations

### Webhooks (`routers/ingest.py`, `services/webhooks.py`, `udeploy_security/webhooks.py`)
- **S** : HMAC SHA-256 GitHub vérifié en temps constant sur les octets bruts **avant** le parsing JSON ;
  GitLab : `X-Gitlab-Token` comparé en temps constant + signing token (Standard Webhooks) optionnel.
- **T** : signature couvrant le corps (GitHub, signing token GitLab).
- **R** : `webhook_deliveries` + `audit_events`.
- **I** : endpoint inconnu ou inactif → même 404 ; secrets jamais journalisés (`masking.py`).
- **D** : limite 1 MiB vérifiée en streaming, `Content-Type` imposé, rate limit Redis par IP.
- **E** : un webhook ne déclenche **aucun** déploiement ; dépôt du payload comparé au dépôt du projet.
- Rejeu : clé d'idempotence `provider:endpoint:delivery:event` unique ; fenêtre de 5 min pour les signatures
  Standard Webhooks.

### Notifications CI et releases (`services/releases.py`)
- Jeton CI limité à un projet ; image imposée = `<namespace>/<image du service>` (anti-substitution).
- Version immuable (409 si contenu différent), vérification par contenu dans le registre, label de
  révision == commit, détection de tag déplacé.
- Notification avant le push : vérification en échec après retries bornés → aucun déploiement.

### API d'administration (`auth.py`, `deps.py`)
- Jetons opaques 256 bits, stockés hachés ; révocation/expiration ; rate limit des échecs d'auth.
- RBAC par organisation/projet ; « non trouvé » et « non visible » indiscernables (pas d'énumération
  inter-tenants).
- Environnements protégés (`requireApproval`) : permission `deploy.protected` + règle des 4 yeux.
- Secrets en écriture seule ; aucune route ne renvoie de valeur.
- Erreurs normalisées sans texte d'exception interne ; `audit_events` nettoyés des clés sensibles.

### Listener agent (`mtls.py`, `routers/agent.py`, `services/hosts.py`)
- **S** : handshake mTLS contre la CA interne, identité = empreinte du certificat en base + SAN vérifié.
- **T/E** : une tâche n'est lisible/modifiable que par l'hôte assigné ; transitions validées par la
  machine à états ; plan vérifié par sha256 à la lecture.
- **I** : secrets livrés seulement pour l'environnement du plan de cet hôte.

### Agent (`agent/udeploy_agent/`)
- Exécute uniquement un `DeploymentPlan` typé ; aucune commande arbitraire ; argv sans shell.
- `AgentPolicy` locale : hôte cible, registres autorisés par la configuration de l'hôte, digest cohérent,
  pas d'uid 0, marqueurs dangereux (`docker.sock`, `seccomp=unconfined`…).
- Sonde HTTP : cible construite par l'agent (nom de conteneur + port du plan + chemin validé), depuis un
  conteneur jetable `--cap-drop ALL --read-only --user 65534` : pas de SSRF par URL fournie.

### Runtime (`udeploy_compose/renderer.py`)
- Socle de durcissement non désactivable, aucun port publié, réseaux par projet, volumes external,
  aucun montage hôte hormis les fichiers de secrets générés par l'agent.

### Routage
- `routes(host, path_prefix)` unique plateforme ; domaines limités à `organizations.allowed_domains` ;
  hôtes réservés (`UDEPLOY_RESERVED_HOSTS`) ; règles Traefik `Host()` exactes.

## 5. Risques résiduels (assumés, documentés)

1. **L'agent est root-équivalent sur l'hôte** (accès à `docker.sock`). Sa compromission = compromission de
   l'hôte et des secrets qui y sont livrés. Mitigation : hôte dédié, agent sans exposition entrante,
   certificat révocable, politique locale.
2. **Docker n'isole pas des locataires adverses** comme une VM. Pour des tenants mutuellement hostiles :
   hôtes ou VM dédiés par tenant (pool dédié). Le mode rootless/userns-remap améliore la posture sans être
   une barrière absolue.
3. **Secrets Compose hors Swarm** : ce sont des bind mounts de fichiers en clair sur l'hôte (0400/0444 dans
   des répertoires 0700). Chiffrer le disque de l'hôte, restreindre l'accès root, purger les anciennes
   releases (`UDEPLOY_AGENT_KEEP_RELEASES`).
4. **`X-Gitlab-Token` n'est pas une signature** : il authentifie l'émetteur mais ne protège pas l'intégrité
   du corps. Configurer un signing token GitLab (`signing_secret` à la création de l'endpoint).
5. **Statut de scan déclaré par la CI** : le control plane fait confiance au jeton CI pour `scan.status`.
   Une CI compromise peut mentir ; protéger le jeton (variable masquée/protégée), le révoquer en cas de doute.
6. **Signature cosign non vérifiée en Phase 1** : `requireSignedArtifact: true` **bloque** tout déploiement
   (fail closed) plutôt que d'accepter un artefact non vérifié.
7. **Egress non filtré** : les réseaux Compose n'interdisent pas les sorties Internet. Appliquer un pare-feu
   hôte (chaîne `DOCKER-USER`) ou un proxy d'egress.
8. **Rate limiting fail-open** si Redis est indisponible (disponibilité privilégiée, journalisé).
9. **Pas d'allowlist IP GitHub/GitLab** sur les webhooks (à placer au niveau du proxy d'entrée si voulu).
10. **Base du control plane** : un attaquant en écriture SQL peut modifier un plan non encore réclamé
    (le sha256 est stocké dans la même base). L'agent limite l'impact (registres locaux autorisés,
    politique locale) mais ne l'annule pas.
11. **Clé de CA sur le control plane** : protéger `pki_dir` (0600, sauvegarde chiffrée).
