# Edge proxy (Traefik v3)

* Static configuration: CLI flags in `infra/agent.compose.yml` (HTTP→HTTPS redirect, ACME HTTP-01
  resolver `letsencrypt`, file provider, no dashboard, JSON access log without headers).
* Dynamic configuration: one file per compose project, `udeploy-<compose_project>.yml`, written by the
  agent into `/var/lib/udeploy-agent/traefik/` with an atomic rename. The proxy never reads the Docker
  socket; it joins each project's `<compose_project>_edge` network (done by the agent).
* `dynamic/control-plane.yml`: example route for the control plane public API when it shares the host.
* Note: because the `web` entry point redirects to HTTPS, a route declared with `tls: false` is still
  redirected. Remove the redirection flags only for hosts that must stay on plain HTTP.
