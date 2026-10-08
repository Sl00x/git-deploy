from __future__ import annotations

from udeploy_compose.renderer import HostLayout, dump_yaml, render_compose, render_traefik_routes

from ..factories import plan

LAYOUT = HostLayout(secrets_dir="/var/lib/udeploy-agent/secrets")


def test_every_service_is_hardened() -> None:
    doc = render_compose(plan(), LAYOUT)
    assert set(doc["services"]) == {"api", "frontend", "worker"}
    for svc in doc["services"].values():
        assert svc["cap_drop"] == ["ALL"]
        assert svc["security_opt"] == ["no-new-privileges:true"]
        assert svc["read_only"] is True
        assert svc["init"] is True
        assert svc["pids_limit"] >= 16
        assert svc["mem_limit"] == svc["memswap_limit"]
        assert "@sha256:" in svc["image"]
        assert svc["pull_policy"] == "never"
        assert svc["logging"]["options"]["max-size"]
        for forbidden in ("ports", "privileged", "network_mode", "pid", "ipc", "cap_add", "devices"):
            assert forbidden not in svc


def test_no_host_paths_except_agent_owned_secret_files() -> None:
    doc = render_compose(plan(), LAYOUT)
    for svc in doc["services"].values():
        for vol in svc.get("volumes", []):
            assert vol["type"] == "volume"
    for secret in doc["secrets"].values():
        assert secret["file"].startswith("/var/lib/udeploy-agent/secrets/")
    assert "docker.sock" not in dump_yaml(doc)


def test_volumes_are_external_and_namespaced() -> None:
    p = plan()
    doc = render_compose(p, LAYOUT)
    assert doc["volumes"]["uploads"] == {"name": f"{p.compose_project}_uploads", "external": True}


def test_secrets_are_files_not_env_values() -> None:
    doc = render_compose(plan(), LAYOUT)
    api = doc["services"]["api"]
    assert api["environment"]["DATABASE_URL_FILE"] == "/run/secrets/database_url"
    assert "DATABASE_URL" not in api["environment"]
    assert api["secrets"] == [{"source": "api__database_url", "target": "database_url"}]


def test_networks_isolated_per_project() -> None:
    p = plan()
    doc = render_compose(p, LAYOUT)
    assert doc["networks"]["backend"]["name"] == f"{p.compose_project}_backend"
    assert doc["networks"]["edge"]["name"] == f"{p.compose_project}_edge"
    assert "edge" not in doc["services"]["worker"]["networks"]
    assert "edge" in doc["services"]["api"]["networks"]


def test_rendering_is_deterministic() -> None:
    assert dump_yaml(render_compose(plan(), LAYOUT)) == dump_yaml(render_compose(plan(), LAYOUT))


def test_traefik_routes_target_concrete_containers() -> None:
    p = plan()
    routes = render_traefik_routes(p, {"api": ["c-api-2", "c-api-1"], "frontend": ["c-fe-1"]}, LAYOUT)
    http = routes["http"]
    api_service = http["services"][f"{p.compose_project}-api"]
    assert [s["url"] for s in api_service["loadBalancer"]["servers"]] == [
        "http://c-api-1:8000",
        "http://c-api-2:8000",
    ]
    router = next(r for r in http["routers"].values() if r["service"].endswith("-api"))
    assert router["rule"] == "Host(`api.inkerflow.example`)"
    assert router["tls"] == {"certResolver": "letsencrypt"}
