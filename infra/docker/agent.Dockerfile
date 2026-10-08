# syntax=docker/dockerfile:1.7
# Host agent. It drives the local Docker Engine through the socket, which makes it
# root-equivalent on the host: it is a critical trusted component (see docs/threat-model.md).
FROM python:3.13-slim-bookworm AS build
WORKDIR /src
RUN pip install --no-cache-dir build==1.2.2.post1
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY agent ./agent
COPY packages ./packages
RUN python -m build --wheel --outdir /wheels .

FROM docker:27.3.1-cli AS dockercli

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=build /wheels /wheels
# The agent only needs the pure packages (domain/planner/renderer/security) + httpx.
RUN pip install /wheels/udeploy-*.whl && rm -rf /wheels && docker --version && docker compose version
LABEL org.opencontainers.image.title="udeploy-agent"
ENTRYPOINT ["udeploy-agent"]
CMD ["run"]
