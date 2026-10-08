# syntax=docker/dockerfile:1.7
# Control plane image: API, agent mTLS listener, Celery worker and beat (different commands).
FROM python:3.13-slim-bookworm AS build
WORKDIR /src
RUN pip install --no-cache-dir build==1.2.2.post1
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY agent ./agent
COPY packages ./packages
RUN python -m build --wheel --outdir /wheels .

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd --system --gid 10001 udeploy && useradd --system --uid 10001 --gid udeploy --home /app udeploy
WORKDIR /app
COPY --from=build /wheels /wheels
RUN WHEEL=$(ls /wheels/udeploy-*.whl) && pip install "${WHEEL}[control-plane]" && rm -rf /wheels
COPY alembic.ini ./
COPY migrations ./migrations
RUN mkdir -p /var/lib/udeploy-pki && chown 10001:10001 /var/lib/udeploy-pki && chmod 0700 /var/lib/udeploy-pki
USER 10001:10001
EXPOSE 8000 8443
LABEL org.opencontainers.image.title="udeploy-control-plane"
CMD ["uvicorn", "udeploy_api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
