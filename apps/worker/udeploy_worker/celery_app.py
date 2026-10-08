from __future__ import annotations

from celery import Celery

from udeploy_api.settings import get_settings

settings = get_settings()

app = Celery("udeploy", broker=settings.redis_url, include=["udeploy_worker.tasks"])
app.conf.update(
    task_acks_late=True,  # a crashed worker's task is redelivered
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_queue="udeploy",
    task_serializer="json",
    accept_content=["json"],
    result_backend=None,
    task_ignore_result=True,
    broker_transport_options={"visibility_timeout": 900},
    broker_connection_retry_on_startup=True,
    timezone="UTC",
    beat_schedule={
        "relay-outbox": {"task": "udeploy.relay_outbox", "schedule": 2.0},
        "reconcile": {"task": "udeploy.reconcile", "schedule": 15.0},
        "prune-deliveries": {"task": "udeploy.prune", "schedule": 3600.0},
    },
)
