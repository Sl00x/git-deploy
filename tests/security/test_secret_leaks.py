"""Secrets must stay masked everywhere except the agent wire format."""

from __future__ import annotations

import json

from udeploy_domain.plan import AgentTask

from ..factories import plan


def _task() -> AgentTask:
    p = plan()
    return AgentTask.model_validate(
        {
            "task_id": "t",
            "kind": "deploy",
            "attempt": 1,
            "plan": p,
            "plan_sha256": p.sha256(),
            "secrets": {"inkerflow/database-url": "pg://u:hunter2@db"},
            "lease_seconds": 60,
        }
    )


def test_default_dumps_and_repr_are_masked() -> None:
    task = _task()
    assert "hunter2" not in task.model_dump_json()
    assert "hunter2" not in json.dumps(task.model_dump(mode="json"))
    assert "hunter2" not in repr(task) and "hunter2" not in str(task)


def test_wire_format_reveals_for_the_agent_only() -> None:
    wire = _task().wire_json()
    assert wire["secrets"] == {"inkerflow/database-url": "pg://u:hunter2@db"}
    # and the agent parses it back into a masked value
    parsed = AgentTask.model_validate(wire)
    assert parsed.secrets["inkerflow/database-url"].get_secret_value() == "pg://u:hunter2@db"
    assert "hunter2" not in repr(parsed)


def test_plan_never_contains_secret_values() -> None:
    assert "hunter2" not in _task().plan.model_dump_json()
