"""Job engine: persisted lifecycle, cancellation, timeouts, backpressure, crash reconcile."""
from __future__ import annotations

import asyncio
import time

import pytest

from sentinel.db.models import Job, JobStatus
from sentinel.services.jobs import JobManager, QueueFull, UnknownJobKind


def ok_handler(params, ctx):
    ctx.emit("progress", step="started", authorization="Bearer leaked")
    return {"echo": params.get("value")}


def failing_handler(params, ctx):
    raise RuntimeError("tool exited 2 password=hunter2")


def cooperative_slow_handler(params, ctx):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ctx.cancelled:
            return None
        time.sleep(0.01)
    return None


async def wait_for_status(q: asyncio.Queue, job_id: str, statuses: set[str], timeout=5.0) -> dict:
    async def _wait():
        while True:
            ev = await q.get()
            if ev["type"] == "job.status" and ev["job_id"] == job_id and ev["status"] in statuses:
                return ev
    return await asyncio.wait_for(_wait(), timeout)


@pytest.fixture
async def manager(factory):
    m = JobManager(factory, workers=1, max_queued=2)
    m.register("ok", ok_handler)
    m.register("fail", failing_handler)
    m.register("slow", cooperative_slow_handler)
    m.register("short_timeout", cooperative_slow_handler, timeout_s=0.2)
    await m.start()
    yield m
    await m.stop()


async def test_success_is_persisted_and_broadcast(manager, session):
    q = manager.subscribe()
    job_id = await manager.submit("ok", {"value": 42, "token": "s3cret"})
    ev = await wait_for_status(q, job_id, {"succeeded"})
    assert ev["status"] == "succeeded"

    job = session.get(Job, job_id)
    assert job.status is JobStatus.SUCCEEDED
    assert job.started_at is not None and job.finished_at is not None
    assert "s3cret" not in str(job.params)  # only a redacted copy is stored


async def test_progress_events_are_redacted(manager):
    q = manager.subscribe()
    job_id = await manager.submit("ok", {})
    events = []

    async def collect():
        while True:
            ev = await q.get()
            events.append(ev)
            if ev["type"] == "job.status" and ev["status"] == "succeeded":
                return

    await asyncio.wait_for(collect(), 5)
    progress = [e for e in events if e["type"] == "job.event" and e["job_id"] == job_id]
    assert progress and progress[0]["data"]["authorization"] == "[REDACTED]"


async def test_handler_failure_is_recorded_redacted(manager, session):
    q = manager.subscribe()
    job_id = await manager.submit("fail", {})
    ev = await wait_for_status(q, job_id, {"failed"})
    assert "RuntimeError" in ev["error"] and "hunter2" not in ev["error"]
    assert session.get(Job, job_id).status is JobStatus.FAILED


async def test_cancel_running_job(manager, session):
    q = manager.subscribe()
    job_id = await manager.submit("slow", {})
    await wait_for_status(q, job_id, {"running"})
    assert manager.cancel(job_id)
    await wait_for_status(q, job_id, {"cancelled"})
    assert session.get(Job, job_id).status is JobStatus.CANCELLED


async def test_timeout_marks_incomplete(manager, session):
    q = manager.subscribe()
    job_id = await manager.submit("short_timeout", {})
    ev = await wait_for_status(q, job_id, {"timed_out"})
    assert "incomplete" in ev["error"]


async def test_queue_backpressure(manager):
    q = manager.subscribe()
    running = await manager.submit("slow", {})
    await wait_for_status(q, running, {"running"})
    queued = [await manager.submit("slow", {}) for _ in range(2)]  # fills max_queued=2
    with pytest.raises(QueueFull):
        await manager.submit("slow", {})
    for jid in [running, *queued]:
        manager.cancel(jid)


async def test_unknown_kind_rejected(manager):
    with pytest.raises(UnknownJobKind):
        await manager.submit("rm -rf", {})


async def test_stale_jobs_reconciled_on_start(factory):
    with factory() as s:
        s.add_all([Job(id="stale-running", kind="ok", status=JobStatus.RUNNING),
                   Job(id="stale-queued", kind="ok", status=JobStatus.QUEUED),
                   Job(id="done", kind="ok", status=JobStatus.SUCCEEDED)])
        s.commit()
    m = JobManager(factory)
    await m.start()
    await m.stop()
    with factory() as s:
        assert s.get(Job, "stale-running").status is JobStatus.FAILED
        assert "Interrupted" in s.get(Job, "stale-running").error
        assert s.get(Job, "stale-queued").status is JobStatus.FAILED
        assert s.get(Job, "done").status is JobStatus.SUCCEEDED


async def test_shutdown_cancels_queued_and_running(factory):
    m = JobManager(factory, workers=1, max_queued=4)
    m.register("slow", cooperative_slow_handler)
    await m.start()
    q = m.subscribe()
    running = await m.submit("slow", {})
    await wait_for_status(q, running, {"running"})
    waiting = await m.submit("slow", {})
    await m.stop()
    with factory() as s:
        assert s.get(Job, running).status is JobStatus.CANCELLED
        assert s.get(Job, waiting).status is JobStatus.CANCELLED
