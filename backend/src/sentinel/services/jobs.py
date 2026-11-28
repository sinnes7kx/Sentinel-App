"""Bounded asynchronous job engine.

* Handlers are ordinary blocking callables (tools wait on subprocesses); they
  run in worker threads behind a bounded asyncio queue.
* Every state transition is persisted and broadcast to subscribers (the
  WebSocket layer). Events never invent progress percentages.
* Cancellation is cooperative through ``JobContext.cancel``; the ported tool
  runner observes it and terminates its subprocess.
* On timeout the job is marked TIMED_OUT and cancellation is signalled. A
  handler thread that ignores cancellation can outlive its job, so handlers
  must poll ``ctx.cancelled`` (the tool runner does).
* Jobs are not resumable. At startup, jobs a previous process left QUEUED or
  RUNNING are marked FAILED as interrupted — never reported as completed.
"""
from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..core.evidence import sanitize
from ..db.base import utcnow
from ..db.models import Job, JobStatus
from . import audit

TERMINAL_STATES = frozenset(
    {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.TIMED_OUT}
)


class QueueFull(RuntimeError):
    pass


class UnknownJobKind(ValueError):
    pass


class JobContext:
    """Passed to handlers: cancellation flag plus a thread-safe event emitter."""

    def __init__(self, job_id: str, cancel: threading.Event, emit: Callable[[dict], None]):
        self.job_id = job_id
        self.cancel = cancel
        self._emit = emit

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def emit(self, event: str, **data: Any) -> None:
        self._emit(
            {
                "type": "job.event",
                "job_id": self.job_id,
                "event": event,
                "data": sanitize(data),
                "at": utcnow().isoformat(),
            }
        )


JobHandler = Callable[[dict[str, Any], JobContext], "dict[str, Any] | None"]


@dataclass(frozen=True)
class _Spec:
    handler: JobHandler
    timeout_s: float


def _short_error(exc: BaseException) -> str:
    return sanitize(f"{type(exc).__name__}: {str(exc)[:300]}")


class JobManager:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        workers: int = 1,
        max_queued: int = 16,
        subscriber_buffer: int = 256,
    ):
        self._sf = session_factory
        self._worker_count = workers
        self._max_queued = max_queued
        self._buffer = subscriber_buffer
        self._specs: dict[str, _Spec] = {}
        self._queue: asyncio.Queue[str] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: list[asyncio.Task] = []
        self._cancels: dict[str, threading.Event] = {}
        self._params: dict[str, dict[str, Any]] = {}
        self._kinds: dict[str, str] = {}
        self._subscribers: set[asyncio.Queue] = set()

    # ---------------------------------------------------------------- lifecycle
    def register(self, kind: str, handler: JobHandler, *, timeout_s: float = 900.0) -> None:
        self._specs[kind] = _Spec(handler, timeout_s)

    @property
    def kinds(self) -> list[str]:
        return sorted(self._specs)

    @property
    def running(self) -> bool:
        return bool(self._tasks)

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=self._max_queued)
        self.reconcile_interrupted()
        self._tasks = [
            asyncio.create_task(self._worker(), name=f"sentinel-job-worker-{i}")
            for i in range(self._worker_count)
        ]

    async def stop(self) -> None:
        for event in self._cancels.values():
            event.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        if self._queue is not None:
            while not self._queue.empty():
                job_id = self._queue.get_nowait()
                self._set_status(job_id, JobStatus.CANCELLED,
                                 error="Sentinel shut down before the job started.")
                self._forget(job_id)

    def reconcile_interrupted(self) -> int:
        with self._sf() as s:
            stale = list(
                s.scalars(select(Job).where(Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])))
            )
            now = utcnow()
            for job in stale:
                job.status = JobStatus.FAILED
                job.finished_at = now
                job.error = (
                    "Interrupted: Sentinel stopped before this job finished. "
                    "No result was recorded; run it again."
                )
            if stale:
                audit.record(s, "jobs.reconciled", "job", "", {"interrupted": len(stale)},
                             actor="system")
            s.commit()
            return len(stale)

    # ---------------------------------------------------------------- commands
    async def submit(self, kind: str, params: dict[str, Any], actor: str = "operator") -> str:
        if kind not in self._specs:
            raise UnknownJobKind(f"Unknown job kind '{kind}'.")
        if self._queue is None or not self._tasks:
            raise RuntimeError("The job engine is not running.")
        if self._queue.full():
            raise QueueFull("Too many queued jobs. Wait for running work to finish.")
        with self._sf() as s:
            # Only a redacted copy of the parameters is persisted.
            job = Job(kind=kind, params=sanitize(params), status=JobStatus.QUEUED)
            s.add(job)
            s.flush()
            job_id = job.id
            audit.record(s, "job.submitted", "job", job_id, {"kind": kind}, actor=actor)
            s.commit()
        self._cancels[job_id] = threading.Event()
        self._params[job_id] = dict(params)
        self._kinds[job_id] = kind
        self._queue.put_nowait(job_id)
        self._broadcast(self._status_event(job_id, JobStatus.QUEUED))
        return job_id

    def cancel(self, job_id: str, actor: str = "operator") -> bool:
        event = self._cancels.get(job_id)
        if event is None:
            return False
        event.set()
        with self._sf() as s:
            audit.record(s, "job.cancel_requested", "job", job_id, actor=actor)
            s.commit()
        return True

    # ---------------------------------------------------------------- events
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._buffer)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, event: dict) -> None:
        for q in list(self._subscribers):
            if q.full():  # slow consumer: drop its oldest event, never block workers
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)

    def _emit_threadsafe(self, event: dict) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._broadcast, event)

    @staticmethod
    def _status_event(job_id: str, status: JobStatus, error: str = "") -> dict:
        return {
            "type": "job.status",
            "job_id": job_id,
            "status": status.value,
            "error": error,
            "at": utcnow().isoformat(),
        }

    # ---------------------------------------------------------------- execution
    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            job_id = await self._queue.get()
            try:
                await self._run(job_id)
            finally:
                self._queue.task_done()
                self._forget(job_id)

    def _forget(self, job_id: str) -> None:
        self._cancels.pop(job_id, None)
        self._params.pop(job_id, None)
        self._kinds.pop(job_id, None)

    async def _run(self, job_id: str) -> None:
        cancel = self._cancels[job_id]
        spec = self._specs[self._kinds[job_id]]
        if cancel.is_set():
            self._set_status(job_id, JobStatus.CANCELLED, error="Cancelled before it started.")
            return

        self._set_status(job_id, JobStatus.RUNNING, started=True)
        ctx = JobContext(job_id, cancel, self._emit_threadsafe)
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(spec.handler, self._params[job_id], ctx), spec.timeout_s
            )
        except TimeoutError:
            cancel.set()
            self._set_status(
                job_id, JobStatus.TIMED_OUT,
                error=f"Exceeded the {spec.timeout_s:g}s limit; results are incomplete.",
            )
            return
        except asyncio.CancelledError:
            cancel.set()
            self._set_status(job_id, JobStatus.CANCELLED,
                             error="Sentinel shut down while the job was running.")
            raise
        except Exception as exc:  # handler failure is a job outcome, not a crash
            status = JobStatus.CANCELLED if cancel.is_set() else JobStatus.FAILED
            self._set_status(job_id, status, error=_short_error(exc))
            return

        if cancel.is_set():
            self._set_status(job_id, JobStatus.CANCELLED,
                             error="Cancelled; results are incomplete.", result=result)
        else:
            self._set_status(job_id, JobStatus.SUCCEEDED, result=result)

    def _set_status(
        self,
        job_id: str,
        status: JobStatus,
        *,
        error: str = "",
        started: bool = False,
        result: dict[str, Any] | None = None,
    ) -> None:
        now = utcnow()
        with self._sf() as s:
            job = s.get(Job, job_id)
            if job is None:
                return
            job.status = status
            if started:
                job.started_at = now
            if status in TERMINAL_STATES:
                job.finished_at = now
                audit.record(s, f"job.{status.value}", "job", job_id, {"kind": job.kind},
                             actor="system")
            if error:
                job.error = error
            if result and isinstance(result.get("assessment_id"), int):
                job.assessment_id = result["assessment_id"]
            s.commit()
        self._broadcast(self._status_event(job_id, status, error))
