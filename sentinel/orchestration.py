"""One bounded application worker. Callbacks must only enqueue data, never touch Tk."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Queue, Full
from threading import Event, Lock, Thread
import logging
import uuid

from .evidence import sanitize

LOG = logging.getLogger('sentinel.jobs')


@dataclass
class Job:
    cancel: Event
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = 'queued'
    events: list = field(default_factory=list)

    def emit(self, state):
        self.state = state
        self.events.append({'state': state, 'at': datetime.now(timezone.utc).isoformat()})
        LOG.info('scan lifecycle', extra={'job_id': self.id, 'state': state})


class Orchestrator:
    """One active job and four waiting jobs by default; no GPU or unbounded pool."""
    def __init__(self, pending=4):
        self.queue = Queue(maxsize=pending)
        self.lock = Lock()
        self.closed = False
        self.jobs = {}
        self.worker = Thread(target=self._work, name='sentinel-worker', daemon=True)
        self.worker.start()

    def submit(self, operation, completed, cancel=None):
        with self.lock:
            if self.closed:
                raise RuntimeError('Sentinel is closing.')
            job = Job(cancel if cancel is not None else Event())
            job.emit('queued')
            try:
                self.queue.put_nowait((job, operation, completed))
            except Full:
                raise RuntimeError('Four checks are already waiting. Wait or cancel a check.') from None
            self.jobs[job.id] = job
            return job

    def _work(self):
        while True:
            item = self.queue.get()
            if item is None:
                self.queue.task_done()
                return
            job, operation, completed = item
            result, error = None, None
            try:
                if not job.cancel.is_set():
                    job.emit('running')
                    result = sanitize(operation())
                if job.cancel.is_set():
                    job.emit('cancelled')
                    if isinstance(result, dict) and 'status' in result:
                        result['status'] = 'cancelled'
                        result['error'] = 'Cancelled; results are incomplete.'
                    else:
                        result, error = None, 'Check cancelled.'
                else:
                    job.emit(result.get('status', 'completed') if isinstance(result, dict) else 'completed')
            except Exception as exc:
                job.emit('cancelled' if job.cancel.is_set() else 'failed')
                # Exception messages may contain targets, credentials or tool output.
                error = 'Check cancelled.' if job.cancel.is_set() else 'Check failed (' + type(exc).__name__ + '). Verify the target, permission, files and tool installation.'
            if isinstance(result, dict):
                result['job_id'] = job.id
                result['events'] = list(job.events)
            try:
                completed(result, error)
            except Exception:
                LOG.error('result delivery failed', extra={'job_id': job.id, 'state': 'delivery_failed'})
            with self.lock:
                self.jobs.pop(job.id, None)
                stop = self.closed and not self.jobs
            self.queue.task_done()
            if stop:
                return

    def shutdown(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for job in self.jobs.values():
                job.cancel.set()
            if not self.jobs:
                self.queue.put_nowait(None)


def for_app(app):
    """Also supports standalone Tk test hosts without creating one pool per window."""
    if not hasattr(app, 'orchestrator'):
        app.orchestrator = Orchestrator()
        app.bind('<Destroy>', lambda event: app.orchestrator.shutdown() if event.widget is app else None, add='+')
    return app.orchestrator
