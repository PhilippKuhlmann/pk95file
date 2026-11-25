"""Background jobs (docs/api.md → Jobs): run one after another per share, kept in memory (the last 100)."""

from __future__ import annotations

import logging
import secrets
import threading

from .errors import conflict, not_found
from .store import now_ms

log = logging.getLogger("pk95file.jobs")
KEEP = 100


class Job:
    def __init__(self, kind: str, share: str = ""):
        self.id = secrets.token_hex(6)
        self.kind = kind
        self.share = share
        self.state = "queued"
        self.done = 0
        self.total = 0
        self.unit = ""
        self.started_at = 0
        self.finished_at = 0
        self.error = ""

    def progress(self, done: int, total: int = 0, unit: str = "") -> None:
        self.done, self.total, self.unit = done, total or self.total, unit or self.unit

    def info(self) -> dict:
        return {"id": self.id, "kind": self.kind, "share": self.share, "state": self.state,
                "progress": {"done": self.done, "total": self.total, "unit": self.unit},
                "started_at": self.started_at, "finished_at": self.finished_at, "error": self.error}


class Jobs:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: list[Job] = []
        self._share_locks: dict[str, threading.Lock] = {}

    def start(self, kind: str, fn, share: str = "", exclusive: bool = False) -> Job:
        """Run fn(job) in a thread. exclusive: refuse (409) while a job of the same kind runs for the share."""
        with self._lock:
            if exclusive and any(j.kind == kind and j.share.lower() == share.lower() and j.state in ("queued", "running")
                                 for j in self._jobs):
                raise conflict("Für diese Freigabe läuft bereits ein solcher Auftrag.")
            job = Job(kind, share)
            self._jobs.append(job)
            del self._jobs[:-KEEP]
            lock = self._share_locks.setdefault(share.lower(), threading.Lock())

        def run():
            with lock:
                job.state, job.started_at = "running", now_ms()
                try:
                    fn(job)
                    job.state = "done"
                except Exception as exc:  # noqa: BLE001 - a job reports its error, it never kills the app
                    log.exception("job %s (%s) failed", job.id, kind)
                    job.state, job.error = "failed", str(exc)
                job.finished_at = now_ms()

        threading.Thread(target=run, name=f"job-{kind}", daemon=True).start()
        return job

    def get(self, job_id: str) -> dict:
        with self._lock:
            for j in self._jobs:
                if j.id == job_id:
                    return j.info()
        raise not_found("Unbekannter Auftrag.")

    def list(self, kind: str = "", state: str = "") -> list[dict]:
        with self._lock:
            return [j.info() for j in reversed(self._jobs)
                    if (not kind or j.kind == kind) and (not state or j.state == state)]
