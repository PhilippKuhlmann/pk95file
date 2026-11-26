"""Events to PK95 Core (app protocol section 4): queued, retried every 30 s, dropped after one hour."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("pk95file.events")

MAX_AGE = 3600.0
MAX_QUEUE = 500
RETRY_EVERY = 30.0
TIMEOUT = 10.0

SETUP_DONE = "file.setup.done"
SETUP_FAILED = "file.setup.failed"
SMBD_DOWN = "file.smbd.down"
SMBD_UP = "file.smbd.up"
TRUST_BROKEN = "file.trust.broken"
TRUST_OK = "file.trust.ok"
IP_CONFLICT = "file.ip.conflict"
DISK_LOW = "file.disk.low"
SOFT_QUOTA_WARNING = "file.soft_quota.warning"
SOFT_QUOTA_EXCEEDED = "file.soft_quota.exceeded"
RID_LIMIT = "file.idmap.rid_limit"
SNAPSHOT_FAILED = "file.snapshot.failed"
SNAPSHOT_SKIPPED = "file.snapshot.skipped"

# The manifest's list (docs/api.md → Manifest, frozen): every type the app may send.
ALL = [SETUP_DONE, SETUP_FAILED, SMBD_DOWN, SMBD_UP, TRUST_BROKEN, TRUST_OK, IP_CONFLICT, DISK_LOW,
       SOFT_QUOTA_WARNING, SOFT_QUOTA_EXCEEDED, RID_LIMIT, SNAPSHOT_FAILED, SNAPSHOT_SKIPPED]


@dataclass
class _Queued:
    body: dict
    queued: float


class Sender:
    """Delivers events in order. With an empty URL or token (standalone) everything is dropped."""

    def __init__(self, core_url: str, token: str, retry: float = RETRY_EVERY, clock=time.monotonic):
        self.url = core_url.rstrip("/") + "/api/v1/events" if core_url else ""
        self.token = token
        self.retry = retry
        self.clock = clock
        self._queue: list[_Queued] = []
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return bool(self.url and self.token)

    def send(self, typ: str, severity: str, title: str, body: str = "", data: dict | None = None) -> None:
        if not self.active:
            log.info("event (not sent, standalone): %s %s", typ, title)
            return
        ev = {
            "type": typ, "severity": severity, "title": title, "body": body, "data": data or {},
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with self._lock:
            self._queue.append(_Queued(ev, self.clock()))
            if len(self._queue) > MAX_QUEUE:
                dropped = len(self._queue) - MAX_QUEUE
                log.warning("events: queue full, %d oldest dropped", dropped)
                del self._queue[:dropped]
        self._wake.set()

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def start(self) -> None:
        if not self.active or self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="events", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.retry)
            self._wake.clear()
            self.deliver()
        self.deliver(timeout=2.0)

    def deliver(self, timeout: float = TIMEOUT) -> None:
        """Send the queue in order; stop at the first failure (Core unreachable)."""
        with self._send_lock:
            while True:
                with self._lock:
                    now = self.clock()
                    while self._queue and now - self._queue[0].queued > MAX_AGE:
                        log.warning("events: dropped after one hour: %s", self._queue[0].body["type"])
                        self._queue.pop(0)
                    if not self._queue:
                        return
                    head = self._queue[0]
                if not self._post(head.body, timeout):
                    return
                with self._lock:
                    if self._queue and self._queue[0] is head:
                        self._queue.pop(0)

    def _post(self, body: dict, timeout: float) -> bool:
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Authorization": "Bearer " + self.token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp.read()
                return True
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 422:
                log.warning("events: Core rejected %s", body["type"])
                return True
            log.warning("events: Core answered %s for %s, will retry", exc.code, body["type"])
            return False
        except (urllib.error.URLError, OSError) as exc:
            log.warning("events: Core not reachable (%s), will retry", exc)
            return False
