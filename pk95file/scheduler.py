"""Time-of-day jobs in local time (TZ from Core): the daily maintenance run (recycle retention) and, per share,
the snapshot times. Every slot runs at most once; a slot missed by more than CATCH_UP (container down) is skipped,
so a restart does not fire a backlog of old runs."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta

from .store import load_json, save_json

log = logging.getLogger("pk95file.scheduler")

TICK = 30.0
CATCH_UP = timedelta(minutes=60)


def due_slot(times: list[str], weekdays: list[int], now: datetime, done: set[str]) -> str | None:
    """The latest slot "YYYY-MM-DD HH:MM" of today that is due (passed, within CATCH_UP) and not done (pure)."""
    if now.isoweekday() not in weekdays:
        return None
    for t in sorted(times, reverse=True):
        h, m = map(int, t.split(":"))
        at = now.replace(hour=h, minute=m, second=0, microsecond=0)
        key = at.strftime("%Y-%m-%d %H:%M")
        if at <= now and now - at <= CATCH_UP:
            return None if key in done else key
    return None


def next_slot(times: list[str], weekdays: list[int], now: datetime) -> datetime | None:
    """The next slot after now within the coming 8 days (pure)."""
    for day in range(8):
        d = now + timedelta(days=day)
        if d.isoweekday() not in weekdays:
            continue
        for t in sorted(times):
            h, m = map(int, t.split(":"))
            at = d.replace(hour=h, minute=m, second=0, microsecond=0)
            if at > now:
                return at
    return None


class Scheduler:
    """Calls each task's tick(now, done) every TICK seconds; a task returns slot keys it ran, which are stored."""

    def __init__(self, app):
        self.app = app
        self.path = app.cfg.path("scheduler.json")
        self.done: dict[str, list[str]] = load_json(self.path, {})
        self.tasks: dict[str, object] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def add(self, name: str, fn) -> None:
        """fn(now: datetime, done: set[str]) -> list[str] of slot keys it handled."""
        self.tasks[name] = fn

    def start(self) -> None:
        if self._thread or not self.app.cfg.manage_processes:
            return
        self._thread = threading.Thread(target=self._run, name="scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.tick(datetime.now())
            self._stop.wait(TICK)

    def tick(self, now: datetime) -> None:
        if self.app.state() != "ready" or self.app.backup_active:
            return
        for name, fn in list(self.tasks.items()):
            try:
                handled = fn(now, set(self.done.get(name, [])))
            except Exception:  # noqa: BLE001 - one task must not stop the others
                log.exception("scheduled task %s failed", name)
                continue
            if handled:
                with self._lock:
                    keys = self.done.get(name, []) + list(handled)
                    self.done[name] = keys[-200:]
                    save_json(self.path, self.done)


def localtime_now() -> datetime:
    return datetime.fromtimestamp(time.time())
