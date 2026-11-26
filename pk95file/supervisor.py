"""Supervised child processes (winbindd, smbd) and a TCP probe."""

from __future__ import annotations

import logging
import socket
import subprocess
import sys
import threading
import time

from .store import now_ms

log = logging.getLogger("pk95file.supervisor")

BACKOFF = [5, 10, 20, 40, 80, 160, 300]
STABLE_AFTER = 600.0  # a run this long resets the backoff


class Process:
    """Runs argv_fn() as a child, forwards its output, restarts it with backoff after unexpected exits."""

    def __init__(self, name: str, argv_fn, on_crash=None, label: str = "", on_line=None):
        self.name = name
        self.label = label or name
        self.argv_fn = argv_fn
        self.on_crash = on_crash
        self.on_line = on_line
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._want = False
        self._timer: threading.Timer | None = None
        self._fails = 0
        self._started = 0.0
        self.state = "stopped"
        self.since = 0
        self.restarts = 0
        self.last_exit = ""

    @property
    def pid(self) -> int:
        p = self._proc
        return p.pid if p is not None and p.poll() is None else 0

    def running(self) -> bool:
        p = self._proc
        return p is not None and p.poll() is None

    def start(self) -> None:
        with self._lock:
            self._want = True
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if self.running():
                return
            self._spawn()

    def _spawn(self) -> None:
        argv = self.argv_fn()
        try:
            # Own session: smbd sends SIGTERM to its process group when it stops, which without this would be the
            # app's own group (winbindd and the API process died on every smbd stop, e.g. rejoin or backup).
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                 text=True, errors="replace", start_new_session=True)
        except OSError as exc:
            self.last_exit = f"{self.label} konnte nicht gestartet werden: {exc}"
            log.error("%s: %s", self.name, self.last_exit)
            self._schedule_restart()
            if self.on_crash:
                threading.Thread(target=self.on_crash, args=(None, self.last_exit), daemon=True).start()
            return
        log.info("%s started (pid %d): %s", self.name, p.pid, " ".join(argv))
        self._proc = p
        self._started = time.monotonic()
        self.state = "starting"
        self.since = now_ms()
        threading.Thread(target=self._pump, args=(p,), name=f"{self.name}-out", daemon=True).start()
        threading.Thread(target=self._wait, args=(p,), name=f"{self.name}-wait", daemon=True).start()

    def _pump(self, p: subprocess.Popen) -> None:
        assert p.stdout is not None
        for line in p.stdout:
            sys.stdout.write(f"[{self.name}] {line}" if line.endswith("\n") else f"[{self.name}] {line}\n")
            sys.stdout.flush()
            if self.on_line:
                try:
                    self.on_line(line.rstrip("\n"))
                except Exception:  # noqa: BLE001 - output watching must never stop the pump
                    log.exception("%s: line callback failed", self.name)

    def _schedule_restart(self) -> None:
        delay = BACKOFF[min(self._fails, len(BACKOFF) - 1)]
        self._fails += 1
        self.state = "restarting"
        self._timer = threading.Timer(delay, self._restart)
        self._timer.daemon = True
        self._timer.start()

    def _wait(self, p: subprocess.Popen) -> None:
        rc = p.wait()
        with self._lock:
            if self._proc is not p:
                return
            self._proc = None
            if not self._want:
                return
            if time.monotonic() - self._started > STABLE_AFTER:
                self._fails = 0
            self.restarts += 1
            self.last_exit = f"{self.label} wurde unerwartet beendet (Code {rc})."
            log.error("%s exited with %s, restarting", self.name, rc)
            self._schedule_restart()
        if self.on_crash:
            self.on_crash(rc, self.last_exit)

    def _restart(self) -> None:
        with self._lock:
            self._timer = None
            if self._want and not self.running():
                self._spawn()

    def stop(self, timeout: float = 30.0, state: str = "stopped") -> None:
        with self._lock:
            self._want = False
            if self._timer:
                self._timer.cancel()
                self._timer = None
            p = self._proc
        if p is not None and p.poll() is None:
            log.info("stopping %s (pid %d)", self.name, p.pid)
            p.terminate()
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                log.warning("%s did not stop within %ss, killing it", self.name, timeout)
                p.kill()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        with self._lock:
            if self._proc is p:
                self._proc = None
            self.state = state
            self.since = now_ms()

    def mark_running(self) -> None:
        with self._lock:
            if self.running() and self.state in ("starting", "restarting"):
                self.state = "running"

    def info(self) -> dict:
        return {"state": self.state, "pid": self.pid, "since": self.since, "restarts": self.restarts,
                "last_exit": self.last_exit}


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
