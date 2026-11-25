"""HTTP server: routing, bearer auth, JSON bodies and the error format of docs/api.md."""

from __future__ import annotations

import hmac
import json
import logging
import re
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import ApiError

log = logging.getLogger("pk95file.http")

MAX_BODY = 2 * 1024 * 1024
MIN_TOKEN = 32

CORE_NOTE = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>PK95 File</title>
</head>
<body style="font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5">
<h1 style="font-size: 1.4rem">PK95 File</h1>
<p>PK95 File wird über PK95 Core verwaltet. Bitte öffne die Oberfläche von PK95 Core.</p>
</body>
</html>
"""


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict
    body: object = None
    params: dict[str, str] = field(default_factory=dict)

    def q(self, name: str, default: str = "") -> str:
        return self.query.get(name, default)

    def flag(self, name: str) -> bool:
        return self.query.get(name, "").lower() in ("1", "true", "yes")

    def json(self) -> dict:
        if self.body is None or self.body == [] or self.body == {}:
            return {}  # Core sends "[]" for POST routes without payload
        if not isinstance(self.body, dict):
            raise ApiError(400, "Der Inhalt muss ein JSON-Objekt sein.")
        return self.body


@dataclass
class Response:
    status: int
    body: object = None
    content_type: str = "application/json; charset=utf-8"


@dataclass
class Route:
    method: str
    pattern: re.Pattern
    handler: object
    auth: bool = True


def compile_path(path: str) -> re.Pattern:
    out, i = [], 0
    while i < len(path):
        if path[i] != "{":
            out.append(re.escape(path[i]))
            i += 1
            continue
        depth, j = 1, i + 1
        while j < len(path) and depth:
            depth += {"{": 1, "}": -1}.get(path[j], 0)
            j += 1
        name, _, rx = path[i + 1:j - 1].partition(":")
        out.append(f"(?P<{name}>{rx or '[^/]+'})")
        i = j
    return re.compile("^" + "".join(out) + "$")


class Router:
    def __init__(self):
        self.routes: list[Route] = []

    def add(self, method: str, path: str, handler, auth: bool = True) -> None:
        """path uses {name} for one segment, {name:regex} for a custom pattern (braces may nest)."""
        self.routes.append(Route(method, compile_path(path), handler, auth))

    def match(self, method: str, path: str):
        allowed = []
        for r in self.routes:
            m = r.pattern.match(path)
            if not m:
                continue
            if r.method == method or (method == "HEAD" and r.method == "GET"):
                return r, {k: unquote(v) for k, v in m.groupdict().items()}, allowed
            allowed.append(r.method)
        return None, {}, allowed


def token_ok(header: str | None, token: str) -> bool:
    if not token or len(token) < MIN_TOKEN or not header:
        return False
    scheme, _, given = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(given.strip().encode("utf-8"), token.encode("utf-8"))


def make_handler(router: Router, token: str, core_mode: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "pk95file"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: N802 - stdlib name
            log.debug("%s %s", self.address_string(), fmt % args)

        def _send(self, resp: Response) -> None:
            if resp.status == 204 or resp.body is None:
                data = b""
            elif isinstance(resp.body, (bytes, str)):
                data = resp.body.encode("utf-8") if isinstance(resp.body, str) else resp.body
            else:
                data = json.dumps(resp.body, ensure_ascii=False).encode("utf-8")
            self.send_response(resp.status)
            if resp.status != 204:
                self.send_header("Content-Type", resp.content_type)
                self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD" and resp.status != 204:
                self.wfile.write(data)

        def _error(self, status: int, message: str, fields=None) -> None:
            self._send(Response(status, ApiError(status, message, fields).body()))

        def _handle(self) -> None:
            url = urlsplit(self.path)
            path = url.path or "/"
            query = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
            method = self.command

            if path == "/" and method in ("GET", "HEAD"):
                if core_mode:
                    self._send(Response(200, CORE_NOTE, "text/html; charset=utf-8"))
                else:
                    self._send(Response(200, {"name": "PK95 File", "api": "/api", "docs": "docs/api.md"}))
                return

            route, params, allowed = router.match(method, path)
            if route is None:
                self._drain()
                if allowed:
                    self.send_response(405)
                    body = json.dumps({"error": "Methode nicht erlaubt."}, ensure_ascii=False).encode()
                    self.send_header("Allow", ", ".join(sorted(set(allowed))))
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._error(404, "Nicht gefunden.")
                return

            if route.auth and not token_ok(self.headers.get("Authorization"), token):
                self._drain()
                self._error(401, "Nicht angemeldet.")
                return

            body = None
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                length = self.headers.get("Content-Length")
                has_body = bool(self.headers.get("Transfer-Encoding")) or (
                    bool(length) and length.isdigit() and int(length) > 0)
                # A request without a body needs no Content-Type (DELETE from Core); with a body it must be JSON.
                if has_body and ctype != "application/json":
                    self._drain()
                    self._error(415, "Bitte Content-Type: application/json senden.")
                    return
                if self.headers.get("Transfer-Encoding"):
                    self._error(411, "Bitte Content-Length senden.")
                    self.close_connection = True
                    return
                n = int(length) if length and length.isdigit() else 0
                if n > MAX_BODY:
                    self._error(413, "Die Anfrage ist zu groß (höchstens 2 MiB).")
                    self.close_connection = True
                    return
                raw = self.rfile.read(n) if n else b""
                if raw.strip():
                    try:
                        body = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        self._error(400, "Ungültiges JSON.")
                        return
            else:
                self._drain()

            req = Request(method, path, query, self.headers, body, params)
            try:
                resp = route.handler(req)
            except ApiError as exc:
                self._send(Response(exc.status, exc.body()))
                return
            except Exception:  # noqa: BLE001 - the API must answer
                log.error("internal error on %s %s\n%s", method, path, traceback.format_exc())
                self._error(500, "Interner Fehler. Details stehen im Log von PK95 File.")
                return
            if not isinstance(resp, Response):
                resp = Response(200, resp)
            self._send(resp)

        def _drain(self) -> None:
            length = self.headers.get("Content-Length")
            if length and length.isdigit():
                n = int(length)
                if n > MAX_BODY:
                    self.close_connection = True
                    return
                self.rfile.read(n)

        def do_GET(self):  # noqa: N802
            self._handle()

        do_HEAD = do_GET
        do_POST = do_GET
        do_PUT = do_GET
        do_DELETE = do_GET
        do_PATCH = do_GET

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(host: str, port: int, router: Router, token: str, core_mode: bool) -> Server:
    return Server((host, port), make_handler(router, token, core_mode))
