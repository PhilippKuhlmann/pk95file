"""Entry point: python3 -m pk95file"""

from __future__ import annotations

import logging
import signal
import sys
import threading

from . import VERSION, config, httpapi, routes
from .app import App

log = logging.getLogger("pk95file")


def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    if cfg.core_mode and len(cfg.token) < httpapi.MIN_TOKEN:
        log.warning("PK95_CORE_TOKEN is missing or shorter than %d characters: every API call will get 401",
                    httpapi.MIN_TOKEN)
    app = App(cfg)
    app.boot()
    server = httpapi.serve(cfg.listen_host, cfg.listen_port, routes.build(app), cfg.token, cfg.core_mode)

    def stop(signum, _frame):
        log.info("signal %s, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("PK95 File %s listening on %s:%d (core mode: %s, state: %s)", VERSION, cfg.listen_host,
             cfg.listen_port, cfg.core_mode, app.state())
    try:
        server.serve_forever()
    finally:
        app.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
