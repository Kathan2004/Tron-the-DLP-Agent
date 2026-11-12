#!/usr/bin/env python3
"""
Tron DLP API: local development entry point.

Runs the API on Werkzeug's development server. For anything reachable from a network use
gunicorn (the Docker image does):

    gunicorn -c gunicorn.conf.py wsgi:app
"""

import logging
import sys

from config.settings import Config
from src.bootstrap import create_app


def main() -> int:
    app = create_app()
    log = logging.getLogger("tron")
    if Config.FLASK_HOST not in {"127.0.0.1", "localhost", "::1"}:
        log.warning("development server bound to %s: use gunicorn (wsgi:app) behind TLS for "
                    "network-facing deployments", Config.FLASK_HOST)
    log.info("API listening on http://%s:%s", Config.FLASK_HOST, Config.FLASK_PORT)
    try:
        app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=Config.DEBUG,
                use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
