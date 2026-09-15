"""The app `run-app-wireguard-hub` (hub design 3.5): the version endpoint and the heartbeat, nothing else.

Unprivileged. The heartbeat is `aeth_ext`'s one-shot call from this module's own loop because the
scheduled helpers cannot pause while the interface is gone, and the loop passes the ping key and
slug only when no supervisor owns the ping (`DEVKIT_SUPERVISED_PING` unset; always, with
`supervise = false`). An interface that vanished stops the beats, the standard healthcheck turns
unhealthy and healthchecks.io alerts.
"""

# Standard library imports
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import override

# Third party imports
from aeth_ext.monitoring.heartbeat import send_heartbeat
from pydantic import SecretStr

HOST = "0.0.0.0"
PORT = 8000
BEAT_SECS = 60
HEARTBEAT_FILE = Path("/app/persisted_data/logs/heartbeat.txt")
INTERFACE = Path("/sys/class/net/wg0")


class _Handler(BaseHTTPRequestHandler):
  """`GET /version` answers `v<package version>` and a newline; every other path 404 (4.1)."""

  def do_GET(self) -> None:
    if self.path != "/version":
      self.send_error(404)
      return
    body = f"v{version('wireguard-hub')}\n".encode()
    self.send_response(200)
    self.send_header("Content-Type", "text/plain; charset=utf-8")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  @override
  def log_message(self, format: str, *args: object) -> None:
    """Silence per-request lines: a 30 s route probe would fill the container log."""


def serve(host: str, port: int) -> ThreadingHTTPServer:
  """Start the HTTP server on a daemon thread and return it."""
  server = ThreadingHTTPServer((host, port), _Handler)
  threading.Thread(target=server.serve_forever, name="http", daemon=True).start()
  return server


def beat() -> bool:
  """One heartbeat, only while the interface exists; `False` when it does not."""
  if not INTERFACE.exists():
    return False
  supervised = bool(os.environ.get("DEVKIT_SUPERVISED_PING", "").strip())
  url = os.environ.get("ALERTS_HEALTHCHECK_PING_URL", "").strip()
  key = os.environ.get("PINGKEY", "").strip()
  send_heartbeat(
    HEARTBEAT_FILE,
    ping_url=SecretStr(url) if url and not supervised else None,
    pingkey=SecretStr(key) if key and not supervised else None,
    slug=os.environ.get("HEARTBEAT_SLUG") if not supervised else None,
  )
  return True


def run_app() -> None:
  """Serve until SIGINT or SIGTERM, beating every `BEAT_SECS`."""
  stop = threading.Event()
  signal.signal(signal.SIGINT, lambda *_: stop.set())
  signal.signal(signal.SIGTERM, lambda *_: stop.set())
  HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
  server = serve(HOST, PORT)
  print(f"run-app-wireguard-hub: serving /version on {HOST}:{PORT}", file=sys.stderr)
  while not stop.is_set():
    beat()
    stop.wait(BEAT_SECS)
  server.shutdown()
  server.server_close()


if __name__ == "__main__":
  run_app()
