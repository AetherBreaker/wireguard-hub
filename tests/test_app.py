# Standard library imports
import http.client
from datetime import datetime
from importlib.metadata import version
from typing import TYPE_CHECKING

# Third party imports
import pytest
from pydantic import SecretStr

# First party imports
import wireguard_hub.__main__ as app

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Iterator
  from http.server import ThreadingHTTPServer
  from pathlib import Path

NOT_FOUND = 404
OK = 200


@pytest.fixture
def server() -> Iterator[ThreadingHTTPServer]:
  srv = app.serve("127.0.0.1", 0)
  yield srv
  srv.shutdown()
  srv.server_close()


def test_version_answers_the_tag_and_every_other_path_is_404(server: ThreadingHTTPServer):
  conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
  conn.request("GET", "/version")
  r = conn.getresponse()
  assert r.status == OK
  assert r.getheader("Content-Type") == "text/plain; charset=utf-8"
  assert r.read() == f"v{version('wireguard-hub')}\n".encode()
  for path in ["/", "/version/", "/versions", "/health"]:
    conn.request("GET", path)
    r = conn.getresponse()
    assert r.status == NOT_FOUND, path
    r.read()


def test_the_heartbeat_is_written_only_while_the_interface_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
  beat_file = tmp_path / "logs" / "heartbeat.txt"
  iface = tmp_path / "wg0"
  monkeypatch.setattr(app, "HEARTBEAT_FILE", beat_file)
  monkeypatch.setattr(app, "INTERFACE", iface)
  monkeypatch.delenv("PINGKEY", raising=False)
  monkeypatch.delenv("ALERTS_HEALTHCHECK_PING_URL", raising=False)
  assert app.beat() is False
  assert not beat_file.exists()
  iface.mkdir()
  beat_file.parent.mkdir()
  assert app.beat() is True
  datetime.fromisoformat(beat_file.read_text(encoding="utf-8").strip())


def test_the_ping_key_and_slug_go_only_when_no_supervisor_owns_the_ping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
  seen: list[dict[str, object]] = []
  monkeypatch.setattr(app, "send_heartbeat", lambda file, **kw: seen.append({"file": file, **kw}))
  monkeypatch.setattr(app, "HEARTBEAT_FILE", tmp_path / "heartbeat.txt")
  monkeypatch.setattr(app, "INTERFACE", tmp_path)
  monkeypatch.setenv("PINGKEY", "k")
  monkeypatch.setenv("HEARTBEAT_SLUG", "wireguard-hub")
  monkeypatch.delenv("DEVKIT_SUPERVISED_PING", raising=False)
  app.beat()
  assert seen[-1]["file"] == tmp_path / "heartbeat.txt"
  key = seen[-1]["pingkey"]
  assert isinstance(key, SecretStr) and key.get_secret_value() == "k"
  assert seen[-1]["slug"] == "wireguard-hub"
  monkeypatch.setenv("DEVKIT_SUPERVISED_PING", "1")
  app.beat()
  assert seen[-1]["pingkey"] is None and seen[-1]["slug"] is None and seen[-1]["ping_url"] is None
