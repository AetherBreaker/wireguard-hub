# Standard library imports
import base64
import subprocess
from typing import TYPE_CHECKING

# Third party imports
import pytest

# First party imports
from wireguard_hub import up

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

HUB_KEY = base64.b64encode(bytes(range(32))).decode()
KEY_A = base64.b64encode(bytes([1] * 32)).decode()
TABLE = f"""
schema = 1
[hub]
name = "wireguard-hub"
public_key = "{HUB_KEY}"
address = "10.8.0.1/24"
listen_port = 51820
endpoint = "tunnels.example:51820"
allowed_ips = ["10.8.0.0/24"]
persistent_keepalive = 25
[[peers]]
name = "a"
public_key = "{KEY_A}"
address = "10.8.0.10/32"
"""
RULES = "*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"


class Recorder:
  def __init__(self, fail_on: str | None = None) -> None:
    self.calls: list[tuple[list[str], str | None]] = []
    self.fail_on = fail_on

  def __call__(self, args: list[str], *, input: str | None = None, **kwargs: object) -> subprocess.CompletedProcess[str]:  # noqa: A002
    self.calls.append((list(args), input))
    if self.fail_on and args[0] == self.fail_on:
      return subprocess.CompletedProcess(args, 3, "", "boom")
    return subprocess.CompletedProcess(args, 0, "PUBKEY\n" if args == ["wg", "pubkey"] else "", "")


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Recorder:
  (tmp_path / "peers.toml").write_text(TABLE, encoding="utf-8")
  (tmp_path / "rules.v4").write_text(RULES, encoding="utf-8")
  (tmp_path / "ip_forward").write_text("1\n", encoding="utf-8")
  monkeypatch.setattr(up, "PEERS_PATH", tmp_path / "peers.toml")
  monkeypatch.setattr(up, "RULES_PATH", tmp_path / "rules.v4")
  monkeypatch.setattr(up, "IP_FORWARD", tmp_path / "ip_forward")
  monkeypatch.setenv("WG_HUB_PRIVATE_KEY", "PRIVATE")
  rec = Recorder()
  monkeypatch.setattr(up.subprocess, "run", rec)
  return rec


def test_the_eight_steps_run_in_order_with_the_key_on_stdin(host: Recorder, capsys: pytest.CaptureFixture[str]):
  up.main()
  assert host.calls == [
    (["ip", "link", "add", "dev", "wg0", "type", "wireguard"], None),
    (["wg", "set", "wg0", "listen-port", "51820", "private-key", "/dev/stdin"], "PRIVATE\n"),
    (["wg", "set", "wg0", "peer", KEY_A, "allowed-ips", "10.8.0.10/32"], None),
    (["ip", "address", "add", "10.8.0.1/24", "dev", "wg0"], None),
    (["ip", "link", "set", "up", "dev", "wg0"], None),
    (["iptables-restore"], RULES),
    (["wg", "pubkey"], "PRIVATE\n"),
  ]
  err = capsys.readouterr().err
  assert "PUBKEY" in err and "1 peer(s)" in err
  assert "PRIVATE" not in err


def test_failures_name_the_cause_never_the_key(host: Recorder, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
  monkeypatch.setenv("WG_HUB_PRIVATE_KEY", " ")
  with pytest.raises(SystemExit, match="1"):
    up.main()
  assert "WG_HUB_PRIVATE_KEY" in capsys.readouterr().err
  monkeypatch.setenv("WG_HUB_PRIVATE_KEY", "PRIVATE")
  up.IP_FORWARD.write_text("0\n", encoding="utf-8")
  with pytest.raises(SystemExit):
    up.main()
  assert "net.ipv4.ip_forward is 0: the compose file needs sysctls net.ipv4.ip_forward=1" in capsys.readouterr().err
  assert host.calls == [], "nothing runs before the checks pass"
  up.IP_FORWARD.write_text("1\n", encoding="utf-8")
  up.PEERS_PATH.write_text(TABLE.replace("listen_port = 51820", "listen_port = 0"), encoding="utf-8")
  with pytest.raises(SystemExit):
    up.main()
  assert "hub.listen_port" in capsys.readouterr().err
  up.PEERS_PATH.write_text(TABLE, encoding="utf-8")
  monkeypatch.setattr(up.subprocess, "run", Recorder(fail_on="iptables-restore"))
  with pytest.raises(SystemExit):
    up.main()
  err = capsys.readouterr().err
  assert "iptables-restore" in err and "exited 3" in err and "PRIVATE" not in err
