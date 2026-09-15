# Standard library imports
import base64
from typing import TYPE_CHECKING

# First party imports
from wireguard_hub import bundle, peers

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

  # Third party imports
  import pytest

HUB_KEY = base64.b64encode(bytes(range(32))).decode()
KEY_A = base64.b64encode(bytes([1] * 32)).decode()
TABLE = f"""schema = 1

[hub]
name = "wireguard-hub"
public_key = "{HUB_KEY}"
address = "10.8.0.1/24"
listen_port = 51820
endpoint = "tunnels.example:51820"
allowed_ips = ["10.8.0.0/24"]
persistent_keepalive = 25

[[peers]]
name = "office-db-pc"
public_key = "{KEY_A}"
address = "10.8.0.10/32"
"""
USAGE = 2


def test_the_bundle_is_the_stamped_table_and_one_conf_per_peer(
  tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
  src = tmp_path / "peers.toml"
  src.write_text(TABLE, encoding="utf-8")
  monkeypatch.setattr(bundle, "SOURCE", src)
  out = tmp_path / "out"
  assert bundle.main(["v1.2.3", str(out)]) == 0
  assert (out / "peers.toml").read_text(encoding="utf-8") == peers.stamp(TABLE, "v1.2.3")
  assert sorted(p.name for p in out.iterdir()) == ["office-db-pc.conf", "peers.toml"]
  assert (out / "office-db-pc.conf").read_text(encoding="utf-8").startswith("[Interface]\n")
  assert "office-db-pc.conf" in capsys.readouterr().err


def test_invalid_input_exits_1_naming_the_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
  src = tmp_path / "peers.toml"
  src.write_text(TABLE.replace("listen_port = 51820", "listen_port = 0"), encoding="utf-8")
  monkeypatch.setattr(bundle, "SOURCE", src)
  assert bundle.main(["v1.2.3", str(tmp_path / "out")]) == 1
  assert "hub.listen_port" in capsys.readouterr().err
  src.write_text(TABLE, encoding="utf-8")
  assert bundle.main(["1.2.3", str(tmp_path / "out")]) == 1
  assert bundle.main(["v1.2.3"]) == USAGE
