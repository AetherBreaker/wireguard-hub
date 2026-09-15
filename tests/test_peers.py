# Standard library imports
import base64

# Third party imports
import pytest

# First party imports
from wireguard_hub import peers
from wireguard_hub.peers import PeersError

HUB_KEY = base64.b64encode(bytes(range(32))).decode()
KEY_A = base64.b64encode(bytes([1] * 32)).decode()
KEY_B = base64.b64encode(bytes([2] * 32)).decode()
LISTEN_PORT = 51820
KEEPALIVE_B = 15

GOOD = f"""
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
name = "office-db-pc"
public_key = "{KEY_A}"
address = "10.8.0.10/32"

[[peers]]
name = "scheduled-report-aggregator"
public_key = "{KEY_B}"
address = "10.8.0.20/32"
endpoint = "wireguard-hub:51820"
allowed_ips = ["10.8.0.10/32"]
persistent_keepalive = 15
"""


def test_a_valid_table_parses_with_defaults_and_overrides():
  t = peers.parse(GOOD)
  assert t.hub.name == "wireguard-hub" and t.hub.listen_port == LISTEN_PORT and t.hub.allowed_ips == ("10.8.0.0/24",)
  assert t.hub_version is None
  assert [p.name for p in t.peers] == ["office-db-pc", "scheduled-report-aggregator"]
  a, b = t.peers
  assert a.endpoint is None and a.allowed_ips is None and a.persistent_keepalive is None
  assert b.endpoint == "wireguard-hub:51820" and b.allowed_ips == ("10.8.0.10/32",) and b.persistent_keepalive == KEEPALIVE_B
  # No peers is a valid table: every rule is "every peer ...".
  assert peers.parse(GOOD.split("[[peers]]", maxsplit=1)[0]).peers == ()
  # A stamped bundle parses and carries its version.
  assert peers.parse(peers.stamp(GOOD, "v1.2.3")).hub_version == "v1.2.3"


@pytest.mark.parametrize(
  ("edit", "field"),
  [
    (("schema = 1", "schema = 2"), "schema"),
    (("schema = 1", ""), "schema"),
    (('name = "wireguard-hub"', 'name = "Wireguard-Hub"'), "hub.name"),
    ((f'public_key = "{HUB_KEY}"', 'public_key = "not-base64"'), "hub.public_key"),
    ((f'public_key = "{HUB_KEY}"', f'public_key = "{base64.b64encode(bytes(31)).decode()}"'), "hub.public_key"),
    (('address = "10.8.0.1/24"', 'address = "10.8.0.0/24"'), "hub.address"),
    (('address = "10.8.0.1/24"', 'address = "10.8.0.1/32"'), "hub.address"),
    (('address = "10.8.0.1/24"', 'address = "10.8.0.1"'), "hub.address"),
    (("listen_port = 51820", "listen_port = 0"), "hub.listen_port"),
    (("listen_port = 51820", "listen_port = 70000"), "hub.listen_port"),
    (("listen_port = 51820", "listen_port = true"), "hub.listen_port"),
    (('endpoint = "tunnels.example:51820"', 'endpoint = "tunnels.example"'), "hub.endpoint"),
    (('endpoint = "tunnels.example:51820"', 'endpoint = "tunnels.example:0"'), "hub.endpoint"),
    (('endpoint = "tunnels.example:51820"', 'endpoint = ":51820"'), "hub.endpoint"),
    (('allowed_ips = ["10.8.0.0/24"]', "allowed_ips = []"), "hub.allowed_ips"),
    (('allowed_ips = ["10.8.0.0/24"]', 'allowed_ips = ["10.8.0.1/24"]'), "hub.allowed_ips"),
    (("persistent_keepalive = 25", "persistent_keepalive = 0"), "hub.persistent_keepalive"),
    (("persistent_keepalive = 25\n", 'persistent_keepalive = 25\ncolour = "red"\n'), "hub.colour"),
    (('name = "office-db-pc"', 'name = "scheduled-report-aggregator"'), "peers[1].name"),
    (('name = "office-db-pc"', 'name = "-bad"'), "peers[0].name"),
    ((f'public_key = "{KEY_A}"', f'public_key = "{KEY_B}"'), "peers[1].public_key"),
    ((f'public_key = "{KEY_A}"', f'public_key = "{KEY_A[:-1]}"'), "peers[0].public_key"),
    (('address = "10.8.0.10/32"', 'address = "10.8.0.10/24"'), "peers[0].address"),
    (('address = "10.8.0.10/32"', 'address = "10.9.0.10/32"'), "peers[0].address"),
    (('address = "10.8.0.10/32"', 'address = "10.8.0.20/32"'), "peers[1].address"),
    (('address = "10.8.0.10/32"', 'address = "10.8.0.1/32"'), "peers[0].address"),
    (('endpoint = "wireguard-hub:51820"', 'endpoint = "wireguard-hub:99999"'), "peers[1].endpoint"),
    (('allowed_ips = ["10.8.0.10/32"]', 'allowed_ips = ["10.8.0.10/33"]'), "peers[1].allowed_ips"),
    (("persistent_keepalive = 15", "persistent_keepalive = 65536"), "peers[1].persistent_keepalive"),
    (("persistent_keepalive = 15\n", "persistent_keepalive = 15\nextra = 1\n"), "peers[1].extra"),
    (("schema = 1\n", 'schema = 1\nhub_version = "1.2.3"\n'), "hub_version"),
    (("schema = 1\n", "schema = 1\nnote = 1\n"), "note"),
  ],
)
def test_each_rule_of_3_2_fails_naming_the_field(edit: tuple[str, str], field: str):
  old, new = edit
  assert old in GOOD
  with pytest.raises(PeersError) as e:
    peers.parse(GOOD.replace(old, new, 1))
  assert field in str(e.value), str(e.value)


def test_a_missing_field_and_bad_toml_name_what_is_wrong():
  with pytest.raises(PeersError, match=r"hub.endpoint"):
    peers.parse(GOOD.replace('endpoint = "tunnels.example:51820"\n', ""))
  with pytest.raises(PeersError, match="TOML"):
    peers.parse("schema = [")
  with pytest.raises(PeersError, match="hub"):
    peers.parse("schema = 1\n")


def test_stamp_prepends_hub_version_and_nothing_else():
  stamped = peers.stamp(GOOD, "v1.2.3")
  assert stamped == 'hub_version = "v1.2.3"\n\n' + GOOD
  for bad in ["1.2.3", "v1.2", "v1.2.3-rc1", "../x"]:
    with pytest.raises(PeersError, match="tag"):
      peers.stamp(GOOD, bad)


def test_render_conf_uses_overrides_else_hub_defaults():
  t = peers.parse(GOOD)
  a, b = t.peers
  assert peers.render_conf(t, a) == (
    "[Interface]\n"
    "PrivateKey = REPLACE_WITH_THIS_PEERS_PRIVATE_KEY\n"
    "Address = 10.8.0.10/32\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {HUB_KEY}\n"
    "Endpoint = tunnels.example:51820\n"
    "AllowedIPs = 10.8.0.0/24\n"
    "PersistentKeepalive = 25\n"
  )
  conf = peers.render_conf(t, b)
  assert "Endpoint = wireguard-hub:51820\n" in conf
  assert "AllowedIPs = 10.8.0.10/32\n" in conf
  assert "PersistentKeepalive = 15\n" in conf
  # Two hub-level lists render comma-separated.
  t2 = peers.parse(GOOD.replace('allowed_ips = ["10.8.0.0/24"]', 'allowed_ips = ["10.8.0.0/24", "10.9.0.0/24"]'))
  assert "AllowedIPs = 10.8.0.0/24, 10.9.0.0/24\n" in peers.render_conf(t2, t2.peers[0])


def test_the_shipped_table_is_valid():
  t = peers.load(peers.default_path())
  assert t.hub.name == "wireguard-hub"
  assert t.hub.address == "10.8.0.1/24" and t.hub.listen_port == LISTEN_PORT
  assert t.hub.endpoint == "tunnels.sweetfiretobacco.com:51820"
