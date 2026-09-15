"""The peer table `peers.toml` (hub design 3.2): loading, validation, the stamped bundle (3.7) and a peer's conf.

Validation is the one copy of 3.2's rules, applied by the startup script at hub start, by the release
job through `bundle.py`, and by the tests; every failure names the field.
"""

# Standard library imports
import base64
import binascii
import ipaddress
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
PORT_MAX = 65535
KEY_CHARS = 44
KEY_BYTES = 32
TOP_KEYS = frozenset({"schema", "hub", "peers", "hub_version"})
HUB_KEYS = frozenset({"name", "public_key", "address", "listen_port", "endpoint", "allowed_ips", "persistent_keepalive"})
PEER_KEYS = frozenset({"name", "public_key", "address", "endpoint", "allowed_ips", "persistent_keepalive"})


class PeersError(ValueError):
  """A `peers.toml` that fails 3.2; the message names the field."""


@dataclass(frozen=True)
class Hub:
  """The `[hub]` table."""

  name: str
  public_key: str
  address: str
  listen_port: int
  endpoint: str
  allowed_ips: tuple[str, ...]
  persistent_keepalive: int


@dataclass(frozen=True)
class Peer:
  """One `[[peers]]` row; `None` means the hub default applies."""

  name: str
  public_key: str
  address: str
  endpoint: str | None = None
  allowed_ips: tuple[str, ...] | None = None
  persistent_keepalive: int | None = None


@dataclass(frozen=True)
class Table:
  """A validated table; `hub_version` is set only on a stamped bundle."""

  hub: Hub
  peers: tuple[Peer, ...]
  hub_version: str | None = None


def default_path() -> Path:
  """The shipped `peers.toml`, inside the package because the image copies `src/`."""
  return Path(str(resources.files("wireguard_hub").joinpath("peers.toml")))


def rules_path() -> Path:
  """The shipped `rules.v4` (3.3)."""
  return Path(str(resources.files("wireguard_hub").joinpath("rules.v4")))


def load(path: Path) -> Table:
  """Read and validate the table at `path`."""
  return parse(path.read_text(encoding="utf-8"))


def parse(text: str) -> Table:
  """Validate `text` as 3.2 describes and return the table."""
  try:
    data = tomllib.loads(text)
  except tomllib.TOMLDecodeError as e:
    raise PeersError(f"peers.toml is not valid TOML: {e}") from None
  for key in data:
    if key not in TOP_KEYS:
      raise PeersError(f"{key}: unknown top-level key")
  schema = data.get("schema")
  if type(schema) is not int or schema != 1:
    raise PeersError("schema: must be 1")
  version = data.get("hub_version")
  if version is not None and not (isinstance(version, str) and TAG_RE.match(version)):
    raise PeersError("hub_version: must be a release tag like v1.2.3")
  hub_data = data.get("hub")
  if not isinstance(hub_data, dict):
    raise PeersError("hub: missing table")
  hub = _hub(hub_data)
  network = ipaddress.ip_interface(hub.address).network
  rows = data.get("peers", [])
  if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
    raise PeersError("peers: must be [[peers]] tables")
  peers: list[Peer] = []
  for i, row in enumerate(rows):
    peers.append(_peer(row, f"peers[{i}]", hub, network, peers))
  return Table(hub=hub, peers=tuple(peers), hub_version=version)


def _hub(d: dict[str, object]) -> Hub:
  for key in d:
    if key not in HUB_KEYS:
      raise PeersError(f"hub.{key}: unknown key")
  address = _text(d, "hub.address")
  try:
    iface = ipaddress.ip_interface(address)
  except ValueError:
    raise PeersError(f"hub.address: {address} is not an address with a prefix") from None
  net = iface.network
  if net.prefixlen >= iface.max_prefixlen or iface.ip in (net.network_address, net.broadcast_address):
    raise PeersError(f"hub.address: {address} must be a host address inside its own network")
  return Hub(
    name=_name(d, "hub.name"),
    public_key=_key(d, "hub.public_key"),
    address=address,
    listen_port=_port(_integer(d, "hub.listen_port"), "hub.listen_port"),
    endpoint=_endpoint(_text(d, "hub.endpoint"), "hub.endpoint"),
    allowed_ips=_cidrs(d, "hub.allowed_ips"),
    persistent_keepalive=_port(_integer(d, "hub.persistent_keepalive"), "hub.persistent_keepalive"),
  )


def _peer(d: dict[str, object], at: str, hub: Hub, network: ipaddress.IPv4Network | ipaddress.IPv6Network, seen: list[Peer]) -> Peer:
  for key in d:
    if key not in PEER_KEYS:
      raise PeersError(f"{at}.{key}: unknown key")
  name = _name(d, f"{at}.name")
  if any(p.name == name for p in seen):
    raise PeersError(f"{at}.name: {name} is used twice")
  key = _key(d, f"{at}.public_key")
  if key == hub.public_key or any(p.public_key == key for p in seen):
    raise PeersError(f"{at}.public_key: used twice")
  address = _text(d, f"{at}.address")
  try:
    iface = ipaddress.ip_interface(address)
  except ValueError:
    raise PeersError(f"{at}.address: {address} is not an address with a prefix") from None
  if iface.network.prefixlen != iface.max_prefixlen:
    raise PeersError(f"{at}.address: {address} must be a /{iface.max_prefixlen}")
  if iface.ip not in network:
    raise PeersError(f"{at}.address: {address} is not inside {network}")
  if iface.ip == ipaddress.ip_interface(hub.address).ip:
    raise PeersError(f"{at}.address: {address} is the hub's own address")
  if any(p.address == address for p in seen):
    raise PeersError(f"{at}.address: {address} is used twice")
  return Peer(
    name=name,
    public_key=key,
    address=address,
    endpoint=_endpoint(_text(d, f"{at}.endpoint"), f"{at}.endpoint") if "endpoint" in d else None,
    allowed_ips=_cidrs(d, f"{at}.allowed_ips") if "allowed_ips" in d else None,
    persistent_keepalive=_port(_integer(d, f"{at}.persistent_keepalive"), f"{at}.persistent_keepalive")
    if "persistent_keepalive" in d
    else None,
  )


def _text(d: dict[str, object], field: str) -> str:
  value = d.get(field.rsplit(".", 1)[1])
  if not isinstance(value, str) or not value:
    raise PeersError(f"{field}: must be a non-empty string")
  return value


def _integer(d: dict[str, object], field: str) -> int:
  value = d.get(field.rsplit(".", 1)[1])
  if type(value) is not int:
    raise PeersError(f"{field}: must be an integer 1 to {PORT_MAX}")
  return value


def _port(value: int, field: str) -> int:
  if not 1 <= value <= PORT_MAX:
    raise PeersError(f"{field}: must be an integer 1 to {PORT_MAX}")
  return value


def _name(d: dict[str, object], field: str) -> str:
  value = _text(d, field)
  if not NAME_RE.match(value):
    raise PeersError(f"{field}: {value!r} must match ^[a-z0-9][a-z0-9-]*$")
  return value


def _key(d: dict[str, object], field: str) -> str:
  value = _text(d, field)
  try:
    raw = base64.b64decode(value, validate=True)
  except binascii.Error, ValueError:
    raw = b""
  if len(value) != KEY_CHARS or len(raw) != KEY_BYTES:
    raise PeersError(f"{field}: must be a {KEY_CHARS}-character base64 string of {KEY_BYTES} bytes")
  return value


def _endpoint(value: str, field: str) -> str:
  host, sep, port = value.rpartition(":")
  if not sep or not host or any(c.isspace() for c in host) or not port.isdigit() or not 1 <= int(port) <= PORT_MAX:
    raise PeersError(f"{field}: {value!r} must be host:port with port 1 to {PORT_MAX}")
  return value


def _cidrs(d: dict[str, object], field: str) -> tuple[str, ...]:
  value = d.get(field.rsplit(".", 1)[1])
  if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
    raise PeersError(f"{field}: must be a non-empty list of CIDRs")
  for v in value:
    try:
      ipaddress.ip_network(v)
    except ValueError:
      raise PeersError(f"{field}: {v!r} is not a CIDR") from None
  return tuple(value)


def stamp(text: str, tag: str) -> str:
  """The bundle: `text` with `hub_version = "<tag>"` as the first top-level key (3.7), nothing else changed."""
  if not TAG_RE.match(tag):
    raise PeersError(f"tag {tag!r} is not a release tag like v1.2.3")
  return f'hub_version = "{tag}"\n\n{text}'


def render_conf(table: Table, peer: Peer) -> str:
  """A spoke's `<name>.conf` (3.7): the peer's overrides, else the hub's defaults."""
  hub = table.hub
  allowed = peer.allowed_ips if peer.allowed_ips is not None else hub.allowed_ips
  keepalive = peer.persistent_keepalive if peer.persistent_keepalive is not None else hub.persistent_keepalive
  return (
    "[Interface]\n"
    "PrivateKey = REPLACE_WITH_THIS_PEERS_PRIVATE_KEY\n"
    f"Address = {peer.address}\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {hub.public_key}\n"
    f"Endpoint = {peer.endpoint or hub.endpoint}\n"
    f"AllowedIPs = {', '.join(allowed)}\n"
    f"PersistentKeepalive = {keepalive}\n"
  )
