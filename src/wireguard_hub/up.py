"""The startup script `wireguard-hub-up` (hub design 3.4).

Runs once as root before the app with the full environment (section 7): brings `wg0` up from the
peer table and applies the firewall rules, then exits. Every command is an argument list; the
private key only ever travels on stdin, so no command line and no error message can carry it.
"""

# Standard library imports
import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

# First party imports
from wireguard_hub import peers

PEERS_PATH = peers.default_path()
RULES_PATH = peers.rules_path()
IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")


def main() -> None:
  """Steps 1 to 8 of 3.4, in order; exit 1 on the first failure."""
  try:
    table = peers.load(PEERS_PATH)
  except (peers.PeersError, OSError) as e:
    _fail(f"{PEERS_PATH.name}: {e}")
  key = os.environ.get("WG_HUB_PRIVATE_KEY", "").strip()
  if not key:
    _fail("WG_HUB_PRIVATE_KEY is not set")
  if IP_FORWARD.read_text(encoding="utf-8").strip() != "1":
    _fail("net.ipv4.ip_forward is 0: the compose file needs sysctls net.ipv4.ip_forward=1")
  hub = table.hub
  _run(["ip", "link", "add", "dev", "wg0", "type", "wireguard"])
  _run(["wg", "set", "wg0", "listen-port", str(hub.listen_port), "private-key", "/dev/stdin"], stdin=key + "\n")
  for peer in table.peers:
    _run(["wg", "set", "wg0", "peer", peer.public_key, "allowed-ips", peer.address])
  _run(["ip", "address", "add", hub.address, "dev", "wg0"])
  _run(["ip", "link", "set", "up", "dev", "wg0"])
  _run(["iptables-restore"], stdin=RULES_PATH.read_text(encoding="utf-8"))
  public = _run(["wg", "pubkey"], stdin=key + "\n").strip()
  print(f"wireguard-hub-up: wg0 up, public key {public}, {len(table.peers)} peer(s)", file=sys.stderr)


def _run(args: list[str], *, stdin: str | None = None) -> str:
  """Run `args`; a nonzero exit names the command (never its stdin) and ends the script."""
  done = subprocess.run(args, input=stdin, capture_output=True, text=True, check=False)
  if done.returncode != 0:
    _fail(f"`{' '.join(args)}` exited {done.returncode}: {done.stderr.strip()}")
  return done.stdout


def _fail(message: str) -> NoReturn:
  print(f"wireguard-hub-up: {message}", file=sys.stderr)
  sys.exit(1)
