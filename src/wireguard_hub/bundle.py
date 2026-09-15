"""The release job's entry (hub design 3.7): `python -m wireguard_hub.bundle <tag> <out-dir>`.

Validates the shipped table, writes the stamped `peers.toml` and one `<peer name>.conf` per peer
into `<out-dir>` for the job to attach. A module rather than a third console script: 3.1 names two
programs. CI runs it with a placeholder tag on every push so a broken table is caught before a
release is attempted.
"""

# Standard library imports
import sys
from pathlib import Path

# First party imports
from wireguard_hub import peers

SOURCE = peers.default_path()
USAGE = 2


def main(argv: list[str]) -> int:
  """Write the bundle; 0 on success, 1 on a validation error, 2 on bad arguments."""
  if len(argv) != USAGE:
    print("usage: python -m wireguard_hub.bundle <tag> <out-dir>", file=sys.stderr)
    return USAGE
  tag, out = argv[0], Path(argv[1])
  try:
    text = SOURCE.read_text(encoding="utf-8")
    table = peers.parse(text)
    stamped = peers.stamp(text, tag)
  except (peers.PeersError, OSError) as e:
    print(f"bundle: {e}", file=sys.stderr)
    return 1
  out.mkdir(parents=True, exist_ok=True)
  (out / "peers.toml").write_text(stamped, encoding="utf-8")
  for peer in table.peers:
    (out / f"{peer.name}.conf").write_text(peers.render_conf(table, peer), encoding="utf-8")
  names = ", ".join(["peers.toml", *(f"{p.name}.conf" for p in table.peers)])
  print(f"bundle: {tag}, {len(table.peers)} peer(s): {names}", file=sys.stderr)
  return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
