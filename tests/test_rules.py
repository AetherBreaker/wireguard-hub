# Standard library imports
import re

# First party imports
from wireguard_hub import peers


def test_every_address_in_rules_v4_is_a_peer_or_hub_address_and_the_policy_holds():
  text = peers.rules_path().read_text(encoding="utf-8")
  lines = [line for line in text.splitlines() if line and not line.startswith("#")]
  assert lines[0] == "*filter" and lines[-1] == "COMMIT"
  assert ":FORWARD DROP [0:0]" in lines
  assert "-A FORWARD -i wg0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" in lines
  assert not any(line.startswith(("-A INPUT", "-I INPUT", ":INPUT DROP")) for line in lines)
  table = peers.load(peers.default_path())
  known = {p.address for p in table.peers} | {table.hub.address}
  for addr in re.findall(r"\b\d+\.\d+\.\d+\.\d+/\d+\b", text):
    assert addr in known, f"{addr} is in rules.v4 but not in peers.toml"
