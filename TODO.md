# TODO

- Generate `rules.v4` from a per-peer `allow` list in `peers.toml`, removing the duplicated addresses (hub design 15; the cross-check test in `tests/test_rules.py` is the guard until then).
- The per-flow `ACCEPT` lines and the office PC's firewall rule, once the database engine, port and protocol are decided (hub design 3.3, 11).
- Preshared keys in fetched mode need a per-peer secret on the hub side (hub design 15).
