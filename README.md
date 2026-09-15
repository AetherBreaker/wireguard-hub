# wireguard-hub

The WireGuard hub of the tunnel (design: `docs/superpowers/specs/2026-09-14-hub-fetched-peer-config-design.md`, section 3). One package, two programs:

- `wireguard-hub-up`: runs once as root before the app (the entrypoint's `startup_scripts`). Validates `src/wireguard_hub/peers.toml`, brings `wg0` up from it with the private key from `WG_HUB_PRIVATE_KEY` (stdin only; scrubbed from the app's environment by `scrub_env`), applies `src/wireguard_hub/rules.v4`, logs the hub's public key and the peer count, exits.
- `run-app-wireguard-hub`: unprivileged. `GET /version` on port 8000 answers `v<version>`; the heartbeat is written every 60 s while `/sys/class/net/wg0` exists, so a vanished interface turns the standard healthcheck unhealthy.

## The peer table

`peers.toml` is the single hand-edited source: the `[hub]` section and one `[[peers]]` row per enrolled spoke (name, public key, `/32` address; optional `endpoint`, `allowed_ips`, `persistent_keepalive` overrides). Addresses: subnet `10.8.0.0/24`, hub `10.8.0.1`, office database PC `10.8.0.10`, ScheduledReportAggregator `10.8.0.20`, `tunnel-probe` `10.8.0.21`, further peers from `.22`. Every rule of the table is checked by the startup script, by `python -m wireguard_hub.bundle`, and by the tests (`uv run pytest`); a failure names the field.

## Releases

`poe release` is the devkit release, unchanged. The `peers` job in `.github/workflows/release.yml` (kept through every `setup-project` run by `[tool.devkit].release-workflow-jobs`) validates the table, writes it with `hub_version = "<tag>"` stamped as the first key, renders `<peer name>.conf` for every peer, and attaches all of them to the GitHub release. Spokes fetch `peers.toml` from that release. `ci.yml` runs the same validation on every push.

## Enrolling a peer

Take the public key from the spoke's `not enrolled` log line, add a `[[peers]]` row with the next address, release the hub, redeploy the spoke. A running, enrolled spoke picks up a later change to its row within its version poll interval.

## Deploying

Coolify: the compose file publishes UDP 51820 directly; the domain `tunnels.sweetfiretobacco.com` is attached to the `wireguard-hub` service on container port 8000 in the Coolify UI. Environment: `WG_HUB_PRIVATE_KEY`, `PINGKEY`, `ALERTS_EMAIL_PWD`. The host needs the WireGuard kernel module and the netfilter modules `iptables-nft` uses; the first-deploy checklist is section 16 of the design.
