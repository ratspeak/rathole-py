<div align="center">

# RATHOLE

**Security suite + transport node for [Reticulum](https://reticulum.network)**

*Run a public gateway from home with I2P*

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Ratspeak](https://img.shields.io/badge/Ratspeak-ratspeak.org-purple.svg)](https://ratspeak.org)

</div>

<div align="center">
<table>
<tr>
<td align="center"><b>Overview</b><br><br><img src="docs/screenshots/overview.svg" width="480"></td>
<td align="center"><b>Peers</b><br><br><img src="docs/screenshots/peers.svg" width="480"></td>
</tr>
<tr><td colspan="2"></td></tr>
<tr>
<td align="center"><b>Interfaces</b><br><br><img src="docs/screenshots/interfaces.svg" width="480"></td>
<td align="center"><b>Blackhole</b><br><br><img src="docs/screenshots/blackhole.svg" width="480"></td>
</tr>
</table>
</div>

Rathole is a transport node and security suite for [Reticulum](https://reticulum.network). It auto-configures a full transport node, wraps it in 12 security filters, and optionally hides it behind [I2P](https://i2p.net/en/) — so anyone can run a public gateway from home without exposing their IP. Zero file editing: configure with a CLI wizard, operate with a full-screen TUI.

## Why

Reticulum's transport layer depends on a small number of public gateways. If a few go offline, large parts of the mesh lose connectivity. The fix is obvious: more gateways, run by more people, in more places.

But running a gateway means exposing your IP to every node that connects. Most people won't do that from home.

Rathole solves both problems:

- **It is a transport node.** Not a bolt-on — Rathole auto-enables transport mode, configures Reticulum, and runs a full `rnsd`-equivalent stack.
- **I2P built-in.** Run a publicly reachable gateway without exposing your IP address. The setup wizard handles i2pd installation and configuration.
- **Auto-discovery.** Gateways optionally publish their I2P address to a shared registry. Clients query the registry and connect automatically. No manual address swapping.
- **12 security guards.** All inbound packets pass through a filter pipeline before propagating. Rate limiting, reputation tracking, anomaly detection, attack correlation — managed through a CLI wizard and full-screen TUI.

Zero file editing required. Three commands to go from nothing to a secured transport node.

## Install

### macOS

```bash
brew install python3
pip install -e ".[all]"
```

### Linux (Debian/Ubuntu)

```bash
sudo apt install python3 python3-pip
pip install -e ".[all]"
```

### Windows

Install Python 3.11+ from [python.org](https://www.python.org/downloads/), then:

```bash
pip install -e ".[all]"
```

## Quick Start


`rat setup` walks you through node mode (gateway or client), preset selection, I2P configuration, and registry opt-in. It writes `rathole.toml` — you never need to edit it by hand.

`rat run` runs the client or gateway if you quit and want to run it again later.

`rat reset` resets (optionally) all of your config and data.

## How It Works

Rathole runs a standard Reticulum transport node. On startup, it monkeypatches `Transport.inbound()` — the single entry point for all inbound packets in RNS — to insert a security filter pipeline.

Every inbound packet passes through two pipeline stages:

1. **Global pipeline** (all packets): Interface Rate Limit → Bandwidth Cap → Packet Size
2. **Type-specific pipeline**: Announce, Path Request, Link Request, or Data filters

The first non-ACCEPT verdict drops the packet (short-circuit). If any filter errors, Rathole fails open — the original RNS handler processes the packet normally. Rathole can never break your node.

All configuration is done through the CLI wizard (`rat setup`) and TUI. You can also use `rat config set` and `rat filters` for live tuning.

## I2P Gateway Mode

I2P gives your node a publicly reachable address without revealing your IP. Rathole's setup wizard handles the entire flow:

1. Installs and configures `i2pd` (if not already present)
2. Creates an I2P tunnel for your Reticulum transport node
3. Optionally publishes your I2P address (B32) to the gateway registry

`NOTE: To ensure you are publishing on the registry, connect via TCP to rns.ratspeak.org:4242 once your I2P client is running. You can only be published if you are seen by the registry node, which may be difficult without TCP until I2P is bootstrapped.`

Other Rathole nodes with registry enabled will discover your gateway automatically and connect. You can run a public transport gateway from your couch.

The registry uses signed registrations (Ed25519, via your node's transport identity) and entries expire after 30 minutes without a heartbeat. No IP addresses are stored or transmitted — only I2P B32 addresses.

## Security Guards

| # | Guard | Pipeline | Protects Against | Default |
|---|-------|----------|-----------------|---------|
| G1 | Interface Rate Limit | Global | Packet-count floods | 10.0 pkts/s |
| G2 | Bandwidth Cap | Global | Byte-rate exhaustion | 500 KB/s |
| G3 | Packet Size | Global | Oversized packets | 600 bytes max |
| A1 | Allow/Deny Lists | Announce | Manual policy overrides | Hash lists |
| A2 | Hop Ceiling | Announce | Deep-topology amplification | 32 hops max |
| A3 | Announce Size | Announce | App-data amplification | 500 bytes max |
| A4 | Rate Limiter | Announce | Per-peer announce floods | 15 burst, 0.5/s refill |
| A5 | Churn Dampening | Announce | Identity churn (RFC 2439-style) | Off by default |
| A6 | Anomaly Detector | Announce | High announce:traffic ratio | 100.0 max ratio |
| P1 | Path Request Filter | Path | Path floods + scanning | 30/min |
| L1 | Link Request Filter | Link | ECDH flood + Slowloris | 10 burst, 50 max pending |
| D1 | Resource Guard | Data | Resource/compression bombs | 16 MB max |

Every guard can be toggled and tuned live:

```bash
rat filters toggle rate_limit on
rat filters set rate_limit burst 20
```

## Presets

| Preset | Mode | Philosophy |
|--------|------|-----------|
| **observe** | Gateway | Dry-run, generous limits, 24h learning, publishes to registry |
| **balanced** | Gateway | Active defense, fair limits, adaptive learning, publishes to registry |
| **fortress** | Gateway | Auto-blackhole, tight limits, defensive correlator |
| **relaxed** | Client | Dry-run, minimal interference, auto-connects to gateways |
| **standard** | Client | Good defaults, adaptive learning, auto-connects to gateways |
| **strict** | Client | Tight rate limits, active monitoring, manual peering only |
| **lora** | Either | Ultra-tight bandwidth for LoRa gateways, registry disabled |

Switch presets live: `rat config preset apply balanced`

## Intelligence

**Reputation Engine** — Every identity scores 0.0–1.0. Good behavior raises the score; bad behavior lowers it 3x faster (accept reward 0.005, drop penalty 0.015). Higher reputation = larger rate limit buckets. Penalties only apply to announce packets — relayed traffic is never falsely penalized.

**Adaptive Learning** — Records per-interface traffic baselines. After learning, auto-sets alert and block thresholds based on standard deviations from your actual traffic. Manual config always overrides.

**Attack Correlator** — Runs every 30s scanning for cross-filter patterns: Sybil clusters, destination scanning, Slowloris links, amplification attacks. In defensive mode, auto-responds with reputation penalties and threshold tightening.

## CLI Reference

```bash
# Setup
rat setup                               # interactive wizard
rat run                                 # start daemon + TUI (shortcut)

# Monitoring
rat status                              # health bar + stats
rat peers [--sort F] [--limit N]        # peer table with reputation
rat interfaces                          # per-interface breakdown
rat events [--severity S] [--type T]    # security event log
rat correlator                          # attack correlation status
rat alerts                              # alert rules status
rat adaptive                            # adaptive threshold status

# Filter management
rat filters                             # all filters by pipeline
rat filters toggle rate_limit on        # enable/disable
rat filters set rate_limit burst 20     # change parameter

# Reputation
rat reputation                          # all identities
rat reputation <hash>                   # detail for one identity
rat reputation pin <hash> 1.0           # pin score
rat reputation unpin <hash>             # remove pin

# Blackhole
rat blackhole list                      # view blackholed identities
rat blackhole add -i <hash> -r "reason"
rat blackhole remove -i <hash>

# Config
rat config show [section]               # view config
rat config set reputation accept_reward 0.01
rat config preset list                  # see presets + diffs
rat config preset apply balanced        # switch preset
rat dry-run [on|off]                    # toggle dry-run
rat reload                              # hot-reload config

# Network
rat network add server 0.0.0.0:4242     # add TCP server interface
rat network add client host:port        # add TCP client interface
rat network remove <name>               # remove interface

# Registry
rat registry                            # registry status
rat registry discover                   # show discovered gateways
rat registry connect <hash>             # connect to gateway
rat registry register                   # publish to registry
rat registry deregister                 # remove from registry

# Lifecycle
rat shutdown                            # stop the daemon
rat reset                               # full reset (config + state)

# Output
rat --json peers                        # JSON output for scripting
```

## TUI Dashboard

`rathole -c rathole.toml` launches a full-screen terminal dashboard. 8 tabs, live updates, preset switching, filter tuning, registry controls — all without leaving the terminal.

Run standalone against a headless daemon: `rathole-tui`

## Deployment

### Linux (systemd)

```bash
sudo cp deploy/rathole.service /etc/systemd/system/
sudo systemctl enable --now rathole
```

### Docker

```bash
cd deploy && docker compose up -d
```

## Configuration

See [`rathole.example.toml`](rathole.example.toml) for the fully commented reference. All settings are accessible via `rat config show` and editable live via `rat config set`.


## Future

If there's interest: encrypted messaging over LXMF, a proper GUI, LoRa and other interface support. This is a starting point.

## Disclaimer

Rathole is a proof of concept and was vibed together — built quickly, tested lightly, and still early. It monkeypatches RNS internals, which means it could break with future Reticulum updates. Pin your RNS version. Use at your own risk. Don't get angry when there are bugs.

## License

[GPL-3.0](LICENSE) · [Ratspeak](https://ratspeak.org)
