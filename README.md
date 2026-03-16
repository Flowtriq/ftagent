# ftagent

**Flowtriq DDoS Detection Agent** Real-time traffic monitoring, attack detection, PCAP capture, and auto-mitigation for Linux servers.

A valid [Flowtriq](https://flowtriq.com) account and API key are required. Start a free 7-day trial at **[flowtriq.com](https://flowtriq.com)**.

---

## Requirements

- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, or equivalent)
- Python 3.8+
- Root / sudo (required for raw packet capture)
- A Flowtriq account — [sign up free](https://flowtriq.com/signup)

---

## Install

### pip (recommended)

```bash
pip install ftagent[full]
```

The `[full]` extra installs all dependencies including `scapy` for packet capture and `psutil` for system metrics.

### From source

```bash
git clone https://github.com/flowtriq/ftagent.git
cd ftagent
pip install -e .[full]
```

---

## Quick start

The fastest way to get running is the built-in setup wizard and service installer. No manual config editing needed.

### 1. Get your API key

Log in to your [Flowtriq dashboard](https://flowtriq.com/dashboard) → **Nodes** → **Add Node** → copy the API key and Node UUID shown.

### 2. Run the setup wizard

```bash
sudo ftagent --setup
```

This creates `/etc/ftagent/config.json` with your API key, Node UUID, and sane defaults. It will prompt you for each value.

### 3. Install as a service

```bash
sudo ftagent --install-service
sudo systemctl enable --now ftagent
```

That's it. The agent will register your node, establish a baseline, and begin monitoring. Your node will appear in the Flowtriq dashboard within 30 seconds.

### Manual config (alternative)

If you prefer to create the config manually:

```bash
sudo mkdir -p /etc/ftagent
sudo cp packaging/config.example.json /etc/ftagent/config.json
sudo nano /etc/ftagent/config.json
```

Set `api_key` and `node_uuid` to the values from your Flowtriq dashboard.

### Verify connectivity

```bash
sudo ftagent --test
```

This sends a test heartbeat to confirm the agent can reach the Flowtriq API.

### Check service status

```bash
sudo systemctl status ftagent
sudo journalctl -u ftagent -f
```

---

## Configuration reference

Config file: `/etc/ftagent/config.json`

| Key | Default | Description |
|---|---|---|
| `api_key` | — | **Required.** Your Flowtriq node API key |
| `node_uuid` | — | **Required.** Node UUID from your Flowtriq dashboard → Nodes |
| `api_base` | `https://flowtriq.com/api/v1` | API endpoint |
| `interface` | `"auto"` | Network interface to monitor (`eth0`, `ens3`, etc.) or `"auto"` |
| `pcap_enabled` | `true` | Enable PCAP capture during incidents |
| `pcap_dir` | `/var/lib/ftagent/pcaps` | Directory for PCAP files |
| `pcap_max_packets` | `10000` | Max packets per PCAP file |
| `pcap_max_seconds` | `60` | Max seconds per PCAP file |
| `pcap_retention_days` | `7` | Delete PCAPs older than N days |
| `log_file` | `/var/log/ftagent.log` | Log file path |
| `log_level` | `"INFO"` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `dynamic_threshold` | `true` | Auto-adjust detection threshold from traffic baseline |
| `baseline_window_minutes` | `60` | Rolling window for baseline calculation |
| `threshold_multiplier` | `3.0` | Alert when PPS exceeds `baseline × multiplier` |
| `heartbeat_interval` | `30` | Seconds between heartbeat pings |
| `metrics_interval` | `10` | Seconds between metrics reports |

---

## CLI flags

```
sudo ftagent [options]

  --setup            Interactive setup wizard (creates config)
  --install-service  Install systemd service unit
  --config PATH      Config file path (default: /etc/ftagent/config.json)
  --test             Test API connectivity and exit
  --version          Show version
```

---

## How it works

1. **Baseline**: The agent collects traffic metrics and establishes a normal PPS/BPS range for the node.
2. **L3/L4 Detection**: Each metrics window is compared against the baseline. If PPS exceeds `baseline x multiplier`, an incident is opened.
3. **L7 Detection**: When enabled, the agent tails your web server access log (nginx, Apache, Caddy, LiteSpeed, HAProxy) and detects HTTP floods via request rate spikes, IP concentration, endpoint targeting, and error rate analysis.
4. **Classification**: Attack traffic is classified by protocol distribution, TCP flags, port patterns, packet size, and IP entropy.
5. **PCAP**: A packet capture starts immediately when an incident opens, giving you forensic data for analysis.
6. **Reporting**: The incident is reported to Flowtriq which dispatches alerts to your configured channels (Discord, Slack, Teams, PagerDuty, etc.).
7. **Mitigation**: If you have mitigation rules configured, the agent executes approved firewall commands (iptables, Cloudflare WAF, etc.) immediately.
8. **Resolution**: When traffic returns to baseline, the incident is closed, undo commands run, and the PCAP is uploaded.

---

## Docs

Full documentation: [flowtriq.com/docs](https://flowtriq.com/docs)

---

## Support

- Docs: [flowtriq.com/docs](https://flowtriq.com/docs)
- Issues: [github.com/flowtriq/ftagent/issues](https://github.com/flowtriq/ftagent/issues)
- Email: [hello@flowtriq.com](mailto:hello@flowtriq.com)
