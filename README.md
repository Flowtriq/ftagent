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

### 1. Get your API key

Log in to your [Flowtriq dashboard](https://flowtriq.com/dashboard) → **Nodes** → **Add Node** → copy the API key shown.

### 2. Create the config

```bash
sudo mkdir -p /etc/ftagent
sudo cp packaging/config.example.json /etc/ftagent/config.json
sudo nano /etc/ftagent/config.json
```

Set `api_key` to your key and `node_uuid` to the Node UUID shown in your Flowtriq dashboard under **Nodes**. Both are required.

### 3. Run

```bash
sudo ftagent
```

Or with the Python module:

```bash
sudo python3 -m ftagent
```

The agent will register your node, establish a baseline, and begin monitoring. Your node will appear in the Flowtriq dashboard within 30 seconds.

---

## Install as a systemd service

```bash
sudo cp packaging/ftagent.service /etc/systemd/system/ftagent.service
sudo systemctl daemon-reload
sudo systemctl enable ftagent
sudo systemctl start ftagent

# Check status
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

  --config PATH      Config file path (default: /etc/ftagent/config.json)
  --interface IFACE  Override interface from config
  --test             Trigger a synthetic detection event and exit
  --version          Show version
```

---

## How it works

1. **Baseline**: The agent collects traffic metrics for the configured baseline window and establishes a normal PPS/BPS range for the node.
2. **Detection**: Each 10-second metrics window is compared against the baseline. If PPS exceeds `baseline × multiplier`, an incident is opened.
3. **Classification**: Attack traffic is classified by protocol distribution, port patterns, packet size, and IP entropy to identify the attack family.
4. **PCAP**: A packet capture starts immediately when an incident opens, giving you forensic data for analysis.
5. **Reporting**: The incident is reported to Flowtriq which dispatches alerts to your configured channels (Discord, Slack, Teams, PagerDuty, etc.).
6. **Mitigation**: If you have mitigation rules configured, the agent executes approved firewall commands (iptables, Cloudflare WAF, etc.) immediately.
7. **Resolution**: When PPS drops back to baseline, the incident is closed, undo commands run, and the PCAP is uploaded.

---

## Docs

Full documentation: [flowtriq.com/docs](https://flowtriq.com/docs)

---

## Support

- Docs: [flowtriq.com/docs](https://flowtriq.com/docs)
- Issues: [github.com/flowtriq/ftagent/issues](https://github.com/flowtriq/ftagent/issues)
- Email: [hello@flowtriq.com](mailto:hello@flowtriq.com)
