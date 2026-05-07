# Changelog

## [1.9.0] — 2026-05-07

### Added
- **GRE Encapsulation Deduplication** — Agent now detects GRE (IP proto 47) tunnel interfaces on startup; strips outer GRE headers before counting bytes/PPS for dashboard stats, preventing double-counting of GRE-encapsulated traffic. Supports nested GRE up to 3 layers deep (configurable via `gre_max_depth`). Original packets are preserved unmodified in PCAP captures and ring buffer. BPS correction applied in `_tick()` using observed overhead ratio. Controlled via `gre_mode`: `auto` (default) / `enabled` / `disabled`.

- **Per-VM / Per-IP Differentiation on Hypervisors** — When `hypervisor_mode: true`, agent extracts inner destination IPs from GRE-decapsulated packets and tracks per-VM PPS, BPS, protocol breakdown, and source IP cardinality. Per-VM stats are flushed to `/agent/vm-stats` every tick and VM-level attack data is included in incident open/update payloads. Up to 1,000 inner IPs tracked per interval.

- **GRE Tunnel Auto-Whitelisting** — On startup, agent enumerates active GRE tunnel interfaces (`ip tunnel show`), reports them to `/agent/gre-tunnels`, and logs which remote endpoints were auto-added to the IP allowlist. Dismissed endpoints (user-removed via dashboard) are not re-added on subsequent reports.

- **Heartbeat carries agent mode flags** — `gre_dedup_enabled`, `hypervisor_mode`, `pcap_active`, `flow_active`, `vm_count` added to heartbeat payload so the dashboard can detect hybrid and flow-only nodes.

- **Setup wizard** prompts for GRE dedup and hypervisor mode when tunnels are detected.

### Changed
- Version `1.8.6` → `1.9.0`

---

## [1.8.6] — 2026-05-07

### Fixed
- Attack detection via sFlow: `peak_pps`/`peak_bps` now initialized from flow aggregator data when it exceeds local interface counters — fixes incidents opening with 0 PPS on transit/monitoring servers where local traffic is near zero
- Attack protocol classification (UDP flood / SYN flood / etc.) now uses flow aggregator protocol breakdown as fallback when scapy ring buffer is empty — fixes "unknown" attack family on sFlow-only nodes

---

## [1.8.5] — 2026-05-07

### Fixed
- sFlow v5 auto-detection broken: version was read as uint16 (always 0), so all sFlow datagrams were silently dropped in auto mode
- sFlow v5 datagram header missing `uptime` field: parsed only 3 uint32s instead of 4, causing the sample loop to start at the wrong offset
- sFlow v5 standard flow sample header misaligned: `source_id` was split into two uint32s, shifting `sampling_rate` and `num_records` by 4 bytes and producing garbage values

---

## [1.3.1] — 2026-03-17

### Fixed
- L7 detection no longer creates dozens of rapid-fire incidents for a single attack
- Added 30-second minimum attack duration before allowing resolve
- Require RPS to stay below threshold for 3 consecutive checks before resolving (prevents flapping)
- L7 monitor loop interval reduced from 2s to 1s for faster detection

---

## [1.3.0] — 2026-03-17

### Added
- PCAP capture for L7 (HTTP flood) attacks -- L7 incidents now get full packet captures like L3/L4
- RPS and baseline RPS sent to server on L7 incident open, update, and resolve
- `attack_subtype` field sent in all L7 incident lifecycle calls
- `top_dst_ports` (HTTP paths) sent on L7 update and resolve for richer analytics

### Fixed
- L7 incidents now resolve correctly with peak RPS, duration, and source IP data
- PCAP capture properly stopped when L7 attack ends
- L7 severity no longer stuck at "low" -- server now calculates from RPS ratio instead of PPS

---

## [1.2.2] — 2026-03-16

### Fixed
- L7 auto-detect status correctly reported back to dashboard

---

## [1.2.1] — 2026-03-16

### Fixed
- Agent now reports L7 monitoring status back to dashboard (sets status to "active" when log tailing starts)
- Prevented duplicate L7 monitoring threads when config syncs during active monitoring
- Added `__main__.py` for `python3 -m ftagent` invocation

### Improved
- README updated with `--setup` wizard and `--install-service` as recommended quickstart
- L7 detection documented in README "How it works" section

---

## [1.2.0] — 2026-03-16

### Added
- Layer 7 (HTTP) DDoS detection via web server access log analysis
- Auto-detection of nginx, Apache, Caddy, LiteSpeed, and HAProxy
- Access log tailing with automatic log rotation handling
- Combined, common, and JSON log format parsing
- L7 attack detection using 5 behavioral signals: RPS spike, IP concentration, endpoint targeting, error rate, and UA uniformity
- L7 metrics reporting (RPS, error rate, unique IPs, top paths, status codes)
- Web server detection results reported to dashboard for confirmation
- L7 incidents flow through the same pipeline as L3/L4 attacks

---

## [1.1.6] — 2026-03-13

### Fixed
- Default `api_base` confirmed as `https://flowtriq.com/api/v1` (no separate subdomain)
- Clearer error messages when `node_uuid` or `api_key` are missing from config

---

## [1.1.5] — 2026-03-13

### Improved
- PCAP ring buffer increased from 500 to 1000 pre-attack packets
- Chunk size reduced from 2000 to 500 packets for faster initial upload
- Upload loop interval reduced from 30s to 10s for near-real-time streaming
- Early flush: pre-buffer packets uploaded immediately on capture start

---

## [1.1.0] — 2026-03-11

### Added
- Dynamic baseline detection with configurable sensitivity
- PCAP capture with per-incident file rotation and automatic expiry
- AI-powered attack classification (attack family + subtype)
- Pending commands API — execute mitigation actions from the Flowtriq dashboard
- IOC pattern sync from remote threat intelligence feed
- Multi-interface support with automatic interface selection
- Colorized terminal output via `colorama`
- `--test` flag to trigger a synthetic detection event for validation

### Improved
- PPS/BPS metrics now sent every 10 seconds for smoother dashboard graphs
- Heartbeat interval reduced to 30 seconds for faster node status detection
- Reconnection logic with exponential backoff on API failures
- Better handling of PCAP writer errors on disk-full conditions

### Fixed
- Interface auto-detection now correctly skips loopback and virtual interfaces
- PCAP files no longer left open if an exception occurs during capture

---

## [1.0.0] — 2025-12-01

### Initial release
- Real-time packet capture and traffic analysis via scapy
- PPS/BPS threshold-based attack detection
- Protocol breakdown (TCP/UDP/ICMP percentages)
- Source IP entropy calculation
- Heartbeat and metrics reporting to Flowtriq API
- Basic incident creation and resolution
- JSON configuration file at `/etc/ftagent/config.json`
