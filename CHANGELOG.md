# Changelog

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
