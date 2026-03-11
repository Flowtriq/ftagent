# Changelog

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
