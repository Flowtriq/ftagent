#!/bin/bash
if [ "$1" = "--version" ]; then
  echo "ftagent 1.9.27"
  exit 0
fi
if [ "$1" = "--test" ]; then
  echo ""
  echo "  Testing connection to https://flowtriq.com/api/v1 ..."
  sleep 0.6
  printf "  Connection: "
  sleep 0.4
  echo "OK"
  echo ""
  echo "  Node:      nyc-edge-01"
  echo "  Tenant:    Acme Hosting"
  echo "  Status:    active"
  echo "  Agent:     1.9.27"
  echo ""
  exit 0
fi
# Main agent run
echo ""
echo "    _____ _               _        _        "
echo "   |  ___| | _____      _| |_ _ __(_) __ _  "
echo "   | |_  | |/ _ \ \ /\ / / __| '__| |/ _\` | "
echo "   |  _| | | (_) \ V  V /| |_| |  | | (_| | "
echo "   |_|   |_|\___/ \_/\_/  \__|_|  |_|\__, | "
echo "                                        |_/  "
echo ""
echo "   ftagent v1.9.27 | eth0 | baseline learning"
echo ""
sleep 0.4
printf "Connecting to Flowtriq API... "
sleep 0.6
echo "Connected."
sleep 0.2
echo "Loading 481,439 threat IOCs from 26 feeds"
sleep 0.3
echo "Loading IP blocklist (4,218 known sources)"
sleep 0.3
echo "L7 monitor: detected nginx, tailing /var/log/nginx/access.log"
sleep 0.3
echo "PCAP ring buffer active on eth0 (tcpdump mode)"
sleep 0.2
echo "Monitoring interface eth0"
echo ""
sleep 0.8
echo "[14:32:01] INFO  Heartbeat OK     | PPS: 1,312    | BPS: 8.2 Mbps"
sleep 0.8
echo "[14:32:31] INFO  Heartbeat OK     | PPS: 1,287    | BPS: 7.9 Mbps"
sleep 0.8
echo "[14:33:01] INFO  Baseline ready   | p99: 1,680    | threshold: 5,040 PPS"
sleep 0.8
echo "[14:33:31] INFO  Heartbeat OK     | PPS: 1,345    | BPS: 8.4 Mbps"
sleep 1
echo "[14:33:42] INFO  Heartbeat OK     | PPS: 8,921    | BPS: 58.3 Mbps"
sleep 0.4
echo "[14:33:42] WARN  Traffic spike    | PPS 5.3x above baseline"
sleep 0.3
echo "[14:33:42] WARN  Blocklist match  | 31% of source IPs are known threat actors"
sleep 0.3
echo "[14:33:42] WARN  Threshold reduced to 3,528 PPS (blocklist ratio 0.31)"
sleep 0.5
echo "[14:33:43] ALERT ATTACK DETECTED  | family: udp_flood | subtype: ntp_amplification"
echo "[14:33:43] ALERT Classification   | confidence: 94% | 1,247 unique IPs | spoofed: yes"
sleep 0.3
echo "[14:33:43] INFO  IOC match        | NTP Monlist Amplification (3 hits)"
echo "[14:33:43] INFO  PCAP capture started (847 pre-attack packets from ring buffer)"
sleep 0.4
echo "[14:33:43] INFO  Mitigation [1/3] | iptables: rate-limit UDP port 123 >50/s per src"
sleep 0.3
echo "[14:33:44] INFO  Mitigation [2/3] | FlowSpec: pushed to ExaBGP upstream (AS64512)"
sleep 0.3
echo "[14:33:44] INFO  Mitigation [3/3] | Scrubbing: diverted to Cloudflare Magic Transit"
sleep 0.4
echo "[14:33:44] INFO  Alerts sent      | Discord, PagerDuty, Slack (3 channels)"
sleep 0.8
echo "[14:34:14] INFO  Attack update    | PPS: 42,891   | BPS: 287 Mbps | peak so far"
sleep 0.8
echo "[14:34:44] INFO  Attack update    | PPS: 31,204   | BPS: 201 Mbps | declining"
sleep 0.8
echo "[14:35:14] INFO  Attack update    | PPS: 4,102    | BPS: 26.1 Mbps"
sleep 0.6
echo "[14:35:44] INFO  Attack subsiding | PPS below threshold for 8/10 ticks"
sleep 0.5
echo "[14:35:54] INFO  ATTACK ENDED     | duration: 131s | peak: 42,891 PPS | 287 Mbps"
echo "[14:35:54] INFO  Classification   | NTP Amplification (UDP flood) | confidence: 94%"
echo "[14:35:54] INFO  Sources          | 1,247 unique IPs | top ASN: AS14061 (DigitalOcean)"
sleep 0.3
echo "[14:35:55] INFO  Mitigation undo  | iptables rule removed, FlowSpec withdrawn"
echo "[14:35:55] INFO  Scrubbing undo   | Cloudflare Magic Transit diversion withdrawn"
sleep 0.3
echo "[14:35:56] INFO  PCAP uploaded    | 8,412 packets | 4.2 MB"
echo "[14:35:56] INFO  Incident closed  | https://flowtriq.com/dashboard/incident/a1b2c3d4"
sleep 0.5
echo ""
echo "[14:36:01] INFO  Heartbeat OK     | PPS: 1,298    | BPS: 8.0 Mbps"
sleep 0.8
echo "[14:36:31] INFO  Heartbeat OK     | PPS: 1,310    | BPS: 8.1 Mbps"
