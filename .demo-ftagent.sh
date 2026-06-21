#!/bin/bash
if [ "$1" = "--version" ]; then
  echo "ftagent 1.9.26"
  exit 0
fi
if [ "$1" = "--setup" ]; then
  echo ""
  echo "  ┌───────────────────────────────────┐"
  echo "  │      Flowtriq Agent Setup         │"
  echo "  └───────────────────────────────────┘"
  echo ""
  printf "  API Key: "
  read -r x
  printf "  Node UUID: "
  read -r x
  printf "  Network interface [auto]: "
  read -r x
  echo ""
  echo "  Config written to /etc/ftagent/config.json"
  echo "  Run: systemctl enable --now ftagent"
  echo ""
  exit 0
fi
echo ""
echo "    _____ _               _        _        "
echo "   |  ___| | _____      _| |_ _ __(_) __ _  "
echo "   | |_  | |/ _ \ \ /\ / / __| '__| |/ _\` | "
echo "   |  _| | | (_) \ V  V /| |_| |  | | (_| | "
echo "   |_|   |_|\___/ \_/\_/  \__|_|  |_|\__, | "
echo "                                        |_/  "
echo ""
echo "   ftagent v1.9.26"
echo ""
sleep 0.5
printf "Connecting to Flowtriq API... "
sleep 0.8
echo "Connected."
sleep 0.3
echo "Monitoring interface eth0 | baseline: 1,240 PPS"
echo ""
sleep 1
echo "[14:32:01] INFO  Heartbeat OK  | PPS: 1,312  | BPS: 8.2 Mbps"
sleep 1
echo "[14:32:31] INFO  Heartbeat OK  | PPS: 1,287  | BPS: 7.9 Mbps"
sleep 1
echo "[14:33:01] INFO  Heartbeat OK  | PPS: 1,345  | BPS: 8.4 Mbps"
sleep 1
echo "[14:33:31] INFO  Heartbeat OK  | PPS: 4,891  | BPS: 31.6 Mbps"
sleep 0.5
echo "[14:33:31] WARN  Traffic spike detected | PPS 3.9x above baseline"
sleep 0.6
echo "[14:33:32] ALERT Incident opened | SYN flood | 423 unique IPs"
sleep 0.4
echo "[14:33:32] INFO  PCAP capture started"
sleep 0.4
echo "[14:33:33] INFO  Mitigation applied | iptables rate-limit SYN >100/s per src"
