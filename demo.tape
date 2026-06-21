# ftagent terminal demo
Output ftagent-demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 500
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 60ms

# Prepare fake ftagent binary while hidden
Hide

Type@0 `export PS1='root@server:~# '`
Enter
Sleep 50ms

Type@0 `mkdir -p /tmp/ftagent-demo/bin`
Enter
Sleep 50ms

# Write the fake ftagent script
Type@0 `cat > /tmp/ftagent-demo/bin/ftagent << 'FAKEBIN'`
Enter
Type@0 `#!/bin/bash`
Enter
Type@0 `if [ "$1" = "--version" ]; then`
Enter
Type@0 `  echo "ftagent 1.9.26"`
Enter
Type@0 `  exit 0`
Enter
Type@0 `fi`
Enter
Type@0 `if [ "$1" = "--setup" ]; then`
Enter
Type@0 `  echo ""`
Enter
Type@0 `  echo "  ┌─────────────────────────────────────┐"`
Enter
Type@0 `  echo "  │       Flowtriq Agent Setup           │"`
Enter
Type@0 `  echo "  └─────────────────────────────────────┘"`
Enter
Type@0 `  echo ""`
Enter
Type@0 `  printf "  API Key: "`
Enter
Type@0 `  read -r x`
Enter
Type@0 `  printf "  Node UUID: "`
Enter
Type@0 `  read -r x`
Enter
Type@0 `  printf "  Network interface [auto]: "`
Enter
Type@0 `  read -r x`
Enter
Type@0 `  echo ""`
Enter
Type@0 `  echo "  Config written to /etc/ftagent/config.json"`
Enter
Type@0 `  echo "  Run: ftagent --install-service to create the systemd unit."`
Enter
Type@0 `  echo ""`
Enter
Type@0 `  exit 0`
Enter
Type@0 `fi`
Enter
Type@0 `echo ""`
Enter
Type@0 `echo "    _____ _               _        _        "`
Enter
Type@0 `echo "   |  ___| | _____      _| |_ _ __(_) __ _  "`
Enter
Type@0 `echo "   | |_  | |/ _ \\ \\ /\\ / / __| '__| |/ _  | "`
Enter
Type@0 `echo "   |  _| | | (_) \\ V  V /| |_| |  | | (_| | "`
Enter
Type@0 `echo "   |_|   |_|\\___/ \\_/\\_/  \\__|_|  |_|\\__, | "`
Enter
Type@0 `echo "                                        |_/  "`
Enter
Type@0 `echo ""`
Enter
Type@0 `echo "   ftagent v1.9.26"`
Enter
Type@0 `echo ""`
Enter
Type@0 `sleep 0.6`
Enter
Type@0 `printf "Connecting to Flowtriq API..."`
Enter
Type@0 `sleep 1.0`
Enter
Type@0 `echo " Connected."`
Enter
Type@0 `sleep 0.4`
Enter
Type@0 `echo "Monitoring interface eth0 - baseline: 1,240 PPS"`
Enter
Type@0 `echo ""`
Enter
Type@0 `sleep 1.0`
Enter
Type@0 `echo "[2026-06-20 14:32:01] INFO  Heartbeat OK | PPS: 1,312 | BPS: 8.2 Mbps"`
Enter
Type@0 `sleep 1.2`
Enter
Type@0 `echo "[2026-06-20 14:32:31] INFO  Heartbeat OK | PPS: 1,287 | BPS: 7.9 Mbps"`
Enter
Type@0 `sleep 1.2`
Enter
Type@0 `echo "[2026-06-20 14:33:01] INFO  Heartbeat OK | PPS: 1,345 | BPS: 8.4 Mbps"`
Enter
Type@0 `sleep 1.2`
Enter
Type@0 `echo "[2026-06-20 14:33:31] INFO  Heartbeat OK | PPS: 4,891 | BPS: 31.6 Mbps"`
Enter
Type@0 `sleep 0.6`
Enter
Type@0 `echo "[2026-06-20 14:33:31] WARN  Traffic spike detected - PPS 3.9x above baseline"`
Enter
Type@0 `sleep 0.8`
Enter
Type@0 `echo "[2026-06-20 14:33:32] ALERT Incident opened - SYN flood | src entropy: high | 423 unique IPs"`
Enter
Type@0 `sleep 0.5`
Enter
Type@0 `echo "[2026-06-20 14:33:32] INFO  PCAP capture started - /var/lib/ftagent/pcaps/inc_20260620_143332.pcap"`
Enter
Type@0 `sleep 0.5`
Enter
Type@0 `echo "[2026-06-20 14:33:33] INFO  Mitigation applied - iptables rate-limit on SYN (>100/s per src)"`
Enter
Type@0 `FAKEBIN`
Enter
Sleep 50ms

Type@0 `chmod +x /tmp/ftagent-demo/bin/ftagent`
Enter
Sleep 50ms

Type@0 `export PATH="/tmp/ftagent-demo/bin:$PATH"`
Enter
Sleep 50ms

# Make sudo a no-op passthrough
Type@0 `alias sudo=""`
Enter
Sleep 50ms

Type@0 `clear`
Enter
Sleep 200ms

Show

# ===== VISIBLE RECORDING =====

# 1. Version check
Sleep 500ms
Type "ftagent --version"
Sleep 400ms
Enter
Sleep 1.5s

# 2. Setup wizard
Type "sudo ftagent --setup"
Sleep 400ms
Enter
Sleep 1.5s

Type "ftk_a1b2c3d4e5f6g7h8i9j0"
Sleep 300ms
Enter
Sleep 800ms

Type "nd-8f3a12b7-c4d5-4e6f-a7b8-9c0d1e2f3a4b"
Sleep 300ms
Enter
Sleep 800ms

# Accept default interface
Enter
Sleep 2s

# Clear screen before agent run
Hide
Type@0 `clear`
Enter
Sleep 200ms
Show

# 3. Agent startup and monitoring
Sleep 400ms
Type "sudo ftagent"
Sleep 400ms
Enter

# Wait for all the sleeps in the script to finish
Sleep 14s

# Hold final frame
Sleep 3s
