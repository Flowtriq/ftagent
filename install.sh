#!/bin/bash
# Flowtriq Agent Installer
# Installs ftagent from PyPI and runs the setup wizard.
#
# Usage:
#   curl -sSL https://flowtriq.com/install.sh | sudo bash
#
# If FTAGENT_API_KEY and FTAGENT_NODE_UUID are set, setup runs
# non-interactively (useful for automation / pre-configured installs).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "  ${CYAN}>${NC} $1"; }
ok()    { echo -e "  ${GREEN}>${NC} $1"; }
fail()  { echo -e "  ${RED}>${NC} $1" >&2; }
fatal() { fail "$1"; exit 1; }

echo ""
echo -e "${CYAN}  Flowtriq Agent Installer${NC}"
echo ""

# ── Root check ───────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    fatal "This script must be run as root (use sudo)."
fi

# ── Detect OS ────────────────────────────────────────────────────────
OS=""
PKG=""
if command -v apt-get >/dev/null 2>&1; then
    OS="debian"; PKG="apt"
elif command -v dnf >/dev/null 2>&1; then
    OS="rhel"; PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
    OS="rhel"; PKG="yum"
elif command -v apk >/dev/null 2>&1; then
    OS="alpine"; PKG="apk"
elif command -v pacman >/dev/null 2>&1; then
    OS="arch"; PKG="pacman"
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "OS: ${PRETTY_NAME:-$ID}"
fi

# ── Find or install Python 3 ────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ver=$("$cmd" -c 'import sys; print(sys.version_info[0])' 2>/dev/null)
        if [ "$ver" = "3" ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    info "Python 3 not found, installing..."
    case "$PKG" in
        apt)    apt-get update -qq && apt-get install -y -qq python3 python3-pip >/dev/null 2>&1 ;;
        dnf)    dnf install -y -q python3 python3-pip >/dev/null 2>&1 ;;
        yum)    yum install -y -q python3 python3-pip >/dev/null 2>&1 ;;
        apk)    apk add --quiet python3 py3-pip >/dev/null 2>&1 ;;
        pacman) pacman -Sy --noconfirm python python-pip >/dev/null 2>&1 ;;
        *)      fatal "Could not auto-install Python 3. Install it manually and re-run." ;;
    esac
    PYTHON="python3"
    ok "Python 3 installed."
fi

PYVER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
info "Python: $PYTHON ($PYVER)"

# ── Ensure pip ───────────────────────────────────────────────────────
if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
    info "pip not found, installing..."
    case "$PKG" in
        apt)    apt-get install -y -qq python3-pip >/dev/null 2>&1 ;;
        dnf)    dnf install -y -q python3-pip >/dev/null 2>&1 ;;
        yum)    yum install -y -q python3-pip >/dev/null 2>&1 ;;
        apk)    apk add --quiet py3-pip >/dev/null 2>&1 ;;
        pacman) pacman -Sy --noconfirm python-pip >/dev/null 2>&1 ;;
        *)      "$PYTHON" -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', '/tmp/get-pip.py')" \
                    && "$PYTHON" /tmp/get-pip.py --quiet ;;
    esac
fi

# ── Install libpcap (needed for packet capture) ─────────────────────
case "$PKG" in
    apt)    dpkg -s libpcap-dev >/dev/null 2>&1 || { info "Installing libpcap..."; apt-get install -y -qq libpcap-dev >/dev/null 2>&1; } ;;
    dnf)    rpm -q libpcap-devel >/dev/null 2>&1 || { info "Installing libpcap..."; dnf install -y -q libpcap-devel >/dev/null 2>&1; } ;;
    yum)    rpm -q libpcap-devel >/dev/null 2>&1 || { info "Installing libpcap..."; yum install -y -q libpcap-devel >/dev/null 2>&1; } ;;
    apk)    apk info -e libpcap-dev >/dev/null 2>&1 || { info "Installing libpcap..."; apk add --quiet libpcap-dev >/dev/null 2>&1; } ;;
    pacman) pacman -Q libpcap >/dev/null 2>&1 || { info "Installing libpcap..."; pacman -Sy --noconfirm libpcap >/dev/null 2>&1; } ;;
esac

# ── Install ftagent ──────────────────────────────────────────────────
info "Installing ftagent..."
if "$PYTHON" -m pip install --quiet --upgrade ftagent 2>/dev/null; then
    true
elif "$PYTHON" -m pip install --quiet --upgrade --break-system-packages ftagent 2>/dev/null; then
    true
else
    # Last resort: try pipx
    if command -v pipx >/dev/null 2>&1; then
        info "pip failed, trying pipx..."
        pipx install ftagent 2>/dev/null || pipx upgrade ftagent 2>/dev/null
    else
        fatal "pip install failed. Check your Python/pip installation and try again."
    fi
fi

# ── Find ftagent binary ─────────────────────────────────────────────
FTAGENT_BIN=$(command -v ftagent 2>/dev/null || true)
if [ -z "$FTAGENT_BIN" ]; then
    FTAGENT_BIN=$("$PYTHON" -c "import shutil; print(shutil.which('ftagent') or '')" 2>/dev/null)
fi
if [ -z "$FTAGENT_BIN" ] || [ ! -f "$FTAGENT_BIN" ]; then
    # Check common locations
    for p in /usr/local/bin/ftagent /usr/bin/ftagent "$HOME/.local/bin/ftagent"; do
        if [ -f "$p" ]; then FTAGENT_BIN="$p"; break; fi
    done
fi
if [ -z "$FTAGENT_BIN" ] || [ ! -f "$FTAGENT_BIN" ]; then
    fatal "ftagent binary not found after install. Try: pip install ftagent"
fi

FTAGENT_VER=$("$FTAGENT_BIN" --version 2>/dev/null || echo "unknown")
ok "ftagent $FTAGENT_VER installed."

# ── Configure ────────────────────────────────────────────────────────
# If key + node are passed via env vars, write config directly (non-interactive).
# Otherwise run the interactive setup wizard.
if [ -n "${FTAGENT_API_KEY:-}" ] && [ -n "${FTAGENT_NODE_UUID:-}" ]; then
    info "Configuring from environment variables..."
    mkdir -p /etc/ftagent
    cat > /etc/ftagent/config.json << FTCFG
{"api_key": "${FTAGENT_API_KEY}", "node_uuid": "${FTAGENT_NODE_UUID}", "api_base": "${FTAGENT_API_BASE:-https://flowtriq.com/api/v1}"}
FTCFG
    ok "Config written to /etc/ftagent/config.json"
else
    echo ""
    # When piped via curl|bash, stdin is the script itself.
    # Redirect stdin to /dev/tty so the setup wizard can read user input.
    "$FTAGENT_BIN" --setup </dev/tty
fi

# ── Install and start systemd service ────────────────────────────────
info "Installing systemd service..."
"$FTAGENT_BIN" --install-service

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
    if systemctl is-active --quiet ftagent 2>/dev/null; then
        systemctl restart ftagent
    else
        systemctl enable --now ftagent 2>/dev/null || true
    fi

    sleep 2
    if systemctl is-active --quiet ftagent 2>/dev/null; then
        echo ""
        ok "Agent is running. It will appear in your dashboard within 30 seconds."
        ok "Baseline learning takes about 5 minutes. After that, detection is fully active."
    else
        echo ""
        fail "Service didn't start. Check: systemctl status ftagent"
        info "Starting manually..."
        nohup "$FTAGENT_BIN" >/dev/null 2>&1 &
        ok "Agent started (PID $!)."
    fi
else
    info "systemd not found. Starting agent directly..."
    nohup "$FTAGENT_BIN" >/dev/null 2>&1 &
    ok "Agent started (PID $!)."
fi

echo ""
echo -e "  Dashboard: ${CYAN}https://flowtriq.com/dashboard/nodes${NC}"
echo ""
