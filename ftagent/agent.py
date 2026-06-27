#!/usr/bin/env python3
from __future__ import annotations
"""
Flowtriq DDoS Detection Agent
Monitors network traffic on Linux servers and reports to the Flowtriq API.
"""

import argparse
import collections
import json
import logging
import math
import os
import re
import signal
import shlex
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.9.28"
CONFIG_PATH = "/etc/ftagent/config.json"
DEFAULT_CONFIG = {
    "api_key": "",
    "node_uuid": "",  # Required — copy from Flowtriq dashboard → Nodes
    "api_base": "https://flowtriq.com/api/v1",
    "interface": "auto",
    "pcap_enabled": True,
    "pcap_mode": "tcpdump",  # "tcpdump" (recommended, near-zero CPU) or "scapy" (per-packet Python analysis — high CPU on busy servers)
    "pcap_dir": "/var/lib/ftagent/pcaps",
    "log_file": "/var/log/ftagent.log",
    "log_level": "INFO",
    "dynamic_threshold": True,
    "baseline_window": 300,
    "health_port": 9100,
    "auto_update": True,
    # Flow protocol collector (sFlow/NetFlow/IPFIX)
    "flow_enabled": False,
    "flow_protocol": "auto",  # "auto", "sflow", "netflow_v5", "netflow_v9", "ipfix"
    "flow_port": 0,           # 0 = use protocol default (6343/2055/4739)
    "flow_bind": "0.0.0.0",
    "flow_sample_rate": 0,    # Override sample rate (0 = use what's in the packets)
    "flow_source_ips": [],    # Allowed source IPs (empty = accept all)
    # GRE encapsulation deduplication (Feature 1)
    # "auto"     = detect GRE interface automatically on startup; enable if found
    # "enabled"  = always strip GRE headers before counting stats
    # "disabled" = never strip (use for bare-metal interfaces, not GRE tunnels)
    "gre_mode": "auto",
    "gre_max_depth": 3,       # max nested GRE layers to strip (handles double/triple GRE)
    # Hypervisor mode — per-VM/per-IP differentiation (Feature 2)
    # When True + GRE mode active, tracks inner dst IP per customer VM
    "hypervisor_mode": False,
    "vm_labels": {},          # {"10.0.0.5": "Customer A", "10.0.0.6": "Customer B"}
    # Mirror/SPAN mode — monitor an entire network segment from a SPAN port
    # Instead of monitoring this server's own traffic, capture mirrored packets
    # and run per-destination-IP detection (like FastNetMon's mirror mode).
    "mirror_mode": False,
    "mirror_interface": "",        # NIC connected to SPAN/mirror port (required when mirror_mode=True)
    "mirror_subnets": [],          # Only monitor these destination CIDRs ["10.0.0.0/24"]
    "mirror_ip_labels": {},        # {"10.0.0.5": "Web Server", "10.0.0.6": "DB Server"}
    "mirror_capture_mode": "af_packet",  # "af_packet" (Linux, high perf) or "tcpdump" (fallback)
}

# Flow collector (built-in, no extra deps)
from ftagent.flow_collector import FlowCollector

# Optional dependency imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, PcapWriter, sniff, GRE
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    COLOR = True
except ImportError:
    COLOR = False


# ---------------------------------------------------------------------------
# Update Checker
# ---------------------------------------------------------------------------

def check_for_updates(force: bool = False, interactive: bool = True) -> None:
    """Check GitHub releases for a newer agent version. Optionally prompt to upgrade."""
    import urllib.request
    import json as _json

    # Throttle: only check once per day unless forced
    state_file = os.path.expanduser("~/.ftagent_update_check")
    if not force:
        try:
            mtime = os.path.getmtime(state_file)
            if time.time() - mtime < 86400:
                return
        except OSError:
            pass

    try:
        # Try GitHub releases first, fall back to tags
        latest = None
        for api_url in [
            "https://api.github.com/repos/Flowtriq/ftagent/releases/latest",
            "https://api.github.com/repos/Flowtriq/ftagent/tags?per_page=1",
        ]:
            try:
                req = urllib.request.Request(api_url, headers={"User-Agent": f"ftagent/{VERSION}"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read().decode())
                if isinstance(data, list) and data:
                    latest = data[0].get("name", "").lstrip("v")
                elif isinstance(data, dict):
                    latest = data.get("tag_name", "").lstrip("v")
                if latest:
                    break
            except Exception:
                continue

        if not latest:
            return

        # Record check time
        Path(state_file).touch()

        def _ver(v):
            try:
                return tuple(int(x) for x in v.split("."))
            except (ValueError, AttributeError):
                return (0,)

        if _ver(latest) <= _ver(VERSION):
            return  # Up to date

        msg = f"A newer version of ftagent is available: v{latest} (you have v{VERSION})"

        if not interactive:
            # Running as daemon: just log it
            try:
                logger.warning("%s. Run: pip install --upgrade ftagent", msg)
            except Exception:
                print(f"  {msg}")
                print("  Run: pip install --upgrade ftagent")
            return

        # Interactive: prompt to upgrade
        print(f"\n  {msg}")
        print(f"  Release: https://github.com/Flowtriq/ftagent/releases/tag/v{latest}\n")

        try:
            answer = input("  Would you like to update now? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if answer not in ("y", "yes"):
            return

        _do_pip_upgrade()

    except Exception:
        pass  # Never let update check break the agent


def _verify_installed_version(expected_version: str) -> bool:
    """Verify the installed ftagent version matches what we expected from PyPI."""
    try:
        import importlib.metadata
        # Force re-read by clearing any cached data
        installed = importlib.metadata.version("ftagent")
        if installed == expected_version:
            return True
        logger.warning(
            "Update verification: expected version %s but got %s",
            expected_version, installed)
        return False
    except Exception as exc:
        logger.warning("Update verification: cannot read installed version: %s", exc)
        return False


def _verify_module_imports() -> bool:
    """Sanity-check that the new ftagent module loads without errors."""
    import subprocess as _sp
    result = _sp.run(
        [sys.executable, "-c", "import ftagent.agent; print('ok')"],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0 and "ok" in result.stdout


def _pip_install_version(version: str, break_system: bool = False) -> bool:
    """Install a specific ftagent version. Returns True on success."""
    import subprocess as _sp
    pip_cmd = [sys.executable, "-m", "pip", "install", f"ftagent=={version}"]
    if break_system:
        pip_cmd.insert(-1, "--break-system-packages")
    result = _sp.run(pip_cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0 and "externally-managed-environment" in result.stderr and not break_system:
        return _pip_install_version(version, break_system=True)
    return result.returncode == 0


def _get_pypi_latest_version() -> str | None:
    """Query PyPI for the latest ftagent version string."""
    import urllib.request
    import json as _json
    try:
        req = urllib.request.Request(
            "https://pypi.org/pypi/ftagent/json",
            headers={"User-Agent": f"ftagent/{VERSION}"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = _json.loads(resp.read())
        return data.get("info", {}).get("version", "") or None
    except Exception:
        return None


def _do_pip_upgrade() -> None:
    """Run pip upgrade with post-install integrity verification."""
    import subprocess as _sp

    previous_version = VERSION
    # Determine what PyPI says is latest before we install
    pypi_latest = _get_pypi_latest_version()

    pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "ftagent"]
    break_system = False

    print("  Updating ftagent...")
    result = _sp.run(pip_cmd, capture_output=True, text=True, timeout=120)

    # PEP 668: externally managed Python (Debian 12+, Ubuntu 23.04+)
    if result.returncode != 0 and "externally-managed-environment" in result.stderr:
        print("  System Python detected. Retrying with --break-system-packages...")
        pip_cmd.insert(-1, "--break-system-packages")
        break_system = True
        result = _sp.run(pip_cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"  Update failed: {result.stderr.strip()}")
        print("  Try manually: pip install --upgrade ftagent")
        return

    # Post-install verification
    verified = True

    # 1. Verify installed version matches PyPI's advertised latest
    if pypi_latest:
        if not _verify_installed_version(pypi_latest):
            print(f"  WARNING: Version mismatch after install (expected {pypi_latest})")
            verified = False
    else:
        print("  WARNING: Could not query PyPI to verify target version")

    # 2. Verify the module imports cleanly
    if not _verify_module_imports():
        print("  WARNING: New version fails to import")
        verified = False

    if not verified:
        print(f"  Rolling back to v{previous_version}...")
        if _pip_install_version(previous_version, break_system=break_system):
            print(f"  Rolled back to v{previous_version}. Update aborted.")
        else:
            print(f"  Rollback failed. Manual intervention required.")
            print(f"  Try: pip install ftagent=={previous_version}")
        return

    print("  Updated successfully. Restart the agent to use the new version.")
    print("  Run: systemctl restart ftagent")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ftagent")


def setup_logging(log_file: str, log_level: str) -> None:
    from logging.handlers import RotatingFileHandler

    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    logger.setLevel(level)
    logger.handlers.clear()

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as exc:
        logger.warning("Cannot open log file %s: %s", log_file, exc)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        logger.warning("Config not found at %s — using defaults", path)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
    return cfg


def save_config(path: str, cfg: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(path, 0o600)
    logger.info("Config saved to %s", path)


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------

class APIClient:
    # Circuit breaker settings
    CB_FAILURE_THRESHOLD = 5       # consecutive failures to trip open
    CB_RECOVERY_TIMEOUT  = 60      # seconds before half-open probe
    CB_HALF_OPEN_MAX     = 1       # probes allowed in half-open state

    def __init__(self, cfg: dict):
        self.base = cfg["api_base"].rstrip("/")
        self.api_key = cfg["api_key"]
        self.node_uuid = cfg["node_uuid"]
        if not self.api_key or not self.node_uuid:
            raise ValueError(
                "API key and node UUID are required. Run 'sudo ftagent --setup' to configure."
            )
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "X-Node-UUID": self.node_uuid,
            "Content-Type": "application/json",
            "User-Agent": f"ftagent/{VERSION}",
        })
        self.retry_queue: collections.deque = collections.deque(maxlen=2000)
        # Circuit breaker state
        self._cb_state = "closed"          # closed | open | half-open
        self._cb_failures = 0
        self._cb_last_failure: float = 0.0
        self._cb_lock = threading.Lock()

    def _cb_record_success(self) -> None:
        with self._cb_lock:
            self._cb_failures = 0
            if self._cb_state != "closed":
                logger.info("Circuit breaker closed — API recovered")
                self._cb_state = "closed"

    def _cb_record_failure(self) -> None:
        with self._cb_lock:
            self._cb_failures += 1
            self._cb_last_failure = time.monotonic()
            if self._cb_failures >= self.CB_FAILURE_THRESHOLD and self._cb_state == "closed":
                self._cb_state = "open"
                logger.warning("Circuit breaker OPEN after %d consecutive failures — "
                               "blocking API calls for %ds",
                               self._cb_failures, self.CB_RECOVERY_TIMEOUT)

    def _cb_allow_request(self) -> bool:
        with self._cb_lock:
            if self._cb_state == "closed":
                return True
            elapsed = time.monotonic() - self._cb_last_failure
            if self._cb_state == "open" and elapsed >= self.CB_RECOVERY_TIMEOUT:
                self._cb_state = "half-open"
                logger.info("Circuit breaker half-open — allowing probe request")
                return True
            if self._cb_state == "half-open":
                return True  # allow the single probe
            return False

    @property
    def circuit_breaker_state(self) -> str:
        return self._cb_state

    def _post(self, path: str, payload: dict, timeout: int = 10,
              retries: int = 3) -> Optional[dict]:
        if not self._cb_allow_request():
            self.retry_queue.append(("POST", path, payload, timeout))
            return None
        url = f"{self.base}{path}"
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.post(url, json=payload, timeout=timeout)
                if resp.status_code == 503:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = int(retry_after)
                        except ValueError:
                            delay = 2 ** attempt
                    else:
                        delay = min(2 ** attempt, 16)
                    logger.warning(
                        "API POST %s returned 503 (attempt %d/%d), "
                        "retrying in %ds", path, attempt, retries, delay)
                    if attempt < retries:
                        time.sleep(delay)
                        continue
                    else:
                        self._cb_record_failure()
                        self.retry_queue.append(("POST", path, payload, timeout))
                        return None
                resp.raise_for_status()
                self._cb_record_success()
                if resp.content:
                    return resp.json()
                return {}
            except Exception as exc:
                logger.warning("API POST %s attempt %d/%d failed: %s",
                               path, attempt, retries, exc)
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 10))
                else:
                    self._cb_record_failure()
                    self.retry_queue.append(("POST", path, payload, timeout))
        return None

    def _get(self, path: str, timeout: int = 10,
             retries: int = 3) -> Optional[dict]:
        if not self._cb_allow_request():
            return None
        url = f"{self.base}{path}"
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.get(url, timeout=timeout)
                if resp.status_code == 503:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = int(retry_after)
                        except ValueError:
                            delay = 2 ** attempt
                    else:
                        delay = min(2 ** attempt, 16)
                    logger.warning(
                        "API GET %s returned 503 (attempt %d/%d), "
                        "retrying in %ds", path, attempt, retries, delay)
                    if attempt < retries:
                        time.sleep(delay)
                        continue
                    else:
                        self._cb_record_failure()
                        return None
                resp.raise_for_status()
                self._cb_record_success()
                return resp.json()
            except Exception as exc:
                logger.warning("API GET %s attempt %d/%d failed: %s",
                               path, attempt, retries, exc)
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 10))
                else:
                    self._cb_record_failure()
        return None

    def send_metrics(self, data: dict) -> None:
        self._post("/agent/metrics", data, timeout=5)

    def open_incident(self, data: dict) -> Optional[dict]:
        return self._post("/agent/incidents", data, timeout=15, retries=3)

    def update_incident(self, inc_uuid: str, data: dict) -> None:
        self._post(f"/agent/incidents/{inc_uuid}", data, timeout=10, retries=3)

    def resolve_incident(self, inc_uuid: str, data: dict) -> None:
        self._post(f"/agent/incidents/{inc_uuid}/resolve", data, timeout=15,
                   retries=3)

    # Max PCAP size to upload (500 MB); files larger than this get truncated
    # to preserve a representative sample while staying within server limits.
    MAX_PCAP_UPLOAD_BYTES = 500 * 1024 * 1024

    def _truncate_pcap(self, filepath: str) -> str:
        """Truncate an oversized PCAP to MAX_PCAP_UPLOAD_BYTES while keeping
        a valid PCAP header so the sample remains usable for analysis."""
        file_size = os.path.getsize(filepath)
        if file_size <= self.MAX_PCAP_UPLOAD_BYTES:
            return filepath
        logger.warning("PCAP too large (%.1f MB), truncating to %.0f MB sample: %s",
                       file_size / 1048576, self.MAX_PCAP_UPLOAD_BYTES / 1048576, filepath)
        with open(filepath, "r+b") as f:
            f.truncate(self.MAX_PCAP_UPLOAD_BYTES)
        logger.info("PCAP truncated: %s now %.1f MB",
                    filepath, os.path.getsize(filepath) / 1048576)
        return filepath

    def upload_pcap(self, inc_uuid: str, filepath: str,
                    retries: int = 3) -> None:
        url = f"{self.base}/agent/incidents/{inc_uuid}/pcap"
        chunk_size = 2 * 1024 * 1024  # 2 MB chunks
        # Unique upload ID prevents server-side chunk directory collisions
        # when multiple pcap files are uploaded for the same incident
        upload_id = uuid.uuid4().hex[:16]

        # Enforce size limit: truncate to a representative sample if too large
        try:
            self._truncate_pcap(filepath)
            file_size = os.path.getsize(filepath)
        except FileNotFoundError:
            logger.warning("PCAP file not found for upload, skipping: %s", filepath)
            return

        for attempt in range(1, retries + 1):
            try:
                if file_size <= chunk_size:
                    # Small file: single upload
                    with open(filepath, "rb") as f:
                        resp = self.session.post(
                            url,
                            files={"pcap": (os.path.basename(filepath), f,
                                            "application/octet-stream")},
                            headers={"Content-Type": None},
                            timeout=120,
                        )
                        resp.raise_for_status()
                else:
                    # Large file: chunked streaming upload
                    total_chunks = math.ceil(file_size / chunk_size)
                    logger.info("PCAP chunked upload: %d chunks (%.1f MB)",
                                total_chunks, file_size / 1048576)
                    with open(filepath, "rb") as f:
                        for i in range(total_chunks):
                            chunk_data = f.read(chunk_size)
                            if not chunk_data:
                                break
                            resp = self.session.post(
                                url,
                                data=chunk_data,
                                headers={
                                    "Content-Type": "application/octet-stream",
                                    "X-Chunk-Index": str(i),
                                    "X-Chunk-Total": str(total_chunks),
                                    "X-Upload-Id": upload_id,
                                },
                                timeout=60,
                            )
                            resp.raise_for_status()
                            logger.debug("Chunk %d/%d uploaded", i + 1,
                                         total_chunks)

                logger.info("PCAP uploaded for incident %s (attempt %d)",
                            inc_uuid, attempt)
                # Remove local file after successful upload
                try:
                    os.unlink(filepath)
                    logger.debug("PCAP file removed after upload: %s", filepath)
                except OSError as rm_err:
                    logger.warning("Could not remove uploaded PCAP %s: %s",
                                   filepath, rm_err)
                return
            except Exception as exc:
                logger.warning("PCAP upload attempt %d/%d failed for %s: %s",
                               attempt, retries, inc_uuid, exc)
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 15))

        logger.error("PCAP upload failed after %d attempts for %s",
                     retries, inc_uuid)

    def heartbeat(self, data: dict) -> None:
        result = self._post("/agent/heartbeat", data, timeout=10)
        if result is not None:
            self.flush_retry_queue()

    def get_config(self) -> Optional[dict]:
        return self._get("/agent/config", timeout=10)

    def flush_retry_queue(self) -> None:
        flushed = 0
        while self.retry_queue:
            method, path, payload, timeout = self.retry_queue.popleft()
            url = f"{self.base}{path}"
            try:
                resp = self.session.post(url, json=payload, timeout=timeout)
                resp.raise_for_status()
                flushed += 1
            except Exception:
                break
        if flushed:
            logger.info("Flushed %d queued requests", flushed)

    def test_connectivity(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.base}/agent/heartbeat",
                json={"version": VERSION, "baseline_ready": False,
                      "baseline_avg_pps": 0, "baseline_p99_pps": 0,
                      "baseline_hourly_ready": False,
                      "baseline_current_hour_p99": 0},
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Connectivity test failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# PPS Monitor — reads /proc/net/dev and /proc/net/snmp
# ---------------------------------------------------------------------------

class PPSMonitor:
    def __init__(self, interface: str = "auto"):
        self.interface = self._resolve_interface(interface)
        self.prev_rx_packets = 0
        self.prev_rx_bytes = 0
        self.prev_time = 0.0
        self.prev_tcp = 0
        self.prev_udp = 0
        self.prev_icmp = 0
        self.first_read = True
        self.pps = 0.0
        self.bps = 0.0
        self.tcp_pct = 0.0
        self.udp_pct = 0.0
        self.icmp_pct = 0.0
        self.conn_count = 0
        self._conn_count_interval = 15  # seconds between /proc/net/tcp reads
        self._last_conn_read = 0.0
        logger.info("Monitoring interface: %s", self.interface)

    @staticmethod
    def _resolve_interface(iface: str) -> str:
        if iface != "auto":
            return iface
        # Pick the non-lo interface with the most received bytes.
        # Handles servers with docker0, br-*, veth*, virbr*, dummy*, tun*, etc.
        skip = {"lo", "docker0"}
        skip_prefix = ("br-", "veth", "virbr", "dummy", "tun", "tap", "flannel", "cni", "cali")
        best_name = None
        best_bytes = -1
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) != 2:
                        continue
                    name = parts[0].strip()
                    if name in skip or name.startswith(skip_prefix):
                        continue
                    fields = parts[1].split()
                    if len(fields) >= 1:
                        rx_bytes = int(fields[0])
                        if rx_bytes > best_bytes:
                            best_bytes = rx_bytes
                            best_name = name
        except (OSError, ValueError):
            pass
        if best_name:
            return best_name
        # Fallback: first non-lo interface
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        name = parts[0].strip()
                        if name != "lo":
                            return name
        except OSError:
            pass
        return "eth0"

    def read(self) -> bool:
        now = time.monotonic()
        rx_packets, rx_bytes = self._read_dev()
        tcp_in, udp_in, icmp_in = self._read_snmp()

        if self.first_read:
            self.prev_rx_packets = rx_packets
            self.prev_rx_bytes = rx_bytes
            self.prev_time = now
            self.prev_tcp = tcp_in
            self.prev_udp = udp_in
            self.prev_icmp = icmp_in
            self.first_read = False
            return False

        dt = now - self.prev_time
        if dt <= 0:
            return False

        self.pps = (rx_packets - self.prev_rx_packets) / dt
        self.bps = (rx_bytes - self.prev_rx_bytes) * 8 / dt

        d_tcp = tcp_in - self.prev_tcp
        d_udp = udp_in - self.prev_udp
        d_icmp = icmp_in - self.prev_icmp
        total_proto = d_tcp + d_udp + d_icmp

        if total_proto > 0:
            self.tcp_pct = round(d_tcp / total_proto * 100, 1)
            self.udp_pct = round(d_udp / total_proto * 100, 1)
            self.icmp_pct = round(d_icmp / total_proto * 100, 1)

        # /proc/net/tcp is expensive (kernel serializes full socket table).
        # Read every 15s instead of every tick — not needed for detection.
        # Auto-scale interval: if server has many connections, read less often
        # to avoid CPU spikes (100K+ conns can take 50-100ms to enumerate).
        if now - self._last_conn_read >= self._conn_count_interval:
            self.conn_count = self._read_conn_count()
            self._last_conn_read = now
            # Back off to 60s if server has many connections
            if self.conn_count > 50000:
                self._conn_count_interval = 60
            elif self.conn_count > 10000:
                self._conn_count_interval = 30
            else:
                self._conn_count_interval = 15

        self.prev_rx_packets = rx_packets
        self.prev_rx_bytes = rx_bytes
        self.prev_time = now
        self.prev_tcp = tcp_in
        self.prev_udp = udp_in
        self.prev_icmp = icmp_in
        return True

    def _read_dev(self) -> tuple:
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if self.interface in line:
                        fields = line.split(":")[1].split()
                        return int(fields[1]), int(fields[0])
        except (OSError, IndexError, ValueError):
            pass
        return 0, 0

    @staticmethod
    def _read_snmp() -> tuple:
        tcp_in = udp_in = icmp_in = 0
        try:
            with open("/proc/net/snmp") as f:
                lines = f.readlines()
            for i in range(0, len(lines) - 1, 2):
                header = lines[i].strip()
                values = lines[i + 1].strip()
                if header.startswith("Tcp:"):
                    cols = header.split()
                    vals = values.split()
                    if "InSegs" in cols:
                        tcp_in = int(vals[cols.index("InSegs")])
                elif header.startswith("Udp:"):
                    cols = header.split()
                    vals = values.split()
                    if "InDatagrams" in cols:
                        udp_in = int(vals[cols.index("InDatagrams")])
                elif header.startswith("Icmp:"):
                    cols = header.split()
                    vals = values.split()
                    if "InMsgs" in cols:
                        icmp_in = int(vals[cols.index("InMsgs")])
        except (OSError, IndexError, ValueError):
            pass
        return tcp_in, udp_in, icmp_in

    @staticmethod
    def _read_conn_count() -> int:
        # Reading /proc/net/tcp line-by-line is expensive on busy servers
        # (kernel serializes the full socket table). Use a bulk read + count
        # newlines instead, which is ~3x faster on servers with 100K+ conns.
        count = 0
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path, "rb") as f:
                    buf = f.read()
                    count += buf.count(b"\n") - 1  # subtract header line
            except OSError:
                pass
        return max(count, 0)


# ---------------------------------------------------------------------------
# Baseline Manager
# ---------------------------------------------------------------------------

class BaselineManager:
    _RECALC_EVERY = 10  # recalculate percentiles every N samples
    # Use a low default floor (150 PPS) only before baseline is established.
    # Once baseline is ready, threshold is purely data-driven (p99 * 3).
    _DEFAULT_FLOOR = 5000
    # Minimum threshold after baseline is ready. Even if p99 * 3 is lower,
    # never trigger below this. A 500 PPS spike on a 100 PPS server is normal
    # traffic variation, not a DDoS attack.
    _MIN_READY_THRESHOLD = 5000
    # Hourly baseline: samples needed per hour bucket before it's trusted.
    _HOURLY_MIN_SAMPLES = 60
    # Per-hour deque size: 360 samples = ~6 hours of data for each hour slot.
    _HOURLY_WINDOW = 360

    def __init__(self, window: int = 300):
        self.WINDOW = window
        self.samples: collections.deque = collections.deque(maxlen=self.WINDOW)
        self.avg_pps = 0.0
        self.p95_pps = 0.0
        self.p99_pps = 0.0
        self.threshold = self._DEFAULT_FLOOR
        self.baseline_ready = False
        self._since_recalc = 0
        self._running_sum = 0.0
        # Time-of-day baselines: per-hour deques for adaptive thresholds
        self._hourly_baselines: dict[int, collections.deque] = {
            h: collections.deque(maxlen=self._HOURLY_WINDOW) for h in range(24)
        }
        self._hourly_p99: dict[int, float] = {}
        self._hourly_ready: bool = False  # True once current hour has enough data

    def add(self, pps: float) -> None:
        # Track evicted sample for running sum
        if len(self.samples) == self.samples.maxlen:
            self._running_sum -= self.samples[0]
        self.samples.append(pps)
        self._running_sum += pps

        # Feed into the hourly bucket for time-of-day awareness
        current_hour = datetime.now().hour
        self._hourly_baselines[current_hour].append(pps)

        n = len(self.samples)
        if n < 2:
            return

        self.avg_pps = self._running_sum / n
        self._since_recalc += 1

        # Full percentile sort only every N ticks (expensive O(n log n))
        if self._since_recalc >= self._RECALC_EVERY:
            self._since_recalc = 0
            sorted_s = sorted(self.samples)
            self.p95_pps = sorted_s[int(n * 0.95)]
            self.p99_pps = sorted_s[int(n * 0.99)]

            # Compute hourly p99 for the current hour if enough samples
            hourly_samples = self._hourly_baselines[current_hour]
            hourly_n = len(hourly_samples)
            hour_has_data = hourly_n >= self._HOURLY_MIN_SAMPLES
            self._hourly_ready = hour_has_data

            if hour_has_data:
                sorted_h = sorted(hourly_samples)
                hourly_p99 = sorted_h[int(hourly_n * 0.99)]
                self._hourly_p99[current_hour] = hourly_p99
                # Hourly p99 drives the threshold, but never below half of
                # the flat p99 to avoid dangerously low thresholds.
                effective_p99 = max(hourly_p99, self.p99_pps * 0.5)
            else:
                effective_p99 = self.p99_pps

            # Before baseline is ready, use a default floor so low-traffic nodes
            # can still detect attacks. Once ready, use data-driven threshold
            # but never go below _MIN_READY_THRESHOLD -- a tiny spike on a
            # quiet server is not a DDoS attack.
            if self.baseline_ready:
                self.threshold = max(effective_p99 * 3, self._MIN_READY_THRESHOLD)
            else:
                self.threshold = max(effective_p99 * 3, self._DEFAULT_FLOOR)

        if n >= self.WINDOW:
            self.baseline_ready = True

    @property
    def hourly_ready(self) -> bool:
        """Whether the current hour's bucket has enough samples."""
        return self._hourly_ready

    @property
    def current_hour_p99(self) -> float:
        """P99 for the current hour, or 0.0 if not enough data yet."""
        current_hour = datetime.now().hour
        return self._hourly_p99.get(current_hour, 0.0)


# ---------------------------------------------------------------------------
# Per-IP Baseline Manager (Mirror Mode)
# ---------------------------------------------------------------------------

class PerIPBaselineManager:
    """Maintains independent BaselineManager instances per destination IP.

    Used by MirrorAgent to detect DDoS attacks on individual IPs within
    a monitored network segment (SPAN/mirror port).

    Memory bounded: LRU eviction at max_ips, stale eviction after 10 min.
    """

    def __init__(self, window: int = 300, max_ips: int = 50_000,
                 stale_seconds: float = 600.0):
        self._window = window
        self._max_ips = max_ips
        self._stale_seconds = stale_seconds
        self._baselines: collections.OrderedDict[str, BaselineManager] = (
            collections.OrderedDict())
        self._last_seen: dict[str, float] = {}
        self._last_prune: float = 0.0

    def add(self, ip: str, pps: float) -> None:
        """Feed a PPS sample for this IP into its baseline."""
        now = time.monotonic()
        self._last_seen[ip] = now

        bl = self._baselines.get(ip)
        if bl is None:
            # Evict if at capacity
            while len(self._baselines) >= self._max_ips:
                oldest_ip, _ = self._baselines.popitem(last=False)
                self._last_seen.pop(oldest_ip, None)
            bl = BaselineManager(window=self._window)
            self._baselines[ip] = bl
        else:
            # LRU touch
            self._baselines.move_to_end(ip)

        bl.add(pps)

        # Periodic stale eviction (every 60s)
        if now - self._last_prune >= 60:
            self._last_prune = now
            self._prune_stale(now)

    def check(self, ip: str, pps: float) -> bool:
        """Returns True if this IP's PPS exceeds its threshold."""
        bl = self._baselines.get(ip)
        if bl is None:
            # No baseline yet -- use absolute floor
            return pps >= 10000
        if not bl.baseline_ready:
            # Baseline still building -- only trigger on absolute floor
            # (don't use the 150 PPS default floor, it's too low for mirror mode
            # where many IPs will have legitimate low-level traffic)
            return pps >= 10000
        return pps > bl.threshold

    def get_threshold(self, ip: str) -> float:
        """Returns current threshold for an IP (0 if unknown)."""
        bl = self._baselines.get(ip)
        if bl is None:
            return 0.0
        return bl.threshold

    def get_baseline(self, ip: str) -> dict:
        """Returns baseline stats for an IP."""
        bl = self._baselines.get(ip)
        if bl is None:
            return {"ready": False, "avg_pps": 0, "p99_pps": 0, "threshold": 0}
        return {
            "ready": bl.baseline_ready,
            "avg_pps": round(bl.avg_pps, 1),
            "p99_pps": round(bl.p99_pps, 1),
            "threshold": round(bl.threshold, 1),
        }

    def _prune_stale(self, now: float) -> None:
        """Remove IPs with no traffic for stale_seconds."""
        cutoff = now - self._stale_seconds
        stale = [ip for ip, ts in self._last_seen.items() if ts < cutoff]
        for ip in stale:
            self._baselines.pop(ip, None)
            self._last_seen.pop(ip, None)
        if stale:
            logger.debug("PerIPBaseline: pruned %d stale IPs", len(stale))

    @property
    def ip_count(self) -> int:
        return len(self._baselines)

    def baseline_summary(self, n: int = 20) -> list[dict]:
        """Top N IPs by threshold for health/debugging."""
        items = [(ip, bl) for ip, bl in self._baselines.items()
                 if bl.baseline_ready]
        items.sort(key=lambda x: x[1].threshold, reverse=True)
        return [
            {"ip": ip, "threshold": round(bl.threshold, 1),
             "avg_pps": round(bl.avg_pps, 1), "p99_pps": round(bl.p99_pps, 1)}
            for ip, bl in items[:n]
        ]


# ---------------------------------------------------------------------------
# Traffic Analyser
# ---------------------------------------------------------------------------

class TrafficAnalyser:
    def __init__(self):
        self.reset()

    # Memory safety caps — prevent OOM on large botnets (10M+ source IPs)
    MAX_SRC_IPS = 100_000       # max unique source IPs tracked
    MAX_PKT_SAMPLES = 50_000    # max packet length / TTL samples
    MAX_DNS_QUERIES = 10_000    # max unique DNS query names
    MAX_IOC_HITS = 5_000        # max IOC match entries
    MAX_TTL_PER_IP = 10         # max unique TTLs per source IP
    MAX_INNER_IPS = 1_000       # max inner dst IPs (VMs) tracked per hypervisor

    def reset(self) -> None:
        self.tcp_flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0,
                          "PSH": 0, "URG": 0}
        self.src_ips: dict = {}        # ip -> count
        self.src_ip_detail: dict = {}  # ip -> {tcp, udp, icmp, other, syn, ack, bytes, ttls}
        self.dst_ports: dict = {}
        self.src_ports: dict = {}      # source port -> count (for amplification detection)
        self.pkt_lengths: list = []
        self.ttl_values: list = []
        self.dns_queries: dict = {}
        self.total_packets = 0
        self.fragment_count = 0        # IP fragmented packets (MF flag or frag offset > 0)
        self.ioc_hits: list = []
        self._src_ip_overflow = False   # flag: True once we hit cap
        # Per-VM tracking (Feature 2): inner dst IP after GRE decapsulation
        self.inner_dst_ips: dict = {}  # inner_dst_ip -> packet count
        self.per_vm_detail: dict = {}  # inner_dst_ip -> {pps, bps, tcp, udp, icmp, src_ips}

    def _evict_low_count_ips(self) -> None:
        """Evict bottom 20% of source IPs by count to make room for new ones.
        Keeps high-count IPs (the real attackers) and removes low-count noise."""
        if not self.src_ips:
            return
        # Find the 20th percentile count threshold
        counts = sorted(self.src_ips.values())
        cutoff_idx = len(counts) // 5  # bottom 20%
        cutoff_count = counts[cutoff_idx] if cutoff_idx < len(counts) else 1

        to_remove = [ip for ip, cnt in self.src_ips.items() if cnt <= cutoff_count]
        # Don't evict more than 20% to avoid over-pruning
        to_remove = to_remove[:len(self.src_ips) // 5]

        for ip in to_remove:
            del self.src_ips[ip]
            self.src_ip_detail.pop(ip, None)

        if to_remove:
            logger.debug("Evicted %d low-count source IPs (threshold=%d, remaining=%d)",
                         len(to_remove), cutoff_count, len(self.src_ips))

    def process_packet(self, pkt, ioc_matcher=None, gre_decap=None,
                       hypervisor_mode: bool = False) -> None:
        """
        Analyse one packet for stats.

        gre_decap: GREDecapsulator instance or None. When set, strips GRE
                   headers from the stats packet. The original pkt is never
                   modified — it's passed separately to PCAP for forensics.

        hypervisor_mode: When True and GRE decapsulation happened, track inner
                         destination IP to attribute traffic to individual VMs.
        """
        self.total_packets += 1

        if not SCAPY_AVAILABLE:
            return

        # GRE decapsulation for stats (Feature 1).
        # stats_pkt = inner packet (stripped of GRE headers).
        # Original pkt is unchanged — caller writes it to PCAP as-is.
        inner_dst_ip = None
        stats_pkt = pkt
        if gre_decap and gre_decap.enabled:
            stats_pkt, was_gre = gre_decap.decapsulate_scapy(pkt)
            if was_gre and hypervisor_mode and stats_pkt.haslayer(IP):
                inner_dst_ip = stats_pkt[IP].dst

        if stats_pkt.haslayer(IP):
            ip = stats_pkt[IP]
            src = ip.src

            # Track IP fragments (MF flag set or fragment offset > 0)
            if ip.flags.MF or ip.frag > 0:
                self.fragment_count += 1

            # Bounded src_ips: only track new IPs if under cap
            if src in self.src_ips:
                self.src_ips[src] += 1
            elif len(self.src_ips) < self.MAX_SRC_IPS:
                self.src_ips[src] = 1
            else:
                # Evict bottom 20% by count to make room for new IPs
                self._evict_low_count_ips()

            # Bounded packet length / TTL samples (use inner packet length)
            if len(self.pkt_lengths) < self.MAX_PKT_SAMPLES:
                self.pkt_lengths.append(len(stats_pkt))
            if len(self.ttl_values) < self.MAX_PKT_SAMPLES:
                self.ttl_values.append(ip.ttl)

            # Bounded per-IP detail tracking
            if src in self.src_ip_detail:
                d = self.src_ip_detail[src]
            elif len(self.src_ip_detail) < self.MAX_SRC_IPS:
                d = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0, "syn": 0, "ack": 0, "bytes": 0, "ttls": set()}
                self.src_ip_detail[src] = d
            else:
                d = None

            if d is not None:
                d["bytes"] += len(stats_pkt)
                if len(d["ttls"]) < self.MAX_TTL_PER_IP:
                    d["ttls"].add(ip.ttl)

            if stats_pkt.haslayer(TCP):
                tcp = stats_pkt[TCP]
                self.dst_ports[tcp.dport] = self.dst_ports.get(tcp.dport, 0) + 1
                self.src_ports[tcp.sport] = self.src_ports.get(tcp.sport, 0) + 1
                if d is not None:
                    d["tcp"] += 1
                flags = tcp.flags
                if flags & 0x02:
                    self.tcp_flags["SYN"] += 1
                    if d is not None: d["syn"] += 1
                if flags & 0x10:
                    self.tcp_flags["ACK"] += 1
                    if d is not None: d["ack"] += 1
                if flags & 0x04:
                    self.tcp_flags["RST"] += 1
                if flags & 0x01:
                    self.tcp_flags["FIN"] += 1
                if flags & 0x08:
                    self.tcp_flags["PSH"] += 1
                if flags & 0x20:
                    self.tcp_flags["URG"] += 1

            elif stats_pkt.haslayer(UDP):
                self.dst_ports[stats_pkt[UDP].dport] = (
                    self.dst_ports.get(stats_pkt[UDP].dport, 0) + 1)
                self.src_ports[stats_pkt[UDP].sport] = (
                    self.src_ports.get(stats_pkt[UDP].sport, 0) + 1)
                if d is not None:
                    d["udp"] += 1

            elif stats_pkt.haslayer(ICMP):
                if d is not None:
                    d["icmp"] += 1

            else:
                # GRE/ESP/IPIP/other protocols
                if d is not None:
                    d["other"] += 1

            if stats_pkt.haslayer(DNS) and stats_pkt[DNS].qr == 0:
                try:
                    qname = stats_pkt[DNS].qd.qname.decode(errors="ignore")
                    if qname in self.dns_queries or len(self.dns_queries) < self.MAX_DNS_QUERIES:
                        self.dns_queries[qname] = self.dns_queries.get(qname, 0) + 1
                except Exception:
                    pass

            # Per-VM inner dst IP tracking (Feature 2)
            if inner_dst_ip:
                if inner_dst_ip in self.inner_dst_ips:
                    self.inner_dst_ips[inner_dst_ip] += 1
                elif len(self.inner_dst_ips) < self.MAX_INNER_IPS:
                    self.inner_dst_ips[inner_dst_ip] = 1
                # Update per-VM protocol detail
                if inner_dst_ip in self.per_vm_detail:
                    vm = self.per_vm_detail[inner_dst_ip]
                elif len(self.per_vm_detail) < self.MAX_INNER_IPS:
                    vm = {"tcp": 0, "udp": 0, "icmp": 0, "bytes": 0, "src_ips": set()}
                    self.per_vm_detail[inner_dst_ip] = vm
                else:
                    vm = None
                if vm is not None:
                    vm["bytes"] += len(stats_pkt)
                    if src not in vm["src_ips"] and len(vm["src_ips"]) < 500:
                        vm["src_ips"].add(src)
                    if stats_pkt.haslayer(TCP):
                        vm["tcp"] += 1
                    elif stats_pkt.haslayer(UDP):
                        vm["udp"] += 1
                    elif stats_pkt.haslayer(ICMP):
                        vm["icmp"] += 1

        if ioc_matcher and pkt.haslayer(Raw):
            hit = ioc_matcher.check(bytes(pkt[Raw].load))
            if hit and len(self.ioc_hits) < self.MAX_IOC_HITS:
                self.ioc_hits.append(hit)

    def src_ip_entropy(self) -> float:
        total = sum(self.src_ips.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in self.src_ips.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def ttl_entropy(self) -> float:
        if not self.ttl_values:
            return 0.0
        freq: dict = {}
        for t in self.ttl_values:
            freq[t] = freq.get(t, 0) + 1
        total = len(self.ttl_values)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def spoofing_detected(self) -> bool:
        return self.ttl_entropy() < 1.5 and len(self.src_ips) > 100

    def botnet_detected(self) -> bool:
        # Heuristic: many source IPs
        if len(self.src_ips) > 300:
            return True
        # IOC-based: any botnet family signature matched
        botnet_keywords = ("mirai", "gafgyt", "bashlite", "mozi", "xorddos",
                           "muhstik", "tsunami", "kaiten", "hajime", "meris",
                           "mantis", "fodcha", "botnet")
        for hit in self.ioc_hits:
            if any(kw in hit.lower() for kw in botnet_keywords):
                return True
        return False

    def blocklist_ratio(self) -> float:
        """Fraction of source IPs that match the threat intel blocklist."""
        if not self.src_ips or not hasattr(self, '_blocklist') or not self._blocklist:
            return 0.0
        matched = sum(1 for ip in self.src_ips if ip in self._blocklist)
        return matched / len(self.src_ips) if self.src_ips else 0.0

    def top_src_ips(self, n: int = 20) -> list:
        total = self.total_packets or 1
        result = []
        for ip, c in sorted(self.src_ips.items(),
                             key=lambda x: x[1], reverse=True)[:n]:
            entry = {"ip": ip, "count": c}
            d = self.src_ip_detail.get(ip)
            if d:
                pct = c / total
                # Confidence scoring: higher = more likely attacker
                conf = 0
                # High packet contribution = likely attacker
                if pct > 0.05: conf += 30
                elif pct > 0.02: conf += 15
                # SYN-only (no ACK) = likely SYN flood source
                if d["tcp"] > 0 and d["ack"] == 0 and d["syn"] > 0:
                    conf += 25
                # Single TTL = likely spoofed
                if len(d["ttls"]) <= 1 and c > 50:
                    conf += 20
                # Pure single-protocol = more suspicious
                protos_used = (1 if d["tcp"] > 0 else 0) + \
                              (1 if d["udp"] > 0 else 0) + \
                              (1 if d["icmp"] > 0 else 0)
                if protos_used == 1 and c > 100:
                    conf += 10
                # Very high packet count (>500 in capture window)
                if c > 500: conf += 15
                elif c > 200: conf += 5
                # Low byte/pkt ratio for UDP = amplification
                avg_pkt = d["bytes"] / max(c, 1)
                if d["udp"] > d["tcp"] and avg_pkt < 100 and c > 100:
                    conf += 10

                conf = min(conf, 100)
                entry["confidence"] = conf
                entry["tcp"] = d["tcp"]
                entry["udp"] = d["udp"]
                entry["icmp"] = d["icmp"]
                entry["ttl_unique"] = len(d["ttls"])
                entry["pct"] = round(pct * 100, 2)
            # Check against threat intel blocklist
            if hasattr(self, '_blocklist') and ip in self._blocklist:
                entry["threat_intel"] = True
                entry["confidence"] = max(entry.get("confidence", 0), 90)
            result.append(entry)
        return result

    def top_dst_ports(self, n: int = 20) -> list:
        return [{"port": p, "count": c}
                for p, c in sorted(self.dst_ports.items(),
                                   key=lambda x: x[1], reverse=True)[:n]]

    def top_src_ports(self, n: int = 20) -> list:
        return [{"port": p, "count": c}
                for p, c in sorted(self.src_ports.items(),
                                   key=lambda x: x[1], reverse=True)[:n]]

    def protocol_breakdown(self) -> dict:
        """Compute protocol percentages from actual packet inspection (scapy).
        This is authoritative — unlike /proc/net/snmp which misses dropped packets."""
        tcp_total = udp_total = icmp_total = other_total = 0
        for d in self.src_ip_detail.values():
            tcp_total += d["tcp"]
            udp_total += d["udp"]
            icmp_total += d["icmp"]
            other_total += d.get("other", 0)
        grand = tcp_total + udp_total + icmp_total + other_total
        frag_pct = round(self.fragment_count / max(self.total_packets, 1) * 100, 1)
        if grand == 0:
            return {"tcp": 0, "udp": 0, "icmp": 0, "other": 0, "fragments": frag_pct}
        return {
            "tcp": round(tcp_total / grand * 100, 1),
            "udp": round(udp_total / grand * 100, 1),
            "icmp": round(icmp_total / grand * 100, 1),
            "other": round(other_total / grand * 100, 1),
            "fragments": frag_pct,
        }

    def fragment_pct(self) -> float:
        """Percentage of total packets that are IP fragments."""
        if self.total_packets == 0:
            return 0.0
        return round(self.fragment_count / self.total_packets * 100, 1)

    def syn_ratio(self) -> float:
        """SYN ratio from captured TCP flags."""
        total = sum(self.tcp_flags.values())
        return (self.tcp_flags["SYN"] / total) if total > 0 else 0.0

    def pkt_length_histogram(self) -> dict:
        buckets = {"0-64": 0, "65-128": 0, "129-256": 0, "257-512": 0,
                   "513-1024": 0, "1025-1500": 0, "1500+": 0}
        for length in self.pkt_lengths:
            if length <= 64:
                buckets["0-64"] += 1
            elif length <= 128:
                buckets["65-128"] += 1
            elif length <= 256:
                buckets["129-256"] += 1
            elif length <= 512:
                buckets["257-512"] += 1
            elif length <= 1024:
                buckets["513-1024"] += 1
            elif length <= 1500:
                buckets["1025-1500"] += 1
            else:
                buckets["1500+"] += 1
        return buckets

    def ttl_distribution(self) -> dict:
        dist: dict = {}
        for t in self.ttl_values:
            dist[t] = dist.get(t, 0) + 1
        return dict(sorted(dist.items(), key=lambda x: x[1], reverse=True)[:15])

    def avg_pkt_length(self) -> float:
        if not self.pkt_lengths:
            return 0.0
        return round(sum(self.pkt_lengths) / len(self.pkt_lengths), 1)

    def dns_query_stats(self) -> dict:
        return {
            "total": sum(self.dns_queries.values()),
            "unique": len(self.dns_queries),
            "top": sorted(self.dns_queries.items(),
                          key=lambda x: x[1], reverse=True)[:10],
        }

    def top_inner_dst_ips(self, n: int = 20) -> list:
        """Top destination IPs inside GRE tunnels (per-VM targets). Feature 2."""
        return [
            {"inner_ip": ip, "count": c}
            for ip, c in sorted(
                self.inner_dst_ips.items(), key=lambda x: x[1], reverse=True
            )[:n]
        ]

    def per_vm_breakdown(self, vm_labels: dict = None) -> list:
        """
        Per-VM traffic breakdown for hypervisor nodes. Feature 2.
        Returns list of per-inner-IP stats, sorted by packet count descending.
        vm_labels: optional {inner_ip: display_name} mapping from config.
        """
        labels = vm_labels or {}
        result = []
        total = max(1, sum(self.inner_dst_ips.values()))
        for ip, count in sorted(
            self.inner_dst_ips.items(), key=lambda x: x[1], reverse=True
        )[:50]:
            vm = self.per_vm_detail.get(ip, {})
            vm_total = max(1, vm.get("tcp", 0) + vm.get("udp", 0) + vm.get("icmp", 0))
            entry = {
                "inner_ip": ip,
                "pps": count,
                "bps": vm.get("bytes", 0),
                "tcp_pct": round(vm.get("tcp", 0) / vm_total * 100, 2),
                "udp_pct": round(vm.get("udp", 0) / vm_total * 100, 2),
                "icmp_pct": round(vm.get("icmp", 0) / vm_total * 100, 2),
                "src_ip_count": len(vm.get("src_ips", set())),
            }
            label = labels.get(ip)
            if label:
                entry["label"] = label
            result.append(entry)
        return result

    def top_attacked_vm(self) -> str:
        """Return the inner dst IP with the most traffic — the primary attack target. Feature 2."""
        if not self.inner_dst_ips:
            return ""
        return max(self.inner_dst_ips.items(), key=lambda x: x[1])[0]


# ---------------------------------------------------------------------------
# IOC Matcher
# ---------------------------------------------------------------------------

class IOCMatcher:
    def __init__(self):
        self.patterns: list = []

    def load(self, patterns: list) -> None:
        self.patterns = patterns
        logger.info("Loaded %d IOC patterns", len(patterns))

    def check(self, payload: bytes) -> Optional[str]:
        for p in self.patterns:
            try:
                if p["pattern"].encode() in payload:
                    return f"{p['attack_name']}:{p['attack_family']}"
            except Exception:
                continue
        return None


# ---------------------------------------------------------------------------
# GRE Decapsulator (Feature 1: GRE Encapsulation Traffic Deduplication)
# ---------------------------------------------------------------------------

class GREDecapsulator:
    """
    Strips GRE encapsulation before counting bytes/PPS for traffic stats.

    Protocol: IP protocol 47 (GRE, RFC 2784/2890/3931)

    Why this matters: On GRE tunnel interfaces the same traffic appears at
    multiple layers — outer IP+GRE wrapper + inner payload. Without stripping,
    bandwidth and PPS stats are inflated by 10-25% (GRE/IP header overhead)
    or more with nested GRE.

    PCAP forensics are NEVER stripped — the full original packet with all
    encapsulation headers is always written to disk for forensic analysis.

    Handles:
    - Single GRE (standard hosting provider setup)
    - Nested GRE-in-GRE (double/triple encapsulation, rare but real)
    - Mixed traffic: non-GRE packets pass through unchanged
    - Malformed GRE: falls back to original packet safely
    """

    GRE_PROTO = 47  # IP protocol number for GRE

    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth
        self.enabled = False
        # Stats for overhead ratio calculation (reset each tick)
        self._outer_bytes = 0
        self._inner_bytes = 0
        self._gre_pkt_count = 0
        self._total_pkt_count = 0

    def decapsulate_scapy(self, pkt):
        """
        Strip GRE layers from a Scapy packet for stats.
        Returns (inner_pkt, was_gre).
        Original pkt is unchanged — caller passes original to PCAP.
        """
        self._total_pkt_count += 1

        if not SCAPY_AVAILABLE or not pkt.haslayer(GRE):
            return pkt, False

        self._gre_pkt_count += 1
        outer_len = len(pkt)

        # Strip up to max_depth GRE layers
        inner = pkt
        for _ in range(self.max_depth):
            if not inner.haslayer(GRE):
                break
            inner = inner[GRE].payload

        inner_len = len(inner)
        self._outer_bytes += outer_len
        self._inner_bytes += inner_len
        return inner, True

    def decapsulate_raw(self, data: bytes):
        """
        Strip GRE from raw packet bytes (no Scapy dependency).
        Used in tcpdump mode for BPS correction calculations.
        Returns (inner_bytes, was_gre).
        """
        self._total_pkt_count += 1
        original = data

        for _ in range(self.max_depth):
            if len(data) < 24:  # min: 20 IP + 4 GRE
                break
            # Validate IP version nibble (must be 4 for IPv4)
            if (data[0] >> 4) != 4:
                break
            # Parse IP header length and protocol
            ihl = (data[0] & 0x0F) * 4
            if ihl < 20 or ihl > 60:  # valid IHL range: 20-60 bytes
                break
            if len(data) < ihl + 4:
                break
            proto = data[9]
            if proto != self.GRE_PROTO:
                break
            gre_flags = struct.unpack('!H', data[ihl:ihl + 2])[0]
            gre_hdr_len = 4
            if gre_flags & 0x8000:  # Checksum + reserved (4 bytes)
                gre_hdr_len += 4
            if gre_flags & 0x2000:  # Key field (4 bytes)
                gre_hdr_len += 4
            if gre_flags & 0x1000:  # Sequence number (4 bytes)
                gre_hdr_len += 4
            inner_start = ihl + gre_hdr_len
            if inner_start >= len(data):
                break
            inner_data = data[inner_start:]
            # Validate inner packet is IP before continuing recursion
            if len(inner_data) < 20 or (inner_data[0] >> 4) != 4:
                break
            data = inner_data

        was_gre = data is not original
        if was_gre:
            self._gre_pkt_count += 1
            self._outer_bytes += len(original)
            self._inner_bytes += len(data)
        return data, was_gre

    @property
    def overhead_ratio(self) -> float:
        """Fraction of bytes that are GRE encapsulation overhead (0.0–1.0)."""
        if self._outer_bytes == 0:
            return 0.0
        return max(0.0, (self._outer_bytes - self._inner_bytes) / self._outer_bytes)

    @property
    def gre_traffic_ratio(self) -> float:
        """Fraction of packets that are GRE-encapsulated (0.0–1.0)."""
        if self._total_pkt_count == 0:
            return 0.0
        return self._gre_pkt_count / self._total_pkt_count

    def reset_window(self) -> None:
        """Reset per-window stats (call each metrics tick)."""
        self._outer_bytes = 0
        self._inner_bytes = 0
        self._gre_pkt_count = 0
        self._total_pkt_count = 0


def detect_gre_interface(iface: str) -> bool:
    """
    Return True if the given interface is a GRE tunnel.
    Uses `ip -d link show` which shows interface type metadata.
    Safe to call on any interface — returns False if indeterminate.
    """
    try:
        import subprocess
        out = subprocess.run(
            ["ip", "-d", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        lower = out.stdout.lower()
        return any(t in lower for t in ("gre ", "gre\n", "gretap", "ip6gre", "ip6gretap"))
    except Exception:
        return False


def detect_gre_tunnels() -> list:
    """
    Enumerate active GRE tunnel interfaces and their endpoints.
    Returns list of dicts: [{name, remote, local, type}, ...]
    Uses `ip tunnel show` (iproute2, standard on all modern Linux).
    """
    tunnels = []
    try:
        import subprocess
        # ip tunnel show lists all GRE/IPIP tunnels with remote+local
        out = subprocess.run(
            ["ip", "tunnel", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Pattern: "gre1: ip/gre remote 203.0.113.1 local 192.0.2.1 ..."
            m = re.match(
                r'(\S+):\s+(ip[/\w]*)(?:/gre|6gre)?\s+remote\s+([\d.a-fA-F:]+)\s+local\s+([\d.a-fA-F:]+)',
                line, re.I,
            )
            if m:
                tunnels.append({
                    "name":      m.group(1),
                    "type":      m.group(2),
                    "remote_ip": m.group(3),
                    "local_ip":  m.group(4),
                })
    except Exception as exc:
        logger.debug("GRE tunnel detection failed: %s", exc)
    return tunnels


# ---------------------------------------------------------------------------
# PCAP Capture
# ---------------------------------------------------------------------------

class PcapCapture:
    def __init__(self, cfg: dict, iface: str, analyser: TrafficAnalyser,
                 ioc_matcher: IOCMatcher, gre_decap: "GREDecapsulator" = None,
                 hypervisor_mode: bool = False):
        self.pcap_mode = cfg.get("pcap_mode", "tcpdump")
        self.enabled = cfg.get("pcap_enabled", True) and (SCAPY_AVAILABLE or self.pcap_mode == "tcpdump")
        self.config_path = cfg.get("_config_path", CONFIG_PATH)
        self.pcap_dir = cfg.get("pcap_dir", "/var/lib/ftagent/pcaps")
        self.snaplen = cfg.get("pcap_snaplen", 0)  # 0 = full packet, or set to e.g. 256 for high-traffic links
        self.iface = iface
        self._tcpdump_proc = None
        self._ring_dir = None
        self.analyser = analyser
        self.ioc_matcher = ioc_matcher
        self._gre_decap = gre_decap
        self._hypervisor_mode = hypervisor_mode
        # In Scapy mode, each packet object can be 1-50KB in memory.
        # Keep ring buffer small (200) to limit memory to ~5-10MB.
        # tcpdump mode writes to disk files, so this buffer is only used
        # as a fallback for pre-attack packet capture in Scapy mode.
        _ring_size = 200 if self.pcap_mode == "scapy" else 1000
        self.ring_buffer: collections.deque = collections.deque(maxlen=_ring_size)
        self.capture_packets: list = []
        self._capture_lock = threading.Lock()
        self.capturing = False
        self.max_capture = 10000
        self._thread = None
        self._stop_event = threading.Event()
        self._pkt_counter = 0
        self._analyse_every = 10  # deep-analyse every Nth packet during capture
        # Retention / disk-cap settings
        self.retention_days = cfg.get("pcap_retention_days", 7)
        self.max_disk_mb = cfg.get("pcap_max_disk_mb", 2000)  # 2 GB default cap
        self._last_cleanup = 0.0

    def background_ring(self, shutdown: threading.Event) -> None:
        if not self.enabled:
            return

        if self.pcap_mode == "tcpdump":
            self._background_ring_tcpdump(shutdown)
        else:
            self._background_ring_scapy(shutdown)

    def _tcpdump_unavailable(self, reason: str) -> None:
        """Handle tcpdump being unavailable — warn the user, prompt to disable
        pcap or let them fix it.  Never silently fall back to scapy."""
        border = "=" * 72
        msg = f"""
{border}
  PCAP CAPTURE UNAVAILABLE — tcpdump could not be started
{border}

  Reason: {reason}

  Your pcap_mode is set to "tcpdump", which is the recommended mode for
  servers handling significant traffic.  tcpdump captures packets at
  native speed with near-zero CPU overhead.

  The alternative "scapy" mode processes every packet in Python and WILL
  cause extremely high CPU usage (90%+) on busy servers — such as game
  servers, proxies, or anything above a few thousand packets/sec.
  If you still want to use scapy, you can change pcap_mode to "scapy"
  in your config file:  {self.config_path}

  You can also ingest traffic data from an upstream router or switch
  using our built-in flow collector instead of local packet capture.
  We support sFlow, NetFlow v5, NetFlow v9, and IPFIX.
  Enable it in your config with "flow_enabled": true — see docs for
  details.

{border}
"""
        # Log it so it always appears in journalctl / log file
        for line in msg.strip().splitlines():
            logger.error(line)

        # Interactive prompt — if stdin is available, let the user choose.
        # In daemon/systemd context this will fall through to disabling pcap.
        try:
            if sys.stdin is not None and sys.stdin.isatty():
                print(msg, file=sys.stderr)
                print(
                    "  WARNING: Disabling packet capture removes a core feature\n"
                    "  of the Flowtriq agent.  Attack analysis, traffic fingerprinting,\n"
                    "  and PCAP evidence collection will all be unavailable.\n"
                    "  This will severely limit our ability to analyze and mitigate attacks.\n",
                    file=sys.stderr,
                )
                answer = input("  Disable packet capture and continue without it? [y/N] ").strip().lower()
                if answer == "y":
                    logger.warning("Packet capture disabled by user — running without PCAP")
                    print("\n  Packet capture disabled.  The agent will continue running but\n"
                          "  attack analysis capabilities are severely reduced.\n",
                          file=sys.stderr)
                    self.enabled = False
                    return
                else:
                    logger.error("User chose not to disable pcap — exiting so tcpdump can be fixed")
                    print("\n  Please install tcpdump and restart the agent.\n"
                          "  On Debian/Ubuntu:  apt-get install -y tcpdump\n"
                          "  On RHEL/CentOS:    yum install -y tcpdump\n"
                          "  On Alpine:         apk add tcpdump\n",
                          file=sys.stderr)
                    os._exit(1)
            else:
                # Non-interactive (systemd, nohup, etc.) — cannot prompt, disable pcap
                logger.error(
                    "Non-interactive session — disabling packet capture.  "
                    "Install tcpdump and restart the agent to restore full functionality."
                )
                self.enabled = False
        except (EOFError, OSError):
            logger.error(
                "Cannot prompt for input — disabling packet capture.  "
                "Install tcpdump and restart the agent to restore full functionality."
            )
            self.enabled = False

    def _cleanup_ring_dir(self, keep_latest: int = 3) -> None:
        """Hard-enforce ring buffer size: keep only the newest `keep_latest`
        files and delete everything else.  Called on startup, before each
        tcpdump restart, and periodically from cleanup_pcaps()."""
        ring_dir = getattr(self, '_ring_dir', None)
        if not ring_dir:
            ring_dir = os.path.join(self.pcap_dir, "_ring")
        try:
            ring_path = Path(ring_dir)
            if not ring_path.is_dir():
                return
            files = sorted(ring_path.glob("*.pcap"), key=lambda f: f.stat().st_mtime)
            to_delete = files[:-keep_latest] if len(files) > keep_latest else []
            for f in to_delete:
                try:
                    sz = f.stat().st_size
                    f.unlink()
                    logger.info("Ring cleanup: deleted %s (%.1f MB)", f.name, sz / 1048576)
                except OSError:
                    pass
            if to_delete:
                logger.info("Ring cleanup: removed %d old file(s), kept %d",
                            len(to_delete), min(len(files), keep_latest))
        except Exception as exc:
            logger.error("Ring cleanup error: %s", exc)

    def _background_ring_tcpdump(self, shutdown: threading.Event) -> None:
        """Use tcpdump for continuous capture. Native speed, near-zero CPU.
        Rotates files every 30s, keeps last 3 as a ring buffer.
        Full-fidelity capture of every packet at any PPS."""
        import subprocess
        ring_dir = os.path.join(self.pcap_dir, "_ring")
        os.makedirs(ring_dir, mode=0o700, exist_ok=True)
        os.chmod(ring_dir, 0o700)
        self._ring_dir = ring_dir

        # Clean up any orphaned ring files from previous runs on startup
        self._cleanup_ring_dir(keep_latest=3)

        ring_file = os.path.join(ring_dir, "ring_%Y%m%d_%H%M%S.pcap")
        snaplen = str(self.snaplen) if self.snaplen else "0"
        tcpdump_cmd = [
            "tcpdump", "-i", self.iface, "-w", ring_file,
            "-G", "30", "-W", "3", "-s", snaplen, "-q",
        ]

        logger.info("PCAP ring buffer active on %s (tcpdump mode)", self.iface)
        try:
            import subprocess

            # Auto-install tcpdump if not present
            if subprocess.run(["which", "tcpdump"], capture_output=True).returncode != 0:
                logger.info("tcpdump not found, attempting to install...")
                installed = False
                for pm_cmd in [
                    ["apt-get", "install", "-y", "tcpdump"],
                    ["yum", "install", "-y", "tcpdump"],
                    ["dnf", "install", "-y", "tcpdump"],
                    ["apk", "add", "tcpdump"],
                    ["pacman", "-S", "--noconfirm", "tcpdump"],
                ]:
                    try:
                        r = subprocess.run(pm_cmd, capture_output=True, timeout=60)
                        if r.returncode == 0:
                            logger.info("tcpdump installed via %s", pm_cmd[0])
                            installed = True
                            break
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        continue
                if not installed:
                    self._tcpdump_unavailable(
                        "tcpdump is not installed and automatic installation failed.  "
                        "Install it manually (e.g. apt-get install tcpdump) and restart the agent."
                    )
                    return

            # Also ensure mergecap is available (for merging ring files on capture stop)
            if subprocess.run(["which", "mergecap"], capture_output=True).returncode != 0:
                for pm_cmd in [
                    ["apt-get", "install", "-y", "wireshark-common"],
                    ["yum", "install", "-y", "wireshark-cli"],
                    ["dnf", "install", "-y", "wireshark-cli"],
                ]:
                    try:
                        r = subprocess.run(pm_cmd, capture_output=True, timeout=120)
                        if r.returncode == 0:
                            logger.info("mergecap installed via %s", pm_cmd[0])
                            break
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        continue

            self._tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _restarts = 0
            _last_start = time.monotonic()
            while not shutdown.is_set():
                shutdown.wait(1)
                if self._tcpdump_proc.poll() is not None:
                    _ran_for = time.monotonic() - _last_start
                    _exit_code = self._tcpdump_proc.returncode
                    # Normal rotation: tcpdump -G exits cleanly after each interval
                    if _exit_code == 0 and _ran_for >= 20:
                        _restarts = 0  # reset — this was a healthy rotation, not a crash
                    else:
                        logger.warning("tcpdump exited (code %d, ran %.0fs)",
                                       _exit_code, _ran_for)
                        _restarts += 1
                    if _restarts > 5:
                        self._tcpdump_unavailable(
                            f"tcpdump crashed {_restarts} times consecutively.  "
                            "It may be incompatible with this system or missing permissions."
                        )
                        return
                    # Fully reap the old process before spawning a new one
                    try:
                        self._tcpdump_proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self._tcpdump_proc.kill()
                        self._tcpdump_proc.wait(timeout=3)
                    # Exponential backoff: 5s, 10s, 20s, 40s, ...
                    _backoff = min(5 * (2 ** (_restarts - 1)), 60)
                    shutdown.wait(_backoff)
                    if not shutdown.is_set():
                        # Clean orphaned files before restart
                        self._cleanup_ring_dir(keep_latest=3)
                        logger.info("Restarting tcpdump (attempt %d, backoff %ds)...",
                                    _restarts, _backoff)
                        self._tcpdump_proc = subprocess.Popen(
                            tcpdump_cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
                        _last_start = time.monotonic()

            self._tcpdump_proc.terminate()
            try:
                self._tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._tcpdump_proc.kill()

        except FileNotFoundError:
            self._tcpdump_unavailable(
                "tcpdump binary not found on this system."
            )
        except Exception as exc:
            self._tcpdump_unavailable(f"Unexpected error starting tcpdump: {exc}")

    def _background_ring_scapy(self, shutdown: threading.Event) -> None:
        """Scapy sniff mode — per-packet Python analysis. Only runs when
        pcap_mode is explicitly set to 'scapy' in the config."""
        logger.warning("PCAP ring buffer active on %s (scapy mode — high CPU on busy servers)", self.iface)
        try:
            sniff(iface=self.iface, prn=self._ring_cb, store=False,
                  stop_filter=lambda _: shutdown.is_set())
        except Exception as exc:
            logger.warning("Ring buffer sniff error: %s", exc)

    def _ring_cb(self, pkt) -> None:
        self.ring_buffer.append(pkt)
        if self.capturing and len(self.capture_packets) < self.max_capture:
            with self._capture_lock:
                self.capture_packets.append(pkt)  # always store original (unstripped) for forensics
            self._pkt_counter += 1
            if self._pkt_counter % self._analyse_every == 0:
                self.analyser.process_packet(
                    pkt, self.ioc_matcher,
                    gre_decap=self._gre_decap,
                    hypervisor_mode=self._hypervisor_mode,
                )

    # Max total size for pre-attack ring snapshot: 100MB
    # This prevents copying multi-GB ring files on high-traffic links
    _MAX_RING_SNAPSHOT_BYTES = 100 * 1024 * 1024

    def start_capture(self, incident_uuid: str = "",
                       api_client=None) -> None:
        if self.pcap_mode == "tcpdump" and self._ring_dir:
            # In tcpdump mode, snapshot the current ring files as the pre-attack sample
            import glob
            import shutil
            self._tcpdump_capture_dir = os.path.join(self.pcap_dir, f"_capture_{incident_uuid[:8]}")
            os.makedirs(self._tcpdump_capture_dir, exist_ok=True)
            # Copy ring files newest-first, up to snapshot size limit
            ring_files = sorted(
                glob.glob(os.path.join(self._ring_dir, "ring*")),
                key=lambda f: os.path.getmtime(f), reverse=True)
            copied_bytes = 0
            for rf in ring_files:
                try:
                    rf_size = os.path.getsize(rf)
                    if copied_bytes + rf_size > self._MAX_RING_SNAPSHOT_BYTES:
                        if copied_bytes == 0:
                            # At least copy one ring file even if oversized, but truncate it
                            dst = os.path.join(self._tcpdump_capture_dir, os.path.basename(rf))
                            with open(rf, "rb") as src_f, open(dst, "wb") as dst_f:
                                remaining = self._MAX_RING_SNAPSHOT_BYTES
                                while remaining > 0:
                                    chunk = src_f.read(min(65536, remaining))
                                    if not chunk:
                                        break
                                    dst_f.write(chunk)
                                    remaining -= len(chunk)
                            copied_bytes = self._MAX_RING_SNAPSHOT_BYTES
                        break
                    shutil.copy2(rf, self._tcpdump_capture_dir)
                    copied_bytes += rf_size
                except Exception:
                    pass
            # Start a dedicated tcpdump for this incident
            import subprocess
            self._capture_file = os.path.join(self._tcpdump_capture_dir, "attack.pcap")
            try:
                _snaplen = str(self.snaplen) if self.snaplen else "0"
                self._capture_proc = subprocess.Popen(
                    ["tcpdump", "-i", self.iface, "-w", self._capture_file,
                     "-s", _snaplen, "-Z", "root", "-c", str(self.max_capture), "-q"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                self._capture_proc = None
        else:
            self._tcpdump_capture_dir = None
            self._capture_proc = None

        with self._capture_lock:
            self.capture_packets = list(self.ring_buffer)
        self.capturing = True
        self._incident_uuid = incident_uuid
        self._api_client = api_client
        self._chunk_index = 0
        self._chunk_size = 500  # packets per chunk file (small for fast first upload)
        self._uploaded_chunks: list = []
        logger.info("PCAP capture started (%d pre-attack packets)",
                    len(self.capture_packets))
        # Start background chunk uploader thread
        if api_client and incident_uuid:
            self._chunk_stop = threading.Event()
            # Immediately flush pre-buffer packets so backend gets early sample
            if len(self.capture_packets) >= 50:
                threading.Thread(
                    target=self._flush_chunk, daemon=True,
                    name="pcap-early-flush").start()
            self._chunk_thread = threading.Thread(
                target=self._chunk_upload_loop, daemon=True,
                name="pcap-chunk-upload")
            self._chunk_thread.start()

    def _chunk_upload_loop(self) -> None:
        """Periodically write and upload PCAP chunks during an attack."""
        while not self._chunk_stop.is_set():
            self._chunk_stop.wait(10)  # check every 10 seconds
            if self._chunk_stop.is_set():
                break
            with self._capture_lock:
                pkt_count = len(self.capture_packets)
            threshold = (self._chunk_index + 1) * self._chunk_size
            if pkt_count >= threshold:
                self._flush_chunk()

    def _check_disk_space(self, min_mb: int = 500) -> bool:
        """Check free disk space AND enforce max_disk_mb cap before writes."""
        try:
            import shutil
            usage = shutil.disk_usage(self.pcap_dir)
            free_mb = usage.free // (1024 * 1024)
            if free_mb < min_mb:
                logger.warning("PCAP write skipped: only %d MB free (minimum %d MB)", free_mb, min_mb)
                return False
        except Exception:
            pass  # If we can't check free space, proceed cautiously

        # Enforce max_disk_mb cap synchronously before every write
        try:
            pcap_root = Path(self.pcap_dir)
            if pcap_root.is_dir():
                pcap_files = [f for f in pcap_root.glob("*.pcap") if f.is_file()]
                total_bytes = sum(f.stat().st_size for f in pcap_files)
                max_bytes = self.max_disk_mb * 1024 * 1024
                if total_bytes >= max_bytes:
                    logger.warning(
                        "PCAP write skipped: %.1f MB on disk >= %d MB cap, "
                        "triggering cleanup", total_bytes / 1048576, self.max_disk_mb)
                    self.cleanup_pcaps()
                    # Re-check after cleanup
                    total_bytes = sum(
                        f.stat().st_size for f in pcap_root.glob("*.pcap")
                        if f.is_file())
                    if total_bytes >= max_bytes:
                        return False
        except Exception:
            pass
        return True

    def _flush_chunk(self) -> Optional[str]:
        """Write current packets to a chunk file and upload it."""
        start_idx = self._chunk_index * self._chunk_size
        end_idx = start_idx + self._chunk_size
        with self._capture_lock:
            chunk_pkts = self.capture_packets[start_idx:end_idx]
        if not chunk_pkts:
            return None
        if not self._check_disk_space():
            return None
        Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filepath = os.path.join(
            self.pcap_dir,
            f"{self._incident_uuid}_{ts}_chunk{self._chunk_index}.pcap")
        try:
            writer = PcapWriter(filepath, append=False, sync=True)
            for pkt in chunk_pkts:
                writer.write(pkt)
            writer.close()
            logger.info("PCAP chunk %d written: %s (%d packets)",
                        self._chunk_index, filepath, len(chunk_pkts))
            self._chunk_index += 1
            # Upload in background, then delete the chunk file from disk
            if self._api_client:
                def _upload_and_delete(api, uuid, path):
                    try:
                        api.upload_pcap(uuid, path)
                    except Exception:
                        pass
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                threading.Thread(
                    target=_upload_and_delete,
                    args=(self._api_client, self._incident_uuid, filepath),
                    daemon=True,
                ).start()
            else:
                # No API client; delete immediately (no point keeping chunks)
                try:
                    os.unlink(filepath)
                except OSError:
                    pass
            self._uploaded_chunks.append(filepath)
            return filepath
        except Exception as exc:
            logger.error("PCAP chunk write failed: %s", exc)
            return None

    def cleanup_pcaps(self) -> None:
        """Remove old / excess pcap files to prevent disk exhaustion."""
        try:
            pcap_root = Path(self.pcap_dir)
            if not pcap_root.is_dir():
                return

            # 1. Remove orphaned temp capture dirs older than 1 hour
            for entry in pcap_root.iterdir():
                if entry.is_dir() and entry.name.startswith("_capture_"):
                    try:
                        age_s = time.time() - entry.stat().st_mtime
                        if age_s > 3600:
                            import shutil
                            shutil.rmtree(entry, ignore_errors=True)
                            logger.info("Cleaned orphaned capture dir: %s", entry.name)
                    except OSError:
                        pass

            # 2. Enforce ring buffer cap (tcpdump -W can fail on restart)
            self._cleanup_ring_dir(keep_latest=3)

            # 3. Collect final pcap files (skip _ring/ and _capture_*/ dirs)
            pcap_files = sorted(
                (f for f in pcap_root.glob("*.pcap") if f.is_file()),
                key=lambda f: f.stat().st_mtime,
            )
            if not pcap_files:
                return

            now = time.time()
            max_age = self.retention_days * 86400
            removed = 0

            # 4. Delete files older than retention_days
            remaining = []
            for f in pcap_files:
                try:
                    if now - f.stat().st_mtime > max_age:
                        f.unlink()
                        removed += 1
                    else:
                        remaining.append(f)
                except OSError:
                    remaining.append(f)

            # 5. Enforce disk cap (delete oldest first)
            max_bytes = self.max_disk_mb * 1024 * 1024
            total = sum(f.stat().st_size for f in remaining)
            while remaining and total > max_bytes:
                oldest = remaining.pop(0)
                try:
                    sz = oldest.stat().st_size
                    oldest.unlink()
                    total -= sz
                    removed += 1
                except OSError:
                    pass

            if removed:
                logger.info("PCAP cleanup: removed %d file(s), %d remaining (%.1f MB)",
                            removed, len(remaining), total / 1048576)
        except Exception as exc:
            logger.error("PCAP cleanup error: %s", exc)

    def stop_capture(self, incident_uuid: str) -> Optional[str]:
        self.capturing = False

        # tcpdump mode: stop capture process and merge files
        if self.pcap_mode == "tcpdump" and hasattr(self, '_capture_proc') and self._capture_proc:
            self._capture_proc.terminate()
            try:
                self._capture_proc.wait(timeout=5)
            except Exception:
                self._capture_proc.kill()

            # Check disk space before merge write
            if not self._check_disk_space():
                import shutil
                shutil.rmtree(self._tcpdump_capture_dir, ignore_errors=True)
                return None

            # Merge ring snapshots + attack capture into one file
            import glob
            Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filepath = os.path.join(self.pcap_dir, f"{incident_uuid}_{ts}.pcap")

            ring_files = sorted(glob.glob(os.path.join(self._tcpdump_capture_dir, "ring*")))
            attack_file = os.path.join(self._tcpdump_capture_dir, "attack.pcap")
            all_files = ring_files + ([attack_file] if os.path.exists(attack_file) else [])

            if all_files:
                try:
                    # Use mergecap if available, else copy first valid file
                    import subprocess
                    merge_result = subprocess.run(
                        ["mergecap", "-w", filepath] + all_files,
                        capture_output=True, timeout=30)
                    if merge_result.returncode != 0:
                        # Fallback: use the largest individual PCAP file
                        # (concatenation corrupts the PCAP global header)
                        best = max(all_files, key=lambda f: os.path.getsize(f))
                        import shutil
                        shutil.copy2(best, filepath)
                    logger.info("PCAP merged: %s (%d source files)", filepath, len(all_files))
                except FileNotFoundError:
                    # No mergecap, just use the attack file
                    if os.path.exists(attack_file):
                        import shutil
                        shutil.move(attack_file, filepath)
                except Exception as exc:
                    logger.error("PCAP merge failed: %s", exc)

            # Cleanup temp dir
            import shutil
            shutil.rmtree(self._tcpdump_capture_dir, ignore_errors=True)

            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                # Truncate merged output if still oversized (safety net)
                max_bytes = self._api_client.MAX_PCAP_UPLOAD_BYTES if hasattr(self, '_api_client') and self._api_client else 500 * 1024 * 1024
                if os.path.getsize(filepath) > max_bytes:
                    with open(filepath, "r+b") as f:
                        f.truncate(max_bytes)
                return filepath
            return None

        # Stop chunk upload thread and clean up leftover chunk files
        if hasattr(self, '_chunk_stop'):
            self._chunk_stop.set()
        for chunk_path in getattr(self, '_uploaded_chunks', []):
            try:
                if os.path.exists(chunk_path):
                    os.unlink(chunk_path)
            except OSError:
                pass
        self._uploaded_chunks = []
        with self._capture_lock:
            packets_copy = list(self.capture_packets)
            self.capture_packets = []
        if not packets_copy:
            return None
        if not self._check_disk_space():
            return None
        Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filepath = os.path.join(self.pcap_dir, f"{incident_uuid}_{ts}.pcap")
        try:
            writer = PcapWriter(filepath, append=False, sync=True)
            for pkt in packets_copy:
                writer.write(pkt)
            writer.close()
            logger.info("PCAP written: %s (%d packets)",
                        filepath, len(packets_copy))
            return filepath
        except Exception as exc:
            logger.error("PCAP write failed: %s", exc)
            return None


# ---------------------------------------------------------------------------
# L7 (HTTP) Detection Module
# ---------------------------------------------------------------------------

WEB_SERVER_LOG_PATHS = {
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/access_log",
        "/usr/local/nginx/logs/access.log",
    ],
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/apache2/other_vhosts_access.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/access.log",
        "/var/log/apache/access.log",
    ],
    "caddy": ["/var/log/caddy/access.log"],
    "litespeed": [
        "/var/log/litespeed/access.log",
        "/usr/local/lsws/logs/access.log",
    ],
    "haproxy": ["/var/log/haproxy.log"],
}

LOG_PATTERN_COMBINED = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(HTTP/\S+)"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"[^"]*"\s+"([^"]*)")?'
)

# Additional log format patterns for more web servers
LOG_PATTERN_TOMCAT = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\S+)'
    r'(?:\s+(\d+))?'  # optional response time in ms
)
LOG_PATTERN_GUNICORN = re.compile(
    r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"[^"]*"\s+"([^"]*)")?'
)

# ── L7 threat pattern signatures ──
L7_THREAT_PATTERNS = {
    "sqli": re.compile(
        r"(?:union\s+select|'?\s*or\s+['\d]|select\s+.*from\s|insert\s+into|"
        r"drop\s+table|update\s+\w+\s+set|;\s*(?:drop|delete|alter)\s)", re.I),
    "xss": re.compile(
        r"(?:<script|javascript:|on(?:error|load|click|mouseover)\s*=|"
        r"eval\s*\(|document\.(?:cookie|write)|alert\s*\()", re.I),
    "path_traversal": re.compile(r"(?:\.\./|\.\.\\|%2e%2e[%/])", re.I),
    "rfi_lfi": re.compile(
        r"(?:(?:file|php|zip|data|expect|glob|phar)://|/etc/(?:passwd|shadow)|"
        r"/proc/self/)", re.I),
    "wordpress": re.compile(
        r"(?:/wp-(?:admin|login|content|includes|config|cron)|/xmlrpc\.php|"
        r"/wp-json/wp/)", re.I),
    "scanner_probe": re.compile(
        r"(?:/\.env|/\.git/|/config\.php|/phpinfo|/server-status|/actuator|"
        r"/containers/json|/debug/vars|/solr/admin|/_cat/indices|/elmah\.axd|"
        r"/telescope/requests|/\.well-known/security\.txt)", re.I),
    "shell_shock": re.compile(r"\(\)\s*\{", re.I),
    "log4j": re.compile(r"\$\{(?:jndi|lower|upper|env):", re.I),
    "api_abuse": re.compile(
        r"(?:/graphql|/api/v\d+/(?:admin|users|tokens|keys)|/oauth/token|"
        r"/\.well-known/openid)", re.I),
    "cve_exploit": re.compile(
        r"(?:/cgi-bin/|/shell|/cmd\.php|/c99\.php|/r57\.php|"
        r"/eval-stdin\.php|/vendor/phpunit)", re.I),
}

# ── Known bot User-Agent patterns ──
L7_BOT_UA_PATTERNS = re.compile(
    r"(?:python-requests|python-urllib|Go-http-client|java/|curl/|"
    r"wget/|libwww-perl|PHP/|Scrapy|nikto|sqlmap|nmap|masscan|"
    r"zgrab|httpx|nuclei|dirsearch|gobuster|ffuf|wfuzz|"
    r"bot|spider|crawl|scan|attack|exploit|hack)", re.I)

def _normalize_http_version(raw: str) -> str:
    """Normalize HTTP protocol string to version shorthand.
    'HTTP/1.1' -> '1.1', 'HTTP/2.0' -> '2', 'HTTP/3.0' -> '3', 'h2' -> '2', etc."""
    if not raw:
        return ""
    r = raw.strip().upper()
    if r.startswith("HTTP/"):
        ver = r[5:]
        # "2.0" -> "2", "3.0" -> "3", "1.1" stays "1.1", "1.0" stays "1.0"
        if ver in ("2.0", "2"):
            return "2"
        if ver in ("3.0", "3"):
            return "3"
        return ver
    r_low = raw.strip().lower()
    if r_low in ("h2", "h2c"):
        return "2"
    if r_low in ("h3",):
        return "3"
    return ""


# ── L7 subtype classification helpers ──
def _classify_l7_subtype(stats: dict) -> str:
    """Classify L7 attack subtype from traffic characteristics."""
    rps = stats.get("rps", 0)
    unique_ips = stats.get("unique_ips", 0)
    error_rate = stats.get("error_rate", 0)
    top_paths = stats.get("top_paths", {})
    top_ips = stats.get("top_ips", {})
    total = stats.get("total_requests", 0)

    if not total:
        return "l7_flood"

    # ── HTTP/2-specific attack pattern detection ──
    h2_pct = stats.get("h2_pct", 0.0)
    h3_pct = stats.get("h3_pct", 0.0)
    status_499 = stats.get("status_499", 0)
    rps_per_ip = stats.get("rps_per_ip", 0.0)

    if h2_pct > 30:
        # HTTP/2 Rapid Reset (CVE-2023-44487): extremely high RPS with many
        # 499/client-closed responses from relatively few source IPs.
        # Attackers open streams then immediately RST them.
        status_499_pct = (status_499 / max(total, 1)) * 100
        if rps > 200 and status_499_pct > 20 and rps_per_ip > 50:
            return "h2_rapid_reset"

        # HTTP/2 SETTINGS flood: few IPs generating extreme per-IP RPS
        # via connection-level abuse (multiplexed streams)
        if rps_per_ip > 200 and unique_ips < 20 and rps > 500:
            return "h2_settings_flood"

        # HTTP/2 CONTINUATION flood (CVE-2024-27983): few IPs, many
        # 400-series errors from malformed continuation frames
        status_4xx = stats.get("status_4xx", 0)
        status_4xx_pct = (status_4xx / max(total, 1)) * 100
        if rps_per_ip > 100 and unique_ips < 30 and status_4xx_pct > 40:
            return "h2_continuation_flood"

    # ── HTTP/3 (QUIC) flood detection ──
    if h3_pct > 30 and rps > 300 and unique_ips > 5:
        return "quic_flood"

    # Single source abuse
    if unique_ips <= 2 and total > 50:
        return "single_source_abuse"

    # Check path concentration for scraping / endpoint targeting
    if top_paths:
        top_path, top_count = max(top_paths.items(), key=lambda x: x[1])
        path_pct = top_count / max(total, 1)

        # Credential stuffing: high error rate on auth endpoints
        auth_paths = {"/login", "/signin", "/auth", "/oauth", "/api/login",
                      "/wp-login.php", "/admin/login", "/user/login"}
        if path_pct > 0.5 and error_rate > 40:
            for ap in auth_paths:
                if ap in top_path.lower():
                    return "credential_stuffing"

        # Scraping: one path hammered, low error rate
        if path_pct > 0.7 and error_rate < 20:
            return "scraping"

        # API abuse: targeting API endpoints
        if "/api/" in top_path.lower() or "/graphql" in top_path.lower():
            return "api_abuse"

    # Slowloris: low RPS but from many IPs (agent won't catch true slowloris
    # since it's connection-based, but low-and-slow patterns show up)
    if rps < 50 and unique_ips > 20 and error_rate > 60:
        return "slow_rate"

    # High volume from many sources = volumetric HTTP flood
    if rps > 500 and unique_ips > 10:
        return "volumetric_flood"

    return "l7_flood"


def detect_web_server() -> dict:
    """Auto-detect running web server and locate access log files."""
    import subprocess

    result = {"web_server": None, "server_version": None, "detected_paths": []}
    checks = [
        ("nginx",     ["nginx", "-v"]),
        ("apache",    ["apache2", "-v"]),
        ("apache",    ["httpd", "-v"]),
        ("caddy",     ["caddy", "version"]),
        ("litespeed", ["litespeed", "-v"]),
        ("haproxy",   ["haproxy", "-v"]),
    ]

    for name, cmd in checks:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 or (r.stderr and name in r.stderr.lower()):
                version_text = (r.stderr or r.stdout).strip().split("\n")[0]
                result["web_server"] = name
                result["server_version"] = version_text[:100]
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not result["web_server"]:
        try:
            r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            ps_out = r.stdout.lower()
            for name in ["nginx", "apache2", "httpd", "caddy", "litespeed", "haproxy"]:
                if name in ps_out:
                    result["web_server"] = "apache" if name in ("apache2", "httpd") else name
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not result["web_server"]:
        return result

    candidates = WEB_SERVER_LOG_PATHS.get(result["web_server"], [])
    all_paths = set()
    for paths in WEB_SERVER_LOG_PATHS.values():
        all_paths.update(paths)
    ordered = list(candidates) + [p for p in all_paths if p not in candidates]

    for path in ordered:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            result["detected_paths"].append(path)

    return result


class L7Monitor:
    """Monitors HTTP access logs for L7 attack patterns."""

    def __init__(self, log_path: str, api: APIClient, l7_config: dict = None):
        self.log_path = log_path
        self.api = api
        self.file = None
        self.inode = 0
        self._window = 10
        self._requests: list = []
        self._baseline_rps: float = 0.0
        self._baseline_samples: int = 0
        self._attack_active = False
        self._attack_start = 0.0
        self._attack_uuid = ""
        self._attack_peak_rps = 0.0
        # Configurable thresholds (from server config)
        cfg = l7_config or {}
        self._rps_threshold_override = cfg.get("rps_threshold")       # None = auto
        self._error_rate_threshold = cfg.get("error_rate_threshold", 50)
        sensitivity = cfg.get("sensitivity", "medium")
        self._sensitivity_multiplier = {"low": 8, "medium": 5, "high": 3}.get(sensitivity, 5)
        self._min_rps = {"low": 250, "medium": 150, "high": 75}.get(sensitivity, 150)
        # Accumulated attack-wide stats (capped to prevent memory bloat
        # from attackers rotating user-agents, paths, or source IPs)
        self._MAX_ATTACK_KEYS = 10_000
        self._attack_ua_counts: dict = {}
        self._attack_threat_hits: dict = {}
        self._attack_status_totals: dict = {}
        self._attack_path_totals: dict = {}
        self._attack_ip_totals: dict = {}
        self._attack_total_requests: int = 0
        self._attack_version_totals: dict = {}  # HTTP version -> request count

    def open(self) -> bool:
        try:
            self.file = open(self.log_path, "r")
            self.file.seek(0, 2)
            self.inode = os.stat(self.log_path).st_ino
            logger.info("L7: tailing %s", self.log_path)
            return True
        except (OSError, IOError) as exc:
            logger.error("L7: cannot open %s: %s", self.log_path, exc)
            return False

    def tick(self) -> Optional[dict]:
        if not self.file:
            return None

        try:
            current_inode = os.stat(self.log_path).st_ino
            if current_inode != self.inode:
                logger.info("L7: log rotated, reopening %s", self.log_path)
                try:
                    self.file.close()
                except Exception:
                    pass
                self.file = None
                self.open()
        except OSError:
            # Log file was deleted, not just rotated
            if self.file:
                self.file.close()
            self.file = None

        new_lines = []
        try:
            while True:
                line = self.file.readline()
                if not line:
                    break
                new_lines.append(line.rstrip("\n"))
        except (OSError, IOError):
            pass

        now = time.monotonic()
        for line in new_lines:
            parsed = self._parse_line(line)
            if parsed:
                self._requests.append((now, *parsed))

        cutoff = now - self._window
        self._requests = [r for r in self._requests if r[0] >= cutoff]
        # Hard safety cap in case clock skew breaks window filtering
        if len(self._requests) > 20_000:
            self._requests = self._requests[-10_000:]

        if not self._requests:
            return None
        return self._compute_stats(now)

    def _parse_line(self, line: str) -> Optional[tuple]:
        # JSON format (nginx json_combined, Caddy, Node.js Morgan/Pino, Go, Python)
        if line.startswith("{"):
            try:
                d = json.loads(line)
                ip = (d.get("remote_addr") or d.get("client_ip") or d.get("host")
                      or d.get("remoteAddress") or d.get("remote_ip")  # Node.js / Go
                      or d.get("clientip") or "")                      # Gunicorn
                method = (d.get("method") or d.get("request_method")
                          or d.get("httpMethod") or "GET")
                path = (d.get("uri") or d.get("path") or d.get("request_uri")
                        or d.get("url") or d.get("pathname") or "/")
                status = int(d.get("status") or d.get("status_code")
                             or d.get("statusCode") or d.get("response_code") or 0)
                size = int(d.get("body_bytes_sent") or d.get("bytes")
                           or d.get("content_length") or d.get("responseSize") or 0)
                ua = (d.get("http_user_agent") or d.get("user_agent")
                      or d.get("userAgent") or d.get("user-agent") or "")
                resp_time = d.get("request_time") or d.get("response_time") or d.get("duration") or d.get("latency")
                if resp_time is not None:
                    try:
                        resp_time = float(resp_time)
                        # Normalize: if > 1000, assume already ms; otherwise assume seconds
                        if resp_time < 100:
                            resp_time = resp_time * 1000
                    except (ValueError, TypeError):
                        resp_time = None
                # HTTP protocol version (e.g. "HTTP/2.0", "HTTP/1.1", "HTTP/3.0")
                raw_proto = (d.get("server_protocol") or d.get("protocol")
                             or d.get("httpVersion") or d.get("http_version") or "")
                http_version = _normalize_http_version(raw_proto)
                if ip and status:
                    return (ip, method, path, status, size, ua, resp_time, http_version)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
            return None

        # Standard combined/CLF format (nginx, Apache, Tomcat, Gunicorn, LiteSpeed, HAProxy)
        m = LOG_PATTERN_COMBINED.match(line)
        if m:
            ip = m.group(1)
            method, path = m.group(3), m.group(4)
            raw_proto = m.group(5)  # e.g. "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"
            status = int(m.group(6))
            size_str = m.group(7)
            ua = m.group(8) or ""
            size = int(size_str) if size_str != "-" else 0
            path = path.split("?")[0] if "?" in path else path
            http_version = _normalize_http_version(raw_proto)
            return (ip, method, path, status, size, ua, None, http_version)
        return None

    def _compute_stats(self, now: float) -> dict:
        n = len(self._requests)
        elapsed = max(1.0, now - self._requests[0][0]) if n > 1 else self._window
        rps = n / elapsed

        ip_counts: dict = {}
        path_counts: dict = {}
        status_counts: dict = {}
        ua_counts: dict = {}
        threat_hits: dict = {}
        resp_times: list = []
        bot_request_count = 0
        version_counts: dict = {}  # HTTP version -> count ("1.1", "2", "3")
        # HTTP/2 rapid reset heuristic: count 499/client-closed status codes
        status_499_count = 0

        for req in self._requests:
            ts, ip, method, path, status, size, ua = req[0], req[1], req[2], req[3], req[4], req[5], req[6]
            resp_time = req[7] if len(req) > 7 else None
            http_version = req[8] if len(req) > 8 else ""

            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            path_counts[path] = path_counts.get(path, 0) + 1
            code_group = f"{status // 100}xx"
            status_counts[code_group] = status_counts.get(code_group, 0) + 1

            # Track HTTP protocol version distribution
            if http_version:
                version_counts[http_version] = version_counts.get(http_version, 0) + 1

            # Track 499 (nginx client closed request) for rapid reset detection
            if status == 499:
                status_499_count += 1

            # User-Agent tracking
            if ua:
                ua_short = ua[:120]
                ua_counts[ua_short] = ua_counts.get(ua_short, 0) + 1
                if L7_BOT_UA_PATTERNS.search(ua):
                    bot_request_count += 1

            # Threat pattern detection on path + query.
            # Fast-path: skip regex if path is short and has no suspicious chars.
            # This avoids 12 regex matches on clean paths like "/", "/index.html".
            full_path = path
            _lp = full_path.lower()
            if len(full_path) > 6 or "'" in _lp or "." in _lp or "$" in _lp or "<" in _lp or "(" in _lp or "/" in _lp[1:]:
                for pattern_name, pattern_re in L7_THREAT_PATTERNS.items():
                    if pattern_re.search(full_path):
                        threat_hits[pattern_name] = threat_hits.get(pattern_name, 0) + 1

            if resp_time is not None:
                resp_times.append(resp_time)

        error_count = status_counts.get("4xx", 0) + status_counts.get("5xx", 0)
        error_rate = (error_count / max(n, 1)) * 100

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:50]
        top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        top_uas = sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        avg_resp_ms = round(sum(resp_times) / len(resp_times), 1) if resp_times else None

        # Protocol version distribution as percentages
        version_total = sum(version_counts.values())
        protocol_versions = {}
        if version_total > 0:
            for ver, cnt in version_counts.items():
                protocol_versions[ver] = round(cnt / version_total * 100, 1)

        # RPS per unique IP (for concurrency-based H2 attack detection)
        rps_per_ip = rps / max(len(ip_counts), 1)

        return {
            "rps": round(rps, 1),
            "error_rate": round(error_rate, 1),
            "unique_ips": len(ip_counts),
            "total_requests": n,
            "top_paths": dict(top_paths),
            "top_ips": dict(top_ips),
            "status_codes": status_counts,
            "window_seconds": round(elapsed, 1),
            "top_user_agents": dict(top_uas),
            "threat_patterns": threat_hits,
            "bot_request_pct": round((bot_request_count / max(n, 1)) * 100, 1),
            "avg_response_ms": avg_resp_ms,
            "status_5xx": status_counts.get("5xx", 0),
            "status_4xx": status_counts.get("4xx", 0),
            "status_499": status_499_count,
            "protocol_versions": protocol_versions,
            "rps_per_ip": round(rps_per_ip, 1),
            "h2_pct": protocol_versions.get("2", 0.0),
            "h3_pct": protocol_versions.get("3", 0.0),
        }

    def check_attack(self, stats: dict) -> Optional[dict]:
        rps = stats["rps"]
        total = stats["total_requests"]
        unique_ips = stats.get("unique_ips", 0)
        error_rate = stats.get("error_rate", 0)

        # Need enough requests in the window to make a judgement
        if total < 15:
            if self._attack_active:
                self._accumulate_attack_stats(stats)
                return self._check_attack_end(stats)
            return None

        # Update baseline only when NOT under attack and traffic looks clean.
        # Skip baseline learning if error rate is very high (likely attack traffic
        # arriving during warmup) or RPS is already extreme.
        if not self._attack_active:
            is_clean = (error_rate < 60
                        and (self._baseline_samples < 3 or rps < self._baseline_rps * 10))
            if is_clean:
                if self._baseline_samples < 300:
                    alpha = 1 / (self._baseline_samples + 1)
                else:
                    alpha = 0.01
                self._baseline_rps = (1 - alpha) * self._baseline_rps + alpha * rps
                self._baseline_samples += 1

        signals = 0
        reasons = []
        warmup = self._baseline_samples < 10
        baseline_ready = self._baseline_samples >= 30

        # RPS threshold: use override if set, otherwise auto-calculate.
        # During warmup (< 10 samples), use a high floor to avoid false positives.
        # Once baseline is established (>= 30 samples), go purely data-driven.
        if self._rps_threshold_override:
            rps_threshold = self._rps_threshold_override
        elif warmup:
            # Not enough data yet -- use high absolute floor
            rps_threshold = 500
        elif baseline_ready:
            # Baseline established -- purely data-driven, no minimum floor
            mult = self._sensitivity_multiplier
            rps_threshold = self._baseline_rps * mult if self._baseline_rps > 1 else 100
        else:
            # Partial baseline -- use data but keep a modest floor
            mult = self._sensitivity_multiplier
            rps_threshold = max(self._baseline_rps * mult, self._min_rps) if self._baseline_rps > 5 else self._min_rps
        if rps > rps_threshold:
            signals += 2
            reasons.append(f"RPS spike: {rps:.0f} (threshold {rps_threshold:.0f})")

        if stats["top_ips"]:
            top_ip_name, top_ip_count = max(stats["top_ips"].items(), key=lambda x: x[1])
            ip_pct = top_ip_count / max(total, 1)
            if ip_pct > 0.3 and top_ip_count > 20:
                signals += 1
                reasons.append(f"IP concentration: {top_ip_name} = {ip_pct:.0%}")

        if stats["top_paths"]:
            top_path_name, top_path_count = max(stats["top_paths"].items(), key=lambda x: x[1])
            path_pct = top_path_count / max(total, 1)
            if path_pct > 0.6 and top_path_count > 30:
                signals += 1
                reasons.append(f"Path focus: {top_path_name} = {path_pct:.0%}")

        # Error rate anomaly (configurable threshold)
        err_threshold = self._error_rate_threshold
        if stats["error_rate"] > err_threshold and total > 20:
            signals += 1
            reasons.append(f"Error rate: {stats['error_rate']:.0f}% (threshold {err_threshold:.0f}%)")

        # 5xx spike: backend under stress (separate signal from general error rate)
        if stats.get("status_5xx", 0) > max(total * 0.3, 15):
            signals += 1
            reasons.append(f"5xx spike: {stats['status_5xx']} server errors")

        # High bot UA percentage
        bot_pct = stats.get("bot_request_pct", 0)
        if bot_pct > 70 and total > 30:
            signals += 1
            reasons.append(f"Bot traffic: {bot_pct:.0f}% from known bot UAs")

        # Threat pattern hits (SQLi, XSS, path traversal, etc.)
        threat_total = sum(stats.get("threat_patterns", {}).values())
        if threat_total > max(total * 0.2, 10):
            signals += 1
            top_threat = max(stats["threat_patterns"].items(), key=lambda x: x[1])[0] if stats.get("threat_patterns") else "unknown"
            reasons.append(f"Threat patterns: {threat_total} hits (top: {top_threat})")

        # Need at least 2 signals AND multiple source IPs (single IP = scanner, not flood)
        if signals >= 2 and unique_ips >= 3 and not self._attack_active:
            self._attack_active = True
            self._attack_start = time.monotonic()
            self._attack_peak_rps = rps
            self._below_count = 0
            self._reset_attack_accumulators()
            self._accumulate_attack_stats(stats)
            subtype = _classify_l7_subtype(stats)
            return {
                "type": "l7_flood",
                "attack_family": "http_flood",
                "attack_subtype": subtype,
                "rps": rps,
                "baseline_rps": round(self._baseline_rps, 1),
                "reasons": reasons,
                "stats": stats,
            }
        elif self._attack_active:
            if rps > self._attack_peak_rps:
                self._attack_peak_rps = rps
            self._accumulate_attack_stats(stats)
            return self._check_attack_end(stats)

        return None

    def _reset_attack_accumulators(self):
        """Reset accumulated attack-wide stats for a new incident."""
        self._attack_ua_counts = {}
        self._attack_threat_hits = {}
        self._attack_status_totals = {}
        self._attack_path_totals = {}
        self._attack_ip_totals = {}
        self._attack_total_requests = 0
        self._attack_version_totals = {}

    def _capped_merge(self, target: dict, source: dict) -> None:
        """Merge counts into target dict, ignoring new keys once cap is hit."""
        cap = self._MAX_ATTACK_KEYS
        for key, cnt in source.items():
            if key in target:
                target[key] += cnt
            elif len(target) < cap:
                target[key] = cnt

    def _accumulate_attack_stats(self, stats: dict):
        """Merge per-window stats into attack-wide accumulators."""
        self._attack_total_requests += stats.get("total_requests", 0)
        self._capped_merge(self._attack_ua_counts, stats.get("top_user_agents", {}))
        self._capped_merge(self._attack_threat_hits, stats.get("threat_patterns", {}))
        self._capped_merge(self._attack_status_totals, stats.get("status_codes", {}))
        self._capped_merge(self._attack_path_totals, stats.get("top_paths", {}))
        self._capped_merge(self._attack_ip_totals, stats.get("top_ips", {}))
        # Accumulate protocol version counts (convert percentages back to counts)
        pv = stats.get("protocol_versions", {})
        total = stats.get("total_requests", 0)
        if pv and total > 0:
            for ver, pct in pv.items():
                cnt = round(pct / 100 * total)
                self._attack_version_totals[ver] = self._attack_version_totals.get(ver, 0) + cnt

    def get_attack_summary(self) -> dict:
        """Return accumulated attack-wide data for incident enrichment."""
        top_uas = sorted(self._attack_ua_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        top_paths = sorted(self._attack_path_totals.items(), key=lambda x: x[1], reverse=True)[:20]
        top_ips = sorted(self._attack_ip_totals.items(), key=lambda x: x[1], reverse=True)[:50]
        # Protocol version distribution as percentages
        ver_total = sum(self._attack_version_totals.values())
        protocol_versions = {}
        if ver_total > 0:
            for ver, cnt in self._attack_version_totals.items():
                protocol_versions[ver] = round(cnt / ver_total * 100, 1)
        return {
            "top_user_agents": dict(top_uas),
            "threat_patterns": self._attack_threat_hits,
            "status_codes": self._attack_status_totals,
            "top_paths": dict(top_paths),
            "top_ips": dict(top_ips),
            "total_requests": self._attack_total_requests,
            "protocol_versions": protocol_versions,
        }

    def _check_attack_end(self, stats: dict) -> Optional[dict]:
        rps = stats["rps"]
        total = stats.get("total_requests", 0)
        error_rate = stats.get("error_rate", 0)
        elapsed = time.monotonic() - self._attack_start

        # Minimum 15s before allowing resolve to prevent rapid open/close flapping
        if elapsed < 15:
            return {"type": "l7_flood_update", "rps": rps, "peak_rps": self._attack_peak_rps, "stats": stats}

        # Resolve when traffic has clearly calmed down. Check multiple conditions:
        # 1. RPS dropped to low absolute level (under 50 RPS)
        # 2. OR error rate normalized AND RPS dropped significantly from peak
        # 3. OR very few requests in the window (traffic stopped)
        should_resolve = False
        if total < 10:
            should_resolve = True
        elif rps < 50:
            should_resolve = True
        elif rps < self._attack_peak_rps * 0.1 and error_rate < 30:
            should_resolve = True
        elif self._baseline_rps > 5 and rps < self._baseline_rps * 2 and error_rate < 30:
            should_resolve = True

        if should_resolve:
            self._below_count = getattr(self, '_below_count', 0) + 1
            if self._below_count >= 3:
                self._attack_active = False
                self._below_count = 0
                # Reset baseline so it relearns from clean traffic
                self._baseline_rps = max(rps, 1.0)
                self._baseline_samples = 1
                summary = self.get_attack_summary()
                subtype = _classify_l7_subtype(stats)
                return {
                    "type": "l7_flood_end",
                    "duration_seconds": round(elapsed, 1),
                    "peak_rps": round(self._attack_peak_rps, 1),
                    "attack_subtype": subtype,
                    "stats": stats,
                    "attack_summary": summary,
                }
            return {"type": "l7_flood_update", "rps": rps, "peak_rps": self._attack_peak_rps, "stats": stats}

        self._below_count = 0
        return {"type": "l7_flood_update", "rps": rps, "peak_rps": self._attack_peak_rps, "stats": stats}


# ---------------------------------------------------------------------------
# Attack Classifier
# ---------------------------------------------------------------------------

def classify_attack(tcp_pct: float, udp_pct: float, icmp_pct: float,
                    syn_ratio: float = 0.0, dns_detected: bool = False,
                    top_ports: list = None, tcp_flags: dict = None,
                    other_pct: float = 0.0,
                    fragment_pct: float = 0.0) -> str:
    # Fragment flood: overwhelmingly fragmented traffic is its own family
    if fragment_pct > 50:
        return "fragment_flood"
    if dns_detected:
        return "dns_flood"
    if udp_pct > 45:
        return "udp_flood"
    if tcp_pct > 45 and syn_ratio > 0.5:
        return "syn_flood"
    if icmp_pct > 30:
        return "icmp_flood"
    elevated = sum(1 for v in (tcp_pct, udp_pct, icmp_pct) if v > 15)
    if elevated >= 2:
        return "multi_vector"
    # GRE/ESP/IPIP/other protocol floods
    if other_pct > 30:
        return "protocol_flood"
    # Last resort: pick dominant protocol.
    if udp_pct >= tcp_pct and udp_pct >= icmp_pct and udp_pct > 5:
        return "udp_flood"
    if tcp_pct >= udp_pct and tcp_pct >= icmp_pct and tcp_pct > 5:
        if syn_ratio >= 0.3:
            return "syn_flood"
        return "tcp_flood"
    if icmp_pct > 5:
        return "icmp_flood"
    # Try harder: classify by whichever protocol is non-zero
    if tcp_pct > 0 or udp_pct > 0 or icmp_pct > 0 or other_pct > 0:
        dominant = max(
            ("tcp_flood", tcp_pct), ("udp_flood", udp_pct),
            ("icmp_flood", icmp_pct), ("protocol_flood", other_pct),
            key=lambda x: x[1],
        )
        return dominant[0]
    return "unknown"


def classify_subtype(family: str, top_ports: list = None,
                     tcp_flags: dict = None, avg_pkt_len: int = 0,
                     src_ports: list = None, fragment_pct: float = 0.0) -> str:
    """Derive attack subtype from port/flag/size evidence."""
    ports = top_ports or []
    top_port = 0
    if ports:
        entry = ports[0]
        top_port = entry.get("port", 0) if isinstance(entry, dict) else int(entry)

    # Source ports for amplification detection (reflectors respond FROM known ports)
    _src_ports = src_ports or []
    top_src_port = 0
    if _src_ports:
        entry = _src_ports[0]
        top_src_port = entry.get("port", 0) if isinstance(entry, dict) else int(entry)

    # ── Unknown/empty family: still try to classify from available evidence ──
    if not family or family == "unknown":
        if tcp_flags:
            tcp_sub = classify_tcp_subtype(tcp_flags)
            if tcp_sub:
                return tcp_sub
        if top_port or top_src_port:
            # Check for amplification by source port
            _amp_ports = {53: "dns_amplification", 123: "ntp_amplification",
                          1900: "ssdp_amplification", 11211: "memcached_amplification",
                          389: "cldap_amplification", 19: "chargen_amplification",
                          161: "snmp_amplification", 3702: "wsd_amplification",
                          5353: "mdns_amplification", 1194: "openvpn_amplification",
                          3283: "apple_remote_amplification", 3389: "rdp_amplification"}
            if top_src_port in _amp_ports:
                return _amp_ports[top_src_port]
            if top_port in _amp_ports:
                return _amp_ports[top_port]
        return ""

    # ── UDP subtypes ──
    if family == "udp_flood":
        # Fragment flood: high percentage of IP fragments indicates fragmentation attack
        if fragment_pct > 30:
            return "udp_fragment_flood"
        # QUIC flood: UDP port 443 is used by HTTP/3 over QUIC
        if top_port == 443:
            return "quic_flood"
        _amp_ports = {53: "dns_amplification", 123: "ntp_amplification",
                      1900: "ssdp_amplification", 11211: "memcached_amplification",
                      389: "cldap_amplification", 19: "chargen_amplification",
                      161: "snmp_amplification", 3702: "wsd_amplification",
                      5353: "mdns_amplification", 1194: "openvpn_amplification",
                      3283: "apple_remote_amplification", 3389: "rdp_amplification"}
        # Check source ports first (amplification comes FROM reflector ports)
        if top_src_port in _amp_ports:
            return _amp_ports[top_src_port]
        if top_port in _amp_ports:
            return _amp_ports[top_port]
        if avg_pkt_len > 0 and avg_pkt_len < 100:
            return "small_packet_flood"
        if avg_pkt_len > 1200:
            return "amplification_generic"
        return "volumetric"

    # ── TCP subtypes (beyond SYN flood) ──
    if family == "syn_flood":
        # Distinguish SYN vs SYN-ACK flood using flags
        if tcp_flags:
            total = sum(tcp_flags.values())
            if total > 0:
                syn_r = tcp_flags.get("SYN", 0) / total
                ack_r = tcp_flags.get("ACK", 0) / total
                if syn_r > 0.3 and ack_r > 0.3:
                    return "syn_ack_flood"
        return "syn_flood"

    # ── TCP flood (non-SYN dominant TCP) ──
    if family == "tcp_flood":
        if tcp_flags:
            return classify_tcp_subtype(tcp_flags) or "tcp_generic"
        return "tcp_generic"

    # ── Multi-vector: identify dominant component ──
    if family == "multi_vector":
        if tcp_flags:
            tcp_sub = classify_tcp_subtype(tcp_flags)
            if tcp_sub:
                return "multi_" + tcp_sub
        # Check for amplification component via source ports
        _amp_ports = {53: "dns_amplification", 123: "ntp_amplification",
                      1900: "ssdp_amplification"}
        if top_src_port in _amp_ports:
            return "multi_" + _amp_ports[top_src_port]
        if top_port in _amp_ports:
            return "multi_" + _amp_ports[top_port]
        return "multi_mixed"

    # ── DNS subtypes ──
    if family == "dns_flood":
        if top_port == 53 and avg_pkt_len > 512:
            return "dns_amplification"
        if top_src_port == 53 and avg_pkt_len > 512:
            return "dns_amplification"
        return "dns_query_flood"

    # ── ICMP subtypes ──
    if family == "icmp_flood":
        if avg_pkt_len > 1000:
            return "ping_of_death"
        return "ping_flood"

    # ── Protocol flood (GRE/ESP/IPIP) ──
    if family == "protocol_flood":
        # Without deep protocol inspection, classify by common protocol floods
        if tcp_flags:
            return classify_tcp_subtype(tcp_flags) or "gre_flood"
        return "gre_flood"

    # ── Fragment flood ──
    if family == "fragment_flood":
        return "ip_fragment_flood"

    return ""


def classify_tcp_subtype(tcp_flags: dict) -> str:
    """Classify TCP attack subtype from flag distribution.
    Only called when tcp_pct is dominant but SYN ratio is below flood threshold."""
    if not tcp_flags:
        return ""
    total = sum(tcp_flags.values())
    if total == 0:
        return ""
    syn_r = tcp_flags.get("SYN", 0) / total
    ack_r = tcp_flags.get("ACK", 0) / total
    rst_r = tcp_flags.get("RST", 0) / total
    fin_r = tcp_flags.get("FIN", 0) / total
    psh_r = tcp_flags.get("PSH", 0) / total
    urg_r = tcp_flags.get("URG", 0) / total

    # XMAS flood: FIN+PSH+URG all elevated
    if fin_r > 0.15 and psh_r > 0.15 and urg_r > 0.15:
        return "xmas_flood"
    # NULL flood: all flag ratios near zero but packets exist
    if total > 0 and syn_r < 0.05 and ack_r < 0.05 and rst_r < 0.05 and fin_r < 0.05 and psh_r < 0.05:
        return "null_flood"
    # SYN-ACK flood: both SYN and ACK high
    if syn_r > 0.3 and ack_r > 0.3:
        return "syn_ack_flood"
    if rst_r > 0.4:
        return "rst_flood"
    if fin_r > 0.4:
        return "fin_flood"
    if ack_r > 0.6 and syn_r < 0.1:
        return "ack_flood"
    if psh_r > 0.4 and ack_r > 0.3:
        return "psh_ack_flood"
    # Fallback: if flags have data, return tcp_generic
    return "tcp_generic"


def enrich_from_ioc(ioc_hits: list, family: str, subtype: str) -> tuple:
    """Enrich family/subtype/tool from IOC pattern matches.
    Returns (family, subtype, attack_tool, confidence_boost)."""
    if not ioc_hits:
        return family, subtype, None, 0

    # Count occurrences of each IOC pattern
    hit_counts = {}
    for hit in ioc_hits:
        hit_counts[hit] = hit_counts.get(hit, 0) + 1

    # Get the most frequent IOC hit
    top_hit = max(hit_counts, key=hit_counts.get)
    top_count = hit_counts[top_hit]

    # Parse "Name:family" format
    parts = top_hit.split(":", 1)
    ioc_name = parts[0].strip().lower()
    ioc_family = parts[1].strip() if len(parts) > 1 else ""

    attack_tool = None
    confidence_boost = min(top_count, 30)  # Up to +30 confidence from IOC matches

    # Map IOC names to tools and subtypes
    tool_map = {
        "mirai": ("mirai_botnet", "Mirai"),
        "gafgyt": ("gafgyt_botnet", "Gafgyt"),
        "bashlite": ("gafgyt_botnet", "Bashlite"),
        "mozi": ("mozi_botnet", "Mozi"),
        "xorddos": ("xorddos_botnet", "XorDDoS"),
        "muhstik": ("muhstik_botnet", "Muhstik"),
        "tsunami": ("tsunami_botnet", "Tsunami/Kaiten"),
        "kaiten": ("tsunami_botnet", "Kaiten"),
        "hajime": ("hajime_botnet", "Hajime"),
        "meris": ("meris_botnet", "Meris"),
        "mantis": ("mantis_botnet", "Mantis"),
        "fodcha": ("fodcha_botnet", "Fodcha"),
        "loic": ("loic", "LOIC"),
        "hoic": ("hoic", "HOIC"),
        "mhddos": ("mhddos", "MHDDoS"),
        "slowloris": ("slowloris", "Slowloris"),
        "goldeneye": ("goldeneye", "GoldenEye"),
        "hulk": ("hulk", "HULK"),
        "xerxes": ("xerxes", "Xerxes"),
        "hping": ("hping", "hping"),
        "rudy": ("rudy", "R.U.D.Y."),
        "ntp monlist": ("ntp_amplification", None),
        "ssdp": ("ssdp_amplification", None),
        "memcached": ("memcached_amplification", None),
        "cldap": ("cldap_amplification", None),
        "chargen": ("chargen_amplification", None),
        "dns amplification": ("dns_amplification", None),
        "stresser": ("booter_service", None),
        "booter": ("booter_service", None),
    }

    for keyword, (mapped_subtype, tool) in tool_map.items():
        if keyword in ioc_name:
            if not subtype or subtype in ("volumetric", "syn_flood", "ping_flood", "tcp_generic"):
                subtype = mapped_subtype
            attack_tool = tool
            break

    # If IOC specified a family and ours is generic, prefer the IOC's
    if ioc_family and ioc_family != "unknown" and family in ("unknown", ""):
        family = ioc_family

    return family, subtype, attack_tool, confidence_boost


# ---------------------------------------------------------------------------
# Health Check Server
# ---------------------------------------------------------------------------

class HealthCheckHandler:
    """Minimal HTTP health endpoint on localhost."""

    def __init__(self, agent, port: int = 9100):
        self._agent = agent
        self._port = port
        self._server = None

    def start(self) -> None:
        from http.server import HTTPServer, BaseHTTPRequestHandler

        agent_ref = self._agent

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = json.dumps({
                    "status": "ok",
                    "version": VERSION,
                    "uptime_seconds": round(time.monotonic() - agent_ref._start_mono, 1),
                    "interface": agent_ref.monitor.interface,
                    "current_pps": round(agent_ref.monitor.pps, 1),
                    "current_bps": round(agent_ref.monitor.bps, 1),
                    "baseline_ready": agent_ref.baseline.baseline_ready,
                    "attack_active": agent_ref.attacking,
                    "incident_uuid": agent_ref.incident_uuid or None,
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                # Suppress default stderr logging
                pass

        try:
            self._server = HTTPServer(("127.0.0.1", self._port), _Handler)
            logger.info("Health check listening on 127.0.0.1:%d", self._port)
            self._server.serve_forever()
        except OSError as exc:
            logger.warning("Health check server failed to start on port %d: %s",
                           self._port, exc)


# ---------------------------------------------------------------------------
# Service Port Detection Engine
# ---------------------------------------------------------------------------

class ServicePortDetector:
    """Port-aware traffic classification and on-node blocking.

    Sets up iptables accounting chains to split inbound traffic into
    service-port and non-service-port streams. Detects threshold crossings
    on non-service traffic, identifies offending source IPs, and deploys
    surgical firewall blocks.
    """

    CHAIN_ACCOUNT = "FT_SP_ACCOUNT"
    CHAIN_BLOCK   = "FT_SP_BLOCK"

    def __init__(self):
        self._lock = threading.RLock()
        self.enabled = False
        self.ports: list = []           # [{"protocol":"tcp","port_value":"80,443"}]
        self.sensitivity = "standard"
        self.pps_threshold = 100
        self.response_mode = "full"     # monitor, onnode, pipeline, full
        self.block_cooldown = 300       # seconds
        self.block_scope = "non_service"
        self._rules_installed = False
        self._block_rules: dict = {}    # {source_ip: expires_at_monotonic}
        self._prev_service_pkts = 0
        self._prev_non_service_pkts = 0
        self._prev_service_bytes = 0
        self._prev_non_service_bytes = 0
        self._last_read: float = 0.0
        self.service_pps = 0
        self.service_bps = 0
        self.non_service_pps = 0
        self.non_service_bps = 0
        self.blocked_pps = 0
        self._prev_blocked_pkts = 0
        self._attacking = False
        self._sp_below_count = 0  # hysteresis: require N ticks below threshold
        self._attack_sources: list = []
        self._config_version = ""
        self.ip_safelist: set = set()
        self._auto_safelist: set = set()  # auto-detected: localhost, own IPs
        self.min_block_pps = 10  # minimum PPS from a source before blocking

    def detect_local_ips(self) -> None:
        """Detect local IPs and add to auto-safelist. Called once on startup."""
        import subprocess
        safe = {"127.0.0.1", "127.0.0.53"}  # always protect localhost
        try:
            r = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("inet "):
                        # "inet 192.168.1.5/24 brd ..."
                        addr_cidr = line.split()[1]
                        ip = addr_cidr.split("/")[0]
                        safe.add(ip)
                        # Also add /24 subnet neighbors
                        parts = ip.split(".")
                        if len(parts) == 4:
                            prefix = ".".join(parts[:3]) + "."
                            for i in range(256):
                                safe.add(prefix + str(i))
        except Exception as e:
            logger.debug("Auto-safelist IP detection: %s", e)
        self._auto_safelist = safe
        if safe:
            logger.info("Auto-safelist: %d local IPs/subnet IPs protected",
                        len(safe))

    def configure(self, sp_cfg: dict) -> None:
        """Apply config from server. Rebuilds accounting rules if ports changed."""
        with self._lock:
            if not sp_cfg or not sp_cfg.get("enabled"):
                if self.enabled:
                    self.cleanup()
                    self.enabled = False
                return

            new_version = self._cfg_hash(sp_cfg)
            was_enabled = self.enabled

            self.enabled = True
            self.ports = sp_cfg.get("ports", [])
            self.sensitivity = sp_cfg.get("sensitivity", "standard")
            self.pps_threshold = max(1, int(sp_cfg.get("pps_threshold", 100)))
            self.response_mode = sp_cfg.get("response_mode", "full")
            self.block_cooldown = max(60, int(sp_cfg.get("block_cooldown", 300)))
            self.block_scope = sp_cfg.get("block_scope", "non_service")
            self.ip_safelist = set(sp_cfg.get("ip_safelist", []))

            if new_version != self._config_version:
                logger.info("Service ports config changed, rebuilding accounting rules")
                self._teardown_accounting()
                self._setup_accounting()
                self._config_version = new_version
            elif not self._rules_installed:
                self._setup_accounting()
                self._config_version = new_version

    def _cfg_hash(self, cfg: dict) -> str:
        """Hash the port config to detect changes."""
        import hashlib
        raw = json.dumps(cfg.get("ports", []), sort_keys=True)
        return hashlib.md5(raw.encode()).hexdigest()

    def _build_port_match(self) -> list:
        """Build iptables multiport match args from port entries.
        Returns list of (protocol, ports_csv) tuples.
        Splits into multiple rules if > 15 port entries (iptables multiport limit)."""
        tcp_ports = []
        udp_ports = []
        for entry in self.ports:
            proto = entry.get("protocol", "both")
            val = str(entry.get("port_value", "")).strip()
            if not val:
                continue
            if proto in ("tcp", "both"):
                tcp_ports.extend(p.strip() for p in val.split(",") if p.strip())
            if proto in ("udp", "both"):
                udp_ports.extend(p.strip() for p in val.split(",") if p.strip())

        result = []
        # iptables multiport allows max 15 port entries per rule; split into chunks
        for proto, ports in [("tcp", tcp_ports), ("udp", udp_ports)]:
            for i in range(0, len(ports), 15):
                chunk = ports[i:i+15]
                if chunk:
                    result.append((proto, ",".join(chunk)))
        return result

    def _run_ipt(self, args: list, check: bool = False) -> bool:
        """Run an iptables command. Returns True on success."""
        import subprocess
        cmd = ["iptables"] + args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if check and r.returncode != 0:
                return False
            return r.returncode == 0
        except Exception as e:
            logger.debug("iptables %s failed: %s", " ".join(args), e)
            return False

    def _input_has_jump(self, chain: str) -> bool:
        """Check if INPUT already has a jump to the given chain."""
        import subprocess
        try:
            r = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if chain in line:
                        return True
        except Exception:
            pass
        return False

    def _setup_accounting(self) -> None:
        """Install iptables accounting chains for traffic splitting."""
        if not self.ports:
            logger.warning("Service ports: no ports configured, skipping setup")
            return

        # Clean up any stale rules first to prevent duplicate jumps
        self.cleanup_stale()

        # Create chains
        self._run_ipt(["-N", self.CHAIN_ACCOUNT])
        self._run_ipt(["-N", self.CHAIN_BLOCK])

        # Flush any existing rules
        self._run_ipt(["-F", self.CHAIN_ACCOUNT])
        self._run_ipt(["-F", self.CHAIN_BLOCK])

        # Insert jumps only if not already present (prevents duplicates on restart)
        if not self._input_has_jump(self.CHAIN_BLOCK):
            self._run_ipt(["-I", "INPUT", "1", "-j", self.CHAIN_BLOCK])
        if not self._input_has_jump(self.CHAIN_ACCOUNT):
            self._run_ipt(["-I", "INPUT", "2", "-j", self.CHAIN_ACCOUNT])

        # Accounting rules: match service ports (just count, no action)
        port_matches = self._build_port_match()
        if not port_matches:
            logger.error("Service ports: no valid port matches built, aborting setup")
            # Remove the jumps we just added to avoid empty chains catching all traffic
            self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_BLOCK])
            self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_ACCOUNT])
            self._run_ipt(["-F", self.CHAIN_ACCOUNT])
            self._run_ipt(["-X", self.CHAIN_ACCOUNT])
            self._run_ipt(["-F", self.CHAIN_BLOCK])
            self._run_ipt(["-X", self.CHAIN_BLOCK])
            return

        # Batch all accounting rules into a single iptables-restore call
        # instead of spawning one subprocess per rule
        restore_lines = ["*filter"]
        for proto, ports in port_matches:
            restore_lines.append(
                f"-A {self.CHAIN_ACCOUNT} -p {proto} -m multiport"
                f" --dports {ports} -m comment --comment ft_sp_service"
                f" -j RETURN"
            )
        # Non-service traffic counter: everything that didn't match above
        restore_lines.append(
            f"-A {self.CHAIN_ACCOUNT} -m comment"
            f" --comment ft_sp_non_service -j RETURN"
        )
        restore_lines.append("COMMIT\n")

        import subprocess
        try:
            r = subprocess.run(
                ["iptables-restore", "--noflush"],
                input="\n".join(restore_lines),
                capture_output=True, text=True, timeout=15)
            if r.returncode != 0:
                logger.error("Service ports: iptables-restore failed: %s",
                             r.stderr.strip())
                # Fallback: try individual rule installation
                rules_ok = True
                for proto, ports in port_matches:
                    if not self._run_ipt([
                        "-A", self.CHAIN_ACCOUNT,
                        "-p", proto, "-m", "multiport", "--dports", ports,
                        "-m", "comment", "--comment", "ft_sp_service",
                        "-j", "RETURN",
                    ]):
                        rules_ok = False
                if not rules_ok:
                    logger.error("Service ports: rule install failed, rolling back")
                    self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_BLOCK])
                    self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_ACCOUNT])
                    self._run_ipt(["-F", self.CHAIN_ACCOUNT])
                    self._run_ipt(["-X", self.CHAIN_ACCOUNT])
                    self._run_ipt(["-F", self.CHAIN_BLOCK])
                    self._run_ipt(["-X", self.CHAIN_BLOCK])
                    return
                self._run_ipt([
                    "-A", self.CHAIN_ACCOUNT,
                    "-m", "comment", "--comment", "ft_sp_non_service",
                    "-j", "RETURN",
                ])
        except FileNotFoundError:
            logger.warning("iptables-restore not found, falling back to per-rule install")
            for proto, ports in port_matches:
                self._run_ipt([
                    "-A", self.CHAIN_ACCOUNT,
                    "-p", proto, "-m", "multiport", "--dports", ports,
                    "-m", "comment", "--comment", "ft_sp_service",
                    "-j", "RETURN",
                ])
            self._run_ipt([
                "-A", self.CHAIN_ACCOUNT,
                "-m", "comment", "--comment", "ft_sp_non_service",
                "-j", "RETURN",
            ])
        except subprocess.TimeoutExpired:
            logger.error("Service ports: iptables-restore timed out, rolling back")
            self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_BLOCK])
            self._run_ipt(["-D", "INPUT", "-j", self.CHAIN_ACCOUNT])
            self._run_ipt(["-F", self.CHAIN_ACCOUNT])
            self._run_ipt(["-X", self.CHAIN_ACCOUNT])
            self._run_ipt(["-F", self.CHAIN_BLOCK])
            self._run_ipt(["-X", self.CHAIN_BLOCK])
            return

        self._rules_installed = True
        self._reset_counters()
        logger.info("Service port accounting installed: %d port entries",
                     len(self.ports))

    def _teardown_accounting(self) -> None:
        """Remove accounting chains from INPUT."""
        if not self._rules_installed:
            return
        # Remove ALL jump rules from INPUT (loop to catch duplicates from past bugs)
        for chain in [self.CHAIN_BLOCK, self.CHAIN_ACCOUNT]:
            for _ in range(5):  # Remove up to 5 duplicates
                if not self._run_ipt(["-D", "INPUT", "-j", chain]):
                    break
        # Flush and delete chains
        self._run_ipt(["-F", self.CHAIN_ACCOUNT])
        self._run_ipt(["-X", self.CHAIN_ACCOUNT])
        self._run_ipt(["-F", self.CHAIN_BLOCK])
        self._run_ipt(["-X", self.CHAIN_BLOCK])
        self._rules_installed = False
        logger.info("Service port accounting removed")

    def _reset_counters(self) -> None:
        """Reset baseline counters after rule setup."""
        self._prev_service_pkts = 0
        self._prev_non_service_pkts = 0
        self._prev_service_bytes = 0
        self._prev_non_service_bytes = 0
        self._prev_blocked_pkts = 0
        self._last_read = time.monotonic()
        # Zero the iptables counters
        self._run_ipt(["-Z", self.CHAIN_ACCOUNT])
        self._run_ipt(["-Z", self.CHAIN_BLOCK])

    def read_counters(self) -> bool:
        """Read iptables packet/byte counters for service vs non-service traffic.
        Returns True if counters were read successfully."""
        with self._lock:
            if not self._rules_installed:
                return False

            import subprocess
            now = time.monotonic()
            dt = now - self._last_read
            if dt < 5.0:
                return False
            self._last_read = now

            try:
                result = subprocess.run(
                    ["iptables", "-L", self.CHAIN_ACCOUNT, "-nvx"],
                    capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    return False

                lines = result.stdout.strip().split("\n")
                service_pkts = 0
                service_bytes = 0
                non_service_pkts = 0
                non_service_bytes = 0

                for line in lines:
                    if "ft_sp_service" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            service_pkts += int(parts[0])
                            service_bytes += int(parts[1])
                    elif "ft_sp_non_service" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            non_service_pkts += int(parts[0])
                            non_service_bytes += int(parts[1])

                # Calculate rates
                self.service_pps = max(0, round((service_pkts - self._prev_service_pkts) / dt))
                self.service_bps = max(0, round((service_bytes - self._prev_service_bytes) * 8 / dt))
                self.non_service_pps = max(0, round((non_service_pkts - self._prev_non_service_pkts) / dt))
                self.non_service_bps = max(0, round((non_service_bytes - self._prev_non_service_bytes) * 8 / dt))

                self._prev_service_pkts = service_pkts
                self._prev_non_service_pkts = non_service_pkts
                self._prev_service_bytes = service_bytes
                self._prev_non_service_bytes = non_service_bytes

                # Read blocked counter
                try:
                    br = subprocess.run(
                        ["iptables", "-L", self.CHAIN_BLOCK, "-nvx"],
                        capture_output=True, text=True, timeout=5)
                    if br.returncode == 0:
                        blocked_total = 0
                        for bline in br.stdout.strip().split("\n"):
                            if "ft_sp_block" in bline:
                                bparts = bline.split()
                                if len(bparts) >= 1:
                                    blocked_total += int(bparts[0])
                        self.blocked_pps = max(0, round((blocked_total - self._prev_blocked_pkts) / dt))
                        self._prev_blocked_pkts = blocked_total
                except Exception:
                    pass

                return True

            except Exception as e:
                logger.debug("Service port counter read failed: %s", e)
                return False

    def check_threshold(self) -> bool:
        """Check if non-service traffic exceeds the threshold.
        Returns True if threshold is crossed."""
        return self.non_service_pps > self.pps_threshold

    def identify_sources(self) -> list:
        """Identify top source IPs responsible for non-service traffic.
        Uses conntrack or ss to find active connections to non-service ports."""
        import subprocess

        # Build a set of service ports for filtering + combined safelist
        with self._lock:
            ports_snapshot = list(self.ports)
            safelist_snapshot = self.ip_safelist | self._auto_safelist

        service_ports = set()
        for entry in ports_snapshot:
            val = str(entry.get("port_value", ""))
            for part in val.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        lo, hi = part.split("-", 1)
                        for p in range(int(lo), int(hi) + 1):
                            service_ports.add(p)
                    except ValueError:
                        pass
                elif part.isdigit():
                    service_ports.add(int(part))

        sources: dict = {}  # {ip: {"pps": approx_count, "ports": set()}}

        # Try conntrack first (most accurate for active connections)
        # Use short timeouts to avoid blocking the main detection loop
        try:
            r = subprocess.run(
                ["conntrack", "-L", "-o", "extended", "--src-nat"],
                capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                # Fallback: try without --src-nat
                r = subprocess.run(
                    ["conntrack", "-L", "-o", "extended"],
                    capture_output=True, text=True, timeout=3)

            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    # Parse: tcp 6 ... src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=22
                    dport_match = re.search(r'dport=(\d+)', line)
                    src_match = re.search(r'src=(\d+\.\d+\.\d+\.\d+)', line)
                    if dport_match and src_match:
                        dport = int(dport_match.group(1))
                        src_ip = src_match.group(1)
                        if dport not in service_ports:
                            if src_ip not in sources:
                                sources[src_ip] = {"pps": 0, "ports": set()}
                            sources[src_ip]["pps"] += 1
                            sources[src_ip]["ports"].add(dport)
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug("conntrack source identification failed: %s", e)

        # Fallback to ss if conntrack gave nothing
        if not sources:
            try:
                r = subprocess.run(
                    ["ss", "-ntu", "state", "established"],
                    capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    for line in r.stdout.splitlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 5:
                            local_addr = parts[3]
                            peer_addr = parts[4]
                            # Parse local port
                            lport_str = local_addr.rsplit(":", 1)[-1]
                            if lport_str.isdigit():
                                lport = int(lport_str)
                                if lport not in service_ports:
                                    peer_ip = peer_addr.rsplit(":", 1)[0]
                                    if peer_ip not in sources:
                                        sources[peer_ip] = {"pps": 0, "ports": set()}
                                    sources[peer_ip]["pps"] += 1
                                    sources[peer_ip]["ports"].add(lport)
            except Exception as e:
                logger.debug("ss source identification failed: %s", e)

        # Remove safelisted IPs before ranking
        for safe_ip in safelist_snapshot:
            sources.pop(safe_ip, None)

        # Sort by connection count descending, take top 50
        top = sorted(sources.items(), key=lambda x: x[1]["pps"], reverse=True)[:50]

        result = []
        for ip, data in top:
            result.append({
                "ip": ip,
                "pps": data["pps"],
                "ports": sorted(data["ports"])[:20],
            })
        self._attack_sources = result
        return result

    MAX_ACTIVE_BLOCKS = 200  # Safety cap: never exceed this many active blocks

    def deploy_blocks(self, sources: list) -> list:
        """Deploy on-node iptables blocks against offending source IPs.
        Returns list of source dicts that were actually blocked."""
        with self._lock:
            if self.response_mode == "pipeline":
                return []

            blocked = []
            now = time.monotonic()
            expires = now + self.block_cooldown

            # Safety cap: don't add blocks if we're already at the limit
            remaining_capacity = max(0, self.MAX_ACTIVE_BLOCKS - len(self._block_rules))
            if remaining_capacity == 0:
                logger.warning("Service port blocks at capacity (%d), skipping new blocks",
                               self.MAX_ACTIVE_BLOCKS)
                return []

            for src in sources[:min(50, remaining_capacity)]:
                ip = src.get("ip", "")
                if not ip or ip in self._block_rules:
                    continue
                # Never block safelisted or local IPs
                if ip in self.ip_safelist or ip in self._auto_safelist:
                    logger.info("Service port block skipped (safelisted): %s", ip)
                    continue
                # Require minimum PPS before blocking (don't block 1-2 PPS noise)
                src_pps = src.get("pps", 0)
                if src_pps < self.min_block_pps:
                    logger.debug("Service port block skipped (pps=%d < min %d): %s",
                                 src_pps, self.min_block_pps, ip)
                    continue

                if self.block_scope == "non_service":
                    # Block only non-service ports: drop packets from this IP
                    # that don't match service ports
                    port_matches = self._build_port_match()
                    # First, allow service port traffic from this IP
                    for proto, ports in port_matches:
                        self._run_ipt([
                            "-I", self.CHAIN_BLOCK, "1",
                            "-s", ip, "-p", proto,
                            "-m", "multiport", "--dports", ports,
                            "-m", "comment", "--comment", f"ft_sp_block_allow_{ip}",
                            "-j", "RETURN",
                        ])
                    # Then drop everything else from this IP
                    self._run_ipt([
                        "-A", self.CHAIN_BLOCK,
                        "-s", ip,
                        "-m", "comment", "--comment", f"ft_sp_block_{ip}",
                        "-j", "DROP",
                    ])
                else:
                    # Full IP block
                    self._run_ipt([
                        "-A", self.CHAIN_BLOCK,
                        "-s", ip,
                        "-m", "comment", "--comment", f"ft_sp_block_{ip}",
                        "-j", "DROP",
                    ])

                self._block_rules[ip] = expires
                blocked.append(src)
                logger.info("Service port block: %s (scope=%s, cooldown=%ds)",
                            ip, self.block_scope, self.block_cooldown)

            return blocked

    def expire_blocks(self) -> int:
        """Remove expired block rules. Returns number removed."""
        with self._lock:
            import subprocess
            now = time.monotonic()
            expired = set()
            for ip, exp_time in list(self._block_rules.items()):
                if now >= exp_time:
                    expired.add(ip)

            if not expired:
                return 0

            # Single iptables call to list all rules, then batch-delete
            try:
                r = subprocess.run(
                    ["iptables", "-L", self.CHAIN_BLOCK, "-n", "--line-numbers"],
                    capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    to_delete = []
                    for line in r.stdout.strip().split("\n"):
                        for ip in expired:
                            # Use exact comment match to avoid substring collisions
                            # (e.g. 1.2.3.4 matching 1.2.3.40)
                            if (f"ft_sp_block_{ip} " in line
                                    or f"ft_sp_block_allow_{ip} " in line
                                    or line.endswith(f"ft_sp_block_{ip}")
                                    or line.endswith(f"ft_sp_block_allow_{ip}")):
                                num = line.split()[0]
                                if num.isdigit():
                                    to_delete.append(int(num))
                                break
                    # Delete in reverse order so line numbers don't shift
                    for num in sorted(to_delete, reverse=True):
                        self._run_ipt(["-D", self.CHAIN_BLOCK, str(num)])
            except Exception as e:
                logger.debug("Block expiry rule cleanup: %s", e)

            for ip in expired:
                del self._block_rules[ip]
                logger.info("Service port block expired: %s", ip)

            return len(expired)

    def cleanup(self) -> None:
        """Remove all accounting and block rules. Called on shutdown/disable."""
        with self._lock:
            if self._rules_installed:
                self._teardown_accounting()
            self._block_rules.clear()
            self._attacking = False
            logger.info("Service port detector cleaned up")

    def cleanup_stale(self) -> None:
        """Check for and remove stale rules from previous runs."""
        import subprocess
        try:
            r = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                lines = r.stdout.strip().split("\n")
                for line in reversed(lines):
                    if self.CHAIN_ACCOUNT in line or self.CHAIN_BLOCK in line:
                        num = line.split()[0]
                        if num.isdigit():
                            self._run_ipt(["-D", "INPUT", num])
                            logger.info("Removed stale INPUT jump to %s (rule #%s)",
                                        self.CHAIN_ACCOUNT if self.CHAIN_ACCOUNT in line else self.CHAIN_BLOCK, num)
            # Try to flush and remove stale chains
            for chain in [self.CHAIN_ACCOUNT, self.CHAIN_BLOCK]:
                self._run_ipt(["-F", chain])
                self._run_ipt(["-X", chain])
        except Exception as e:
            logger.debug("Stale rule cleanup: %s", e)


# ---------------------------------------------------------------------------
# Agent Core
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.shutdown = threading.Event()
        self.api = APIClient(cfg)
        self.monitor = PPSMonitor(cfg.get("interface", "auto"))
        self.baseline = BaselineManager(
            window=cfg.get("baseline_window", 300))
        self.analyser = TrafficAnalyser()
        self.ioc_matcher = IOCMatcher()
        self.ip_blocklist: set = set()  # threat intel IPs from server

        # GRE deduplication (Feature 1)
        self.gre_decap = GREDecapsulator(
            max_depth=cfg.get("gre_max_depth", 3))
        gre_mode = cfg.get("gre_mode", "auto")
        if gre_mode == "enabled":
            self.gre_decap.enabled = True
            logger.info("GRE deduplication: enabled (forced via config)")
        elif gre_mode == "auto":
            # Auto-detect: check if monitored interface is a GRE tunnel
            if detect_gre_interface(self.monitor.interface):
                self.gre_decap.enabled = True
                logger.info("GRE deduplication: auto-enabled (interface %s is a GRE tunnel)",
                            self.monitor.interface)
            else:
                logger.debug("GRE deduplication: auto — interface %s is not GRE, disabled",
                             self.monitor.interface)
        else:
            logger.debug("GRE deduplication: disabled via config")

        # Hypervisor mode — per-VM tracking (Feature 2)
        self.hypervisor_mode = bool(cfg.get("hypervisor_mode", False))
        self.vm_labels: dict = cfg.get("vm_labels", {})
        if self.hypervisor_mode:
            logger.info("Hypervisor mode enabled — per-VM inner IP tracking active")

        self.pcap = PcapCapture(
            cfg, self.monitor.interface, self.analyser, self.ioc_matcher,
            gre_decap=self.gre_decap, hypervisor_mode=self.hypervisor_mode)

        # Flow collector (sFlow/NetFlow/IPFIX)
        self.flow: Optional[FlowCollector] = None
        if cfg.get("flow_enabled"):
            self.flow = FlowCollector(cfg)

        # L7 monitoring (configured via server config)
        self.l7: Optional[L7Monitor] = None
        self.l7_enabled = False
        self.l7_thread_running = False
        self.l7_incident_uuid = ""
        self.l7_last_metric_push: float = 0.0

        # Service Port Detection
        self.sp_detector = ServicePortDetector()
        self.sp_detector.detect_local_ips()
        self._sp_last_metrics_push: float = 0.0
        self._sp_metrics_interval = 5  # push split metrics every 5s

        self.attacking = False
        self.attack_start: float = 0.0
        self.incident_uuid: str = ""
        self.peak_pps: float = 0.0
        self.peak_bps: float = 0.0
        self.below_count: int = 0
        self._last_attack_end: float = 0.0
        self._attack_cooldown: float = 60.0  # suppress re-detection for 60s after attack ends
        self.velocity_curve: list = []
        self._MAX_VELOCITY_POINTS = 2000
        self.last_update: float = 0.0
        self.server_threshold: float | None = None

        # Metrics batching: buffer locally, POST every N seconds
        self._metrics_interval = 5  # seconds between API POSTs
        self._metrics_buffer: list = []
        self._last_metrics_push: float = 0.0
        self._start_mono: float = time.monotonic()

        # Startup grace period: suppress attack detection for the first 90 seconds
        # so the baseline has time to warm up. Without this, normal traffic spikes
        # during startup (cache warming, log rotation, backup flush) can trigger
        # false positives that erode user trust in the first few minutes.
        self._STARTUP_GRACE_SECONDS = 90

        # Command deduplication: track executed command IDs
        self._executed_command_ids: set = set()

    @property
    def threshold(self) -> float:
        if self.server_threshold is not None:
            return self.server_threshold
        return self.baseline.threshold

    def _proto_breakdown(self) -> dict:
        """Protocol breakdown from the best available source:
        1. Scapy packet inspection (ground truth — sees drops)
        2. Flow collector data (upstream router visibility)
        3. /proc/net/snmp (kernel counters only)"""
        scapy_proto = self.analyser.protocol_breakdown()
        if sum(scapy_proto.values()) > 0:
            return scapy_proto
        # Flow collector has per-protocol breakdowns from flow records
        if self.flow and self.flow.aggregator.flow_count > 0:
            return {
                "tcp": self.flow.aggregator.tcp_pct,
                "udp": self.flow.aggregator.udp_pct,
                "icmp": self.flow.aggregator.icmp_pct,
                "other": 0,
            }
        return {
            "tcp": self.monitor.tcp_pct,
            "udp": self.monitor.udp_pct,
            "icmp": self.monitor.icmp_pct,
            "other": 0,
        }

    def run(self) -> None:
        logger.info("Flowtriq Agent %s starting on %s",
                    VERSION, self.monitor.interface)

        # Check for updates on startup
        check_for_updates()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        threads = [
            threading.Thread(target=self._heartbeat_loop, daemon=True,
                             name="heartbeat"),
            threading.Thread(target=self._config_loop, daemon=True,
                             name="config"),
            threading.Thread(target=self._command_poll_loop, daemon=True,
                             name="command-poll"),
        ]

        # PCAP sniffer thread (tracked for watchdog restart)
        self._sniffer_thread = None
        if self.pcap.enabled:
            self._sniffer_thread = threading.Thread(
                target=self.pcap.background_ring, args=(self.shutdown,),
                daemon=True, name="pcap-ring")
            threads.append(self._sniffer_thread)

        # Health check HTTP server
        health_port = self.cfg.get("health_port", 9100)
        if health_port:
            health = HealthCheckHandler(self, port=health_port)
            threads.append(threading.Thread(
                target=health.start, daemon=True, name="health-check"))

        # Flow collector thread (sFlow/NetFlow/IPFIX)
        if self.flow:
            threads.append(threading.Thread(
                target=self.flow.start, args=(self.shutdown,),
                daemon=True, name="flow-collector"))

        # Auto-update thread
        if self.cfg.get("auto_update", False):
            threads.append(threading.Thread(
                target=self._auto_update_loop, daemon=True,
                name="auto-update"))

        for t in threads:
            t.start()

        # Clean up stale firewall rules from previous runs BEFORE first config fetch
        self.sp_detector.cleanup_stale()
        try:
            import subprocess
            subprocess.run(
                ["nft", "delete", "table", "inet", "flowtriq_xdp"],
                capture_output=True, timeout=5)
        except Exception:
            pass

        # Register atexit handler as backup cleanup for iptables/nft rules.
        # Runs on normal exit and unhandled exceptions (not SIGKILL/OOM).
        import atexit
        def _atexit_cleanup():
            try:
                self.sp_detector.cleanup_stale()
            except Exception:
                pass
            try:
                subprocess.run(
                    ["nft", "delete", "table", "inet", "flowtriq_xdp"],
                    capture_output=True, timeout=5)
            except Exception:
                pass
        atexit.register(_atexit_cleanup)

        self._fetch_config()

        # Detect and report GRE tunnels on startup (Features 1 & 3)
        threading.Thread(
            target=self._report_gre_tunnels, daemon=True,
            name="gre-tunnel-detect").start()

        # Start L7 thread if enabled by server config
        if self.l7 and self.l7_enabled and not self.l7_thread_running:
            self.l7_thread_running = True
            l7t = threading.Thread(target=self._l7_loop, daemon=True, name="l7-monitor")
            l7t.start()

        logger.info("Entering main monitoring loop")
        last_watchdog = time.monotonic()
        while not self.shutdown.is_set():
            loop_start = time.monotonic()
            try:
                self._tick()
            except Exception as exc:
                logger.error("Tick error: %s", exc)

            # Watchdog: check sniffer thread health every 60s
            if (self._sniffer_thread is not None
                    and loop_start - last_watchdog >= 60):
                last_watchdog = loop_start
                if not self._sniffer_thread.is_alive():
                    logger.warning(
                        "Sniffer thread died, restarting...")
                    self._sniffer_thread = threading.Thread(
                        target=self.pcap.background_ring,
                        args=(self.shutdown,),
                        daemon=True, name="pcap-ring")
                    self._sniffer_thread.start()

            # Periodic pcap cleanup every 60 seconds
            if (self.pcap.enabled
                    and loop_start - self.pcap._last_cleanup >= 60):
                self.pcap._last_cleanup = loop_start
                self.pcap.cleanup_pcaps()

            elapsed = time.monotonic() - loop_start
            sleep_for = max(0, 1.0 - elapsed)
            self.shutdown.wait(sleep_for)

        logger.info("Agent shutting down")

    def _signal_handler(self, signum, frame) -> None:
        logger.info("Received signal %d, shutting down...", signum)
        # Clean up service port firewall rules before exit
        try:
            if self.sp_detector.enabled:
                self.sp_detector.cleanup()
        except Exception as e:
            logger.error("Service port cleanup failed during shutdown: %s", e)
        # Clean up nftables XDP rules if any were deployed
        try:
            import subprocess
            subprocess.run(
                ["nft", "delete", "table", "inet", "flowtriq_xdp"],
                capture_output=True, timeout=5)
        except Exception:
            pass
        self.shutdown.set()

    def _tick(self) -> None:
        if not self.monitor.read():
            return

        pps = self.monitor.pps
        bps = self.monitor.bps

        # GRE deduplication: subtract encapsulation overhead from BPS (Feature 1).
        # PPS doesn't change (one outer packet = one inner packet).
        # BPS is deflated by the GRE overhead ratio observed in the last window.
        # This makes reported bandwidth match the actual inner traffic volume.
        if self.gre_decap.enabled:
            overhead = self.gre_decap.overhead_ratio
            if overhead > 0:
                bps = bps * (1.0 - overhead)
            self.gre_decap.reset_window()

        # Merge flow collector data when active — flow data provides richer
        # protocol breakdown and source IP visibility from upstream routers.
        # Use flow PPS/BPS if higher than local /proc/net/dev (flow sees
        # traffic before it reaches the kernel, e.g. upstream aggregation).
        if self.flow and self.flow.aggregator.read(dt=1.0):
            flow_pps = self.flow.aggregator.pps
            flow_bps = self.flow.aggregator.bps
            if flow_pps > pps:
                pps = flow_pps
                bps = flow_bps

        # Don't pollute baseline with attack traffic — it would inflate the
        # threshold and make future detection less sensitive.
        # Also skip samples above the absolute floor when baseline isn't ready,
        # so a new node getting attacked doesn't build a baseline from attack data.
        _abs_floor = self.server_threshold or 10000
        if not self.attacking and (self.baseline.baseline_ready or pps < _abs_floor):
            self.baseline.add(pps)

        # Buffer metrics locally, flush every _metrics_interval seconds.
        # Detection still runs every 1s tick — only the API POST is batched.
        # Use flow protocol breakdown when flow data is richer than /proc/net/snmp
        tcp_pct = self.monitor.tcp_pct
        udp_pct = self.monitor.udp_pct
        icmp_pct = self.monitor.icmp_pct
        if self.flow and self.flow.aggregator.flow_count > 0:
            tcp_pct = self.flow.aggregator.tcp_pct
            udp_pct = self.flow.aggregator.udp_pct
            icmp_pct = self.flow.aggregator.icmp_pct
        self._metrics_buffer.append({
            "pps": round(pps, 1),
            "bps": round(bps, 1),
            "tcp_pct": tcp_pct,
            "udp_pct": udp_pct,
            "icmp_pct": icmp_pct,
            "conn_count": self.monitor.conn_count,
            "threshold": round(self.threshold, 1),
        })
        now = time.monotonic()
        if now - self._last_metrics_push >= self._metrics_interval:
            self._last_metrics_push = now
            self._flush_metrics()
            # Per-VM stats push (Feature 2) — only in hypervisor mode
            if self.hypervisor_mode and self.analyser.inner_dst_ips:
                self._flush_vm_stats()

        # ── Service Port Detection ──────────────────────────────────
        if self.sp_detector.enabled:
            self.sp_detector.read_counters()
            self.sp_detector.expire_blocks()

            # Push split metrics periodically
            if now - self._sp_last_metrics_push >= self._sp_metrics_interval:
                self._sp_last_metrics_push = now
                self._flush_sp_metrics()

            # Check non-service threshold
            if not self.sp_detector._attacking and self.sp_detector.check_threshold():
                self.sp_detector._attacking = True
                logger.warning("SERVICE PORT THRESHOLD CROSSED — non-service PPS=%d threshold=%d",
                               self.sp_detector.non_service_pps, self.sp_detector.pps_threshold)

                # Identify offending sources
                sources = self.sp_detector.identify_sources()

                # Deploy on-node blocks (if response mode includes on-node)
                blocked_sources = []
                if self.sp_detector.response_mode in ("onnode", "full"):
                    blocked_sources = self.sp_detector.deploy_blocks(sources)
                blocks_deployed = len(blocked_sources)

                # Open pipeline incident (if response mode includes pipeline)
                if self.sp_detector.response_mode in ("pipeline", "full") and not self.attacking:
                    self._begin_sp_attack(sources, blocks_deployed)

                # Report blocks AFTER incident opens so we have the UUID
                if blocked_sources:
                    self._report_sp_blocks(blocked_sources)

            elif self.sp_detector._attacking and not self.sp_detector.check_threshold():
                # Require 5 consecutive ticks below threshold (hysteresis)
                self.sp_detector._sp_below_count += 1
                if self.sp_detector._sp_below_count >= 5:
                    self.sp_detector._attacking = False
                    self.sp_detector._sp_below_count = 0
                    logger.info("Service port non-service traffic returned to normal (PPS=%d)",
                                self.sp_detector.non_service_pps)
            elif self.sp_detector._attacking:
                # Still above threshold, reset below counter
                self.sp_detector._sp_below_count = 0

        if not self.attacking:
            # Two detection paths:
            # 1. Baseline-driven: PPS exceeds the dynamic threshold (p99 * 3)
            # 2. Absolute floor: if baseline isn't ready yet and PPS exceeds
            #    a hard floor (10K), treat it as an attack immediately.
            #    This catches attacks on brand-new nodes before enough
            #    samples exist for a meaningful baseline.
            _absolute_floor = self.server_threshold or 10000
            # Lower threshold when 30%+ of source IPs are known-bad (threat intel)
            _effective_threshold = self.threshold
            if self.analyser.blocklist_ratio() > 0.3:
                _effective_threshold = self.threshold * 0.7
            _trigger = pps > _effective_threshold
            if not self.baseline.baseline_ready and pps >= _absolute_floor:
                _trigger = True

            # Startup grace period: don't trigger during the first 90 seconds
            # so the baseline can warm up. This prevents false positives from
            # normal startup spikes (cache warming, log rotation, etc.).
            # Exception: truly massive floods (>5x absolute floor) still trigger
            # immediately because those are unambiguously attacks.
            if _trigger and not self.baseline.baseline_ready:
                uptime = time.monotonic() - self._start_mono
                if uptime < self._STARTUP_GRACE_SECONDS and pps < _absolute_floor * 5:
                    _trigger = False

            # Post-attack cooldown: suppress re-detection for N seconds after
            # the last attack ended.  Prevents rapid-fire micro-burst incidents
            # (e.g. 10s open → 10s close → 10s open) that cause alert fatigue.
            # Exception: truly massive spikes (>5x floor) bypass the cooldown
            # because those are unambiguously real attacks.
            if _trigger and self._last_attack_end > 0:
                _cd_elapsed = time.monotonic() - self._last_attack_end
                if _cd_elapsed < self._attack_cooldown and pps < _absolute_floor * 5:
                    _trigger = False

            # Sustained-attack confirmation: require 3 consecutive ticks above
            # threshold before opening an incident. VoIP registration storms,
            # CDN cache refills, and game heartbeats produce brief 1-2 tick
            # spikes that aren't attacks. Real DDoS sustains for many seconds.
            # Exception: massive floods (>5x floor) trigger immediately.
            if _trigger:
                self._above_count = getattr(self, '_above_count', 0) + 1
                if self._above_count < 3 and pps < _absolute_floor * 5:
                    _trigger = False  # wait for sustained confirmation
            else:
                self._above_count = 0

            if _trigger:
                # Flush buffered metrics immediately so the dashboard sees the spike
                self._flush_metrics()
                self._last_metrics_push = now
                self._begin_attack()
        else:
            if pps > self.peak_pps:
                self.peak_pps = pps
            if bps > self.peak_bps:
                self.peak_bps = bps

            if pps < self.threshold:
                self.below_count += 1
            else:
                self.below_count = 0

            if self.below_count >= 10:
                # Flush metrics immediately so dashboard sees the resolution
                self._flush_metrics()
                self._last_metrics_push = now
                self._end_attack()
            elif time.monotonic() - self.last_update >= 5:
                self._update_attack()

    def _flush_metrics(self) -> None:
        """Aggregate buffered metrics and send a single API POST."""
        buf = self._metrics_buffer
        if not buf:
            return
        n = len(buf)
        # Send the latest snapshot with peak values from the buffer window
        agg = {
            "pps":       round(max(m["pps"] for m in buf), 1),
            "bps":       round(max(m["bps"] for m in buf), 1),
            "tcp_pct":   buf[-1]["tcp_pct"],
            "udp_pct":   buf[-1]["udp_pct"],
            "icmp_pct":  buf[-1]["icmp_pct"],
            "conn_count": buf[-1]["conn_count"],
            "threshold": buf[-1]["threshold"],
            "avg_pps":   round(sum(m["pps"] for m in buf) / n, 1),
            "samples":   n,
        }
        self._metrics_buffer = []
        self.api.send_metrics(agg)

    def _flush_vm_stats(self) -> None:
        """Send per-VM inner IP stats to the backend (Feature 2)."""
        vm_stats = self.analyser.per_vm_breakdown(self.vm_labels)
        if not vm_stats:
            return
        self.api._post("/agent/vm-stats", {
            "vms": vm_stats,
            "gre_dedup_active": self.gre_decap.enabled,
        }, timeout=5)

    def _begin_attack(self) -> None:
        self.attacking = True
        self.attack_start = time.time()
        self.peak_pps = self.monitor.pps
        self.peak_bps = self.monitor.bps
        if self.flow and self.flow.aggregator.pps > self.peak_pps:
            self.peak_pps = self.flow.aggregator.pps
            self.peak_bps = self.flow.aggregator.bps
        self.below_count = 0
        self.velocity_curve = []
        self.analyser.reset()
        self.last_update = time.monotonic()

        # Flush buffered metrics immediately so dashboard sees the spike
        self._flush_metrics()

        # Estimate protocol breakdown + SYN ratio from ring buffer for accurate
        # initial classification.  /proc/net/snmp misses dropped flood packets,
        # so we inspect the actual captured packets from scapy's ring buffer.
        _syn_est = 0.0
        _ring_tcp = _ring_udp = _ring_icmp = 0
        if SCAPY_AVAILABLE and self.pcap.ring_buffer:
            try:
                _ring_snapshot = list(self.pcap.ring_buffer)
            except RuntimeError:
                _ring_snapshot = []
            _syn_c = _ack_c = 0
            for _rpkt in _ring_snapshot:
                if _rpkt.haslayer(TCP):
                    _ring_tcp += 1
                    _f = _rpkt[TCP].flags
                    if _f & 0x02: _syn_c += 1
                    if _f & 0x10: _ack_c += 1
                elif _rpkt.haslayer(UDP):
                    _ring_udp += 1
                elif _rpkt.haslayer(ICMP):
                    _ring_icmp += 1
            if _syn_c + _ack_c > 0:
                _syn_est = _syn_c / (_syn_c + _ack_c)

        # tcpdump mode: parse ring files for protocol classification
        _ring_total = _ring_tcp + _ring_udp + _ring_icmp
        if self.pcap.pcap_mode == "tcpdump" and _ring_total == 0 and self.pcap._ring_dir:
            try:
                import glob, subprocess
                ring_files = sorted(glob.glob(os.path.join(self.pcap._ring_dir, "ring_*.pcap")))
                if ring_files:
                    # Use the most recent ring file
                    latest = ring_files[-1]
                    out = subprocess.run(
                        ["tcpdump", "-nn", "-r", latest, "-c", "200", "-q"],
                        capture_output=True, text=True, timeout=3)
                    for _tline in out.stdout.splitlines():
                        if "UDP" in _tline or "udp" in _tline:
                            _ring_udp += 1
                        elif "TCP" in _tline or "Flags" in _tline:
                            _ring_tcp += 1
                            if " S " in _tline or "[S]" in _tline:
                                _syn_c += 1
                            if "[.]" in _tline or " ack " in _tline:
                                _ack_c += 1
                        elif "ICMP" in _tline or "icmp" in _tline:
                            _ring_icmp += 1
                    if _syn_c + _ack_c > 0:
                        _syn_est = _syn_c / (_syn_c + _ack_c)
            except Exception as _e:
                logger.debug("tcpdump ring parse for classify: %s", _e)

        # Use ring buffer protocol data if available, fall back to SNMP
        _ring_total = _ring_tcp + _ring_udp + _ring_icmp
        if _ring_total > 10:
            _init_tcp = round(_ring_tcp / _ring_total * 100, 1)
            _init_udp = round(_ring_udp / _ring_total * 100, 1)
            _init_icmp = round(_ring_icmp / _ring_total * 100, 1)
        elif self.flow and self.flow.aggregator.flow_count > 0:
            _init_tcp = self.flow.aggregator.tcp_pct
            _init_udp = self.flow.aggregator.udp_pct
            _init_icmp = self.flow.aggregator.icmp_pct
        else:
            _init_tcp = self.monitor.tcp_pct
            _init_udp = self.monitor.udp_pct
            _init_icmp = self.monitor.icmp_pct

        family = classify_attack(_init_tcp, _init_udp, _init_icmp,
                                 syn_ratio=_syn_est,
                                 dns_detected=bool(self.analyser.dns_queries),
                                 top_ports=self.analyser.top_dst_ports(),
                                 tcp_flags=dict(self.analyser.tcp_flags),
                                 fragment_pct=self.analyser.fragment_pct())
        # Enrich classification with IOC threat intel
        family, _init_subtype, _init_tool, _ = enrich_from_ioc(
            self.analyser.ioc_hits, family, "")
        started_at = datetime.now(timezone.utc).isoformat()

        # Per-VM: identify which inner IP is being attacked (Feature 2)
        target_vm_ip = ""
        if self.hypervisor_mode and self.gre_decap.enabled:
            target_vm_ip = self.analyser.top_attacked_vm()
            if target_vm_ip:
                vm_label = self.vm_labels.get(target_vm_ip, "")
                label_str = f" ({vm_label})" if vm_label else ""
                logger.warning("ATTACK DETECTED — PPS=%.0f threshold=%.0f family=%s target_vm=%s%s",
                               self.peak_pps, self.threshold, family, target_vm_ip, label_str)
            else:
                logger.warning("ATTACK DETECTED — PPS=%.0f threshold=%.0f family=%s",
                               self.peak_pps, self.threshold, family)
        else:
            logger.warning("ATTACK DETECTED — PPS=%.0f threshold=%.0f family=%s",
                           self.peak_pps, self.threshold, family)

        # Alert-first: open incident before starting PCAP capture
        inc_data = {
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "started_at": started_at,
            "attack_family": family,
            "attack_subtype": _init_subtype or None,
            "baseline_pps": round(self.baseline.avg_pps, 1),
            "duration": 0,
            # GRE / hypervisor metadata (Features 1 & 2)
            "gre_dedup_active": self.gre_decap.enabled,
        }
        if _init_tool:
            inc_data["attack_tool"] = _init_tool
        if target_vm_ip:
            inc_data["inner_ip"] = target_vm_ip
            label = self.vm_labels.get(target_vm_ip, "")
            if label:
                inc_data["inner_ip_label"] = label
        if self.hypervisor_mode and self.analyser.inner_dst_ips:
            inc_data["vm_breakdown"] = self.analyser.per_vm_breakdown(self.vm_labels)
        # Include flow collector source IPs + ports for immediate visibility
        if self.flow and self.flow.aggregator.src_ip_count > 0:
            inc_data["top_src_ips"] = [
                {"ip": ip, "count": pkts}
                for ip, pkts in self.flow.aggregator.top_src_ips(20)
            ]
            inc_data["top_dst_ports"] = [
                {"port": port, "count": pkts}
                for port, pkts in self.flow.aggregator.top_dst_ports(20)
            ]
            inc_data["source_ip_count"] = self.flow.aggregator.src_ip_count
        result = self.api.open_incident(inc_data)

        if result and "uuid" in result:
            self.incident_uuid = result["uuid"]
            logger.info("Incident opened: %s", self.incident_uuid)
            # Apply auto-mitigation commands returned with the incident response
            # so firewall rules take effect immediately without waiting for next poll
            if "pending_commands" in result and result["pending_commands"]:
                logger.info("Applying %d auto-mitigation command(s) from incident response",
                            len(result["pending_commands"]))
                for cmd in result["pending_commands"]:
                    self._execute_command(cmd)
        else:
            self.incident_uuid = str(uuid.uuid4())
            logger.warning("Using local incident UUID: %s", self.incident_uuid)

        if self.pcap.enabled:
            self.pcap.start_capture(
                incident_uuid=self.incident_uuid,
                api_client=self.api)

        self.velocity_curve.append({
            "t": 0,
            "pps": round(self.peak_pps, 1),
        })

        # Immediately fetch config to pick up any mitigation commands
        # queued by the server in response to the incident we just opened
        threading.Thread(target=self._fetch_config, daemon=True,
                         name="attack-config-fetch").start()

    # ── Service Port helpers ─────────────────────────────────────────

    def _flush_sp_metrics(self) -> None:
        """Push split traffic metrics to the API."""
        if not self.sp_detector.enabled:
            return
        try:
            self.api._post("/agent/sp/metrics", {
                "service_pps": self.sp_detector.service_pps,
                "service_bps": self.sp_detector.service_bps,
                "non_service_pps": self.sp_detector.non_service_pps,
                "non_service_bps": self.sp_detector.non_service_bps,
                "blocked_pps": self.sp_detector.blocked_pps,
                "active_blocks": len(self.sp_detector._block_rules),
            }, timeout=5)
        except Exception as e:
            logger.debug("SP metrics push failed: %s", e)

    def _report_sp_blocks(self, sources: list) -> None:
        """Report deployed on-node blocks to the API."""
        blocks = []
        for src in sources:
            blocks.append({
                "source_ip": src["ip"],
                "block_scope": self.sp_detector.block_scope,
                "src_pps": src.get("pps", 0),
                "dst_ports": src.get("ports", []),
                "cooldown": self.sp_detector.block_cooldown,
            })
        try:
            self.api._post("/agent/sp/blocks", {
                "incident_uuid": self.incident_uuid if self.attacking else None,
                "blocks": blocks,
            }, timeout=10)
        except Exception as e:
            logger.debug("SP blocks report failed: %s", e)

    def _begin_sp_attack(self, sources: list, blocks_deployed: int) -> None:
        """Open an incident triggered by non-service port threshold crossing.
        Flows through the standard incident pipeline."""
        self.attacking = True
        self.attack_start = time.time()
        # Use the higher of aggregate PPS or non-service PPS as peak
        # (non-service PPS is from iptables counters which may be more accurate)
        self.peak_pps = max(self.monitor.pps, self.sp_detector.non_service_pps)
        self.peak_bps = max(self.monitor.bps, self.sp_detector.non_service_bps)
        self.below_count = 0
        self.velocity_curve = []
        self.analyser.reset()
        self.last_update = time.monotonic()

        # Determine zone: check if regular volumetric threshold is also crossed
        regular_trigger = self.monitor.pps > self.threshold
        sp_zone = "both" if regular_trigger else "non_service"

        family = "udp_flood"  # most non-service port attacks are UDP
        proto = self._proto_breakdown()
        family = classify_attack(proto["tcp"], proto["udp"], proto["icmp"],
                                 syn_ratio=self.analyser.syn_ratio(),
                                 dns_detected=bool(self.analyser.dns_queries),
                                 top_ports=self.analyser.top_dst_ports(),
                                 tcp_flags=dict(self.analyser.tcp_flags),
                                 other_pct=proto.get("other", 0.0),
                                 fragment_pct=self.analyser.fragment_pct())

        started_at = datetime.now(timezone.utc).isoformat()

        logger.warning("SP INCIDENT OPENING — zone=%s non_service_pps=%d service_pps=%d blocks=%d",
                        sp_zone, self.sp_detector.non_service_pps,
                        self.sp_detector.service_pps, blocks_deployed)

        # Build source IP list for incident
        sp_top_sources = [
            {"ip": s["ip"], "pps": s.get("pps", 0), "ports": s.get("ports", [])}
            for s in sources[:50]
        ]

        inc_data = {
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "started_at": started_at,
            "attack_family": family,
            "baseline_pps": round(self.baseline.avg_pps, 1),
            "duration": 0,
            "gre_dedup_active": self.gre_decap.enabled,
            # Service port zone metadata
            "sp_zone": sp_zone,
            "sp_service_pps": self.sp_detector.service_pps,
            "sp_non_service_pps": self.sp_detector.non_service_pps,
            "sp_top_sources": sp_top_sources,
            "sp_blocks_deployed": blocks_deployed,
            # Include source IPs in standard format too
            "top_src_ips": [{"ip": s["ip"], "count": s.get("pps", 0)} for s in sources[:20]],
            "source_ip_count": len(sources),
        }

        result = self.api.open_incident(inc_data)

        if result and "uuid" in result:
            self.incident_uuid = result["uuid"]
            logger.info("SP incident opened: %s", self.incident_uuid)
            if "pending_commands" in result and result["pending_commands"]:
                logger.info("Applying %d auto-mitigation command(s)",
                            len(result["pending_commands"]))
                for cmd in result["pending_commands"]:
                    self._execute_command(cmd)
        else:
            self.incident_uuid = str(uuid.uuid4())
            logger.warning("SP using local incident UUID: %s", self.incident_uuid)

        if self.pcap.enabled:
            self.pcap.start_capture(
                incident_uuid=self.incident_uuid,
                api_client=self.api)

        self.velocity_curve.append({"t": 0, "pps": round(self.peak_pps, 1)})

        threading.Thread(target=self._fetch_config, daemon=True,
                         name="sp-attack-config-fetch").start()

    # ── Standard attack lifecycle ─────────────────────────────────

    def _update_attack(self) -> None:
        if not self.incident_uuid:
            logger.warning("Skipping attack update — no incident UUID")
            return
        self.last_update = time.monotonic()
        elapsed = time.time() - self.attack_start
        if len(self.velocity_curve) < self._MAX_VELOCITY_POINTS:
            self.velocity_curve.append({
                "t": round(elapsed, 1),
                "pps": round(self.monitor.pps, 1),
            })
        else:
            # Past cap: update the last point so we always have the latest reading
            self.velocity_curve[-1] = {"t": round(elapsed, 1), "pps": round(self.monitor.pps, 1)}

        proto = self._proto_breakdown()
        _frag_pct = self.analyser.fragment_pct()
        family = classify_attack(proto["tcp"], proto["udp"], proto["icmp"],
                                 syn_ratio=self.analyser.syn_ratio(),
                                 dns_detected=bool(self.analyser.dns_queries),
                                 top_ports=self.analyser.top_dst_ports(),
                                 tcp_flags=dict(self.analyser.tcp_flags),
                                 other_pct=proto.get("other", 0.0),
                                 fragment_pct=_frag_pct)
        # Enrich classification with IOC threat intel
        family, _upd_subtype, _upd_tool, _ = enrich_from_ioc(
            self.analyser.ioc_hits, family, "")

        # Merge source IP data: use whichever source (scapy or flow) has more visibility
        _scapy_src_count = len(self.analyser.src_ips)
        _scapy_top_ips = self.analyser.top_src_ips()
        _scapy_top_ports = self.analyser.top_dst_ports()
        _src_count = _scapy_src_count
        _top_ips = _scapy_top_ips
        _top_ports = _scapy_top_ports
        if self.flow and self.flow.aggregator.src_ip_count > _scapy_src_count:
            _src_count = self.flow.aggregator.src_ip_count
            _top_ips = [{"ip": ip, "count": pkts}
                        for ip, pkts in self.flow.aggregator.top_src_ips(20)]
        if self.flow and len(self.flow.aggregator.top_dst_ports(20)) > len(_scapy_top_ports):
            _top_ports = [{"port": p, "count": pkts}
                          for p, pkts in self.flow.aggregator.top_dst_ports(20)]

        update_payload = {
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "attack_family": family,
            "attack_subtype": _upd_subtype or None,
            "protocol_breakdown": proto,
            "source_ip_count": _src_count,
            "total_packets": self.analyser.total_packets,
            "top_src_ips": _top_ips,
            "top_dst_ports": _top_ports,
            "ioc_hits": list(set(self.analyser.ioc_hits)),
            "spoofing_detected": self.analyser.spoofing_detected(),
            "botnet_detected": self.analyser.botnet_detected(),
            "fragment_count": self.analyser.fragment_count,
            "fragment_pct": _frag_pct,
        }
        if _upd_tool:
            update_payload["attack_tool"] = _upd_tool
        # Per-VM breakdown update (Feature 2)
        if self.hypervisor_mode and self.analyser.inner_dst_ips:
            top_vm = self.analyser.top_attacked_vm()
            if top_vm:
                update_payload["inner_ip"] = top_vm
                label = self.vm_labels.get(top_vm, "")
                if label:
                    update_payload["inner_ip_label"] = label
            update_payload["vm_breakdown"] = self.analyser.per_vm_breakdown(self.vm_labels)
        self.api.update_incident(self.incident_uuid, update_payload)

    def _end_attack(self) -> None:
        duration = time.time() - self.attack_start
        proto = self._proto_breakdown()
        _top_ports = self.analyser.top_dst_ports()
        _src_ports = self.analyser.top_src_ports()
        _flags = dict(self.analyser.tcp_flags)
        _avg_pkt = self.analyser.avg_pkt_length()
        _frag_pct = self.analyser.fragment_pct()
        family = classify_attack(
            proto["tcp"], proto["udp"], proto["icmp"],
            syn_ratio=self.analyser.syn_ratio(),
            dns_detected=bool(self.analyser.dns_queries),
            top_ports=_top_ports,
            tcp_flags=_flags,
            other_pct=proto.get("other", 0.0),
            fragment_pct=_frag_pct,
        )
        # Derive subtype from port/flag/size evidence
        subtype = classify_subtype(family, _top_ports, _flags, _avg_pkt,
                                   src_ports=_src_ports, fragment_pct=_frag_pct)
        # For TCP-dominant traffic that isn't SYN flood, check for other TCP subtypes
        if family in ("unknown", "tcp_flood") and proto["tcp"] > 40:
            tcp_sub = classify_tcp_subtype(_flags)
            if tcp_sub:
                subtype = tcp_sub
                if family == "unknown":
                    family = "tcp_flood"
        # Enrich classification with IOC threat intel
        family, subtype, _end_tool, _ = enrich_from_ioc(
            self.analyser.ioc_hits, family, subtype)

        logger.warning("ATTACK ENDED — duration=%.0fs peak_pps=%.0f family=%s subtype=%s",
                       duration, self.peak_pps, family, subtype or "none")

        if not self.incident_uuid:
            logger.error("Cannot resolve incident — UUID is empty (open_incident likely failed)")
            self.attacking = False
            return

        # Merge source IP data: prefer flow collector if it has broader visibility
        _scapy_src_count = len(self.analyser.src_ips)
        _src_count = _scapy_src_count
        _top_ips = self.analyser.top_src_ips()
        _top_ports_final = _top_ports
        if self.flow and self.flow.aggregator.src_ip_count > _scapy_src_count:
            _src_count = self.flow.aggregator.src_ip_count
            _top_ips = [{"ip": ip, "count": pkts}
                        for ip, pkts in self.flow.aggregator.top_src_ips(20)]
        if self.flow and len(self.flow.aggregator.top_dst_ports(20)) > len(_top_ports):
            _top_ports_final = [{"port": p, "count": pkts}
                                for p, pkts in self.flow.aggregator.top_dst_ports(20)]

        _resolve_data = {
            "duration_seconds": round(duration, 1),
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "attack_family": family,
            "attack_subtype": subtype or None,
            "protocol_breakdown": proto,
            "ioc_hits": list(set(self.analyser.ioc_hits)),
            "spoofing_detected": self.analyser.spoofing_detected(),
            "botnet_detected": self.analyser.botnet_detected(),
            "total_packets": self.analyser.total_packets,
            "source_ip_count": _src_count,
            "src_ip_entropy": self.analyser.src_ip_entropy(),
            "tcp_flag_breakdown": _flags,
            "dns_query_stats": self.analyser.dns_query_stats(),
            "pkt_length_histogram": self.analyser.pkt_length_histogram(),
            "ttl_distribution": self.analyser.ttl_distribution(),
            "velocity_curve": self.velocity_curve,
            "top_src_ips": _top_ips,
            "top_dst_ports": _top_ports_final,
            "avg_pkt_length": self.analyser.avg_pkt_length(),
            "fragment_count": self.analyser.fragment_count,
            "fragment_pct": _frag_pct,
        }
        if _end_tool:
            _resolve_data["attack_tool"] = _end_tool
        self.api.resolve_incident(self.incident_uuid, _resolve_data)

        if self.pcap.enabled:
            pcap_path = self.pcap.stop_capture(self.incident_uuid)
            if pcap_path:
                threading.Thread(
                    target=self.api.upload_pcap,
                    args=(self.incident_uuid, pcap_path),
                    daemon=True,
                ).start()
            self.pcap.cleanup_pcaps()

        self.attacking = False
        self.incident_uuid = ""
        self._last_attack_end = time.monotonic()

    def _heartbeat_loop(self) -> None:
        _last_update_check = time.monotonic()
        while not self.shutdown.is_set():
            self.shutdown.wait(30)
            if self.shutdown.is_set():
                break
            try:
                hb = {
                    "version": VERSION,
                    "baseline_ready": self.baseline.baseline_ready,
                    "baseline_avg_pps": round(self.baseline.avg_pps, 1),
                    "baseline_p99_pps": round(self.baseline.p99_pps, 1),
                    "baseline_hourly_ready": self.baseline.hourly_ready,
                    "baseline_current_hour_p99": round(self.baseline.current_hour_p99, 1),
                    "circuit_breaker": self.api.circuit_breaker_state,
                    "retry_queue_size": len(self.api.retry_queue),
                    # GRE dedup status (Feature 1)
                    "gre_dedup_enabled": self.gre_decap.enabled,
                    # Hypervisor mode status (Feature 2)
                    "hypervisor_mode": self.hypervisor_mode,
                    # Hybrid mode: report whether agent has PCAP active (Feature 5)
                    "pcap_active": self.pcap.enabled,
                    "flow_active": self.flow is not None,
                }
                # Export analyser overflow metrics
                if hasattr(self, 'analyser'):
                    hb["src_ip_overflow"] = self.analyser._src_ip_overflow
                    hb["src_ip_count"] = len(self.analyser.src_ips)
                    hb["pkt_samples_count"] = len(self.analyser.pkt_lengths)
                    if self.hypervisor_mode:
                        hb["vm_count"] = len(self.analyser.inner_dst_ips)
                # Export flow collector stats
                if self.flow:
                    hb["flow_collector"] = self.flow.stats
                self.api.heartbeat(hb)
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)

            # Check for updates every 6 hours
            if time.monotonic() - _last_update_check >= 21600:
                _last_update_check = time.monotonic()
                check_for_updates()

    def _auto_update_loop(self) -> None:
        """Check PyPI for newer version; upgrade if auto_update is on.
        First check after 60 seconds (catch updates quickly), then every 6 hours."""
        first_run = True
        while not self.shutdown.is_set():
            wait_time = 60 if first_run else 21600  # 60s first, then 6 hours
            first_run = False
            self.shutdown.wait(wait_time)
            if self.shutdown.is_set():
                break
            try:
                import urllib.request
                url = "https://pypi.org/pypi/ftagent/json"
                req = urllib.request.Request(
                    url, headers={"User-Agent": f"ftagent/{VERSION}"})
                resp = urllib.request.urlopen(req, timeout=15)
                data = json.loads(resp.read())
                latest = data.get("info", {}).get("version", "")
                if not latest:
                    continue

                def _ver_tuple(v):
                    parts = []
                    for p in v.split("."):
                        try:
                            parts.append(int(p))
                        except ValueError:
                            parts.append(0)
                    return tuple(parts)

                if _ver_tuple(latest) > _ver_tuple(VERSION):
                    logger.info(
                        "Auto-update: newer version %s available (current %s), "
                        "upgrading...", latest, VERSION)
                    previous_version = VERSION
                    import subprocess
                    pip_cmd = [sys.executable, "-m", "pip", "install",
                               "--upgrade", "ftagent"]
                    break_system = False
                    result = subprocess.run(
                        pip_cmd, capture_output=True, text=True, timeout=120,
                    )
                    # Handle PEP 668 (externally managed Python on Debian 12+, Ubuntu 23.04+)
                    if result.returncode != 0 and "externally-managed-environment" in result.stderr:
                        pip_cmd.insert(-1, "--break-system-packages")
                        break_system = True
                        result = subprocess.run(
                            pip_cmd, capture_output=True, text=True, timeout=120,
                        )
                    if result.returncode != 0:
                        logger.warning(
                            "Auto-update: pip upgrade failed: %s",
                            result.stderr.strip()[:500])
                        continue

                    # Post-install integrity verification
                    verified = True

                    # Verify installed version matches PyPI's advertised latest
                    if not _verify_installed_version(latest):
                        logger.warning(
                            "Auto-update: version mismatch after install "
                            "(expected %s)", latest)
                        verified = False

                    # Verify the module imports cleanly before restarting
                    if not _verify_module_imports():
                        logger.warning(
                            "Auto-update: new version fails import check")
                        verified = False

                    if not verified:
                        logger.warning(
                            "Auto-update: verification failed, rolling back "
                            "to v%s", previous_version)
                        if _pip_install_version(previous_version, break_system):
                            logger.info(
                                "Auto-update: rolled back to v%s",
                                previous_version)
                        else:
                            logger.error(
                                "Auto-update: rollback to v%s failed, "
                                "manual intervention required",
                                previous_version)
                        continue

                    logger.info(
                        "Auto-update: ftagent upgraded to %s (verified). "
                        "Restarting service...", latest)
                    # Auto-restart via systemd if running as service
                    try:
                        subprocess.run(
                            ["systemctl", "restart", "ftagent"],
                            capture_output=True, timeout=30,
                        )
                    except Exception as restart_exc:
                        logger.warning("Auto-update: systemctl restart failed (%s), restart ftagent manually to use v%s", restart_exc, latest)
            except Exception as exc:
                logger.warning("Auto-update check failed: %s", exc)
                # Report update failure to dashboard so operators can see it
                try:
                    self.api.post("heartbeat", {
                        "update_error": str(exc)[:200],
                        "current_version": VERSION,
                    })
                except Exception:
                    pass

    def _command_poll_loop(self) -> None:
        """Poll for pending commands (iptables rules).
        Normal: every 5 minutes. During attack: every 10 seconds for fast mitigation."""
        while not self.shutdown.is_set():
            interval = 10 if self.attacking else 300
            self.shutdown.wait(interval)
            if self.shutdown.is_set():
                break
            try:
                data = self.api.get_config()
                if data and "pending_commands" in data and data["pending_commands"]:
                    executed = 0
                    for cmd in data["pending_commands"]:
                        cmd_id = cmd.get("id", 0)
                        if cmd_id and cmd_id in self._executed_command_ids:
                            continue
                        self._execute_command(cmd)
                        if cmd_id:
                            self._executed_command_ids.add(cmd_id)
                        executed += 1
                    if executed:
                        logger.info("Command poll: processed %d commands", executed)
            except Exception as exc:
                logger.error("Command poll error: %s", exc)

    def _config_loop(self) -> None:
        while not self.shutdown.is_set():
            self.shutdown.wait(300)
            if self.shutdown.is_set():
                break
            self._fetch_config()

    def _fetch_config(self) -> None:
        try:
            data = self.api.get_config()
            if data is None:
                return
            # Handle workspace suspension (trial expired / billing inactive)
            if data.get("suspended"):
                if not getattr(self, '_suspended_logged', False):
                    logger.warning("Workspace suspended (billing inactive). "
                                   "Detection paused. Visit your dashboard to subscribe.")
                    self._suspended_logged = True
                # Disable service ports if active
                if self.sp_detector.enabled:
                    self.sp_detector.configure({"enabled": False})
                return
            self._suspended_logged = False
            # Server-triggered forced update
            force_ver = data.get("force_update")
            if force_ver and isinstance(force_ver, str):
                def _ver(v):
                    try: return tuple(int(x) for x in v.split("."))
                    except: return (0,)
                if _ver(force_ver) > _ver(VERSION):
                    logger.warning("Server requests forced update to v%s (current v%s), upgrading...",
                                   force_ver, VERSION)
                    import subprocess as _sub
                    try:
                        r = _sub.run([sys.executable, "-m", "pip", "install",
                                      "--no-cache-dir", "--upgrade", f"ftagent=={force_ver}"],
                                     capture_output=True, text=True, timeout=120)
                        if r.returncode != 0 and "externally-managed" in r.stderr:
                            r = _sub.run([sys.executable, "-m", "pip", "install",
                                          "--no-cache-dir", "--upgrade", "--break-system-packages",
                                          f"ftagent=={force_ver}"],
                                         capture_output=True, text=True, timeout=120)
                        if r.returncode == 0:
                            logger.warning("Updated to v%s. Restarting...", force_ver)
                            try:
                                _sub.run(["systemctl", "restart", "ftagent"],
                                         capture_output=True, timeout=30)
                            except Exception:
                                logger.info("Update installed. Restart ftagent manually.")
                        else:
                            logger.warning("Forced update failed: %s", r.stderr[:300])
                    except Exception as e:
                        logger.warning("Forced update error: %s", e)

            if "pps_threshold" in data and data["pps_threshold"]:
                self.server_threshold = float(data["pps_threshold"])
                logger.info("Server threshold: %.0f", self.server_threshold)
            elif data.get("dynamic_threshold", True):
                self.server_threshold = None
            if "ioc_patterns" in data:
                self.ioc_matcher.load(data["ioc_patterns"])
            if "pcap_enabled" in data:
                self.pcap.enabled = data["pcap_enabled"] and SCAPY_AVAILABLE
            # Threat intel IP blocklist from server
            if "ip_blocklist" in data and isinstance(data["ip_blocklist"], list):
                new_bl = {entry["indicator"] for entry in data["ip_blocklist"]
                          if isinstance(entry, dict) and entry.get("indicator")}
                if new_bl != self.ip_blocklist:
                    self.ip_blocklist = new_bl
                    self.analyser._blocklist = new_bl
                    logger.info("Threat intel blocklist: %d IPs loaded", len(new_bl))
            # GRE deduplication config from server (Feature 1)
            if "gre_mode" in data:
                gre_mode = data["gre_mode"]
                if gre_mode == "enabled":
                    if not self.gre_decap.enabled:
                        logger.info("GRE dedup: enabled by server config")
                    self.gre_decap.enabled = True
                elif gre_mode == "disabled":
                    if self.gre_decap.enabled:
                        logger.info("GRE dedup: disabled by server config")
                    self.gre_decap.enabled = False
                elif gre_mode == "auto":
                    self.gre_decap.enabled = detect_gre_interface(self.monitor.interface)
            if "gre_max_depth" in data:
                self.gre_decap.max_depth = int(data["gre_max_depth"])
            # Hypervisor mode config from server (Feature 2)
            if "hypervisor_mode" in data:
                was = self.hypervisor_mode
                self.hypervisor_mode = bool(data["hypervisor_mode"])
                self.pcap._hypervisor_mode = self.hypervisor_mode
                if not was and self.hypervisor_mode:
                    logger.info("Hypervisor mode: enabled by server config")
            if "vm_labels" in data and isinstance(data["vm_labels"], dict):
                self.vm_labels = data["vm_labels"]
            # Process pending commands (iptables rules from dashboard)
            # Note: _command_poll_loop also processes these, so deduplicate by command ID
            if "pending_commands" in data and data["pending_commands"]:
                for cmd in data["pending_commands"]:
                    cmd_id = cmd.get("id", 0)
                    if cmd_id and cmd_id in self._executed_command_ids:
                        continue
                    self._execute_command(cmd)
                    if cmd_id:
                        self._executed_command_ids.add(cmd_id)
                        # Prevent unbounded growth: keep only last 500 IDs
                        if len(self._executed_command_ids) > 500:
                            self._executed_command_ids = set(list(self._executed_command_ids)[-250:])

            # Flow collector config from server (dashboard can enable/configure per node)
            flow_cfg = data.get("flow", {})
            if flow_cfg.get("enabled") and not self.flow:
                # Server enabled flow collection — start collector
                merged = dict(self.cfg)
                merged["flow_enabled"] = True
                merged["flow_protocol"] = flow_cfg.get("protocol", "auto")
                merged["flow_port"] = flow_cfg.get("port", 0)
                merged["flow_sample_rate"] = flow_cfg.get("sample_rate", 0)
                merged["flow_source_ips"] = flow_cfg.get("source_ips", [])
                self.flow = FlowCollector(merged)
                self.flow.aggregator.node_ip = flow_cfg.get("node_ip", "")
                threading.Thread(
                    target=self.flow.start, args=(self.shutdown,),
                    daemon=True, name="flow-collector").start()
                logger.info("Flow collector enabled by server config: %s port %d (filtering dst_ip=%s)",
                           merged["flow_protocol"], self.flow.port, flow_cfg.get("node_ip", ""))
            elif flow_cfg.get("enabled") and self.flow:
                # Update node IP filter (in case node IP changes)
                self.flow.aggregator.node_ip = flow_cfg.get("node_ip", "")
            elif not flow_cfg.get("enabled") and self.flow:
                logger.info("Flow collector disabled by server config")
                self.flow = None  # thread will exit on next shutdown check

            # L7 config from server
            l7_cfg = data.get("l7", {})
            if l7_cfg.get("enabled"):
                was_enabled = self.l7_enabled
                self.l7_enabled = True
                action = l7_cfg.get("action")
                if action == "auto_detect" and not self.l7:
                    self._l7_auto_detect()
                elif l7_cfg.get("log_path"):
                    self._l7_start(l7_cfg["log_path"], l7_config=l7_cfg)
                    # Start L7 thread if not already running
                    if self.l7 and not self.l7_thread_running:
                        self.l7_thread_running = True
                        l7t = threading.Thread(
                            target=self._l7_loop, daemon=True, name="l7-monitor")
                        l7t.start()
            elif self.l7:
                logger.info("L7: disabled by server config")
                self.l7 = None
                self.l7_enabled = False

            # Service Ports config from server
            sp_cfg = data.get("service_ports", {})
            self.sp_detector.configure(sp_cfg)

            # Mirror mode config from server
            if data.get("mirror_blocked"):
                if hasattr(self, 'mirror_engine'):
                    logger.warning("Mirror mode blocked by server: %s",
                                   data.get("mirror_message", 'subscription required'))
            if "mirror_ip_limit" in data and hasattr(self, 'mirror_counter'):
                ip_limit = int(data["mirror_ip_limit"])
                if ip_limit > 0:
                    self.mirror_counter._max_ips = min(ip_limit, 100000)
                    logger.debug("Mirror IP limit set to %d", ip_limit)
            if "mirror_ip_labels" in data and hasattr(self, 'mirror_ip_labels'):
                self.mirror_ip_labels = data["mirror_ip_labels"]

        except Exception as exc:
            logger.error("Config fetch error: %s", exc)

    # ── GRE Tunnel Detection & Auto-Whitelisting (Feature 3) ───────────────

    def _report_gre_tunnels(self) -> None:
        """
        Detect active GRE tunnels on this node and report them to the backend.
        Backend will:
          - Auto-whitelist tunnel endpoint IPs to prevent accidental blocking
          - Store tunnel metadata for dashboard display
          - Prompt the user to review the auto-whitelist

        Called once on startup in a background thread. Safe to call if no GRE
        tunnels exist — sends empty list, backend records nothing.
        """
        tunnels = detect_gre_tunnels()
        if tunnels:
            names = [t["name"] for t in tunnels]
            remotes = [t["remote_ip"] for t in tunnels]
            logger.info("GRE tunnels detected: %s (remote endpoints: %s)",
                        ", ".join(names), ", ".join(remotes))
        else:
            logger.debug("GRE tunnel detection: no tunnels found on this node")

        # Report to backend regardless (empty list = no tunnels, backend clears stale)
        try:
            result = self.api._post("/agent/gre-tunnels", {
                "tunnels": tunnels,
                "gre_dedup_active": self.gre_decap.enabled,
            }, timeout=10, retries=2)
            if result and result.get("whitelisted"):
                logger.info("Backend auto-whitelisted GRE endpoint(s): %s",
                            ", ".join(result["whitelisted"]))
        except Exception as exc:
            logger.debug("GRE tunnel report failed (non-critical): %s", exc)

    # ── L7 Methods ─────────────────────────────────────────────────────────

    def _l7_auto_detect(self) -> None:
        logger.info("L7: running web server auto-detection...")
        result = detect_web_server()
        self.api._post("/agent/l7/detect", {
            "web_server": result["web_server"],
            "server_version": result.get("server_version"),
            "detected_paths": result["detected_paths"],
        }, retries=2)
        if result["web_server"]:
            logger.info("L7: detected %s, paths: %s",
                        result["web_server"], result["detected_paths"])
        else:
            logger.info("L7: no web server detected")

    def _l7_start(self, log_path: str, l7_config: dict = None) -> None:
        if self.l7 and self.l7.log_path == log_path:
            # Update thresholds on existing monitor without restarting
            if l7_config and self.l7:
                cfg = l7_config
                if cfg.get("rps_threshold"):
                    self.l7._rps_threshold_override = cfg["rps_threshold"]
                if cfg.get("error_rate_threshold"):
                    self.l7._error_rate_threshold = cfg["error_rate_threshold"]
                sens = cfg.get("sensitivity", "medium")
                self.l7._sensitivity_multiplier = {"low": 8, "medium": 5, "high": 3}.get(sens, 5)
                self.l7._min_rps = {"low": 250, "medium": 150, "high": 75}.get(sens, 150)
            return
        self._l7_log_path = log_path
        logger.info("L7: starting access log monitoring on %s", log_path)
        self.l7 = L7Monitor(log_path, self.api, l7_config=l7_config)
        if not self.l7.open():
            logger.warning("L7: %s not available yet, will retry on next cycle", log_path)
            self.l7 = None
            # Don't report failure -- file may appear after log rotation
        else:
            # Tell server we're actively monitoring this path
            self.api._post("/agent/l7/detect", {
                "web_server": "detected",
                "detected_paths": [log_path],
                "active_log_path": log_path,
            }, retries=1)

    def _l7_loop(self) -> None:
        logger.info("L7: monitoring thread started")
        _l7_retry_count = 0
        while not self.shutdown.is_set():
            self.shutdown.wait(1)
            if self.shutdown.is_set():
                break
            if not self.l7:
                # File wasn't available (log rotation). Retry every 30s.
                _l7_retry_count += 1
                if _l7_retry_count % 30 == 0:  # every 30s (30 * 1s)
                    cfg = {"log_path": getattr(self, '_l7_log_path', None)}
                    if cfg["log_path"]:
                        self._l7_start(cfg["log_path"])
                        if self.l7:
                            _l7_retry_count = 0
                continue
            try:
                stats = self.l7.tick()
                if not stats:
                    continue
                now = time.monotonic()
                if now - self.l7_last_metric_push >= 10:
                    self.l7_last_metric_push = now
                    self.api._post("/agent/l7/metrics", stats, retries=1)
                attack_info = self.l7.check_attack(stats)
                if not attack_info:
                    continue
                # When L3/L4 attack is active, still report L7 but flag as correlated
                # so the dashboard can show the full picture of multi-vector attacks.
                if attack_info["type"] == "l7_flood" and self.attacking:
                    logger.info("L7: detected during active L3/L4 attack — reporting as correlated")
                    attack_info["correlated_l3l4"] = True
                if attack_info["type"] == "l7_flood":
                    self._l7_begin_attack(attack_info)
                elif attack_info["type"] == "l7_flood_end":
                    self._l7_end_attack(attack_info)
                elif attack_info["type"] == "l7_flood_update":
                    self._l7_update_attack(attack_info)
            except Exception as exc:
                logger.error("L7 tick error: %s", exc)

    def _l7_begin_attack(self, info: dict) -> None:
        rps = info["rps"]
        baseline_rps = info.get("baseline_rps", 0)
        subtype = info.get("attack_subtype", "l7_flood")
        logger.warning("L7 ATTACK DETECTED — type=%s RPS=%.0f baseline=%.0f reasons=%s",
                       subtype, rps, baseline_rps, info["reasons"])
        self.l7_peak_rps = rps
        self.l7_baseline_rps = baseline_rps
        self.l7_velocity_curve = [{"t": 0, "rps": round(rps, 1)}]
        self.l7_attack_start = time.time()
        stats = info.get("stats", {})
        payload = {
            "peak_pps": 0,
            "peak_bps": 0,
            "rps": round(rps),
            "baseline_rps": round(baseline_rps, 1),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "attack_family": "http_flood",
            "attack_subtype": subtype,
        }
        if info.get("correlated_l3l4"):
            payload["correlated_l3l4"] = True
        result = self.api.open_incident(payload)
        if result and "uuid" in result:
            self.l7_incident_uuid = result["uuid"]
        else:
            self.l7_incident_uuid = str(uuid.uuid4())

        # Trigger PCAP capture for L7 attacks too
        if self.pcap.enabled:
            self.pcap.start_capture(
                incident_uuid=self.l7_incident_uuid,
                api_client=self.api)

        # Use real protocol data from scapy/SNMP instead of hardcoding
        real_proto = self._proto_breakdown()
        self.api.update_incident(self.l7_incident_uuid, {
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "rps": round(rps),
            "baseline_rps": round(baseline_rps, 1),
            "source_ip_count": stats.get("unique_ips", 0),
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(stats.get("top_ips", {}).items())[:50]],
            "top_dst_ports": stats.get("top_paths", {}),
            "protocol_breakdown": real_proto,
            # New L7-specific fields
            "l7_error_rate": stats.get("error_rate", 0),
            "l7_status_codes": stats.get("status_codes", {}),
            "l7_top_user_agents": stats.get("top_user_agents", {}),
            "l7_threat_patterns": stats.get("threat_patterns", {}),
            "l7_protocol_versions": stats.get("protocol_versions", {}),
        })

    def _l7_update_attack(self, info: dict) -> None:
        if not self.l7_incident_uuid:
            return
        rps = info.get("rps", 0)
        if rps > getattr(self, 'l7_peak_rps', 0):
            self.l7_peak_rps = rps
        stats = info.get("stats", {})
        subtype = _classify_l7_subtype(stats) if stats else "l7_flood"

        # Track RPS velocity curve (capped to prevent memory bloat on long attacks)
        elapsed = time.time() - getattr(self, 'l7_attack_start', time.time())
        curve = getattr(self, 'l7_velocity_curve', [])
        if len(curve) < self._MAX_VELOCITY_POINTS:
            curve.append({"t": round(elapsed, 1), "rps": round(rps, 1)})
        else:
            curve[-1] = {"t": round(elapsed, 1), "rps": round(rps, 1)}
        self.l7_velocity_curve = curve

        bot_pct = stats.get("bot_request_pct", 0)
        # Use accumulated attack-wide data for IPs, paths, UAs, status codes
        # so dashboard shows running totals, not just the last 10-second window
        accum = self.l7.get_attack_summary() if self.l7 else {}
        accum_ips = accum.get("top_ips", stats.get("top_ips", {}))
        accum_paths = accum.get("top_paths", stats.get("top_paths", {}))
        accum_total = accum.get("total_requests", stats.get("total_requests", 0))

        self.api.update_incident(self.l7_incident_uuid, {
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "rps": round(rps),
            "baseline_rps": round(getattr(self, 'l7_baseline_rps', 0), 1),
            "source_ip_count": len(accum_ips),
            "total_packets": accum_total,
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(accum_ips.items())[:50]],
            "top_dst_ports": accum_paths,
            "protocol_breakdown": self._proto_breakdown(),
            "botnet_detected": bot_pct > 70,
            "l7_error_rate": stats.get("error_rate", 0),
            "l7_status_codes": accum.get("status_codes", stats.get("status_codes", {})),
            "l7_top_user_agents": accum.get("top_user_agents", stats.get("top_user_agents", {})),
            "l7_threat_patterns": accum.get("threat_patterns", stats.get("threat_patterns", {})),
            "l7_protocol_versions": accum.get("protocol_versions", stats.get("protocol_versions", {})),
        })

    def _l7_end_attack(self, info: dict) -> None:
        if not self.l7_incident_uuid:
            return
        duration = info.get("duration_seconds", 0)
        peak_rps = getattr(self, 'l7_peak_rps', info.get("peak_rps", 0))
        baseline_rps = getattr(self, 'l7_baseline_rps', 0)
        subtype = info.get("attack_subtype", "l7_flood")
        logger.warning("L7 ATTACK ENDED — type=%s duration=%.0fs peak_rps=%.0f",
                       subtype, duration, peak_rps)

        # Stop PCAP capture
        try:
            if self.pcap.capturing:
                pcap_path = self.pcap.stop_capture(self.l7_incident_uuid)
                if pcap_path:
                    threading.Thread(
                        target=self.api.upload_pcap,
                        args=(self.l7_incident_uuid, pcap_path),
                        daemon=True,
                    ).start()
                self.pcap.cleanup_pcaps()
        except Exception as exc:
            logger.error("L7: PCAP stop error: %s", exc)

        stats = info.get("stats", {})
        summary = info.get("attack_summary", {})
        bot_pct = stats.get("bot_request_pct", summary.get("bot_request_pct", 0))

        # Finalize velocity curve
        velocity = getattr(self, 'l7_velocity_curve', [])
        velocity.append({"t": round(duration, 1), "rps": round(info.get("rps", 0), 1)})

        self.api.resolve_incident(self.l7_incident_uuid, {
            "duration_seconds": duration,
            "peak_pps": 0,
            "peak_bps": 0,
            "peak_rps": round(peak_rps),
            "baseline_rps": round(baseline_rps, 1),
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "protocol_breakdown": self._proto_breakdown(),
            "source_ip_count": len(summary.get("top_ips", stats.get("top_ips", {}))),
            "total_packets": summary.get("total_requests", stats.get("total_requests", 0)),
            "botnet_detected": bot_pct > 70,
            "velocity_curve": velocity,
            # Use accumulated attack-wide data (summary), not last-window (stats)
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(summary.get("top_ips", stats.get("top_ips", {})).items())[:50]],
            "top_dst_ports": summary.get("top_paths", stats.get("top_paths", {})),
            # Full attack-wide L7 enrichment
            "l7_error_rate": summary.get("error_rate", stats.get("error_rate", 0)),
            "l7_status_codes": summary.get("status_codes", stats.get("status_codes", {})),
            "l7_top_user_agents": summary.get("top_user_agents", stats.get("top_user_agents", {})),
            "l7_targeted_paths": summary.get("top_paths", stats.get("top_paths", {})),
            "l7_threat_patterns": summary.get("threat_patterns", stats.get("threat_patterns", {})),
            "l7_protocol_versions": summary.get("protocol_versions", stats.get("protocol_versions", {})),
        })
        self.l7_incident_uuid = ""
        self.l7_peak_rps = 0

    def _execute_command(self, cmd: dict) -> None:
        """Execute a pending command (iptables/sysctl/xdp) from the dashboard."""
        cmd_id = cmd.get("id", 0)
        cmd_type = cmd.get("command_type", "iptables")
        cmd_text = cmd.get("command_text", "")
        title = cmd.get("title", "")

        if not cmd_text:
            return

        logger.info("Executing %s command #%d: %s", cmd_type, cmd_id, title)

        # XDP/eBPF commands: JSON-based spec, handled separately
        if cmd_type == "xdp":
            result = self._execute_xdp_command(cmd_id, cmd_text, title)
            return

        allowed_prefixes = (
            "iptables ", "ip6tables ", "ipset ", "sysctl ",
            "nft ", "ufw ", "firewall-cmd ", "tc ", "ip route ",
            "fail2ban-client ", "nginx ", "apache2ctl ",
            "rm -f /etc/nginx/conf.d/ft_",
            "rm -f /etc/apache2/conf-enabled/ft_",
            "for cc in ",
        )
        errors = []
        applied = 0

        for line in cmd_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Safety: only allow iptables/ipset/sysctl commands
            if not any(line.startswith(p) for p in allowed_prefixes):
                errors.append(f"Blocked unsafe command: {line}")
                logger.warning("Blocked unsafe command: %s", line)
                continue
            # Block shell metacharacters that enable injection
            if ';' in line or '`' in line or '$' in line or '|' in line or '>' in line or '<' in line:
                errors.append(f"Blocked command with shell injection chars: {line}")
                logger.warning("Blocked shell injection in command: %s", line)
                continue
            # Block destructive commands that could lock out the server
            _tokens = line.split()
            _destructive_tokens = {"-F", "-X", "--flush", "--delete-chain"}
            _destructive_policy = [("-P", "INPUT", "DROP"), ("-P", "INPUT", "REJECT")]
            if any(t in _destructive_tokens for t in _tokens):
                errors.append(f"Blocked destructive firewall command: {line}")
                logger.warning("Blocked destructive command: %s", line)
                continue
            if any(all(p in _tokens for p in combo) for combo in _destructive_policy):
                errors.append(f"Blocked destructive firewall command: {line}")
                logger.warning("Blocked destructive command: %s", line)
                continue
            # Sysctl whitelist: only allow known-safe kernel parameters
            if line.startswith("sysctl "):
                _safe_sysctl = {
                    "net.ipv4.tcp_syncookies", "net.ipv4.tcp_max_syn_backlog",
                    "net.ipv4.tcp_synack_retries", "net.ipv4.tcp_syn_retries",
                    "net.ipv4.icmp_echo_ignore_broadcasts",
                    "net.ipv4.icmp_ignore_bogus_error_responses",
                    "net.ipv4.conf.all.log_martians",
                    "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_time",
                    "net.core.somaxconn", "net.core.netdev_max_backlog",
                }
                # Extract exact sysctl key: "sysctl -w key=value" or "sysctl key=value"
                _sysctl_parts = line.split()
                _sysctl_key = None
                for _sp in _sysctl_parts[1:]:
                    if _sp.startswith("-"):
                        continue
                    _sysctl_key = _sp.split("=")[0]
                    break
                if _sysctl_key not in _safe_sysctl:
                    errors.append(f"Blocked unsafe sysctl: {line}")
                    logger.warning("Blocked non-whitelisted sysctl: %s", line)
                    continue
            # Block null routes to private/reserved IPs
            if "blackhole" in line and line.startswith("ip route "):
                import ipaddress as _ipa
                _parts = line.split()
                for _p in _parts:
                    try:
                        _addr = _ipa.ip_address(_p.split("/")[0])
                        if _addr.is_private or _addr.is_loopback or _addr.is_reserved:
                            errors.append(f"Blocked blackhole route to private/reserved IP: {line}")
                            logger.warning("Blocked blackhole to private IP: %s", line)
                            break
                    except ValueError:
                        continue
                else:
                    pass  # no private IP found, allow
                if any("Blocked blackhole" in e for e in errors[-1:]):
                    continue
            try:
                import subprocess
                result = subprocess.run(
                    shlex.split(line), capture_output=True, text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    applied += 1
                    logger.info("Applied: %s", line)
                else:
                    err = result.stderr.strip() or f"exit code {result.returncode}"
                    errors.append(f"{line}: {err}")
                    logger.warning("Command failed: %s — %s", line, err)
            except Exception as exc:
                errors.append(f"{line}: {exc}")
                logger.error("Command error: %s — %s", line, exc)

        # Report back to server
        status = "applied" if not errors else ("failed" if not applied else "applied")
        error_msg = "; ".join(errors) if errors else None
        self.api._post("/agent/commands/ack", {
            "command_id": cmd_id,
            "status": status,
            "error": error_msg,
        }, retries=2)

    def _execute_xdp_command(self, cmd_id: int, spec_json: str, title: str) -> None:
        """Execute an XDP/eBPF filter command.

        XDP filters provide kernel-bypass packet filtering at line rate,
        orders of magnitude faster than iptables for high-PPS attacks.

        Supports two modes:
        1. nftables-based (fallback): uses nft for filtering when XDP tools unavailable
        2. XDP-native: uses ip link + BPF programs when xdp-loader/bpftool available

        Spec format (JSON):
        {
            "type": "xdp_filter" | "xdp_filter_remove",
            "target": "192.0.2.1",
            "proto": "udp" | "tcp" | "icmp" | "any",
            "dport": 53,           // optional
            "action": "drop" | "pass",
            "rate_pps": 10000      // optional, packets per second
        }
        """
        import json as _json
        import subprocess

        errors = []
        applied = 0

        try:
            spec = _json.loads(spec_json)
        except Exception as exc:
            self.api._post("/agent/commands/ack", {
                "command_id": cmd_id,
                "status": "failed",
                "error": f"Invalid XDP spec JSON: {exc}",
            }, retries=2)
            return

        spec_type = spec.get("type", "")
        target = spec.get("target", "")
        proto = spec.get("proto", "any")
        dport = spec.get("dport")
        action = spec.get("action", "drop")
        rate_pps = spec.get("rate_pps")

        if not target:
            self.api._post("/agent/commands/ack", {
                "command_id": cmd_id,
                "status": "failed",
                "error": "XDP spec missing target IP",
            }, retries=2)
            return

        # Sanitize target IP (prevent injection)
        import re
        if not re.match(r'^[\da-fA-F.:]+$', target):
            self.api._post("/agent/commands/ack", {
                "command_id": cmd_id,
                "status": "failed",
                "error": f"Invalid target IP: {target}",
            }, retries=2)
            return

        # Use nftables for high-performance filtering (widely available, fast path in kernel)
        # XDP-native would require precompiled BPF programs; nft is the practical approach
        nft_table = "flowtriq_xdp"
        nft_chain = "filter"
        nft_comment = f"flowtriq_xdp_{target.replace('.', '_').replace(':', '_')}"

        if spec_type == "xdp_filter_remove":
            # Remove all nft rules matching this target
            cmds = [
                f"nft delete rule inet {nft_table} {nft_chain} comment \"{nft_comment}\" 2>/dev/null || true",
            ]
            # Also try removing by handle (more reliable)
            cmds.append(
                f"for h in $(nft -a list chain inet {nft_table} {nft_chain} 2>/dev/null "
                f"| grep '{nft_comment}' | grep -oP 'handle \\K\\d+'); do "
                f"nft delete rule inet {nft_table} {nft_chain} handle $h; done 2>/dev/null || true"
            )
        elif spec_type == "xdp_filter":
            # Ensure table and chain exist
            cmds = [
                f"nft add table inet {nft_table} 2>/dev/null || true",
                f"nft add chain inet {nft_table} {nft_chain} "
                f"{{ type filter hook ingress priority -500\\; policy accept\\; }} 2>/dev/null || true",
            ]

            # Build the match expression
            match_parts = [f"ip daddr {target}"]
            if proto in ("tcp", "udp"):
                match_parts.append(f"meta l4proto {proto}")
                if dport:
                    match_parts.append(f"th dport {int(dport)}")
            elif proto == "icmp":
                match_parts.append("meta l4proto icmp")

            match_expr = " ".join(match_parts)

            if rate_pps and int(rate_pps) > 0:
                # Rate-limit mode: allow up to rate_pps, drop excess
                cmds.append(
                    f"nft add rule inet {nft_table} {nft_chain} "
                    f"{match_expr} limit rate over {max(1, int(rate_pps))}/second "
                    f"drop comment \"{nft_comment}\""
                )
            else:
                # Full drop mode
                nft_action = "drop" if action == "drop" else "accept"
                cmds.append(
                    f"nft add rule inet {nft_table} {nft_chain} "
                    f"{match_expr} {nft_action} comment \"{nft_comment}\""
                )
        else:
            self.api._post("/agent/commands/ack", {
                "command_id": cmd_id,
                "status": "failed",
                "error": f"Unknown XDP spec type: {spec_type}",
            }, retries=2)
            return

        # Execute nft commands
        for c in cmds:
            try:
                result = subprocess.run(
                    c, shell=True, capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    applied += 1
                    logger.info("XDP/nft applied: %s", c)
                else:
                    err = result.stderr.strip() or f"exit code {result.returncode}"
                    errors.append(f"{c}: {err}")
                    logger.warning("XDP/nft failed: %s — %s", c, err)
            except Exception as exc:
                errors.append(f"{c}: {exc}")
                logger.error("XDP/nft error: %s — %s", c, exc)

        status = "applied" if not errors else ("failed" if not applied else "applied")
        error_msg = "; ".join(errors) if errors else None
        logger.info("XDP command #%d: %s (%d applied, %d errors)", cmd_id, status, applied, len(errors))
        self.api._post("/agent/commands/ack", {
            "command_id": cmd_id,
            "status": status,
            "error": error_msg,
        }, retries=2)


# ---------------------------------------------------------------------------
# Mirror Agent (SPAN/TAP per-IP detection)
# ---------------------------------------------------------------------------

class MirrorAgent(Agent):
    """DDoS detection agent for SPAN/mirror port monitoring.

    Instead of monitoring a single server's own traffic (Agent mode), this
    captures mirrored traffic from an entire network segment and runs
    independent baseline + threshold detection per destination IP.

    Architecture:
      - MirrorCaptureEngine (AF_PACKET or tcpdump) feeds PerIPCounter
      - PerIPBaselineManager tracks baselines per destination IP
      - Multiple concurrent incidents (one per attacked IP)
      - Reuses parent Agent's API client, heartbeat, config, and command execution
    """

    def __init__(self, cfg: dict):
        # Initialize parent — sets up API, baseline (aggregate), analyser, pcap, etc.
        super().__init__(cfg)

        # Mirror-specific config
        self.mirror_interface = cfg.get("mirror_interface", "")
        if not self.mirror_interface:
            logger.error("mirror_mode=True but mirror_interface not set. "
                         "Set it to the NIC connected to your SPAN/mirror port.")
            raise SystemExit(1)

        self.mirror_ip_labels: dict = cfg.get("mirror_ip_labels", {})
        mirror_subnets = cfg.get("mirror_subnets", [])
        gre_strip = self.gre_decap.enabled

        # Per-IP tracking
        from ftagent.mirror_engine import PerIPCounter, MirrorCaptureEngine
        self.mirror_counter = PerIPCounter()
        self.mirror_engine = MirrorCaptureEngine(
            interface=self.mirror_interface,
            counter=self.mirror_counter,
            mode=cfg.get("mirror_capture_mode", "af_packet"),
            subnets=mirror_subnets if mirror_subnets else None,
            gre_strip=gre_strip,
        )
        self.per_ip_baseline = PerIPBaselineManager(
            window=cfg.get("baseline_window", 300))

        # Active attacks: dict[dst_ip -> IPAttackState]
        self.active_attacks: dict[str, dict] = {}
        # Per-IP PCAP processes (BPF-filtered per attacked IP)
        self._ip_pcap_procs: dict[str, subprocess.Popen] = {}

        # Enable per-dst-IP tracking on flow collector if available
        if self.flow:
            self.flow.aggregator._per_dst_ip_mode = True
            self.flow.aggregator._node_ip = ""  # unrestricted

        # Override: disable the parent's single-IP PPSMonitor-based detection
        # (mirror mode doesn't monitor /proc/net/dev for its own traffic)
        self.attacking = False

        # Latest snapshot for aggregate metrics
        self._last_snapshot: dict = {}
        self._last_aggregate_pps: float = 0.0
        self._last_aggregate_bps: float = 0.0

    def run(self) -> None:
        logger.info("Flowtriq Mirror Agent %s starting on SPAN interface %s",
                     VERSION, self.mirror_interface)

        check_for_updates()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        threads = [
            threading.Thread(target=self._heartbeat_loop, daemon=True,
                             name="heartbeat"),
            threading.Thread(target=self._config_loop, daemon=True,
                             name="config"),
            threading.Thread(target=self._command_poll_loop, daemon=True,
                             name="command-poll"),
        ]

        # Mirror capture engine thread
        threads.append(threading.Thread(
            target=self.mirror_engine.start, args=(self.shutdown,),
            daemon=True, name="mirror-capture"))

        # Health check
        health_port = self.cfg.get("health_port", 9100)
        if health_port:
            health = HealthCheckHandler(self, port=health_port)
            threads.append(threading.Thread(
                target=health.start, daemon=True, name="health-check"))

        # Flow collector (can supplement mirror capture with flow data)
        if self.flow:
            threads.append(threading.Thread(
                target=self.flow.start, args=(self.shutdown,),
                daemon=True, name="flow-collector"))

        # Auto-update
        if self.cfg.get("auto_update", False):
            threads.append(threading.Thread(
                target=self._auto_update_loop, daemon=True,
                name="auto-update"))

        for t in threads:
            t.start()

        self._fetch_config()

        logger.info("Entering mirror monitoring loop")
        while not self.shutdown.is_set():
            loop_start = time.monotonic()
            try:
                self._tick()
            except Exception as exc:
                logger.error("Mirror tick error: %s", exc)

            elapsed = time.monotonic() - loop_start
            sleep_for = max(0, 1.0 - elapsed)
            self.shutdown.wait(sleep_for)

        # Graceful shutdown: resolve any open incidents
        for ip in list(self.active_attacks.keys()):
            try:
                self._end_ip_attack(ip)
            except Exception:
                pass

        logger.info("Mirror Agent shutting down")

    def _tick(self) -> None:
        # 1. Snapshot per-IP counters from mirror capture engine
        ip_snapshots = self.mirror_counter.snapshot_and_reset()

        # Merge flow collector per-IP data when available (takes higher PPS per IP)
        if self.flow and self.flow.aggregator.read(dt=1.0):
            flow_per_ip = self.flow.aggregator.per_dst_ip_data
            if flow_per_ip:
                from ftagent.mirror_engine import IPSnapshot, IPStats
                for dst_ip, fdata in flow_per_ip.items():
                    existing = ip_snapshots.get(dst_ip)
                    if existing is None or fdata["packets"] > existing.packets:
                        # Build IPSnapshot from flow data
                        stats = IPStats()
                        stats.packets = fdata["packets"]
                        stats.octets = fdata["octets"]
                        stats.tcp_packets = fdata.get("tcp", 0)
                        stats.udp_packets = fdata.get("udp", 0)
                        stats.icmp_packets = fdata.get("icmp", 0)
                        stats.src_ips = fdata.get("src_ips", {})
                        stats.dst_ports = fdata.get("dst_ports", {})
                        stats.tcp_flags = fdata.get("tcp_flags", {
                            "SYN": 0, "ACK": 0, "RST": 0, "FIN": 0, "PSH": 0, "URG": 0})
                        ip_snapshots[dst_ip] = IPSnapshot(dst_ip, stats)

        self._last_snapshot = ip_snapshots

        if not ip_snapshots:
            return

        # 2. Compute aggregate PPS/BPS for node-level metrics
        total_pps = sum(s.pps for s in ip_snapshots.values())
        total_bps = sum(s.bps for s in ip_snapshots.values())
        self._last_aggregate_pps = total_pps
        self._last_aggregate_bps = total_bps

        # Also update parent's aggregate baseline for overall node monitoring
        if not self.active_attacks:
            self.baseline.add(total_pps)

        # 3. Feed each non-attacking IP into per-IP baselines
        for ip, snap in ip_snapshots.items():
            if ip not in self.active_attacks:
                _abs_floor = self.server_threshold or 10000
                bl = self.per_ip_baseline._baselines.get(ip)
                if bl is None or bl.baseline_ready or snap.pps < _abs_floor:
                    self.per_ip_baseline.add(ip, snap.pps)

        # 4. Per-IP detection
        for ip, snap in ip_snapshots.items():
            if ip not in self.active_attacks:
                if self.per_ip_baseline.check(ip, snap.pps):
                    self._begin_ip_attack(ip, snap)
            else:
                # Update existing attack
                state = self.active_attacks[ip]
                if snap.pps > state["peak_pps"]:
                    state["peak_pps"] = snap.pps
                if snap.bps > state["peak_bps"]:
                    state["peak_bps"] = snap.bps

                threshold = self.per_ip_baseline.get_threshold(ip)
                if threshold <= 0:
                    threshold = self.server_threshold or 10000

                if snap.pps < threshold:
                    state["below_count"] += 1
                else:
                    state["below_count"] = 0

                if state["below_count"] >= 10:
                    self._end_ip_attack(ip)
                elif time.monotonic() - state["last_update"] >= 5:
                    self._update_ip_attack(ip, snap)

        # Check for attacks that have had no traffic at all this window
        for ip in list(self.active_attacks.keys()):
            if ip not in ip_snapshots:
                state = self.active_attacks[ip]
                state["below_count"] += 1
                if state["below_count"] >= 10:
                    self._end_ip_attack(ip)

        # 5. Buffer aggregate metrics (same format as parent)
        # Use weighted protocol breakdown from all IPs
        total_tcp = sum(s.tcp_pct * s.packets for s in ip_snapshots.values())
        total_udp = sum(s.udp_pct * s.packets for s in ip_snapshots.values())
        total_icmp = sum(s.icmp_pct * s.packets for s in ip_snapshots.values())
        total_pkts = sum(s.packets for s in ip_snapshots.values())
        tcp_pct = round(total_tcp / total_pkts, 1) if total_pkts > 0 else 0
        udp_pct = round(total_udp / total_pkts, 1) if total_pkts > 0 else 0
        icmp_pct = round(total_icmp / total_pkts, 1) if total_pkts > 0 else 0

        self._metrics_buffer.append({
            "pps": round(total_pps, 1),
            "bps": round(total_bps, 1),
            "tcp_pct": tcp_pct,
            "udp_pct": udp_pct,
            "icmp_pct": icmp_pct,
            "conn_count": 0,
            "threshold": round(self.baseline.threshold, 1),
        })

        now = time.monotonic()
        if now - self._last_metrics_push >= self._metrics_interval:
            self._last_metrics_push = now
            self._flush_metrics()
            # Push per-IP stats for top IPs (reuse vm-stats endpoint)
            self._flush_mirror_ip_stats(ip_snapshots)

    def _begin_ip_attack(self, ip: str, snap) -> None:
        """Open a new incident for a specific destination IP."""
        from ftagent.mirror_engine import IPSnapshot

        baseline = self.per_ip_baseline.get_baseline(ip)
        label = self.mirror_ip_labels.get(ip, "")
        label_str = f" ({label})" if label else ""

        logger.warning("MIRROR ATTACK DETECTED on %s%s -- PPS=%.0f threshold=%.0f",
                       ip, label_str, snap.pps, baseline.get("threshold", 0))

        # Classify from snapshot protocol data
        _snap_flags = snap.tcp_flags or {}
        _snap_flag_total = sum(_snap_flags.values()) if _snap_flags else 0
        _snap_syn_ratio = (_snap_flags.get("SYN", 0) / _snap_flag_total) if _snap_flag_total > 0 else 0.0
        _snap_top_ports = [{"port": p, "count": c} for p, c in snap.top_dst_ports] if snap.top_dst_ports else []
        _snap_frag_pct = getattr(snap, 'fragment_pct', 0.0)
        family = classify_attack(snap.tcp_pct, snap.udp_pct, snap.icmp_pct,
                                 syn_ratio=_snap_syn_ratio,
                                 top_ports=_snap_top_ports,
                                 tcp_flags=_snap_flags,
                                 fragment_pct=_snap_frag_pct)

        started_at = datetime.now(timezone.utc).isoformat()

        inc_data = {
            "peak_pps": round(snap.pps, 1),
            "peak_bps": round(snap.bps, 1),
            "started_at": started_at,
            "attack_family": family,
            "baseline_pps": round(baseline.get("avg_pps", 0), 1),
            "duration": 0,
            "inner_ip": ip,
            "mirror_mode": True,
            "source_ip_count": snap.src_ip_count,
            "fragment_pct": _snap_frag_pct,
        }
        if label:
            inc_data["inner_ip_label"] = label
        if snap.top_src_ips:
            inc_data["top_src_ips"] = [
                {"ip": sip, "count": cnt} for sip, cnt in snap.top_src_ips
            ]
        if snap.top_dst_ports:
            inc_data["top_dst_ports"] = [
                {"port": p, "count": cnt} for p, cnt in snap.top_dst_ports
            ]

        result = self.api.open_incident(inc_data)
        incident_uuid = ""
        if result and "uuid" in result:
            incident_uuid = result["uuid"]
            logger.info("Mirror incident opened for %s: %s", ip, incident_uuid)
            if "pending_commands" in result and result["pending_commands"]:
                for cmd in result["pending_commands"]:
                    self._execute_command(cmd)
        else:
            incident_uuid = str(uuid.uuid4())
            logger.warning("Using local mirror incident UUID for %s: %s",
                           ip, incident_uuid)

        self.active_attacks[ip] = {
            "incident_uuid": incident_uuid,
            "attack_start": time.time(),
            "peak_pps": snap.pps,
            "peak_bps": snap.bps,
            "below_count": 0,
            "last_update": time.monotonic(),
            "velocity_curve": [{"t": 0, "pps": round(snap.pps, 1)}],
            "family": family,
        }

        # Start BPF-filtered PCAP for this IP
        self._start_ip_pcap(ip, incident_uuid)

        # Fetch config for mitigation commands
        threading.Thread(target=self._fetch_config, daemon=True,
                         name=f"attack-config-{ip}").start()

    def _update_ip_attack(self, ip: str, snap) -> None:
        """Send periodic update for an ongoing per-IP attack."""
        state = self.active_attacks.get(ip)
        if not state or not state["incident_uuid"]:
            return

        state["last_update"] = time.monotonic()
        elapsed = time.time() - state["attack_start"]
        if len(state["velocity_curve"]) < 2000:
            state["velocity_curve"].append({
                "t": round(elapsed, 1),
                "pps": round(snap.pps, 1),
            })
        else:
            state["velocity_curve"][-1] = {"t": round(elapsed, 1), "pps": round(snap.pps, 1)}

        _snap_flags = snap.tcp_flags or {}
        _snap_flag_total = sum(_snap_flags.values()) if _snap_flags else 0
        _snap_syn_ratio = (_snap_flags.get("SYN", 0) / _snap_flag_total) if _snap_flag_total > 0 else 0.0
        _snap_top_ports = [{"port": p, "count": c} for p, c in snap.top_dst_ports] if snap.top_dst_ports else []
        _snap_frag_pct = getattr(snap, 'fragment_pct', 0.0)
        family = classify_attack(snap.tcp_pct, snap.udp_pct, snap.icmp_pct,
                                 syn_ratio=_snap_syn_ratio,
                                 top_ports=_snap_top_ports,
                                 tcp_flags=_snap_flags,
                                 fragment_pct=_snap_frag_pct)

        update_payload = {
            "peak_pps": round(state["peak_pps"], 1),
            "peak_bps": round(state["peak_bps"], 1),
            "attack_family": family,
            "protocol_breakdown": {
                "tcp": snap.tcp_pct,
                "udp": snap.udp_pct,
                "icmp": snap.icmp_pct,
                "fragments": _snap_frag_pct,
            },
            "source_ip_count": snap.src_ip_count,
            "top_src_ips": [
                {"ip": sip, "count": cnt} for sip, cnt in snap.top_src_ips
            ],
            "top_dst_ports": [
                {"port": p, "count": cnt} for p, cnt in snap.top_dst_ports
            ],
            "inner_ip": ip,
            "mirror_mode": True,
            "tcp_flag_breakdown": snap.tcp_flags,
            "fragment_pct": _snap_frag_pct,
        }
        label = self.mirror_ip_labels.get(ip, "")
        if label:
            update_payload["inner_ip_label"] = label

        self.api.update_incident(state["incident_uuid"], update_payload)

    def _end_ip_attack(self, ip: str) -> None:
        """Resolve an incident for a specific destination IP."""
        state = self.active_attacks.get(ip)
        if not state:
            return

        duration = time.time() - state["attack_start"]
        family = state.get("family", "unknown")

        # Get last known snapshot for subtype classification
        last_snap = self._last_snapshot.get(ip)
        tcp_flags = last_snap.tcp_flags if last_snap else {}
        avg_pkt = last_snap.avg_pkt_size if last_snap else 0
        _snap_frag_pct = getattr(last_snap, 'fragment_pct', 0.0) if last_snap else 0.0
        top_ports = []
        if last_snap and last_snap.top_dst_ports:
            top_ports = [{"port": p, "count": c} for p, c in last_snap.top_dst_ports]

        subtype = classify_subtype(family, top_ports, tcp_flags, avg_pkt,
                                   fragment_pct=_snap_frag_pct)

        label = self.mirror_ip_labels.get(ip, "")
        label_str = f" ({label})" if label else ""
        logger.warning("MIRROR ATTACK ENDED on %s%s -- duration=%.0fs peak_pps=%.0f family=%s subtype=%s",
                       ip, label_str, duration, state["peak_pps"], family, subtype or "none")

        if state["incident_uuid"]:
            resolve_data = {
                "duration_seconds": round(duration, 1),
                "peak_pps": round(state["peak_pps"], 1),
                "peak_bps": round(state["peak_bps"], 1),
                "attack_family": family,
                "attack_subtype": subtype or None,
                "inner_ip": ip,
                "mirror_mode": True,
                "velocity_curve": state["velocity_curve"],
            }
            if last_snap:
                resolve_data["protocol_breakdown"] = {
                    "tcp": last_snap.tcp_pct,
                    "udp": last_snap.udp_pct,
                    "icmp": last_snap.icmp_pct,
                    "fragments": _snap_frag_pct,
                }
                resolve_data["source_ip_count"] = last_snap.src_ip_count
                resolve_data["top_src_ips"] = [
                    {"ip": sip, "count": cnt} for sip, cnt in last_snap.top_src_ips
                ]
                resolve_data["top_dst_ports"] = top_ports
                resolve_data["tcp_flag_breakdown"] = tcp_flags
                resolve_data["avg_pkt_length"] = avg_pkt
                resolve_data["fragment_pct"] = _snap_frag_pct

            self.api.resolve_incident(state["incident_uuid"], resolve_data)

        # Stop per-IP PCAP
        self._stop_ip_pcap(ip, state.get("incident_uuid", ""))

        del self.active_attacks[ip]

    _MAX_IP_PCAP_PROCS = 10  # prevent subprocess explosion during wide DDoS

    def _start_ip_pcap(self, ip: str, incident_uuid: str) -> None:
        """Start a BPF-filtered tcpdump capture for a specific attacked IP."""
        import subprocess
        if not self.pcap.enabled:
            return
        if len(self._ip_pcap_procs) >= self._MAX_IP_PCAP_PROCS:
            logger.warning("Mirror PCAP cap reached (%d), skipping %s",
                           self._MAX_IP_PCAP_PROCS, ip)
            return
        pcap_dir = self.pcap.pcap_dir
        os.makedirs(pcap_dir, exist_ok=True)
        pcap_path = os.path.join(pcap_dir, f"mirror_{incident_uuid}.pcap")

        try:
            cmd = [
                "tcpdump", "-i", self.mirror_interface,
                "-nn", "-w", pcap_path,
                "-s", str(self.pcap.snaplen or 0),
                "-c", str(self.pcap.max_capture),
                f"dst host {ip}",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            self._ip_pcap_procs[ip] = proc
            logger.info("Mirror PCAP started for %s (pid=%d, file=%s)",
                        ip, proc.pid, pcap_path)
        except Exception as e:
            logger.warning("Could not start mirror PCAP for %s: %s", ip, e)

    def _stop_ip_pcap(self, ip: str, incident_uuid: str) -> None:
        """Stop per-IP PCAP capture and upload."""
        import subprocess
        proc = self._ip_pcap_procs.pop(ip, None)
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if incident_uuid:
            pcap_path = os.path.join(self.pcap.pcap_dir,
                                     f"mirror_{incident_uuid}.pcap")
            if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24:
                threading.Thread(
                    target=self.api.upload_pcap,
                    args=(incident_uuid, pcap_path),
                    daemon=True,
                ).start()

    def _flush_mirror_ip_stats(self, ip_snapshots: dict) -> None:
        """Push per-IP stats to backend (top N IPs + all attacking IPs)."""
        if not ip_snapshots:
            return

        # Build list: always include attacking IPs, then fill with top by PPS
        ip_stats = []
        attacking_ips = set(self.active_attacks.keys())

        # First: all attacking IPs
        for ip in attacking_ips:
            snap = ip_snapshots.get(ip)
            if snap:
                bl = self.per_ip_baseline.get_baseline(ip)
                ip_stats.append({
                    "ip": ip,
                    "label": self.mirror_ip_labels.get(ip, ""),
                    "pps": round(snap.pps, 1),
                    "bps": round(snap.bps, 1),
                    "tcp_pct": snap.tcp_pct,
                    "udp_pct": snap.udp_pct,
                    "icmp_pct": snap.icmp_pct,
                    "baseline_pps": bl.get("avg_pps", 0),
                    "threshold_pps": bl.get("threshold", 0),
                    "status": "attack",
                    "src_ip_count": snap.src_ip_count,
                })

        # Then: top IPs by PPS (exclude already-added attacking IPs)
        remaining = sorted(
            [(ip, s) for ip, s in ip_snapshots.items() if ip not in attacking_ips],
            key=lambda x: x[1].pps, reverse=True,
        )[:100]

        for ip, snap in remaining:
            bl = self.per_ip_baseline.get_baseline(ip)
            threshold = bl.get("threshold", 0)
            status = "normal"
            if threshold > 0 and snap.pps > threshold * 0.7:
                status = "elevated"
            ip_stats.append({
                "ip": ip,
                "label": self.mirror_ip_labels.get(ip, ""),
                "pps": round(snap.pps, 1),
                "bps": round(snap.bps, 1),
                "tcp_pct": snap.tcp_pct,
                "udp_pct": snap.udp_pct,
                "icmp_pct": snap.icmp_pct,
                "baseline_pps": bl.get("avg_pps", 0),
                "threshold_pps": bl.get("threshold", 0),
                "status": status,
                "src_ip_count": snap.src_ip_count,
            })

        self.api._post("/agent/mirror-metrics", {
            "ips": ip_stats,
            "total_pps": round(self._last_aggregate_pps, 1),
            "total_bps": round(self._last_aggregate_bps, 1),
            "tracked_ip_count": len(ip_snapshots),
            "active_attacks": len(self.active_attacks),
            "mirror_engine": self.mirror_engine.stats,
        }, timeout=10)

    def _heartbeat_loop(self) -> None:
        """Override heartbeat to include mirror-specific stats."""
        _last_update_check = time.monotonic()
        while not self.shutdown.is_set():
            self.shutdown.wait(30)
            if self.shutdown.is_set():
                break
            try:
                hb = {
                    "version": VERSION,
                    "baseline_ready": self.baseline.baseline_ready,
                    "baseline_avg_pps": round(self.baseline.avg_pps, 1),
                    "baseline_p99_pps": round(self.baseline.p99_pps, 1),
                    "baseline_hourly_ready": self.baseline.hourly_ready,
                    "baseline_current_hour_p99": round(self.baseline.current_hour_p99, 1),
                    "circuit_breaker": self.api.circuit_breaker_state,
                    "retry_queue_size": len(self.api.retry_queue),
                    "gre_dedup_enabled": self.gre_decap.enabled,
                    "hypervisor_mode": False,
                    "pcap_active": self.pcap.enabled,
                    "flow_active": self.flow is not None,
                    # Mirror-specific
                    "mirror_mode": True,
                    "mirror_interface": self.mirror_interface,
                    "mirror_tracked_ips": self.per_ip_baseline.ip_count,
                    "mirror_active_attacks": len(self.active_attacks),
                    "mirror_engine": self.mirror_engine.stats,
                }
                if self.flow:
                    hb["flow_collector"] = self.flow.stats
                self.api.heartbeat(hb)
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)

            if time.monotonic() - _last_update_check >= 21600:
                _last_update_check = time.monotonic()
                check_for_updates()


# ---------------------------------------------------------------------------
# CLI: Setup Wizard
# ---------------------------------------------------------------------------

def setup_wizard(config_path: str) -> None:
    print("\n  Flowtriq Agent Setup Wizard\n")
    cfg = dict(DEFAULT_CONFIG)

    cfg["api_key"] = input("  API Key: ").strip()
    node = ""
    while not node:
        node = input("  Node UUID (from your Flowtriq dashboard): ").strip()
        if not node:
            print("  Node UUID is required. Copy it from your Flowtriq dashboard → Nodes.")
    cfg["node_uuid"] = node
    base = input(f"  API Base URL [{cfg['api_base']}]: ").strip()
    if base:
        cfg["api_base"] = base
    iface = input(f"  Network interface [{cfg['interface']}]: ").strip()
    if iface:
        cfg["interface"] = iface
    pcap = input("  Enable PCAP capture? [Y/n]: ").strip().lower()
    cfg["pcap_enabled"] = pcap != "n"

    if cfg["pcap_enabled"]:
        print("\n  PCAP capture mode:")
        print("    1. scapy   - Real-time per-packet analysis (default)")
        print("                 Best for most servers. Higher CPU at very high PPS (50K+).")
        print("    2. tcpdump - Native kernel-speed capture, near-zero CPU")
        print("                 Best for high-traffic servers or nodes that regularly see 10K+ PPS.")
        pcap_choice = input("  Choose [1/2, default=1]: ").strip()
        if pcap_choice == "2":
            cfg["pcap_mode"] = "tcpdump"
            print("  Using tcpdump mode. The agent will auto-install tcpdump if needed.")
        else:
            cfg["pcap_mode"] = "scapy"

    # Mirror/SPAN mode
    print("\n  Monitoring Mode:")
    print("    1. Agent mode (default) - Monitor this server's own traffic")
    print("    2. Mirror/SPAN mode    - Monitor mirrored traffic from a switch/router")
    print("                             Detects attacks on any IP in the monitored segment")
    mode_choice = input("  Choose [1/2, default=1]: ").strip()
    if mode_choice == "2":
        cfg["mirror_mode"] = True
        mirror_iface = input("  Mirror interface (NIC connected to SPAN port): ").strip()
        if mirror_iface:
            cfg["mirror_interface"] = mirror_iface
        else:
            print("  Warning: mirror_interface is required for mirror mode.")
        subnets_input = input("  Monitored subnets (comma-separated CIDRs, blank=all): ").strip()
        if subnets_input:
            cfg["mirror_subnets"] = [s.strip() for s in subnets_input.split(",") if s.strip()]
        capture_mode = input("  Capture mode [af_packet/tcpdump, default=af_packet]: ").strip().lower()
        if capture_mode == "tcpdump":
            cfg["mirror_capture_mode"] = "tcpdump"
        else:
            cfg["mirror_capture_mode"] = "af_packet"
        print("  Mirror mode configured. Per-IP DDoS detection will be active.")

    # GRE interface check
    print("\n  GRE Tunnel Setup:")
    tunnels = detect_gre_tunnels()
    if tunnels:
        names = [t["name"] for t in tunnels]
        print(f"  Detected GRE tunnel(s): {', '.join(names)}")
        print("  GRE deduplication prevents stats inflation from encapsulation overhead.")
        gre = input("  Enable GRE deduplication? [Y/n]: ").strip().lower()
        cfg["gre_mode"] = "disabled" if gre == "n" else "enabled"
        hyp = input("  Enable hypervisor mode (per-VM traffic breakdown)? [y/N]: ").strip().lower()
        cfg["hypervisor_mode"] = hyp in ("y", "yes")
    else:
        detected = detect_gre_interface(cfg.get("interface", "auto"))
        if detected:
            print(f"  Interface {cfg['interface']} appears to be a GRE tunnel.")
            gre = input("  Enable GRE deduplication? [Y/n]: ").strip().lower()
            cfg["gre_mode"] = "disabled" if gre == "n" else "enabled"
        else:
            cfg["gre_mode"] = "auto"  # auto-detect at runtime

    save_config(config_path, cfg)
    print(f"\n  Config written to {config_path}")
    print(f"  Node UUID: {cfg['node_uuid']}\n")


# ---------------------------------------------------------------------------
# CLI: Install systemd service
# ---------------------------------------------------------------------------

SYSTEMD_UNIT = """[Unit]
Description=Flowtriq DDoS Detection Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


def install_service() -> None:
    script = os.path.abspath(__file__)
    unit = SYSTEMD_UNIT.format(script_path=script)
    svc_path = "/etc/systemd/system/ftagent.service"
    try:
        with open(svc_path, "w") as f:
            f.write(unit)
        print(f"  Service file written to {svc_path}")
        os.system("systemctl daemon-reload")
        print("  Run: systemctl enable --now ftagent")
    except PermissionError:
        print("  Error: must run as root to install service.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI: Test connectivity
# ---------------------------------------------------------------------------

def test_connectivity(config_path: str) -> None:
    if not REQUESTS_AVAILABLE:
        print("  Error: 'requests' package is required. pip install requests")
        sys.exit(1)
    cfg = load_config(config_path)
    if not cfg["api_key"]:
        print("  Error: api_key not set. Run --setup first.")
        sys.exit(1)
    client = APIClient(cfg)
    print(f"  Testing connection to {cfg['api_base']} ...")
    if client.test_connectivity():
        ok = f"{Fore.GREEN}OK{Style.RESET_ALL}" if COLOR else "OK"
        print(f"  Connection: {ok}")
    else:
        fail = f"{Fore.RED}FAILED{Style.RESET_ALL}" if COLOR else "FAILED"
        print(f"  Connection: {fail}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Flowtriq DDoS Detection Agent v{VERSION}")
    parser.add_argument("--version", action="version",
                        version=f"ftagent {VERSION}")
    parser.add_argument("--config", default=CONFIG_PATH,
                        help="Path to config file")
    parser.add_argument("--setup", action="store_true",
                        help="Run interactive setup wizard")
    parser.add_argument("--api-key", default=None,
                        help="API key (skips interactive setup)")
    parser.add_argument("--node-uuid", default=None,
                        help="Node UUID (skips interactive setup)")
    parser.add_argument("--test", action="store_true",
                        help="Test API connectivity")
    parser.add_argument("--install-service", action="store_true",
                        help="Install systemd service unit")
    parser.add_argument("--update", action="store_true",
                        help="Check for and install agent updates")
    parser.add_argument("--no-update-check", action="store_true",
                        help="Skip automatic update check on startup")
    parser.add_argument("--tui", action="store_true",
                        help="Enable terminal UI dashboard (requires 'rich' package)")
    args = parser.parse_args()

    if args.update:
        check_for_updates(force=True, interactive=True)
        return

    # Non-interactive setup: --api-key + --node-uuid writes config directly
    if args.api_key and args.node_uuid:
        cfg = dict(DEFAULT_CONFIG)
        cfg["api_key"] = args.api_key
        cfg["node_uuid"] = args.node_uuid
        save_config(args.config, cfg)
        print(f"  Config written to {args.config}")
        print(f"  API key: {args.api_key[:8]}...{args.api_key[-4:]}")
        print(f"  Node UUID: {args.node_uuid}")
        return

    if args.setup:
        setup_wizard(args.config)
        return

    if args.install_service:
        install_service()
        return

    if not REQUESTS_AVAILABLE:
        print("Error: 'requests' package is required. pip install requests")
        sys.exit(1)

    cfg = load_config(args.config)
    cfg["_config_path"] = args.config  # pass through so PcapCapture can reference it
    setup_logging(cfg["log_file"], cfg["log_level"])

    if args.test:
        test_connectivity(args.config)
        return

    if not cfg["api_key"]:
        logger.error("No api_key configured. Run: ftagent --setup")
        sys.exit(1)

    if not cfg["node_uuid"]:
        logger.error("No node_uuid configured. Set it to the Node UUID from your Flowtriq dashboard. Run: ftagent --setup")
        sys.exit(1)

    # Check for updates on startup (non-blocking, logs only)
    if not args.no_update_check:
        check_for_updates(force=False, interactive=False)

    if cfg.get("mirror_mode"):
        agent = MirrorAgent(cfg)
    else:
        agent = Agent(cfg)

    if args.tui:
        from ftagent.tui import run_tui
        run_tui(agent)
    else:
        agent.run()


if __name__ == "__main__":
    main()
