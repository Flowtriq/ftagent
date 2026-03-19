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
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.4.6"
CONFIG_PATH = "/etc/ftagent/config.json"
DEFAULT_CONFIG = {
    "api_key": "",
    "node_uuid": "",  # Required — copy from Flowtriq dashboard → Nodes
    "api_base": "https://flowtriq.com/api/v1",
    "interface": "auto",
    "pcap_enabled": True,
    "pcap_dir": "/var/lib/ftagent/pcaps",
    "log_file": "/var/log/ftagent.log",
    "log_level": "INFO",
    "dynamic_threshold": True,
}

# Optional dependency imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, PcapWriter, sniff
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

def check_for_updates() -> None:
    """Check GitHub releases Atom feed for a newer version of ftagent."""
    try:
        import urllib.request
        import xml.etree.ElementTree as ET

        url = "https://github.com/Flowtriq/ftagent/releases.atom"
        req = urllib.request.Request(url, headers={"User-Agent": f"ftagent/{VERSION}"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = resp.read()
        root = ET.fromstring(data)

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall("atom:entry", ns)
        if not entries:
            return

        title = entries[0].find("atom:title", ns)
        if title is None or title.text is None:
            return

        latest = title.text.strip().lstrip("vV")
        current = VERSION.lstrip("vV")

        if latest != current:
            # Compare version tuples
            def _ver_tuple(v):
                parts = []
                for p in v.split("."):
                    try:
                        parts.append(int(p))
                    except ValueError:
                        parts.append(0)
                return tuple(parts)

            if _ver_tuple(latest) > _ver_tuple(current):
                logger.warning(
                    "A newer version of ftagent is available: %s (current: %s). "
                    "Run: pip install --upgrade ftagent",
                    latest, VERSION,
                )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ftagent")


def setup_logging(log_file: str, log_level: str) -> None:
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
        fh = logging.FileHandler(log_file)
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
    def __init__(self, cfg: dict):
        self.base = cfg["api_base"].rstrip("/")
        self.api_key = cfg["api_key"]
        self.node_uuid = cfg["node_uuid"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "X-Node-UUID": self.node_uuid,
            "Content-Type": "application/json",
            "User-Agent": f"ftagent/{VERSION}",
        })
        self.retry_queue: collections.deque = collections.deque(maxlen=2000)

    def _post(self, path: str, payload: dict, timeout: int = 10,
              retries: int = 3) -> Optional[dict]:
        url = f"{self.base}{path}"
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.post(url, json=payload, timeout=timeout)
                resp.raise_for_status()
                if resp.content:
                    return resp.json()
                return {}
            except Exception as exc:
                logger.warning("API POST %s attempt %d/%d failed: %s",
                               path, attempt, retries, exc)
                if attempt < retries:
                    time.sleep(min(2 ** attempt, 10))
                else:
                    self.retry_queue.append(("POST", path, payload, timeout))
        return None

    def _get(self, path: str, timeout: int = 10) -> Optional[dict]:
        url = f"{self.base}{path}"
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("API GET %s failed: %s", path, exc)
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

    def upload_pcap(self, inc_uuid: str, filepath: str,
                    retries: int = 3) -> None:
        url = f"{self.base}/agent/incidents/{inc_uuid}/pcap"
        file_size = os.path.getsize(filepath)
        chunk_size = 2 * 1024 * 1024  # 2 MB chunks

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
                                },
                                timeout=60,
                            )
                            resp.raise_for_status()
                            logger.debug("Chunk %d/%d uploaded", i + 1,
                                         total_chunks)

                logger.info("PCAP uploaded for incident %s (attempt %d)",
                            inc_uuid, attempt)
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
                      "baseline_avg_pps": 0, "baseline_p99_pps": 0},
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
        if now - self._last_conn_read >= self._conn_count_interval:
            self.conn_count = self._read_conn_count()
            self._last_conn_read = now

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
        count = 0
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    count += sum(1 for _ in f) - 1
            except OSError:
                pass
        return max(count, 0)


# ---------------------------------------------------------------------------
# Baseline Manager
# ---------------------------------------------------------------------------

class BaselineManager:
    WINDOW = 300
    _RECALC_EVERY = 10  # recalculate percentiles every N samples

    def __init__(self):
        self.samples: collections.deque = collections.deque(maxlen=self.WINDOW)
        self.avg_pps = 0.0
        self.p95_pps = 0.0
        self.p99_pps = 0.0
        self.threshold = 1000.0
        self.baseline_ready = False
        self._since_recalc = 0
        self._running_sum = 0.0

    def add(self, pps: float) -> None:
        # Track evicted sample for running sum
        if len(self.samples) == self.samples.maxlen:
            self._running_sum -= self.samples[0]
        self.samples.append(pps)
        self._running_sum += pps
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
            self.threshold = max(self.p99_pps * 3, 1000.0)

        if n >= self.WINDOW:
            self.baseline_ready = True


# ---------------------------------------------------------------------------
# Traffic Analyser
# ---------------------------------------------------------------------------

class TrafficAnalyser:
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.tcp_flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0,
                          "PSH": 0, "URG": 0}
        self.src_ips: dict = {}        # ip -> count
        self.src_ip_detail: dict = {}  # ip -> {tcp, udp, icmp, syn, ack, bytes, ttls}
        self.dst_ports: dict = {}
        self.pkt_lengths: list = []
        self.ttl_values: list = []
        self.dns_queries: dict = {}
        self.total_packets = 0
        self.ioc_hits: list = []

    def process_packet(self, pkt, ioc_matcher=None) -> None:
        self.total_packets += 1

        if not SCAPY_AVAILABLE:
            return

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src = ip.src
            self.src_ips[src] = self.src_ips.get(src, 0) + 1
            self.pkt_lengths.append(len(pkt))
            self.ttl_values.append(ip.ttl)

            # Per-IP detail tracking for confidence scoring
            if src not in self.src_ip_detail:
                self.src_ip_detail[src] = {
                    "tcp": 0, "udp": 0, "icmp": 0,
                    "syn": 0, "ack": 0, "bytes": 0, "ttls": set()
                }
            d = self.src_ip_detail[src]
            d["bytes"] += len(pkt)
            d["ttls"].add(ip.ttl)

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                self.dst_ports[tcp.dport] = self.dst_ports.get(tcp.dport, 0) + 1
                d["tcp"] += 1
                flags = tcp.flags
                if flags & 0x02:
                    self.tcp_flags["SYN"] += 1
                    d["syn"] += 1
                if flags & 0x10:
                    self.tcp_flags["ACK"] += 1
                    d["ack"] += 1
                if flags & 0x04:
                    self.tcp_flags["RST"] += 1
                if flags & 0x01:
                    self.tcp_flags["FIN"] += 1
                if flags & 0x08:
                    self.tcp_flags["PSH"] += 1
                if flags & 0x20:
                    self.tcp_flags["URG"] += 1

            elif pkt.haslayer(UDP):
                self.dst_ports[pkt[UDP].dport] = (
                    self.dst_ports.get(pkt[UDP].dport, 0) + 1)
                d["udp"] += 1

            elif pkt.haslayer(ICMP):
                d["icmp"] += 1

            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors="ignore")
                    self.dns_queries[qname] = self.dns_queries.get(qname, 0) + 1
                except Exception:
                    pass

        if ioc_matcher and pkt.haslayer(Raw):
            hit = ioc_matcher.check(bytes(pkt[Raw].load))
            if hit:
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
        return len(self.src_ips) > 300

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
            result.append(entry)
        return result

    def top_dst_ports(self, n: int = 20) -> list:
        return [{"port": p, "count": c}
                for p, c in sorted(self.dst_ports.items(),
                                   key=lambda x: x[1], reverse=True)[:n]]

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
# PCAP Capture
# ---------------------------------------------------------------------------

class PcapCapture:
    def __init__(self, cfg: dict, iface: str, analyser: TrafficAnalyser,
                 ioc_matcher: IOCMatcher):
        self.enabled = cfg.get("pcap_enabled", True) and SCAPY_AVAILABLE
        self.pcap_dir = cfg.get("pcap_dir", "/var/lib/ftagent/pcaps")
        self.iface = iface
        self.analyser = analyser
        self.ioc_matcher = ioc_matcher
        self.ring_buffer: collections.deque = collections.deque(maxlen=1000)
        self.capture_packets: list = []
        self.capturing = False
        self.max_capture = 10000
        self._thread = None
        self._stop_event = threading.Event()
        self._pkt_counter = 0
        self._analyse_every = 10  # deep-analyse every Nth packet during capture

    def background_ring(self, shutdown: threading.Event) -> None:
        if not self.enabled:
            return
        logger.info("PCAP ring buffer active on %s", self.iface)
        try:
            sniff(iface=self.iface, prn=self._ring_cb, store=False,
                  stop_filter=lambda _: shutdown.is_set())
        except Exception as exc:
            logger.warning("Ring buffer sniff error: %s", exc)

    def _ring_cb(self, pkt) -> None:
        self.ring_buffer.append(pkt)
        if self.capturing and len(self.capture_packets) < self.max_capture:
            self.capture_packets.append(pkt)
            # Deep analysis (protocol parsing + IOC matching) is expensive.
            # Sample every Nth packet to keep CPU bounded at high PPS.
            self._pkt_counter += 1
            if self._pkt_counter % self._analyse_every == 0:
                self.analyser.process_packet(pkt, self.ioc_matcher)

    def start_capture(self, incident_uuid: str = "",
                       api_client=None) -> None:
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
            pkt_count = len(self.capture_packets)
            threshold = (self._chunk_index + 1) * self._chunk_size
            if pkt_count >= threshold:
                self._flush_chunk()

    def _flush_chunk(self) -> Optional[str]:
        """Write current packets to a chunk file and upload it."""
        start_idx = self._chunk_index * self._chunk_size
        end_idx = start_idx + self._chunk_size
        chunk_pkts = self.capture_packets[start_idx:end_idx]
        if not chunk_pkts:
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
            # Upload in background
            if self._api_client:
                threading.Thread(
                    target=self._api_client.upload_pcap,
                    args=(self._incident_uuid, filepath),
                    daemon=True,
                ).start()
            self._uploaded_chunks.append(filepath)
            return filepath
        except Exception as exc:
            logger.error("PCAP chunk write failed: %s", exc)
            return None

    def stop_capture(self, incident_uuid: str) -> Optional[str]:
        self.capturing = False
        # Stop chunk upload thread
        if hasattr(self, '_chunk_stop'):
            self._chunk_stop.set()
        if not self.capture_packets:
            return None
        Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filepath = os.path.join(self.pcap_dir, f"{incident_uuid}_{ts}.pcap")
        try:
            writer = PcapWriter(filepath, append=False, sync=True)
            for pkt in self.capture_packets:
                writer.write(pkt)
            writer.close()
            logger.info("PCAP written: %s (%d packets)",
                        filepath, len(self.capture_packets))
            self.capture_packets = []
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
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\S+)'
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
        # Accumulated attack-wide stats
        self._attack_ua_counts: dict = {}
        self._attack_threat_hits: dict = {}
        self._attack_status_totals: dict = {}
        self._attack_path_totals: dict = {}
        self._attack_ip_totals: dict = {}
        self._attack_total_requests: int = 0

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
                self.file.close()
                self.open()
        except OSError:
            pass

        new_lines = []
        try:
            while True:
                line = self.file.readline()
                if not line:
                    break
                new_lines.append(line.rstrip("\n"))
        except (OSError, IOError):
            pass

        now = time.time()
        for line in new_lines:
            parsed = self._parse_line(line)
            if parsed:
                self._requests.append((now, *parsed))

        cutoff = now - self._window
        self._requests = [r for r in self._requests if r[0] >= cutoff]

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
                if ip and status:
                    return (ip, method, path, status, size, ua, resp_time)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
            return None

        # Standard combined/CLF format (nginx, Apache, Tomcat, Gunicorn, LiteSpeed, HAProxy)
        m = LOG_PATTERN_COMBINED.match(line)
        if m:
            ip = m.group(1)
            method, path = m.group(3), m.group(4)
            status = int(m.group(5))
            size_str = m.group(6)
            ua = m.group(7) or ""
            size = int(size_str) if size_str != "-" else 0
            path = path.split("?")[0] if "?" in path else path
            return (ip, method, path, status, size, ua, None)
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

        for req in self._requests:
            ts, ip, method, path, status, size, ua = req[0], req[1], req[2], req[3], req[4], req[5], req[6]
            resp_time = req[7] if len(req) > 7 else None

            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            path_counts[path] = path_counts.get(path, 0) + 1
            code_group = f"{status // 100}xx"
            status_counts[code_group] = status_counts.get(code_group, 0) + 1

            # User-Agent tracking
            if ua:
                ua_short = ua[:120]
                ua_counts[ua_short] = ua_counts.get(ua_short, 0) + 1
                if L7_BOT_UA_PATTERNS.search(ua):
                    bot_request_count += 1

            # Threat pattern detection on path + query
            full_path = path
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

        # RPS threshold: use override if set, otherwise auto-calculate.
        # During warmup (no baseline yet), only trigger RPS signal if RPS is
        # clearly extreme in absolute terms (>500 RPS).
        if self._rps_threshold_override:
            rps_threshold = self._rps_threshold_override
        elif warmup:
            rps_threshold = 500  # absolute floor during warmup
        else:
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
            self._attack_start = time.time()
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

    def _accumulate_attack_stats(self, stats: dict):
        """Merge per-window stats into attack-wide accumulators."""
        self._attack_total_requests += stats.get("total_requests", 0)
        for ua, cnt in stats.get("top_user_agents", {}).items():
            self._attack_ua_counts[ua] = self._attack_ua_counts.get(ua, 0) + cnt
        for pat, cnt in stats.get("threat_patterns", {}).items():
            self._attack_threat_hits[pat] = self._attack_threat_hits.get(pat, 0) + cnt
        for code, cnt in stats.get("status_codes", {}).items():
            self._attack_status_totals[code] = self._attack_status_totals.get(code, 0) + cnt
        for path, cnt in stats.get("top_paths", {}).items():
            self._attack_path_totals[path] = self._attack_path_totals.get(path, 0) + cnt
        for ip, cnt in stats.get("top_ips", {}).items():
            self._attack_ip_totals[ip] = self._attack_ip_totals.get(ip, 0) + cnt

    def get_attack_summary(self) -> dict:
        """Return accumulated attack-wide data for incident enrichment."""
        top_uas = sorted(self._attack_ua_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        top_paths = sorted(self._attack_path_totals.items(), key=lambda x: x[1], reverse=True)[:20]
        top_ips = sorted(self._attack_ip_totals.items(), key=lambda x: x[1], reverse=True)[:50]
        return {
            "top_user_agents": dict(top_uas),
            "threat_patterns": self._attack_threat_hits,
            "status_codes": self._attack_status_totals,
            "top_paths": dict(top_paths),
            "top_ips": dict(top_ips),
            "total_requests": self._attack_total_requests,
        }

    def _check_attack_end(self, stats: dict) -> Optional[dict]:
        rps = stats["rps"]
        total = stats.get("total_requests", 0)
        error_rate = stats.get("error_rate", 0)
        elapsed = time.time() - self._attack_start

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
                    syn_ratio: float = 0.0, dns_detected: bool = False) -> str:
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
    # Last resort: pick dominant protocol.
    # Only label TCP-dominant as syn_flood when we have actual flag evidence
    # (syn_ratio > 0); without it, return unknown so _end_attack can correct.
    if udp_pct >= tcp_pct and udp_pct >= icmp_pct and udp_pct > 5:
        return "udp_flood"
    if tcp_pct >= udp_pct and tcp_pct >= icmp_pct and tcp_pct > 5:
        return "syn_flood" if syn_ratio > 0 else "unknown"
    if icmp_pct > 5:
        return "icmp_flood"
    return "unknown"


# ---------------------------------------------------------------------------
# Agent Core
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.shutdown = threading.Event()
        self.api = APIClient(cfg)
        self.monitor = PPSMonitor(cfg.get("interface", "auto"))
        self.baseline = BaselineManager()
        self.analyser = TrafficAnalyser()
        self.ioc_matcher = IOCMatcher()
        self.pcap = PcapCapture(cfg, self.monitor.interface,
                                self.analyser, self.ioc_matcher)

        # L7 monitoring (configured via server config)
        self.l7: Optional[L7Monitor] = None
        self.l7_enabled = False
        self.l7_thread_running = False
        self.l7_incident_uuid = ""
        self.l7_last_metric_push: float = 0.0

        self.attacking = False
        self.attack_start: float = 0.0
        self.incident_uuid: str = ""
        self.peak_pps: float = 0.0
        self.peak_bps: float = 0.0
        self.below_count: int = 0
        self.velocity_curve: list = []
        self.last_update: float = 0.0
        self.server_threshold: float | None = None

        # Metrics batching: buffer locally, POST every N seconds
        self._metrics_interval = 5  # seconds between API POSTs
        self._metrics_buffer: list = []
        self._last_metrics_push: float = 0.0

    @property
    def threshold(self) -> float:
        if self.server_threshold is not None:
            return self.server_threshold
        return self.baseline.threshold

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
        if self.pcap.enabled:
            threads.append(threading.Thread(
                target=self.pcap.background_ring, args=(self.shutdown,),
                daemon=True, name="pcap-ring"))

        for t in threads:
            t.start()

        self._fetch_config()

        # Start L7 thread if enabled by server config
        if self.l7 and self.l7_enabled and not self.l7_thread_running:
            self.l7_thread_running = True
            l7t = threading.Thread(target=self._l7_loop, daemon=True, name="l7-monitor")
            l7t.start()

        logger.info("Entering main monitoring loop")
        while not self.shutdown.is_set():
            loop_start = time.monotonic()
            try:
                self._tick()
            except Exception as exc:
                logger.error("Tick error: %s", exc)
            elapsed = time.monotonic() - loop_start
            sleep_for = max(0, 1.0 - elapsed)
            self.shutdown.wait(sleep_for)

        logger.info("Agent shutting down")

    def _signal_handler(self, signum, frame) -> None:
        logger.info("Received signal %d, shutting down...", signum)
        self.shutdown.set()

    def _tick(self) -> None:
        if not self.monitor.read():
            return

        pps = self.monitor.pps
        bps = self.monitor.bps
        # Don't pollute baseline with attack traffic — it would inflate the
        # threshold and make future detection less sensitive.
        if not self.attacking:
            self.baseline.add(pps)

        # Buffer metrics locally, flush every _metrics_interval seconds.
        # Detection still runs every 1s tick — only the API POST is batched.
        self._metrics_buffer.append({
            "pps": round(pps, 1),
            "bps": round(bps, 1),
            "tcp_pct": self.monitor.tcp_pct,
            "udp_pct": self.monitor.udp_pct,
            "icmp_pct": self.monitor.icmp_pct,
            "conn_count": self.monitor.conn_count,
            "threshold": round(self.threshold, 1),
        })
        now = time.monotonic()
        if now - self._last_metrics_push >= self._metrics_interval:
            self._last_metrics_push = now
            self._flush_metrics()

        if not self.attacking:
            if pps > self.threshold:
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

    def _begin_attack(self) -> None:
        self.attacking = True
        self.attack_start = time.time()
        self.peak_pps = self.monitor.pps
        self.peak_bps = self.monitor.bps
        self.below_count = 0
        self.velocity_curve = []
        self.analyser.reset()
        self.last_update = time.monotonic()

        # Flush buffered metrics immediately so dashboard sees the spike
        self._flush_metrics()

        family = classify_attack(self.monitor.tcp_pct, self.monitor.udp_pct,
                                 self.monitor.icmp_pct)
        started_at = datetime.now(timezone.utc).isoformat()

        logger.warning("ATTACK DETECTED — PPS=%.0f threshold=%.0f family=%s",
                       self.peak_pps, self.threshold, family)

        # Alert-first: open incident before starting PCAP capture
        result = self.api.open_incident({
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "started_at": started_at,
            "attack_family": family,
            "duration": 0,
        })

        if result and "uuid" in result:
            self.incident_uuid = result["uuid"]
            logger.info("Incident opened: %s", self.incident_uuid)
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

    def _update_attack(self) -> None:
        self.last_update = time.monotonic()
        elapsed = time.time() - self.attack_start
        self.velocity_curve.append({
            "t": round(elapsed, 1),
            "pps": round(self.monitor.pps, 1),
        })

        family = classify_attack(self.monitor.tcp_pct, self.monitor.udp_pct,
                                 self.monitor.icmp_pct)

        self.api.update_incident(self.incident_uuid, {
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "attack_family": family,
            "protocol_breakdown": {
                "tcp": self.monitor.tcp_pct,
                "udp": self.monitor.udp_pct,
                "icmp": self.monitor.icmp_pct,
            },
            "source_ip_count": len(self.analyser.src_ips),
            "total_packets": self.analyser.total_packets,
            "ioc_hits": list(set(self.analyser.ioc_hits)),
            "spoofing_detected": self.analyser.spoofing_detected(),
            "botnet_detected": self.analyser.botnet_detected(),
        })

    def _end_attack(self) -> None:
        duration = time.time() - self.attack_start
        syn_total = sum(self.analyser.tcp_flags.values())
        syn_ratio = (self.analyser.tcp_flags["SYN"] / max(syn_total, 1))
        family = classify_attack(
            self.monitor.tcp_pct, self.monitor.udp_pct,
            self.monitor.icmp_pct,
            syn_ratio=syn_ratio,
            dns_detected=bool(self.analyser.dns_queries),
        )

        logger.warning("ATTACK ENDED — duration=%.0fs peak_pps=%.0f family=%s",
                       duration, self.peak_pps, family)

        self.api.resolve_incident(self.incident_uuid, {
            "duration_seconds": round(duration, 1),
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "attack_family": family,
            "protocol_breakdown": {
                "tcp": self.monitor.tcp_pct,
                "udp": self.monitor.udp_pct,
                "icmp": self.monitor.icmp_pct,
            },
            "ioc_hits": list(set(self.analyser.ioc_hits)),
            "spoofing_detected": self.analyser.spoofing_detected(),
            "botnet_detected": self.analyser.botnet_detected(),
            "total_packets": self.analyser.total_packets,
            "source_ip_count": len(self.analyser.src_ips),
            "src_ip_entropy": self.analyser.src_ip_entropy(),
            "tcp_flag_breakdown": self.analyser.tcp_flags,
            "dns_query_stats": self.analyser.dns_query_stats(),
            "pkt_length_histogram": self.analyser.pkt_length_histogram(),
            "ttl_distribution": self.analyser.ttl_distribution(),
            "velocity_curve": self.velocity_curve,
            "top_src_ips": self.analyser.top_src_ips(),
            "top_dst_ports": self.analyser.top_dst_ports(),
            "avg_pkt_length": self.analyser.avg_pkt_length(),
        })

        if self.pcap.enabled:
            pcap_path = self.pcap.stop_capture(self.incident_uuid)
            if pcap_path:
                threading.Thread(
                    target=self.api.upload_pcap,
                    args=(self.incident_uuid, pcap_path),
                    daemon=True,
                ).start()

        self.attacking = False
        self.incident_uuid = ""

    def _heartbeat_loop(self) -> None:
        _last_update_check = time.monotonic()
        while not self.shutdown.is_set():
            self.shutdown.wait(30)
            if self.shutdown.is_set():
                break
            try:
                self.api.heartbeat({
                    "version": VERSION,
                    "baseline_ready": self.baseline.baseline_ready,
                    "baseline_avg_pps": round(self.baseline.avg_pps, 1),
                    "baseline_p99_pps": round(self.baseline.p99_pps, 1),
                })
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)

            # Check for updates every 6 hours
            if time.monotonic() - _last_update_check >= 21600:
                _last_update_check = time.monotonic()
                check_for_updates()

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
                    for cmd in data["pending_commands"]:
                        self._execute_command(cmd)
                    logger.info("Command poll: processed %d commands",
                                len(data["pending_commands"]))
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
            if "pps_threshold" in data and data["pps_threshold"]:
                self.server_threshold = float(data["pps_threshold"])
                logger.info("Server threshold: %.0f", self.server_threshold)
            elif data.get("dynamic_threshold", True):
                self.server_threshold = None
            if "ioc_patterns" in data:
                self.ioc_matcher.load(data["ioc_patterns"])
            if "pcap_enabled" in data:
                self.pcap.enabled = data["pcap_enabled"] and SCAPY_AVAILABLE
            # Process pending commands (iptables rules from dashboard)
            if "pending_commands" in data and data["pending_commands"]:
                for cmd in data["pending_commands"]:
                    self._execute_command(cmd)

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

        except Exception as exc:
            logger.error("Config fetch error: %s", exc)

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
        stats = info.get("stats", {})
        result = self.api.open_incident({
            "peak_pps": 0,
            "peak_bps": 0,
            "rps": round(rps),
            "baseline_rps": round(baseline_rps, 1),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "attack_family": "http_flood",
            "attack_subtype": subtype,
        })
        if result and "uuid" in result:
            self.l7_incident_uuid = result["uuid"]
        else:
            self.l7_incident_uuid = str(uuid.uuid4())

        # Trigger PCAP capture for L7 attacks too
        if self.pcap.enabled:
            self.pcap.start_capture(
                incident_uuid=self.l7_incident_uuid,
                api_client=self.api)

        self.api.update_incident(self.l7_incident_uuid, {
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "rps": round(rps),
            "baseline_rps": round(baseline_rps, 1),
            "source_ip_count": stats.get("unique_ips", 0),
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(stats.get("top_ips", {}).items())[:50]],
            "top_dst_ports": stats.get("top_paths", {}),
            "protocol_breakdown": {"tcp": 100, "udp": 0, "icmp": 0},
            # New L7-specific fields
            "l7_error_rate": stats.get("error_rate", 0),
            "l7_status_codes": stats.get("status_codes", {}),
            "l7_top_user_agents": stats.get("top_user_agents", {}),
            "l7_threat_patterns": stats.get("threat_patterns", {}),
        })

    def _l7_update_attack(self, info: dict) -> None:
        if not self.l7_incident_uuid:
            return
        rps = info.get("rps", 0)
        if rps > getattr(self, 'l7_peak_rps', 0):
            self.l7_peak_rps = rps
        stats = info.get("stats", {})
        subtype = _classify_l7_subtype(stats) if stats else "l7_flood"
        self.api.update_incident(self.l7_incident_uuid, {
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "rps": round(rps),
            "baseline_rps": round(getattr(self, 'l7_baseline_rps', 0), 1),
            "source_ip_count": stats.get("unique_ips", 0),
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(stats.get("top_ips", {}).items())[:50]],
            "top_dst_ports": stats.get("top_paths", {}),
            "l7_error_rate": stats.get("error_rate", 0),
            "l7_status_codes": stats.get("status_codes", {}),
            "l7_top_user_agents": stats.get("top_user_agents", {}),
            "l7_threat_patterns": stats.get("threat_patterns", {}),
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
                self.pcap.stop_capture(self.l7_incident_uuid)
        except Exception as exc:
            logger.error("L7: PCAP stop error: %s", exc)

        stats = info.get("stats", {})
        summary = info.get("attack_summary", {})
        self.api.resolve_incident(self.l7_incident_uuid, {
            "duration_seconds": duration,
            "peak_pps": 0,
            "peak_bps": 0,
            "peak_rps": round(peak_rps),
            "baseline_rps": round(baseline_rps, 1),
            "attack_family": "http_flood",
            "attack_subtype": subtype,
            "protocol_breakdown": {"tcp": 100, "udp": 0, "icmp": 0},
            "source_ip_count": stats.get("unique_ips", 0),
            "top_src_ips": [{"ip": ip, "count": cnt}
                           for ip, cnt in list(stats.get("top_ips", {}).items())[:50]],
            "top_dst_ports": stats.get("top_paths", {}),
            # Full attack-wide L7 enrichment
            "l7_error_rate": stats.get("error_rate", 0),
            "l7_status_codes": summary.get("status_codes", stats.get("status_codes", {})),
            "l7_top_user_agents": summary.get("top_user_agents", stats.get("top_user_agents", {})),
            "l7_targeted_paths": summary.get("top_paths", stats.get("top_paths", {})),
            "l7_threat_patterns": summary.get("threat_patterns", stats.get("threat_patterns", {})),
        })
        self.l7_incident_uuid = ""
        self.l7_peak_rps = 0

    def _execute_command(self, cmd: dict) -> None:
        """Execute a pending command (iptables/sysctl) from the dashboard."""
        cmd_id = cmd.get("id", 0)
        cmd_type = cmd.get("command_type", "iptables")
        cmd_text = cmd.get("command_text", "")
        title = cmd.get("title", "")

        if not cmd_text:
            return

        logger.info("Executing %s command #%d: %s", cmd_type, cmd_id, title)

        allowed_prefixes = ("iptables ", "ip6tables ", "ipset ", "sysctl ")
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
            try:
                import subprocess
                result = subprocess.run(
                    line, shell=True, capture_output=True, text=True,
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
    parser.add_argument("--test", action="store_true",
                        help="Test API connectivity")
    parser.add_argument("--install-service", action="store_true",
                        help="Install systemd service unit")
    args = parser.parse_args()

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

    agent = Agent(cfg)
    agent.run()


if __name__ == "__main__":
    main()
