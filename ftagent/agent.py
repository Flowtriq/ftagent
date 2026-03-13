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
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.1.6"
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
        logger.info("Monitoring interface: %s", self.interface)

    @staticmethod
    def _resolve_interface(iface: str) -> str:
        if iface != "auto":
            return iface
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

        self.conn_count = self._read_conn_count()

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

    def __init__(self):
        self.samples: collections.deque = collections.deque(maxlen=self.WINDOW)
        self.avg_pps = 0.0
        self.p95_pps = 0.0
        self.p99_pps = 0.0
        self.threshold = 1000.0
        self.baseline_ready = False

    def add(self, pps: float) -> None:
        self.samples.append(pps)
        n = len(self.samples)
        if n < 2:
            return
        sorted_s = sorted(self.samples)
        self.avg_pps = sum(sorted_s) / n
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
        self.src_ips: dict = {}
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

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                self.dst_ports[tcp.dport] = self.dst_ports.get(tcp.dport, 0) + 1
                flags = tcp.flags
                if flags & 0x02:
                    self.tcp_flags["SYN"] += 1
                if flags & 0x10:
                    self.tcp_flags["ACK"] += 1
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
        return [{"ip": ip, "count": c}
                for ip, c in sorted(self.src_ips.items(),
                                    key=lambda x: x[1], reverse=True)[:n]]

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

        self.attacking = False
        self.attack_start: float = 0.0
        self.incident_uuid: str = ""
        self.peak_pps: float = 0.0
        self.peak_bps: float = 0.0
        self.below_count: int = 0
        self.velocity_curve: list = []
        self.last_update: float = 0.0
        self.server_threshold: float | None = None

    @property
    def threshold(self) -> float:
        if self.server_threshold is not None:
            return self.server_threshold
        return self.baseline.threshold

    def run(self) -> None:
        logger.info("Flowtriq Agent %s starting on %s",
                    VERSION, self.monitor.interface)

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

        self.api.send_metrics({
            "pps": round(pps, 1),
            "bps": round(bps, 1),
            "tcp_pct": self.monitor.tcp_pct,
            "udp_pct": self.monitor.udp_pct,
            "icmp_pct": self.monitor.icmp_pct,
            "conn_count": self.monitor.conn_count,
            "threshold": round(self.threshold, 1),
        })

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

    def _begin_attack(self) -> None:
        self.attacking = True
        self.attack_start = time.time()
        self.peak_pps = self.monitor.pps
        self.peak_bps = self.monitor.bps
        self.below_count = 0
        self.velocity_curve = []
        self.analyser.reset()
        self.last_update = time.monotonic()

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

    def _command_poll_loop(self) -> None:
        """Poll for pending commands (iptables rules) every 5 minutes."""
        while not self.shutdown.is_set():
            self.shutdown.wait(300)  # 5 minutes
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
        except Exception as exc:
            logger.error("Config fetch error: %s", exc)

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
