"""
Flowtriq Mirror/SPAN Capture Engine

Captures packets from a SPAN/mirror port or network TAP interface and
maintains per-destination-IP traffic counters for DDoS detection across
an entire network segment.

Backends:
  - AF_PACKET (Linux)  — raw socket with PACKET_FANOUT for multi-thread capture
  - tcpdump fallback   — shell out to tcpdump and parse output

The MirrorAgent (in agent.py) reads per-IP snapshots at 1 Hz and runs
independent baseline/detection per destination IP.
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import os
import socket
import struct
import subprocess
import threading
import time
from typing import Optional

logger = logging.getLogger("ftagent.mirror")

# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1
PROTO_ICMPv6 = 58
PROTO_GRE  = 47

ETH_P_ALL  = 0x0003     # capture all protocols
ETH_P_IP   = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100    # VLAN-tagged
ETH_P_8021AD = 0x88A8   # QinQ outer tag

# AF_PACKET fanout
PACKET_FANOUT       = 18
PACKET_FANOUT_HASH  = 0

# Memory caps
MAX_DST_IPS_PER_WINDOW = 100_000
MAX_SRC_IPS_PER_DST    = 5_000

# GRE header: 4 bytes minimum (flags + protocol)
GRE_HEADER_MIN = 4


# ═══════════════════════════════════════════════════════════════════════
# Per-IP Stats
# ═══════════════════════════════════════════════════════════════════════

class IPStats:
    """Mutable accumulator for one destination IP in the current window."""
    __slots__ = ("packets", "octets", "tcp_packets", "udp_packets",
                 "icmp_packets", "src_ips", "dst_ports", "tcp_flags",
                 "pkt_sizes")

    def __init__(self):
        self.packets: int = 0
        self.octets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.icmp_packets: int = 0
        self.src_ips: dict[str, int] = {}       # src_ip -> packet count
        self.dst_ports: dict[int, int] = {}     # dst_port -> packet count
        self.tcp_flags: dict[str, int] = {
            "SYN": 0, "ACK": 0, "RST": 0, "FIN": 0, "PSH": 0, "URG": 0,
        }
        self.pkt_sizes: list[int] = []          # sample of packet sizes


class IPSnapshot:
    """Immutable snapshot for one destination IP, produced by PerIPCounter.snapshot_and_reset()."""
    __slots__ = ("dst_ip", "pps", "bps", "tcp_pct", "udp_pct", "icmp_pct",
                 "src_ip_count", "top_src_ips", "top_dst_ports",
                 "tcp_flags", "avg_pkt_size", "packets", "octets")

    def __init__(self, dst_ip: str, stats: IPStats):
        self.dst_ip = dst_ip
        self.packets = stats.packets
        self.octets = stats.octets
        self.pps = float(stats.packets)
        self.bps = float(stats.octets * 8)

        total_proto = stats.tcp_packets + stats.udp_packets + stats.icmp_packets
        if total_proto > 0:
            self.tcp_pct = round(stats.tcp_packets / total_proto * 100, 1)
            self.udp_pct = round(stats.udp_packets / total_proto * 100, 1)
            self.icmp_pct = round(stats.icmp_packets / total_proto * 100, 1)
        else:
            self.tcp_pct = self.udp_pct = self.icmp_pct = 0.0

        self.src_ip_count = len(stats.src_ips)
        self.top_src_ips = sorted(stats.src_ips.items(),
                                  key=lambda x: x[1], reverse=True)[:20]
        self.top_dst_ports = sorted(stats.dst_ports.items(),
                                    key=lambda x: x[1], reverse=True)[:20]
        self.tcp_flags = dict(stats.tcp_flags)
        self.avg_pkt_size = (
            sum(stats.pkt_sizes) / len(stats.pkt_sizes)
            if stats.pkt_sizes else 0.0
        )


# ═══════════════════════════════════════════════════════════════════════
# Per-IP Counter (thread-safe accumulator)
# ═══════════════════════════════════════════════════════════════════════

class PerIPCounter:
    """Thread-safe per-destination-IP traffic counter.

    Writer threads (capture workers) call record_packet().
    The main agent tick calls snapshot_and_reset() once per second to
    consume the accumulated data and reset for the next window.
    """

    def __init__(self, max_ips: int = MAX_DST_IPS_PER_WINDOW,
                 max_src_per_dst: int = MAX_SRC_IPS_PER_DST):
        self._lock = threading.Lock()
        self._ips: dict[str, IPStats] = {}
        self._max_ips = max_ips
        self._max_src = max_src_per_dst
        self._overflow_packets = 0
        self._overflow_octets = 0
        # Aggregate counters (always maintained regardless of per-IP cap)
        self._total_packets = 0
        self._total_octets = 0

    def record_packet(self, dst_ip: str, src_ip: str, protocol: int,
                      pkt_len: int, dst_port: int = 0,
                      tcp_flags: int = 0) -> None:
        """Record a single parsed packet. Called from capture worker threads."""
        with self._lock:
            self._total_packets += 1
            self._total_octets += pkt_len

            stats = self._ips.get(dst_ip)
            if stats is None:
                if len(self._ips) >= self._max_ips:
                    self._overflow_packets += 1
                    self._overflow_octets += pkt_len
                    return
                stats = IPStats()
                self._ips[dst_ip] = stats

            stats.packets += 1
            stats.octets += pkt_len

            if protocol == PROTO_TCP:
                stats.tcp_packets += 1
                if tcp_flags & 0x02:
                    stats.tcp_flags["SYN"] += 1
                if tcp_flags & 0x10:
                    stats.tcp_flags["ACK"] += 1
                if tcp_flags & 0x04:
                    stats.tcp_flags["RST"] += 1
                if tcp_flags & 0x01:
                    stats.tcp_flags["FIN"] += 1
                if tcp_flags & 0x08:
                    stats.tcp_flags["PSH"] += 1
                if tcp_flags & 0x20:
                    stats.tcp_flags["URG"] += 1
            elif protocol == PROTO_UDP:
                stats.udp_packets += 1
            elif protocol in (PROTO_ICMP, PROTO_ICMPv6):
                stats.icmp_packets += 1

            if src_ip:
                if len(stats.src_ips) < self._max_src or src_ip in stats.src_ips:
                    stats.src_ips[src_ip] = stats.src_ips.get(src_ip, 0) + 1

            if dst_port:
                stats.dst_ports[dst_port] = stats.dst_ports.get(dst_port, 0) + 1

            if len(stats.pkt_sizes) < 1000:
                stats.pkt_sizes.append(pkt_len)

    def snapshot_and_reset(self) -> dict[str, IPSnapshot]:
        """Snapshot all per-IP stats, reset accumulators. Returns dict[dst_ip -> IPSnapshot]."""
        with self._lock:
            result = {}
            for dst_ip, stats in self._ips.items():
                if stats.packets > 0:
                    result[dst_ip] = IPSnapshot(dst_ip, stats)
            # Reset
            self._ips.clear()
            overflow_pkts = self._overflow_packets
            self._overflow_packets = 0
            self._overflow_octets = 0
            total_pkts = self._total_packets
            total_octets = self._total_octets
            self._total_packets = 0
            self._total_octets = 0

        if overflow_pkts > 0:
            logger.debug("Mirror counter overflow: %d packets for IPs beyond %d cap",
                         overflow_pkts, self._max_ips)

        return result

    @property
    def aggregate_packets(self) -> int:
        """Total packets in current (incomplete) window. For health checks."""
        return self._total_packets

    @property
    def tracked_ips(self) -> int:
        """Number of IPs in current window. For health checks."""
        return len(self._ips)


# ═══════════════════════════════════════════════════════════════════════
# Packet Parser
# ═══════════════════════════════════════════════════════════════════════

def _parse_ethernet(data: bytes, counter: PerIPCounter,
                    subnets: Optional[list] = None,
                    gre_strip: bool = False,
                    _depth: int = 0) -> None:
    """Parse an Ethernet frame, extract IP header fields, record into counter.

    Handles VLAN tags (802.1Q, QinQ), IPv4, IPv6, and optionally GRE decap.
    """
    if len(data) < 14:
        return

    # Ethernet header: 6 dst + 6 src + 2 ethertype
    ethertype = struct.unpack_from("!H", data, 12)[0]
    offset = 14

    # Strip VLAN tags (802.1Q and QinQ)
    for _ in range(3):  # max 3 tags
        if ethertype in (ETH_P_8021Q, ETH_P_8021AD):
            if offset + 4 > len(data):
                return
            ethertype = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        else:
            break

    if ethertype == ETH_P_IP:
        _parse_ipv4(data, offset, counter, subnets, gre_strip, _depth)
    elif ethertype == ETH_P_IPV6:
        _parse_ipv6(data, offset, counter, subnets, gre_strip, _depth)


def _parse_ipv4(data: bytes, offset: int, counter: PerIPCounter,
                subnets: Optional[list], gre_strip: bool,
                _depth: int) -> None:
    """Parse IPv4 header and record packet."""
    if offset + 20 > len(data):
        return

    version_ihl = data[offset]
    if (version_ihl >> 4) != 4:
        return

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or offset + ihl > len(data):
        return

    total_len = struct.unpack_from("!H", data, offset + 2)[0]
    protocol = data[offset + 9]
    src_ip = socket.inet_ntoa(data[offset + 12:offset + 16])
    dst_ip = socket.inet_ntoa(data[offset + 16:offset + 20])

    # GRE decapsulation: strip outer GRE and parse inner packet
    if gre_strip and protocol == PROTO_GRE and _depth < 3:
        gre_offset = offset + ihl
        if gre_offset + GRE_HEADER_MIN <= len(data):
            gre_flags = struct.unpack_from("!H", data, gre_offset)[0]
            gre_proto = struct.unpack_from("!H", data, gre_offset + 2)[0]
            gre_hdr_len = GRE_HEADER_MIN
            if gre_flags & 0x8000:  # checksum present
                gre_hdr_len += 4
            if gre_flags & 0x2000:  # key present
                gre_hdr_len += 4
            if gre_flags & 0x1000:  # sequence present
                gre_hdr_len += 4

            inner_offset = gre_offset + gre_hdr_len
            if gre_proto == ETH_P_IP and inner_offset < len(data):
                _parse_ipv4(data, inner_offset, counter, subnets,
                            gre_strip, _depth + 1)
                return
            elif gre_proto == ETH_P_IPV6 and inner_offset < len(data):
                _parse_ipv6(data, inner_offset, counter, subnets,
                            gre_strip, _depth + 1)
                return
        # Fall through if GRE parse fails — count the outer packet

    # Subnet filter: only record if dst_ip is in monitored subnets
    if subnets:
        try:
            addr = ipaddress.ip_address(dst_ip)
            if not any(addr in net for net in subnets):
                return
        except ValueError:
            return

    # Extract L4 info
    dst_port = 0
    tcp_flags = 0
    l4_offset = offset + ihl

    if protocol == PROTO_TCP and l4_offset + 14 <= len(data):
        dst_port = struct.unpack_from("!H", data, l4_offset + 2)[0]
        tcp_flags = data[l4_offset + 13]
    elif protocol == PROTO_UDP and l4_offset + 4 <= len(data):
        dst_port = struct.unpack_from("!H", data, l4_offset + 2)[0]

    counter.record_packet(
        dst_ip=dst_ip, src_ip=src_ip, protocol=protocol,
        pkt_len=total_len, dst_port=dst_port, tcp_flags=tcp_flags,
    )


def _parse_ipv6(data: bytes, offset: int, counter: PerIPCounter,
                subnets: Optional[list], gre_strip: bool,
                _depth: int) -> None:
    """Parse IPv6 header and record packet."""
    if offset + 40 > len(data):
        return

    version = (data[offset] >> 4)
    if version != 6:
        return

    payload_len = struct.unpack_from("!H", data, offset + 4)[0]
    next_header = data[offset + 6]
    src_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 8:offset + 24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 24:offset + 40])
    total_len = 40 + payload_len

    # GRE decapsulation for IPv6
    if gre_strip and next_header == PROTO_GRE and _depth < 3:
        gre_offset = offset + 40
        if gre_offset + GRE_HEADER_MIN <= len(data):
            gre_flags = struct.unpack_from("!H", data, gre_offset)[0]
            gre_proto = struct.unpack_from("!H", data, gre_offset + 2)[0]
            gre_hdr_len = GRE_HEADER_MIN
            if gre_flags & 0x8000:
                gre_hdr_len += 4
            if gre_flags & 0x2000:
                gre_hdr_len += 4
            if gre_flags & 0x1000:
                gre_hdr_len += 4

            inner_offset = gre_offset + gre_hdr_len
            if gre_proto == ETH_P_IP and inner_offset < len(data):
                _parse_ipv4(data, inner_offset, counter, subnets,
                            gre_strip, _depth + 1)
                return
            elif gre_proto == ETH_P_IPV6 and inner_offset < len(data):
                _parse_ipv6(data, inner_offset, counter, subnets,
                            gre_strip, _depth + 1)
                return

    # Subnet filter
    if subnets:
        try:
            addr = ipaddress.ip_address(dst_ip)
            if not any(addr in net for net in subnets):
                return
        except ValueError:
            return

    # Extract L4 info (skip extension headers — use next_header directly)
    dst_port = 0
    tcp_flags = 0
    l4_offset = offset + 40

    if next_header == PROTO_TCP and l4_offset + 14 <= len(data):
        dst_port = struct.unpack_from("!H", data, l4_offset + 2)[0]
        tcp_flags = data[l4_offset + 13]
    elif next_header == PROTO_UDP and l4_offset + 4 <= len(data):
        dst_port = struct.unpack_from("!H", data, l4_offset + 2)[0]

    counter.record_packet(
        dst_ip=dst_ip, src_ip=src_ip, protocol=next_header,
        pkt_len=total_len, dst_port=dst_port, tcp_flags=tcp_flags,
    )


# ═══════════════════════════════════════════════════════════════════════
# Mirror Capture Engine
# ═══════════════════════════════════════════════════════════════════════

class MirrorCaptureEngine:
    """Captures packets from a SPAN/mirror interface and feeds PerIPCounter.

    Two capture backends:
    1. AF_PACKET (Linux) — raw socket in promiscuous mode with PACKET_FANOUT
       for multi-thread distribution. High performance, no dependencies.
    2. tcpdump fallback — shells out to tcpdump for capture, parses output.
       Works on any OS with tcpdump installed.
    """

    def __init__(self, interface: str, counter: PerIPCounter,
                 mode: str = "af_packet",
                 subnets: Optional[list[str]] = None,
                 gre_strip: bool = False,
                 fanout_workers: int = 0):
        self.interface = interface
        self.counter = counter
        self.mode = mode
        self.gre_strip = gre_strip
        self._fanout_workers = fanout_workers or max(os.cpu_count() or 1, 1)
        self._threads: list[threading.Thread] = []
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._tcpdump_proc: Optional[subprocess.Popen] = None

        # Parse subnet filters to ipaddress.ip_network objects
        self._subnets: Optional[list] = None
        if subnets:
            self._subnets = []
            for s in subnets:
                try:
                    self._subnets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    logger.warning("Invalid mirror subnet: %s (skipped)", s)
            if not self._subnets:
                self._subnets = None

        # Stats
        self._packets_captured = 0
        self._packets_errors = 0
        self._capture_start: float = 0.0

    def start(self, shutdown: threading.Event) -> None:
        """Start capture (blocking). Call from a daemon thread."""
        self._running = True
        self._capture_start = time.monotonic()

        if self.mode == "af_packet":
            self._start_af_packet(shutdown)
        else:
            self._start_tcpdump(shutdown)

    def _start_af_packet(self, shutdown: threading.Event) -> None:
        """AF_PACKET capture with PACKET_FANOUT for multi-thread scaling."""
        try:
            # Verify we're on Linux
            if not hasattr(socket, "AF_PACKET"):
                logger.warning("AF_PACKET not available (not Linux), falling back to tcpdump")
                self.mode = "tcpdump"
                self._start_tcpdump(shutdown)
                return

            # Get interface index
            ifindex = socket.if_nametoindex(self.interface)

            # Enable promiscuous mode
            self._set_promisc(True)

            if self._fanout_workers > 1:
                # Multi-thread: each worker gets its own socket in a fanout group
                fanout_group_id = os.getpid() & 0xFFFF
                fanout_arg = fanout_group_id | (PACKET_FANOUT_HASH << 16)

                for i in range(self._fanout_workers):
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.htons(ETH_P_ALL))
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                    8 * 1024 * 1024)
                    sock.bind((self.interface, ETH_P_ALL))
                    sock.setsockopt(socket.SOL_PACKET, PACKET_FANOUT, fanout_arg)
                    sock.settimeout(1.0)

                    t = threading.Thread(
                        target=self._af_packet_worker,
                        args=(sock, shutdown),
                        daemon=True,
                        name=f"mirror-worker-{i}",
                    )
                    self._threads.append(t)
                    t.start()

                logger.info("Mirror capture started on %s with %d AF_PACKET fanout workers",
                            self.interface, self._fanout_workers)
            else:
                # Single thread
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(ETH_P_ALL))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                8 * 1024 * 1024)
                sock.bind((self.interface, ETH_P_ALL))
                sock.settimeout(1.0)
                self._sock = sock

                logger.info("Mirror capture started on %s (single AF_PACKET socket)",
                            self.interface)
                self._af_packet_worker(sock, shutdown)

            # Wait for shutdown
            while not shutdown.is_set():
                shutdown.wait(1.0)

        except PermissionError:
            logger.error("Mirror capture requires root (CAP_NET_RAW). "
                         "Run with sudo or set CAP_NET_RAW on the ftagent binary.")
            self._running = False
        except OSError as e:
            logger.error("Mirror capture failed on %s: %s", self.interface, e)
            self._running = False
        finally:
            self._set_promisc(False)
            self._running = False

    def _af_packet_worker(self, sock: socket.socket,
                          shutdown: threading.Event) -> None:
        """Worker thread: read packets from AF_PACKET socket and parse them."""
        subnets = self._subnets
        counter = self.counter
        gre_strip = self.gre_strip

        while not shutdown.is_set():
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if shutdown.is_set():
                    break
                self._packets_errors += 1
                continue

            self._packets_captured += 1
            try:
                _parse_ethernet(data, counter, subnets, gre_strip)
            except Exception:
                self._packets_errors += 1

        try:
            sock.close()
        except OSError:
            pass

    def _start_tcpdump(self, shutdown: threading.Event) -> None:
        """tcpdump fallback: capture packets and parse tcpdump binary output."""
        try:
            # Build BPF filter for subnet restriction
            bpf_filter = ""
            if self._subnets:
                parts = []
                for net in self._subnets:
                    parts.append(f"dst net {net}")
                bpf_filter = " or ".join(parts)

            cmd = [
                "tcpdump", "-i", self.interface,
                "-nn", "-l",          # no DNS, line-buffered
                "-e",                 # print link-layer header
                "--immediate-mode",   # don't buffer
                "-w", "-",            # write raw pcap to stdout
                "-s", "128",          # snap length (headers only)
            ]
            if bpf_filter:
                cmd.append(bpf_filter)

            self._tcpdump_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

            logger.info("Mirror capture started on %s via tcpdump (pid=%d)",
                        self.interface, self._tcpdump_proc.pid)

            # Read pcap global header (24 bytes)
            global_header = self._tcpdump_proc.stdout.read(24)
            if len(global_header) < 24:
                logger.error("tcpdump exited before writing pcap header")
                self._running = False
                return

            magic = struct.unpack_from("<I", global_header, 0)[0]
            if magic == 0xA1B2C3D4:
                endian = "<"
            elif magic == 0xD4C3B2A1:
                endian = ">"
            else:
                logger.error("Invalid pcap magic from tcpdump: 0x%08X", magic)
                self._running = False
                return

            link_type = struct.unpack_from(f"{endian}I", global_header, 20)[0]
            if link_type != 1:  # LINKTYPE_ETHERNET
                logger.warning("Mirror tcpdump link type %d (expected 1/Ethernet)", link_type)

            subnets = self._subnets
            counter = self.counter
            gre_strip = self.gre_strip
            stdout = self._tcpdump_proc.stdout

            while not shutdown.is_set():
                # Read pcap record header (16 bytes)
                rec_hdr = stdout.read(16)
                if len(rec_hdr) < 16:
                    if not shutdown.is_set():
                        logger.warning("tcpdump stream ended")
                    break

                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(
                    f"{endian}IIII", rec_hdr, 0)

                if incl_len > 65535:
                    logger.debug("Skipping oversized pcap record: %d bytes", incl_len)
                    stdout.read(min(incl_len, 65535))
                    continue

                pkt_data = stdout.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                self._packets_captured += 1
                try:
                    _parse_ethernet(pkt_data, counter, subnets, gre_strip)
                except Exception:
                    self._packets_errors += 1

        except FileNotFoundError:
            logger.error("tcpdump not found. Install tcpdump for mirror capture.")
            self._running = False
        except Exception as e:
            logger.error("Mirror tcpdump capture error: %s", e)
            self._running = False
        finally:
            if self._tcpdump_proc:
                try:
                    self._tcpdump_proc.terminate()
                    self._tcpdump_proc.wait(timeout=5)
                except Exception:
                    try:
                        self._tcpdump_proc.kill()
                    except Exception:
                        pass
            self._running = False

    def _set_promisc(self, enable: bool) -> None:
        """Enable/disable promiscuous mode on the mirror interface."""
        try:
            import fcntl
            SIOCGIFFLAGS = 0x8913
            SIOCSIFFLAGS = 0x8914
            IFF_PROMISC = 0x100

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack("16sH14s", self.interface.encode(), 0, b"\x00" * 14)
            result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
            flags = struct.unpack_from("16sH", result)[1]

            if enable:
                flags |= IFF_PROMISC
            else:
                flags &= ~IFF_PROMISC

            ifreq = struct.pack("16sH14s", self.interface.encode(), flags, b"\x00" * 14)
            fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)
            sock.close()

            if enable:
                logger.debug("Promiscuous mode enabled on %s", self.interface)
        except Exception as e:
            logger.debug("Could not set promiscuous mode on %s: %s",
                         self.interface, e)

    def stop(self) -> None:
        """Stop capture gracefully."""
        self._running = False
        if self._tcpdump_proc:
            try:
                self._tcpdump_proc.terminate()
            except Exception:
                pass
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        uptime = time.monotonic() - self._capture_start if self._capture_start else 0
        return {
            "mode": self.mode,
            "interface": self.interface,
            "running": self._running,
            "packets_captured": self._packets_captured,
            "packets_errors": self._packets_errors,
            "tracked_ips": self.counter.tracked_ips,
            "uptime_seconds": round(uptime, 1),
            "workers": self._fanout_workers if self.mode == "af_packet" else 1,
            "subnets": [str(s) for s in self._subnets] if self._subnets else [],
        }
