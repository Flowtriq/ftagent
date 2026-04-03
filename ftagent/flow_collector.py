"""
Flowtriq Flow Protocol Collector

Native sFlow v5, NetFlow v5/v9, and IPFIX (NetFlow v10) listener.
Receives flow data from routers/switches via UDP, parses binary protocols,
aggregates into per-second PPS/BPS metrics, and exposes a PPSMonitor-compatible
interface for the main agent detection loop.

Protocols:
  - sFlow v5   (RFC 3176) — sampled packet headers + counter samples
  - NetFlow v5 (Cisco)    — fixed 48-byte flow records
  - NetFlow v9 (RFC 3954) — template-based variable records
  - IPFIX      (RFC 7011) — template-based (NetFlow v10)
"""

from __future__ import annotations

import collections
import logging
import socket
import struct
import threading
import time
from typing import Optional

logger = logging.getLogger("ftagent.flow")

# ═══════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════��══════════════════════

PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1

DEFAULT_PORTS = {
    "sflow":      6343,
    "netflow_v5": 2055,
    "netflow_v9": 2055,
    "ipfix":      4739,
}

# IPFIX / NetFlow v9 Information Element IDs
IE_OCTET_DELTA_COUNT     = 1
IE_PACKET_DELTA_COUNT    = 2
IE_PROTOCOL_IDENTIFIER   = 4
IE_IP_CLASS_OF_SERVICE   = 5
IE_TCP_CONTROL_BITS      = 6
IE_SOURCE_TRANSPORT_PORT = 7
IE_SOURCE_IPV4_ADDRESS   = 8
IE_DEST_TRANSPORT_PORT   = 11
IE_DEST_IPV4_ADDRESS     = 12
IE_SOURCE_IPV6_ADDRESS   = 27
IE_DEST_IPV6_ADDRESS     = 28
IE_FLOW_START_MILLISECONDS = 152
IE_FLOW_END_MILLISECONDS   = 153

# Max unique source IPs tracked per aggregation window
MAX_FLOW_SRC_IPS = 50_000


# ═══════════════════��═══════════════════════════════��═══════════════════
# Flow Record (normalized across all protocols)
# ═════��════════════════════════════════���════════════════════════════════

class FlowRecord:
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "packets", "octets", "tcp_flags", "sample_rate")

    def __init__(self, src_ip: str = "", dst_ip: str = "", src_port: int = 0,
                 dst_port: int = 0, protocol: int = 0, packets: int = 0,
                 octets: int = 0, tcp_flags: int = 0, sample_rate: int = 1):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = packets
        self.octets = octets
        self.tcp_flags = tcp_flags
        self.sample_rate = sample_rate


# ═══��═════════════════���═════════════════════════════════════════════════
# Protocol Parsers
# ═══════════════════════════════════════════════════════════════════════

def _ip4(data: bytes, offset: int) -> str:
    return socket.inet_ntoa(data[offset:offset + 4])


def _ip6(data: bytes, offset: int) -> str:
    return socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])


# ─── sFlow v5 ──────────────────────────────────────────────────────

def parse_sflow_v5(data: bytes) -> list[FlowRecord]:
    """Parse sFlow v5 datagram. Returns normalized flow records."""
    records = []
    if len(data) < 28:
        return records

    version = struct.unpack_from("!I", data, 0)[0]
    if version != 5:
        return records

    addr_type = struct.unpack_from("!I", data, 4)[0]
    # addr_type: 1=IPv4, 2=IPv6
    addr_len = 4 if addr_type == 1 else 16
    offset = 8 + addr_len  # skip agent address

    if offset + 12 > len(data):
        return records

    _sub_agent_id, _seq, num_samples = struct.unpack_from("!III", data, offset)
    offset += 12

    for _ in range(min(num_samples, 200)):  # safety cap
        if offset + 8 > len(data):
            break

        sample_type_raw = struct.unpack_from("!I", data, offset)[0]
        sample_len = struct.unpack_from("!I", data, offset + 4)[0]
        offset += 8

        # Enterprise << 12 | format
        sample_format = sample_type_raw & 0xFFF
        next_sample = offset + sample_len

        if sample_format == 1:
            # Flow sample
            records.extend(_parse_sflow_flow_sample(data, offset, sample_len))
        elif sample_format == 3:
            # Expanded flow sample
            records.extend(_parse_sflow_expanded_flow_sample(data, offset, sample_len))
        # sample_format 2 = counter sample (we extract interface counters below)
        # sample_format 4 = expanded counter sample

        offset = next_sample

    return records


def _parse_sflow_flow_sample(data: bytes, offset: int, length: int) -> list[FlowRecord]:
    """Parse a standard sFlow flow sample."""
    records = []
    end = offset + length
    if offset + 32 > end:
        return records

    (_seq, _src_id_type, _src_id_idx, sampling_rate, _sample_pool,
     _drops, _input, _output, num_records) = struct.unpack_from("!IIIIIIIII", data, offset)
    offset += 36

    for _ in range(min(num_records, 50)):
        if offset + 8 > end:
            break
        rec_format = struct.unpack_from("!I", data, offset)[0] & 0xFFF
        rec_len = struct.unpack_from("!I", data, offset + 4)[0]
        offset += 8
        rec_end = offset + rec_len

        if rec_format == 1:  # Raw packet header
            rec = _parse_sflow_raw_header(data, offset, rec_len, sampling_rate)
            if rec:
                records.append(rec)

        offset = rec_end

    return records


def _parse_sflow_expanded_flow_sample(data: bytes, offset: int, length: int) -> list[FlowRecord]:
    """Parse an expanded sFlow flow sample (uses 32-bit IDs)."""
    records = []
    end = offset + length
    if offset + 44 > end:
        return records

    _seq = struct.unpack_from("!I", data, offset)[0]
    # expanded: src_id_type(4) + src_id_idx(4)
    sampling_rate = struct.unpack_from("!I", data, offset + 12)[0]
    # sample_pool(4), drops(4), input_format(4), input_value(4), output_format(4), output_value(4)
    num_records = struct.unpack_from("!I", data, offset + 40)[0]
    offset += 44

    for _ in range(min(num_records, 50)):
        if offset + 8 > end:
            break
        rec_format = struct.unpack_from("!I", data, offset)[0] & 0xFFF
        rec_len = struct.unpack_from("!I", data, offset + 4)[0]
        offset += 8
        rec_end = offset + rec_len

        if rec_format == 1:  # Raw packet header
            rec = _parse_sflow_raw_header(data, offset, rec_len, sampling_rate)
            if rec:
                records.append(rec)

        offset = rec_end

    return records


def _parse_sflow_raw_header(data: bytes, offset: int, length: int,
                            sampling_rate: int) -> Optional[FlowRecord]:
    """Parse sFlow raw packet header record — extract IP/TCP/UDP from sampled header."""
    if length < 16:
        return None

    _header_proto = struct.unpack_from("!I", data, offset)[0]
    frame_length = struct.unpack_from("!I", data, offset + 4)[0]
    _stripped = struct.unpack_from("!I", data, offset + 8)[0]
    header_length = struct.unpack_from("!I", data, offset + 12)[0]
    offset += 16

    if header_length < 1 or offset + header_length > len(data):
        return None

    # Parse Ethernet header (14 bytes)
    hdr = data[offset:offset + header_length]
    if len(hdr) < 14:
        return None

    ethertype = struct.unpack_from("!H", hdr, 12)[0]
    ip_offset = 14

    # Handle 802.1Q VLAN tag
    if ethertype == 0x8100:
        if len(hdr) < 18:
            return None
        ethertype = struct.unpack_from("!H", hdr, 16)[0]
        ip_offset = 18

    if ethertype != 0x0800:  # Only IPv4 for now
        return None

    return _parse_ip_header(hdr, ip_offset, frame_length, sampling_rate)


def _parse_ip_header(hdr: bytes, ip_offset: int, frame_length: int,
                     sampling_rate: int) -> Optional[FlowRecord]:
    """Parse IP + transport header from raw bytes."""
    if len(hdr) < ip_offset + 20:
        return None

    version_ihl = hdr[ip_offset]
    ihl = (version_ihl & 0x0F) * 4
    protocol = hdr[ip_offset + 9]
    src_ip = socket.inet_ntoa(hdr[ip_offset + 12:ip_offset + 16])
    dst_ip = socket.inet_ntoa(hdr[ip_offset + 16:ip_offset + 20])

    src_port = dst_port = tcp_flags = 0
    transport_offset = ip_offset + ihl

    if protocol == PROTO_TCP and len(hdr) >= transport_offset + 14:
        src_port, dst_port = struct.unpack_from("!HH", hdr, transport_offset)
        tcp_flags = hdr[transport_offset + 13]
    elif protocol == PROTO_UDP and len(hdr) >= transport_offset + 4:
        src_port, dst_port = struct.unpack_from("!HH", hdr, transport_offset)

    return FlowRecord(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        protocol=protocol, packets=sampling_rate,  # each sample represents N packets
        octets=frame_length * sampling_rate,
        tcp_flags=tcp_flags, sample_rate=sampling_rate,
    )


# ─── NetFlow v5 ───────────��────────────────────────────────────────

_NFV5_HEADER = struct.Struct("!HHIIIIBBh")  # 24 bytes
_NFV5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBB2x")  # 48 bytes

def parse_netflow_v5(data: bytes) -> list[FlowRecord]:
    """Parse NetFlow v5 datagram. Fixed-format 48-byte records."""
    records = []
    if len(data) < 24:
        return records

    hdr = _NFV5_HEADER.unpack_from(data, 0)
    version, count = hdr[0], hdr[1]
    if version != 5:
        return records

    # Sampling interval is in the header (last 2 bytes, bits 0-13 = interval, 14-15 = mode)
    sampling_raw = hdr[8] if len(hdr) > 8 else 0
    sample_interval = sampling_raw & 0x3FFF
    if sample_interval == 0:
        sample_interval = 1

    offset = 24
    for _ in range(min(count, 30)):  # v5 max 30 records per packet
        if offset + 48 > len(data):
            break

        rec = _NFV5_RECORD.unpack_from(data, offset)
        offset += 48

        src_ip = socket.inet_ntoa(rec[0])
        dst_ip = socket.inet_ntoa(rec[1])
        packets = rec[5]
        octets = rec[6]
        src_port = rec[9]
        dst_port = rec[10]
        tcp_flags = rec[11]
        protocol = rec[12]

        records.append(FlowRecord(
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
            dst_port=dst_port, protocol=protocol,
            packets=packets * sample_interval,
            octets=octets * sample_interval,
            tcp_flags=tcp_flags, sample_rate=sample_interval,
        ))

    return records


# ─── NetFlow v9 / IPFIX ────────────────────────────────────────────

class TemplateCache:
    """Thread-safe template cache for NetFlow v9 and IPFIX.
    Templates are keyed by (source_ip, observation_domain, template_id).
    """

    def __init__(self):
        self._lock = threading.Lock()
        # key: (source_ip, domain_id, template_id) → list of (field_id, field_length)
        self._templates: dict[tuple, list[tuple[int, int]]] = {}
        self._last_seen: dict[tuple, float] = {}

    def store(self, source_ip: str, domain_id: int, template_id: int,
              fields: list[tuple[int, int]]) -> None:
        key = (source_ip, domain_id, template_id)
        with self._lock:
            self._templates[key] = fields
            self._last_seen[key] = time.monotonic()

    def get(self, source_ip: str, domain_id: int,
            template_id: int) -> Optional[list[tuple[int, int]]]:
        key = (source_ip, domain_id, template_id)
        with self._lock:
            return self._templates.get(key)

    def prune(self, max_age: float = 3600) -> None:
        """Remove templates not seen in max_age seconds."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, t in self._last_seen.items() if now - t > max_age]
            for k in expired:
                self._templates.pop(k, None)
                self._last_seen.pop(k, None)


def parse_netflow_v9(data: bytes, source_ip: str,
                     cache: TemplateCache) -> list[FlowRecord]:
    """Parse NetFlow v9 datagram with template handling."""
    records = []
    if len(data) < 20:
        return records

    version, count = struct.unpack_from("!HH", data, 0)
    if version != 9:
        return records

    source_id = struct.unpack_from("!I", data, 16)[0]
    offset = 20

    for _ in range(min(count, 100)):
        if offset + 4 > len(data):
            break

        flowset_id = struct.unpack_from("!H", data, offset)[0]
        flowset_len = struct.unpack_from("!H", data, offset + 2)[0]

        if flowset_len < 4:
            break  # malformed
        next_flowset = offset + flowset_len

        if flowset_id == 0:
            # Template FlowSet
            _parse_v9_template_flowset(data, offset + 4, flowset_len - 4,
                                       source_ip, source_id, cache)
        elif flowset_id == 1:
            # Options Template FlowSet — skip
            pass
        elif flowset_id >= 256:
            # Data FlowSet
            recs = _parse_v9_data_flowset(data, offset + 4, flowset_len - 4,
                                          flowset_id, source_ip, source_id, cache)
            records.extend(recs)

        offset = next_flowset

    return records


def parse_ipfix(data: bytes, source_ip: str,
                cache: TemplateCache) -> list[FlowRecord]:
    """Parse IPFIX (NetFlow v10) message."""
    records = []
    if len(data) < 16:
        return records

    version = struct.unpack_from("!H", data, 0)[0]
    if version != 10:
        return records

    msg_len = struct.unpack_from("!H", data, 2)[0]
    domain_id = struct.unpack_from("!I", data, 12)[0]
    offset = 16

    while offset + 4 <= min(len(data), msg_len):
        set_id = struct.unpack_from("!H", data, offset)[0]
        set_len = struct.unpack_from("!H", data, offset + 2)[0]

        if set_len < 4:
            break
        next_set = offset + set_len

        if set_id == 2:
            # Template Set
            _parse_ipfix_template_set(data, offset + 4, set_len - 4,
                                      source_ip, domain_id, cache)
        elif set_id == 3:
            # Options Template Set — skip
            pass
        elif set_id >= 256:
            # Data Set
            recs = _parse_v9_data_flowset(data, offset + 4, set_len - 4,
                                          set_id, source_ip, domain_id, cache)
            records.extend(recs)

        offset = next_set

    return records


def _parse_v9_template_flowset(data: bytes, offset: int, length: int,
                                source_ip: str, domain_id: int,
                                cache: TemplateCache) -> None:
    """Parse NetFlow v9 template flowset and store in cache."""
    end = offset + length
    while offset + 4 <= end:
        template_id = struct.unpack_from("!H", data, offset)[0]
        field_count = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4

        fields = []
        for _ in range(field_count):
            if offset + 4 > end:
                return
            fid = struct.unpack_from("!H", data, offset)[0]
            flen = struct.unpack_from("!H", data, offset + 2)[0]
            fields.append((fid, flen))
            offset += 4

        if fields:
            cache.store(source_ip, domain_id, template_id, fields)
            logger.debug("Cached v9 template %d from %s: %d fields",
                        template_id, source_ip, len(fields))


def _parse_ipfix_template_set(data: bytes, offset: int, length: int,
                               source_ip: str, domain_id: int,
                               cache: TemplateCache) -> None:
    """Parse IPFIX template set and store in cache."""
    end = offset + length
    while offset + 4 <= end:
        template_id = struct.unpack_from("!H", data, offset)[0]
        field_count = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4

        fields = []
        for _ in range(field_count):
            if offset + 4 > end:
                return
            fid_raw = struct.unpack_from("!H", data, offset)[0]
            flen = struct.unpack_from("!H", data, offset + 2)[0]
            # IPFIX: bit 15 = enterprise bit
            fid = fid_raw & 0x7FFF
            enterprise = bool(fid_raw & 0x8000)
            offset += 4
            if enterprise:
                offset += 4  # skip enterprise number
            fields.append((fid, flen))

        if fields:
            cache.store(source_ip, domain_id, template_id, fields)
            logger.debug("Cached IPFIX template %d from %s: %d fields",
                        template_id, source_ip, len(fields))


def _parse_v9_data_flowset(data: bytes, offset: int, length: int,
                            template_id: int, source_ip: str,
                            domain_id: int,
                            cache: TemplateCache) -> list[FlowRecord]:
    """Parse data flowset using cached template (NetFlow v9 + IPFIX)."""
    records = []
    template = cache.get(source_ip, domain_id, template_id)
    if template is None:
        return records  # no template yet — will arrive later

    record_len = sum(flen for _, flen in template)
    if record_len == 0:
        return records

    end = offset + length
    while offset + record_len <= end:
        rec = _decode_template_record(data, offset, template)
        if rec:
            records.append(rec)
        offset += record_len

    return records


def _decode_template_record(data: bytes, offset: int,
                            template: list[tuple[int, int]]) -> Optional[FlowRecord]:
    """Decode a single data record using a template definition."""
    src_ip = dst_ip = ""
    src_port = dst_port = protocol = tcp_flags = 0
    packets = octets = 0

    pos = offset
    for field_id, field_len in template:
        if pos + field_len > len(data):
            return None

        if field_id == IE_SOURCE_IPV4_ADDRESS and field_len == 4:
            src_ip = _ip4(data, pos)
        elif field_id == IE_DEST_IPV4_ADDRESS and field_len == 4:
            dst_ip = _ip4(data, pos)
        elif field_id == IE_SOURCE_IPV6_ADDRESS and field_len == 16:
            src_ip = _ip6(data, pos)
        elif field_id == IE_DEST_IPV6_ADDRESS and field_len == 16:
            dst_ip = _ip6(data, pos)
        elif field_id == IE_SOURCE_TRANSPORT_PORT and field_len == 2:
            src_port = struct.unpack_from("!H", data, pos)[0]
        elif field_id == IE_DEST_TRANSPORT_PORT and field_len == 2:
            dst_port = struct.unpack_from("!H", data, pos)[0]
        elif field_id == IE_PROTOCOL_IDENTIFIER and field_len == 1:
            protocol = data[pos]
        elif field_id == IE_TCP_CONTROL_BITS:
            if field_len == 1:
                tcp_flags = data[pos]
            elif field_len == 2:
                tcp_flags = struct.unpack_from("!H", data, pos)[0] & 0xFF
        elif field_id == IE_PACKET_DELTA_COUNT:
            packets = int.from_bytes(data[pos:pos + field_len], "big")
        elif field_id == IE_OCTET_DELTA_COUNT:
            octets = int.from_bytes(data[pos:pos + field_len], "big")

        pos += field_len

    if not src_ip and not dst_ip:
        return None

    return FlowRecord(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
        dst_port=dst_port, protocol=protocol,
        packets=max(packets, 1), octets=octets,
        tcp_flags=tcp_flags, sample_rate=1,
    )


# ══════════════════════════════════��════════════════════════════════════
# Flow Aggregator — 1-second sliding window
# ══════════════���════════════════════════════���═══════════════════════════

class FlowAggregator:
    """Aggregates flow records into 1-second windows for the detection loop.

    Thread-safe: the UDP receiver thread calls `ingest()`, the agent's
    main tick loop calls `read()` to consume the latest window.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # Accumulator for current window
        self._packets = 0
        self._octets = 0
        self._tcp_packets = 0
        self._udp_packets = 0
        self._icmp_packets = 0
        self._src_ips: dict[str, int] = {}
        self._dst_ports: dict[int, int] = {}
        self._tcp_flags: dict[str, int] = {
            "SYN": 0, "ACK": 0, "RST": 0, "FIN": 0, "PSH": 0, "URG": 0,
        }
        self._flow_count = 0
        # Snapshot from last read()
        self._snap_packets = 0
        self._snap_octets = 0
        self._snap_tcp_pct = 0.0
        self._snap_udp_pct = 0.0
        self._snap_icmp_pct = 0.0
        self._snap_src_ips: dict[str, int] = {}
        self._snap_dst_ports: dict[int, int] = {}
        self._snap_tcp_flags: dict[str, int] = {}
        self._snap_flow_count = 0

    def ingest(self, records: list[FlowRecord]) -> None:
        """Ingest parsed flow records into the current aggregation window."""
        with self._lock:
            for rec in records:
                self._packets += rec.packets
                self._octets += rec.octets
                self._flow_count += 1

                if rec.protocol == PROTO_TCP:
                    self._tcp_packets += rec.packets
                    if rec.tcp_flags & 0x02:
                        self._tcp_flags["SYN"] += rec.packets
                    if rec.tcp_flags & 0x10:
                        self._tcp_flags["ACK"] += rec.packets
                    if rec.tcp_flags & 0x04:
                        self._tcp_flags["RST"] += rec.packets
                    if rec.tcp_flags & 0x01:
                        self._tcp_flags["FIN"] += rec.packets
                    if rec.tcp_flags & 0x08:
                        self._tcp_flags["PSH"] += rec.packets
                    if rec.tcp_flags & 0x20:
                        self._tcp_flags["URG"] += rec.packets
                elif rec.protocol == PROTO_UDP:
                    self._udp_packets += rec.packets
                elif rec.protocol == PROTO_ICMP:
                    self._icmp_packets += rec.packets

                if rec.src_ip:
                    if len(self._src_ips) < MAX_FLOW_SRC_IPS or rec.src_ip in self._src_ips:
                        self._src_ips[rec.src_ip] = (
                            self._src_ips.get(rec.src_ip, 0) + rec.packets)

                if rec.dst_port:
                    self._dst_ports[rec.dst_port] = (
                        self._dst_ports.get(rec.dst_port, 0) + rec.packets)

    def read(self, dt: float) -> bool:
        """Snapshot the current window, reset accumulators, compute rates.
        Returns True if any data was received. Called from agent _tick() @ 1Hz."""
        with self._lock:
            self._snap_packets = self._packets
            self._snap_octets = self._octets
            self._snap_flow_count = self._flow_count
            self._snap_src_ips = dict(self._src_ips)
            self._snap_dst_ports = dict(self._dst_ports)
            self._snap_tcp_flags = dict(self._tcp_flags)

            total_proto = self._tcp_packets + self._udp_packets + self._icmp_packets
            if total_proto > 0:
                self._snap_tcp_pct = round(self._tcp_packets / total_proto * 100, 1)
                self._snap_udp_pct = round(self._udp_packets / total_proto * 100, 1)
                self._snap_icmp_pct = round(self._icmp_packets / total_proto * 100, 1)
            else:
                self._snap_tcp_pct = self._snap_udp_pct = self._snap_icmp_pct = 0.0

            # Reset accumulators
            self._packets = 0
            self._octets = 0
            self._tcp_packets = 0
            self._udp_packets = 0
            self._icmp_packets = 0
            self._src_ips.clear()
            self._dst_ports.clear()
            for k in self._tcp_flags:
                self._tcp_flags[k] = 0
            self._flow_count = 0

        return self._snap_packets > 0

    @property
    def pps(self) -> float:
        return float(self._snap_packets)

    @property
    def bps(self) -> float:
        return float(self._snap_octets * 8)

    @property
    def tcp_pct(self) -> float:
        return self._snap_tcp_pct

    @property
    def udp_pct(self) -> float:
        return self._snap_udp_pct

    @property
    def icmp_pct(self) -> float:
        return self._snap_icmp_pct

    @property
    def flow_count(self) -> int:
        return self._snap_flow_count

    def top_src_ips(self, n: int = 20) -> list[tuple[str, int]]:
        return sorted(self._snap_src_ips.items(), key=lambda x: x[1],
                       reverse=True)[:n]

    def top_dst_ports(self, n: int = 20) -> list[tuple[int, int]]:
        return sorted(self._snap_dst_ports.items(), key=lambda x: x[1],
                       reverse=True)[:n]

    @property
    def src_ip_count(self) -> int:
        return len(self._snap_src_ips)

    @property
    def tcp_flag_breakdown(self) -> dict[str, int]:
        return dict(self._snap_tcp_flags)


# ═══════════════════════════════════════════════════════════════════════
# Flow Collector — UDP listener + dispatcher
# ��═══════════════��══════════════════════════════════════════════════════

class FlowCollector:
    """UDP listener for sFlow/NetFlow/IPFIX.

    Runs as a daemon thread, receiving flow datagrams, parsing them, and
    feeding normalized records into a FlowAggregator. The agent's main loop
    reads aggregated metrics via the PPSMonitor-compatible interface.

    Usage:
        collector = FlowCollector(cfg)
        collector.start(shutdown_event)
        # In agent _tick():
        if collector.aggregator.read(dt=1.0):
            pps = collector.aggregator.pps
            bps = collector.aggregator.bps
    """

    def __init__(self, cfg: dict):
        self.protocol = cfg.get("flow_protocol", "auto")
        self.port = cfg.get("flow_port", 0) or DEFAULT_PORTS.get(self.protocol, 6343)
        self.bind_addr = cfg.get("flow_bind", "0.0.0.0")
        self.sample_rate_override = cfg.get("flow_sample_rate", 0)
        self.aggregator = FlowAggregator()
        self.template_cache = TemplateCache()
        self._sock: Optional[socket.socket] = None
        self._running = False
        # Metrics
        self._datagrams_received = 0
        self._datagrams_errors = 0
        self._records_parsed = 0
        self._last_template_prune: float = 0.0

    def start(self, shutdown: threading.Event) -> None:
        """Run the UDP listener loop (blocking — call from a daemon thread)."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Increase receive buffer for high-volume flow sources
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self._sock.settimeout(1.0)  # allow shutdown check every second
        self._sock.bind((self.bind_addr, self.port))
        self._running = True

        logger.info("Flow collector listening on %s:%d (protocol=%s)",
                    self.bind_addr, self.port, self.protocol)

        while not shutdown.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if shutdown.is_set():
                    break
                logger.warning("Flow collector recv error: %s", e)
                self._datagrams_errors += 1
                continue

            self._datagrams_received += 1
            source_ip = addr[0]

            try:
                records = self._parse(data, source_ip)
                if records:
                    self._records_parsed += len(records)
                    self.aggregator.ingest(records)
            except Exception as e:
                self._datagrams_errors += 1
                logger.debug("Flow parse error from %s: %s", source_ip, e)

            # Prune stale templates every 5 minutes
            now = time.monotonic()
            if now - self._last_template_prune >= 300:
                self._last_template_prune = now
                self.template_cache.prune()

        self._running = False
        self._sock.close()
        logger.info("Flow collector stopped")

    def _parse(self, data: bytes, source_ip: str) -> list[FlowRecord]:
        """Auto-detect protocol or use configured protocol."""
        if self.protocol == "auto":
            return self._auto_parse(data, source_ip)

        if self.protocol == "sflow":
            return parse_sflow_v5(data)
        elif self.protocol == "netflow_v5":
            return parse_netflow_v5(data)
        elif self.protocol == "netflow_v9":
            return parse_netflow_v9(data, source_ip, self.template_cache)
        elif self.protocol == "ipfix":
            return parse_ipfix(data, source_ip, self.template_cache)

        return self._auto_parse(data, source_ip)

    def _auto_parse(self, data: bytes, source_ip: str) -> list[FlowRecord]:
        """Auto-detect protocol from packet header."""
        if len(data) < 4:
            return []

        version = struct.unpack_from("!H", data, 0)[0]

        if version == 5:
            # Could be sFlow v5 (32-bit version) or NetFlow v5 (16-bit)
            # sFlow uses 32-bit version field; check if first 4 bytes == 5
            v32 = struct.unpack_from("!I", data, 0)[0]
            if v32 == 5 and len(data) > 28:
                return parse_sflow_v5(data)
            elif version == 5 and len(data) >= 24:
                return parse_netflow_v5(data)
        elif version == 9:
            return parse_netflow_v9(data, source_ip, self.template_cache)
        elif version == 10:
            return parse_ipfix(data, source_ip, self.template_cache)

        return []

    @property
    def stats(self) -> dict:
        return {
            "datagrams_received": self._datagrams_received,
            "datagrams_errors": self._datagrams_errors,
            "records_parsed": self._records_parsed,
            "templates_cached": len(self.template_cache._templates),
            "protocol": self.protocol,
            "port": self.port,
            "running": self._running,
        }
