"""
Flow collector tests for ftagent.

Covers:
  - NetFlow v5 parsing (header, records, sampling)
  - NetFlow v9 parsing (templates, data flowsets)
  - sFlow v5 parsing (flow samples, expanded samples, raw headers)
  - IPFIX parsing (templates, data sets, enterprise fields)
  - FlowAggregator (ingest, read/snapshot, protocol breakdown, per-dst-IP mode)
  - TemplateCache (store, get, prune, LRU eviction)
  - FlowCollector auto-detect protocol
  - Edge cases (malformed packets, empty datagrams, truncated records)
"""

import collections
import socket
import struct
import threading
import time

import pytest

from ftagent.flow_collector import (
    FlowRecord,
    FlowAggregator,
    FlowCollector,
    TemplateCache,
    parse_netflow_v5,
    parse_netflow_v9,
    parse_sflow_v5,
    parse_ipfix,
    _parse_ip_header,
    _parse_ipv6_header,
    _ip4,
    _ip6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    IE_SOURCE_IPV4_ADDRESS,
    IE_DEST_IPV4_ADDRESS,
    IE_SOURCE_TRANSPORT_PORT,
    IE_DEST_TRANSPORT_PORT,
    IE_PROTOCOL_IDENTIFIER,
    IE_PACKET_DELTA_COUNT,
    IE_OCTET_DELTA_COUNT,
    IE_TCP_CONTROL_BITS,
    DEFAULT_PORTS,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _build_netflow_v5(records_data):
    """Build a NetFlow v5 datagram from a list of record tuples.

    Each record tuple: (src_ip, dst_ip, packets, octets, src_port, dst_port,
                        tcp_flags, protocol)
    """
    count = len(records_data)
    # Header: version(2) + count(2) + sys_uptime(4) + unix_secs(4) + unix_nsecs(4)
    #         + flow_seq(4) + engine_type(1) + engine_id(1) + sampling_interval(2)
    hdr = struct.pack("!HHIIIIBBh",
                       5, count,    # version, count
                       0, 0, 0,     # uptime, secs, nsecs
                       0,           # flow seq
                       0, 0, 1)     # engine_type, engine_id, sampling(=1)

    body = b""
    for rec in records_data:
        src_ip, dst_ip, packets, octets, src_port, dst_port, tcp_flags, protocol = rec
        # NetFlow v5 record: 48 bytes
        # src_addr(4) dst_addr(4) nexthop(4) input(2) output(2)
        # packets(4) octets(4) first(4) last(4) src_port(2) dst_port(2)
        # pad(1) tcp_flags(1) protocol(1) tos(1) src_as(2) dst_as(2)
        # src_mask(1) dst_mask(1) pad(2)
        body += socket.inet_aton(src_ip)
        body += socket.inet_aton(dst_ip)
        body += b"\x00" * 4      # nexthop
        body += struct.pack("!HH", 0, 0)  # input, output
        body += struct.pack("!IIII", packets, octets, 0, 0)  # packets, octets, first, last
        body += struct.pack("!HH", src_port, dst_port)
        body += struct.pack("!xBBBHHBB2x", tcp_flags, protocol, 0, 0, 0, 0, 0)

    return hdr + body


def _build_netflow_v9_template(source_id, template_id, fields):
    """Build a NetFlow v9 datagram containing a template flowset.

    fields: list of (field_id, field_length) tuples
    """
    # NetFlow v9 header (20 bytes)
    header = struct.pack("!HH III I",
                          9, 1,      # version=9, count=1 flowset
                          0, 0, 0,   # sys_uptime, unix_secs, seq
                          source_id)

    # Template FlowSet
    # FlowSet header: id=0, length
    field_data = b""
    for fid, flen in fields:
        field_data += struct.pack("!HH", fid, flen)

    template_body = struct.pack("!HH", template_id, len(fields)) + field_data
    flowset_len = 4 + len(template_body)  # 4 for flowset header
    # Pad to 4-byte boundary
    padding = (4 - flowset_len % 4) % 4
    flowset = struct.pack("!HH", 0, flowset_len + padding) + template_body + b"\x00" * padding

    return header + flowset


def _build_netflow_v9_data(source_id, template_id, records_bytes):
    """Build a NetFlow v9 datagram containing a data flowset."""
    header = struct.pack("!HH III I",
                          9, 1,      # version=9, count=1
                          0, 0, 0,   # sys_uptime, unix_secs, seq
                          source_id)

    flowset_len = 4 + len(records_bytes)
    padding = (4 - flowset_len % 4) % 4
    flowset = struct.pack("!HH", template_id, flowset_len + padding)
    flowset += records_bytes + b"\x00" * padding

    return header + flowset


def _build_sflow_v5_flow_sample(src_ip, dst_ip, src_port, dst_port,
                                  protocol=PROTO_TCP, sampling_rate=1000,
                                  frame_length=1500):
    """Build a minimal sFlow v5 datagram with one flow sample containing
    a raw packet header record."""
    # Build the raw Ethernet+IP+TCP/UDP header that sFlow sampled
    eth_hdr = b"\x00" * 12 + struct.pack("!H", 0x0800)  # dst+src MAC + ethertype
    ip_hdr = struct.pack("!BBHHHBBH",
                          0x45, 0, 40, 0, 0, 64, protocol, 0)
    ip_hdr += socket.inet_aton(src_ip)
    ip_hdr += socket.inet_aton(dst_ip)

    transport_hdr = b""
    if protocol == PROTO_TCP:
        transport_hdr = struct.pack("!HH", src_port, dst_port)
        transport_hdr += b"\x00" * 10  # seq(4)+ack(4)+offset+flags(2)
    elif protocol == PROTO_UDP:
        transport_hdr = struct.pack("!HH", src_port, dst_port)

    raw_header = eth_hdr + ip_hdr + transport_hdr
    header_length = len(raw_header)
    # Pad to 4-byte boundary
    pad_len = (4 - header_length % 4) % 4
    raw_header_padded = raw_header + b"\x00" * pad_len

    # Raw packet header record (format=1)
    #   header_protocol(4) + frame_length(4) + stripped(4) + header_length(4)
    #   + header data
    rec_data = struct.pack("!IIII",
                            1,              # header_protocol (ethernet)
                            frame_length,
                            0,              # stripped
                            header_length)
    rec_data += raw_header_padded
    rec_len = len(rec_data)

    # Flow record wrapper: format(4) + length(4) + data
    rec_wrapper = struct.pack("!II", 1, rec_len) + rec_data

    # Flow sample (format=1)
    #   seq(4) + source_id(4) + sampling_rate(4) + sample_pool(4)
    #   + drops(4) + input(4) + output(4) + num_records(4) + records
    sample_body = struct.pack("!IIIIIIII",
                               1,               # seq
                               0,               # source_id
                               sampling_rate,
                               0, 0, 0, 0,      # pool, drops, input, output
                               1)               # num_records
    sample_body += rec_wrapper
    sample_len = len(sample_body)

    # Sample wrapper: type(4) + length(4) + data
    sample_wrapper = struct.pack("!II", 1, sample_len) + sample_body

    # sFlow v5 header
    #   version(4) + addr_type(4) + agent_addr(4) + sub_agent_id(4)
    #   + seq(4) + uptime(4) + num_samples(4)
    sflow_hdr = struct.pack("!II", 5, 1)          # version=5, addr_type=1 (IPv4)
    sflow_hdr += socket.inet_aton("10.0.0.1")     # agent address
    sflow_hdr += struct.pack("!IIII", 0, 1, 0, 1) # sub_agent, seq, uptime, num_samples

    return sflow_hdr + sample_wrapper


# ═══════════════════════════════════════════════════════════════════════
# FlowRecord
# ═══════════════════════════════════════════════════════════════════════

class TestFlowRecord:
    """Tests for FlowRecord data class."""

    def test_default_values(self):
        rec = FlowRecord()
        assert rec.src_ip == ""
        assert rec.dst_ip == ""
        assert rec.src_port == 0
        assert rec.dst_port == 0
        assert rec.protocol == 0
        assert rec.packets == 0
        assert rec.octets == 0
        assert rec.tcp_flags == 0
        assert rec.sample_rate == 1

    def test_custom_values(self):
        rec = FlowRecord(src_ip="1.2.3.4", dst_ip="5.6.7.8",
                          src_port=12345, dst_port=80,
                          protocol=PROTO_TCP, packets=100, octets=50000)
        assert rec.src_ip == "1.2.3.4"
        assert rec.dst_port == 80
        assert rec.packets == 100


# ═══════════════════════════════════════════════════════════════════════
# NetFlow v5 Parsing
# ═══════════════════════════════════════════════════════════════════════

class TestNetFlowV5:
    """Tests for parse_netflow_v5()."""

    def test_single_record(self):
        data = _build_netflow_v5([
            ("1.2.3.4", "5.6.7.8", 100, 50000, 12345, 80, 0x02, PROTO_TCP),
        ])
        records = parse_netflow_v5(data)
        assert len(records) == 1
        rec = records[0]
        assert rec.src_ip == "1.2.3.4"
        assert rec.dst_ip == "5.6.7.8"
        assert rec.src_port == 12345
        assert rec.dst_port == 80
        assert rec.protocol == PROTO_TCP
        assert rec.tcp_flags == 0x02

    def test_multiple_records(self):
        data = _build_netflow_v5([
            ("1.1.1.1", "2.2.2.2", 50, 25000, 1000, 443, 0x10, PROTO_TCP),
            ("3.3.3.3", "4.4.4.4", 200, 100000, 5000, 53, 0, PROTO_UDP),
        ])
        records = parse_netflow_v5(data)
        assert len(records) == 2
        assert records[0].src_ip == "1.1.1.1"
        assert records[1].src_ip == "3.3.3.3"
        assert records[1].protocol == PROTO_UDP

    def test_wrong_version(self):
        data = struct.pack("!HH", 9, 0) + b"\x00" * 20  # version 9
        records = parse_netflow_v5(data)
        assert len(records) == 0

    def test_empty_data(self):
        assert parse_netflow_v5(b"") == []

    def test_truncated_data(self):
        assert parse_netflow_v5(b"\x00\x05") == []

    def test_header_only_no_records(self):
        data = _build_netflow_v5([])
        records = parse_netflow_v5(data)
        assert len(records) == 0

    def test_packets_multiplied_by_sample_rate(self):
        # Build with sample_interval=1 (default in our helper)
        data = _build_netflow_v5([
            ("1.1.1.1", "2.2.2.2", 10, 5000, 100, 80, 0, PROTO_TCP),
        ])
        records = parse_netflow_v5(data)
        assert len(records) == 1
        # With sample_interval=1, packets = 10*1 = 10
        assert records[0].packets == 10


# ═══════════════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX Parsing
# ═══════════════════════════════════════════════════════════════════════

class TestNetFlowV9:
    """Tests for parse_netflow_v9() with template handling."""

    def test_template_parsing(self):
        cache = TemplateCache()
        fields = [
            (IE_SOURCE_IPV4_ADDRESS, 4),
            (IE_DEST_IPV4_ADDRESS, 4),
            (IE_PROTOCOL_IDENTIFIER, 1),
            (IE_SOURCE_TRANSPORT_PORT, 2),
            (IE_DEST_TRANSPORT_PORT, 2),
            (IE_PACKET_DELTA_COUNT, 4),
            (IE_OCTET_DELTA_COUNT, 4),
        ]
        data = _build_netflow_v9_template(100, 256, fields)
        records = parse_netflow_v9(data, "10.0.0.1", cache)
        # Template flowset produces no data records
        assert len(records) == 0
        # But template should be cached
        tpl = cache.get("10.0.0.1", 100, 256)
        assert tpl is not None
        assert len(tpl) == 7

    def test_data_with_template(self):
        cache = TemplateCache()
        fields = [
            (IE_SOURCE_IPV4_ADDRESS, 4),
            (IE_DEST_IPV4_ADDRESS, 4),
            (IE_PROTOCOL_IDENTIFIER, 1),
            (IE_SOURCE_TRANSPORT_PORT, 2),
            (IE_DEST_TRANSPORT_PORT, 2),
            (IE_PACKET_DELTA_COUNT, 4),
            (IE_OCTET_DELTA_COUNT, 4),
        ]

        # First: send template
        tpl_data = _build_netflow_v9_template(100, 256, fields)
        parse_netflow_v9(tpl_data, "10.0.0.1", cache)

        # Build data record: src(4)+dst(4)+proto(1)+sport(2)+dport(2)+pkts(4)+octets(4)
        record = socket.inet_aton("192.168.1.1") + socket.inet_aton("10.0.0.5")
        record += struct.pack("!B", PROTO_TCP)
        record += struct.pack("!HH", 54321, 80)
        record += struct.pack("!II", 500, 250000)

        data_pkt = _build_netflow_v9_data(100, 256, record)
        records = parse_netflow_v9(data_pkt, "10.0.0.1", cache)
        assert len(records) == 1
        assert records[0].src_ip == "192.168.1.1"
        assert records[0].dst_ip == "10.0.0.5"
        assert records[0].dst_port == 80
        assert records[0].packets == 500

    def test_data_without_template_returns_empty(self):
        cache = TemplateCache()
        record = b"\x00" * 21  # dummy record data
        data_pkt = _build_netflow_v9_data(100, 256, record)
        records = parse_netflow_v9(data_pkt, "10.0.0.1", cache)
        assert len(records) == 0

    def test_wrong_version(self):
        data = struct.pack("!HH", 5, 0) + b"\x00" * 16
        cache = TemplateCache()
        records = parse_netflow_v9(data, "10.0.0.1", cache)
        assert len(records) == 0

    def test_empty_data(self):
        cache = TemplateCache()
        assert parse_netflow_v9(b"", "10.0.0.1", cache) == []


class TestIPFIX:
    """Tests for parse_ipfix()."""

    def _build_ipfix_template(self, domain_id, template_id, fields):
        """Build an IPFIX message with a template set."""
        # Template set body
        template_body = struct.pack("!HH", template_id, len(fields))
        for fid, flen in fields:
            template_body += struct.pack("!HH", fid, flen)

        set_len = 4 + len(template_body)
        padding = (4 - set_len % 4) % 4
        template_set = struct.pack("!HH", 2, set_len + padding)  # set_id=2 for templates
        template_set += template_body + b"\x00" * padding

        msg_len = 16 + len(template_set)
        header = struct.pack("!HH II I",
                              10, msg_len,   # version=10, length
                              0, 0,          # export_time, seq
                              domain_id)
        return header + template_set

    def test_template_parsing(self):
        cache = TemplateCache()
        fields = [
            (IE_SOURCE_IPV4_ADDRESS, 4),
            (IE_DEST_IPV4_ADDRESS, 4),
            (IE_PROTOCOL_IDENTIFIER, 1),
        ]
        data = self._build_ipfix_template(1, 256, fields)
        records = parse_ipfix(data, "10.0.0.1", cache)
        assert len(records) == 0
        tpl = cache.get("10.0.0.1", 1, 256)
        assert tpl is not None
        assert len(tpl) == 3

    def test_wrong_version(self):
        data = struct.pack("!HH", 9, 20) + b"\x00" * 12
        cache = TemplateCache()
        records = parse_ipfix(data, "10.0.0.1", cache)
        assert len(records) == 0

    def test_empty_data(self):
        cache = TemplateCache()
        assert parse_ipfix(b"", "10.0.0.1", cache) == []


# ═══════════════════════════════════════════════════════════════════════
# sFlow v5 Parsing
# ═══════════════════════════════════════════════════════════════════════

class TestSFlowV5:
    """Tests for parse_sflow_v5()."""

    def test_basic_flow_sample(self):
        data = _build_sflow_v5_flow_sample(
            src_ip="192.168.1.100", dst_ip="10.0.0.1",
            src_port=54321, dst_port=80,
            protocol=PROTO_TCP, sampling_rate=1000)
        records = parse_sflow_v5(data)
        assert len(records) >= 1
        rec = records[0]
        assert rec.src_ip == "192.168.1.100"
        assert rec.dst_ip == "10.0.0.1"
        assert rec.dst_port == 80
        assert rec.sample_rate == 1000

    def test_wrong_version(self):
        data = struct.pack("!I", 4) + b"\x00" * 24  # version 4
        records = parse_sflow_v5(data)
        assert len(records) == 0

    def test_empty_data(self):
        assert parse_sflow_v5(b"") == []

    def test_truncated_data(self):
        assert parse_sflow_v5(b"\x00\x00\x00\x05") == []

    def test_udp_sample(self):
        data = _build_sflow_v5_flow_sample(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=53, dst_port=12345,
            protocol=PROTO_UDP, sampling_rate=500)
        records = parse_sflow_v5(data)
        assert len(records) >= 1
        assert records[0].protocol == PROTO_UDP


# ═══════════════════════════════════════════════════════════════════════
# TemplateCache
# ═══════════════════════════════════════════════════════════════════════

class TestTemplateCache:
    """Tests for TemplateCache."""

    def test_store_and_get(self):
        cache = TemplateCache()
        fields = [(8, 4), (12, 4)]
        cache.store("10.0.0.1", 100, 256, fields)
        result = cache.get("10.0.0.1", 100, 256)
        assert result == fields

    def test_get_missing(self):
        cache = TemplateCache()
        assert cache.get("1.1.1.1", 0, 999) is None

    def test_different_sources(self):
        cache = TemplateCache()
        cache.store("10.0.0.1", 0, 256, [(8, 4)])
        cache.store("10.0.0.2", 0, 256, [(12, 4)])
        assert cache.get("10.0.0.1", 0, 256) == [(8, 4)]
        assert cache.get("10.0.0.2", 0, 256) == [(12, 4)]

    def test_prune_stale(self):
        cache = TemplateCache()
        cache.store("10.0.0.1", 0, 256, [(8, 4)])
        # Manually set last_seen to old timestamp
        key = ("10.0.0.1", 0, 256)
        cache._last_seen[key] = time.monotonic() - 7200  # 2 hours ago
        cache.prune(max_age=3600)
        assert cache.get("10.0.0.1", 0, 256) is None

    def test_lru_eviction(self):
        cache = TemplateCache()
        cache.MAX_ENTRIES = 3
        cache.store("10.0.0.1", 0, 256, [(1, 4)])
        cache.store("10.0.0.2", 0, 256, [(2, 4)])
        cache.store("10.0.0.3", 0, 256, [(3, 4)])
        # Adding 4th should evict oldest
        cache.store("10.0.0.4", 0, 256, [(4, 4)])
        assert len(cache._templates) <= 3

    def test_template_update(self):
        cache = TemplateCache()
        cache.store("10.0.0.1", 0, 256, [(8, 4)])
        cache.store("10.0.0.1", 0, 256, [(8, 4), (12, 4)])
        result = cache.get("10.0.0.1", 0, 256)
        assert len(result) == 2


# ═══════════════════════════════════════════════════════════════════════
# FlowAggregator
# ═══════════════════════════════════════════════════════════════════════

class TestFlowAggregator:
    """Tests for FlowAggregator."""

    def test_initial_state(self):
        agg = FlowAggregator()
        assert agg.pps == 0.0
        assert agg.bps == 0.0
        assert agg.flow_count == 0

    def test_ingest_single_record(self):
        agg = FlowAggregator()
        rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                          protocol=PROTO_TCP, packets=100, octets=50000)
        agg.ingest([rec])
        assert agg.read(dt=1.0) is True
        assert agg.pps == 100.0
        assert agg.bps == 50000 * 8

    def test_protocol_breakdown(self):
        agg = FlowAggregator()
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        protocol=PROTO_TCP, packets=60, octets=30000),
            FlowRecord(src_ip="3.3.3.3", dst_ip="2.2.2.2",
                        protocol=PROTO_UDP, packets=30, octets=15000),
            FlowRecord(src_ip="4.4.4.4", dst_ip="2.2.2.2",
                        protocol=PROTO_ICMP, packets=10, octets=5000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        assert agg.tcp_pct == 60.0
        assert agg.udp_pct == 30.0
        assert agg.icmp_pct == 10.0

    def test_tcp_flags_aggregation(self):
        agg = FlowAggregator()
        rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                          protocol=PROTO_TCP, packets=100, octets=50000,
                          tcp_flags=0x02)  # SYN
        agg.ingest([rec])
        agg.read(dt=1.0)
        assert agg.tcp_flag_breakdown["SYN"] == 100

    def test_src_ip_tracking(self):
        agg = FlowAggregator()
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        protocol=PROTO_TCP, packets=50, octets=25000),
            FlowRecord(src_ip="3.3.3.3", dst_ip="2.2.2.2",
                        protocol=PROTO_TCP, packets=150, octets=75000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        assert agg.src_ip_count == 2
        top = agg.top_src_ips(n=2)
        assert top[0][0] == "3.3.3.3"  # highest first

    def test_dst_port_tracking(self):
        agg = FlowAggregator()
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        dst_port=80, protocol=PROTO_TCP, packets=50, octets=25000),
            FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        dst_port=443, protocol=PROTO_TCP, packets=200, octets=100000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        top = agg.top_dst_ports(n=2)
        assert top[0][0] == 443  # highest first

    def test_read_resets_accumulators(self):
        agg = FlowAggregator()
        rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                          protocol=PROTO_TCP, packets=100, octets=50000)
        agg.ingest([rec])
        agg.read(dt=1.0)
        assert agg.pps == 100.0
        # Second read without new data
        result = agg.read(dt=1.0)
        assert result is False
        assert agg.pps == 0.0

    def test_node_ip_filter(self):
        agg = FlowAggregator()
        agg.node_ip = "10.0.0.1"
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1",
                        protocol=PROTO_TCP, packets=100, octets=50000),
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.2",
                        protocol=PROTO_TCP, packets=200, octets=100000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        # Only the record for 10.0.0.1 should be counted
        assert agg.pps == 100.0

    def test_node_ip_filter_empty(self):
        agg = FlowAggregator()
        agg.node_ip = ""  # no filter
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1",
                        protocol=PROTO_TCP, packets=100, octets=50000),
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.2",
                        protocol=PROTO_TCP, packets=200, octets=100000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        assert agg.pps == 300.0  # both counted

    def test_per_dst_ip_mode(self):
        agg = FlowAggregator(per_dst_ip_mode=True)
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1",
                        protocol=PROTO_TCP, packets=100, octets=50000),
            FlowRecord(src_ip="2.2.2.2", dst_ip="10.0.0.2",
                        protocol=PROTO_UDP, packets=200, octets=100000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        per_dst = agg.per_dst_ip_data
        assert "10.0.0.1" in per_dst
        assert "10.0.0.2" in per_dst
        assert per_dst["10.0.0.1"]["packets"] == 100
        assert per_dst["10.0.0.2"]["packets"] == 200

    def test_per_dst_ip_pps(self):
        agg = FlowAggregator(per_dst_ip_mode=True)
        records = [
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1",
                        protocol=PROTO_TCP, packets=100, octets=50000),
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        pps_map = agg.per_dst_ip_pps()
        assert pps_map["10.0.0.1"] == 100.0

    def test_thread_safety(self):
        agg = FlowAggregator()
        errors = []

        def producer():
            try:
                for _ in range(100):
                    rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                      protocol=PROTO_TCP, packets=1, octets=100)
                    agg.ingest([rec])
            except Exception as e:
                errors.append(str(e))

        def consumer():
            try:
                for _ in range(50):
                    agg.read(dt=1.0)
                    _ = agg.pps
                    _ = agg.tcp_pct
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=producer)
        t2 = threading.Thread(target=consumer)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert errors == []

    def test_empty_ingest(self):
        agg = FlowAggregator()
        agg.ingest([])
        assert agg.read(dt=1.0) is False


# ═══════════════════════════════════════════════════════════════════════
# FlowCollector
# ═══════════════════════════════════════════════════════════════════════

class TestFlowCollector:
    """Tests for FlowCollector configuration and protocol auto-detection."""

    def test_default_port_sflow(self):
        cfg = {"flow_protocol": "sflow", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        assert fc.port == 6343

    def test_default_port_netflow_v5(self):
        cfg = {"flow_protocol": "netflow_v5", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        assert fc.port == 2055

    def test_default_port_ipfix(self):
        cfg = {"flow_protocol": "ipfix", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        assert fc.port == 4739

    def test_custom_port(self):
        cfg = {"flow_protocol": "sflow", "flow_port": 9999,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        assert fc.port == 9999

    def test_allowed_sources(self):
        cfg = {"flow_protocol": "auto", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": ["10.0.0.1", "10.0.0.2"]}
        fc = FlowCollector(cfg)
        assert "10.0.0.1" in fc.allowed_sources
        assert "10.0.0.2" in fc.allowed_sources

    def test_auto_parse_netflow_v5(self):
        cfg = {"flow_protocol": "auto", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        data = _build_netflow_v5([
            ("1.2.3.4", "5.6.7.8", 100, 50000, 12345, 80, 0x02, PROTO_TCP),
        ])
        records = fc._auto_parse(data, "10.0.0.1")
        assert len(records) == 1
        assert records[0].src_ip == "1.2.3.4"

    def test_auto_parse_sflow(self):
        cfg = {"flow_protocol": "auto", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        data = _build_sflow_v5_flow_sample(
            src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=54321, dst_port=80)
        records = fc._auto_parse(data, "10.0.0.1")
        assert len(records) >= 1

    def test_auto_parse_empty(self):
        cfg = {"flow_protocol": "auto", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        records = fc._auto_parse(b"", "10.0.0.1")
        assert records == []

    def test_auto_parse_too_short(self):
        cfg = {"flow_protocol": "auto", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        records = fc._auto_parse(b"\x00\x01", "10.0.0.1")
        assert records == []

    def test_stats_property(self):
        cfg = {"flow_protocol": "sflow", "flow_port": 0,
               "flow_bind": "0.0.0.0", "flow_sample_rate": 0,
               "flow_source_ips": []}
        fc = FlowCollector(cfg)
        stats = fc.stats
        assert "datagrams_received" in stats
        assert "protocol" in stats
        assert stats["running"] is False


# ═══════════════════════════════════════════════════════════════════════
# IP Header Parsing Helpers
# ═══════════════════════════════════════════════════════════════════════

class TestIPParsing:
    """Tests for _parse_ip_header and _parse_ipv6_header."""

    def test_parse_ip_header_tcp(self):
        # Build Ethernet(14) + IP(20) + TCP(14+) header
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip_hdr = struct.pack("!BBHHHBBH",
                              0x45, 0, 40, 0, 0, 64, PROTO_TCP, 0)
        ip_hdr += socket.inet_aton("1.2.3.4")
        ip_hdr += socket.inet_aton("5.6.7.8")
        # TCP: sport(2)+dport(2)+seq(4)+ack(4)+offset_flags(2)
        tcp_hdr = struct.pack("!HH", 12345, 80)
        tcp_hdr += b"\x00" * 8  # seq + ack
        tcp_hdr += struct.pack("!BB", 0x50, 0x02)  # data offset + SYN flag
        tcp_hdr += b"\x00" * 2  # remaining

        hdr = eth + ip_hdr + tcp_hdr
        rec = _parse_ip_header(hdr, 14, 1500, 1)
        assert rec is not None
        assert rec.src_ip == "1.2.3.4"
        assert rec.dst_ip == "5.6.7.8"
        assert rec.dst_port == 80
        assert rec.protocol == PROTO_TCP

    def test_parse_ip_header_udp(self):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip_hdr = struct.pack("!BBHHHBBH",
                              0x45, 0, 28, 0, 0, 64, PROTO_UDP, 0)
        ip_hdr += socket.inet_aton("10.0.0.1")
        ip_hdr += socket.inet_aton("10.0.0.2")
        udp_hdr = struct.pack("!HH", 53, 12345)

        hdr = eth + ip_hdr + udp_hdr
        rec = _parse_ip_header(hdr, 14, 500, 100)
        assert rec is not None
        assert rec.src_port == 53
        assert rec.dst_port == 12345
        assert rec.sample_rate == 100
        assert rec.packets == 100

    def test_parse_ip_header_truncated(self):
        rec = _parse_ip_header(b"\x00" * 10, 0, 100, 1)
        assert rec is None

    def test_parse_ipv6_header(self):
        eth = b"\x00" * 12 + struct.pack("!H", 0x86DD)
        # IPv6: version(4b)+tc(8b)+flowlabel(20b) = 4 bytes, payload_len(2), next_hdr(1), hop(1)
        ipv6_hdr = struct.pack("!IHBB",
                                0x60000000,  # version=6
                                20,          # payload length
                                PROTO_TCP,   # next header
                                64)          # hop limit
        ipv6_hdr += socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ipv6_hdr += socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        # TCP header
        tcp_hdr = struct.pack("!HH", 54321, 443)
        tcp_hdr += b"\x00" * 8
        tcp_hdr += struct.pack("!BB", 0x50, 0x02)
        tcp_hdr += b"\x00" * 2

        hdr = eth + ipv6_hdr + tcp_hdr
        rec = _parse_ipv6_header(hdr, 14, 1500, 1)
        assert rec is not None
        assert rec.src_ip == "2001:db8::1"
        assert rec.dst_ip == "2001:db8::2"
        assert rec.dst_port == 443

    def test_ip4_helper(self):
        data = socket.inet_aton("192.168.1.1")
        assert _ip4(data, 0) == "192.168.1.1"

    def test_ip6_helper(self):
        data = socket.inet_pton(socket.AF_INET6, "::1")
        assert _ip6(data, 0) == "::1"


# ═══════════════════════════════════════════════════════════════════════
# Edge Cases / Malformed Packets
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Tests for malformed and edge case flow data."""

    def test_netflow_v5_truncated_record(self):
        # Header says 1 record but data is too short
        hdr = struct.pack("!HHIIIIBBh", 5, 1, 0, 0, 0, 0, 0, 0, 1)
        data = hdr + b"\x00" * 10  # only 10 bytes, need 48
        records = parse_netflow_v5(data)
        assert len(records) == 0

    def test_sflow_zero_samples(self):
        # sFlow with 0 samples
        sflow_hdr = struct.pack("!II", 5, 1)
        sflow_hdr += socket.inet_aton("10.0.0.1")
        sflow_hdr += struct.pack("!IIII", 0, 1, 0, 0)  # 0 samples
        records = parse_sflow_v5(sflow_hdr)
        assert len(records) == 0

    def test_netflow_v9_malformed_flowset_length(self):
        cache = TemplateCache()
        # Header with a data flowset that has length=0 (should break loop)
        header = struct.pack("!HH III I", 9, 1, 0, 0, 0, 100)
        flowset = struct.pack("!HH", 256, 0)  # length=0
        data = header + flowset
        records = parse_netflow_v9(data, "10.0.0.1", cache)
        assert len(records) == 0

    def test_aggregator_max_dst_ips(self):
        agg = FlowAggregator(per_dst_ip_mode=True)
        original_max = agg.MAX_DST_IPS
        agg.MAX_DST_IPS = 5  # temporarily lower for testing
        for i in range(10):
            rec = FlowRecord(src_ip="1.1.1.1", dst_ip=f"10.0.0.{i}",
                              protocol=PROTO_TCP, packets=1, octets=100)
            agg.ingest([rec])
        agg.read(dt=1.0)
        assert len(agg.per_dst_ip_data) <= 5
        agg.MAX_DST_IPS = original_max

    def test_aggregator_max_src_ips(self):
        agg = FlowAggregator()
        # Just verify the constant exists
        from ftagent.flow_collector import MAX_FLOW_SRC_IPS
        assert MAX_FLOW_SRC_IPS == 50_000
