"""
Pre-staging tests for Mirror Mode DDoS detection.

Tests cover:
  A. PerIPCounter correctness (thread safety, memory caps, protocol breakdown)
  B. PerIPBaselineManager (independent baselines, LRU/stale eviction, isolation)
  C. MirrorAgent._tick() logic (per-IP detection, concurrent incidents, resolution)
  D. Packet parsing edge cases (VLAN, IPv6, GRE, non-IP, fragments)
  E. Flow collector per-dst-IP tracking
  F. Collision checks (mode conflicts, backward compatibility)
"""

import collections
import socket
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# Mirror engine imports
from ftagent.mirror_engine import (
    PerIPCounter, IPSnapshot, IPStats, MirrorCaptureEngine,
    _parse_ethernet, _parse_ipv4,
    ETH_P_IP, ETH_P_IPV6, ETH_P_8021Q, ETH_P_8021AD,
    PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_GRE,
)

# Agent imports
from ftagent.agent import (
    BaselineManager, PerIPBaselineManager, classify_attack,
    classify_subtype, DEFAULT_CONFIG,
)

# Flow collector imports
from ftagent.flow_collector import FlowAggregator, FlowRecord


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_eth_ipv4(src_ip: str, dst_ip: str, protocol: int = PROTO_TCP,
                   pkt_len: int = 60, dst_port: int = 80,
                   tcp_flags: int = 0x02, vlan: int = 0,
                   qinq: int = 0) -> bytes:
    """Build a minimal Ethernet + IPv4 + L4 frame for testing."""
    # Ethernet header
    eth = b"\x00" * 6 + b"\x00" * 6  # dst + src MAC

    # VLAN tags
    if qinq:
        eth += struct.pack("!HHH", ETH_P_8021AD, qinq & 0xFFF, ETH_P_8021Q)
        eth += struct.pack("!HH", vlan & 0xFFF, ETH_P_IP)
    elif vlan:
        eth += struct.pack("!HHH", ETH_P_8021Q, vlan & 0xFFF, ETH_P_IP)
    else:
        eth += struct.pack("!H", ETH_P_IP)

    # IPv4 header (20 bytes, no options)
    ihl = 5
    version_ihl = (4 << 4) | ihl
    total_len = max(pkt_len, 40)
    ttl = 64
    ip_hdr = struct.pack("!BBHHHBBH",
                         version_ihl, 0, total_len, 0, 0,
                         ttl, protocol, 0)  # checksum = 0 (not validated)
    ip_hdr += socket.inet_aton(src_ip)
    ip_hdr += socket.inet_aton(dst_ip)

    # L4 header
    l4 = b""
    if protocol == PROTO_TCP:
        l4 = struct.pack("!HH", 12345, dst_port)  # src_port, dst_port
        l4 += b"\x00" * 8  # seq, ack
        l4 += struct.pack("!BB", 0x50, tcp_flags)  # data offset, flags
        l4 += b"\x00" * 6  # window, checksum, urgent
    elif protocol == PROTO_UDP:
        l4 = struct.pack("!HH", 12345, dst_port)
        l4 += struct.pack("!HH", total_len - 20, 0)

    # Pad to pkt_len
    payload_len = max(0, total_len - 20 - len(l4))
    frame = eth + ip_hdr + l4 + (b"\x00" * payload_len)
    return frame


def _make_eth_ipv6(src_ip: str, dst_ip: str, protocol: int = PROTO_TCP,
                   pkt_len: int = 60) -> bytes:
    """Build a minimal Ethernet + IPv6 frame."""
    eth = b"\x00" * 12 + struct.pack("!H", ETH_P_IPV6)
    payload_len = max(pkt_len - 40, 20)
    ip6 = struct.pack("!IHBB",
                      0x60000000,  # version=6, traffic class, flow label
                      payload_len,
                      protocol,
                      64)  # hop limit
    ip6 += socket.inet_pton(socket.AF_INET6, src_ip)
    ip6 += socket.inet_pton(socket.AF_INET6, dst_ip)
    # Minimal L4
    l4 = b"\x00" * payload_len
    return eth + ip6 + l4


def _make_gre_frame(outer_src: str, outer_dst: str,
                    inner_src: str, inner_dst: str,
                    inner_proto: int = PROTO_UDP) -> bytes:
    """Build Ethernet + IPv4(GRE(IPv4)) frame."""
    # Inner IP packet
    inner_ip = struct.pack("!BBHHHBBH", 0x45, 0, 60, 0, 0, 64, inner_proto, 0)
    inner_ip += socket.inet_aton(inner_src)
    inner_ip += socket.inet_aton(inner_dst)
    inner_ip += b"\x00" * 40  # payload

    # GRE header: flags=0, protocol=ETH_P_IP
    gre = struct.pack("!HH", 0x0000, ETH_P_IP)

    # Outer IP
    outer_total = 20 + 4 + len(inner_ip)
    outer_ip = struct.pack("!BBHHHBBH", 0x45, 0, outer_total, 0, 0, 64, PROTO_GRE, 0)
    outer_ip += socket.inet_aton(outer_src)
    outer_ip += socket.inet_aton(outer_dst)

    # Ethernet
    eth = b"\x00" * 12 + struct.pack("!H", ETH_P_IP)

    return eth + outer_ip + gre + inner_ip


# ═══════════════════════════════════════════════════════════════════════
# A. PerIPCounter Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPerIPCounter(unittest.TestCase):

    def test_basic_counting(self):
        """Feed packets for multiple IPs, verify per-IP PPS/BPS."""
        counter = PerIPCounter()
        counter.record_packet("10.0.0.1", "1.2.3.4", PROTO_TCP, 100, dst_port=80)
        counter.record_packet("10.0.0.1", "1.2.3.5", PROTO_TCP, 150, dst_port=80)
        counter.record_packet("10.0.0.2", "1.2.3.6", PROTO_UDP, 200, dst_port=53)

        snap = counter.snapshot_and_reset()
        self.assertEqual(len(snap), 2)

        s1 = snap["10.0.0.1"]
        self.assertEqual(s1.packets, 2)
        self.assertEqual(s1.pps, 2.0)
        self.assertEqual(s1.bps, (100 + 150) * 8)
        self.assertEqual(s1.tcp_pct, 100.0)
        self.assertEqual(s1.src_ip_count, 2)

        s2 = snap["10.0.0.2"]
        self.assertEqual(s2.packets, 1)
        self.assertEqual(s2.udp_pct, 100.0)

    def test_snapshot_resets(self):
        """After snapshot_and_reset, counters should be empty."""
        counter = PerIPCounter()
        counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_TCP, 100)
        snap1 = counter.snapshot_and_reset()
        self.assertEqual(len(snap1), 1)
        snap2 = counter.snapshot_and_reset()
        self.assertEqual(len(snap2), 0)

    def test_memory_cap(self):
        """Counter should respect max_ips cap."""
        counter = PerIPCounter(max_ips=100)
        for i in range(200):
            counter.record_packet(f"10.0.{i//256}.{i%256}", "1.1.1.1", PROTO_TCP, 100)
        snap = counter.snapshot_and_reset()
        self.assertEqual(len(snap), 100)

    def test_thread_safety(self):
        """Concurrent writers + reader should not crash or produce partial reads."""
        counter = PerIPCounter()
        errors = []

        def writer(thread_id):
            for i in range(1000):
                counter.record_packet(
                    f"10.0.{thread_id}.{i%256}",
                    f"1.{thread_id}.0.1",
                    PROTO_TCP, 100,
                )

        def reader():
            for _ in range(50):
                snap = counter.snapshot_and_reset()
                for ip, s in snap.items():
                    if s.packets <= 0:
                        errors.append(f"Zero packets for {ip}")
                time.sleep(0.01)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        threads.append(threading.Thread(target=reader))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")

    def test_protocol_breakdown(self):
        """Mixed protocol traffic should produce correct percentages."""
        counter = PerIPCounter()
        for _ in range(6):
            counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_TCP, 100)
        for _ in range(3):
            counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_UDP, 100)
        counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_ICMP, 100)

        snap = counter.snapshot_and_reset()
        s = snap["10.0.0.1"]
        self.assertAlmostEqual(s.tcp_pct, 60.0, places=0)
        self.assertAlmostEqual(s.udp_pct, 30.0, places=0)
        self.assertAlmostEqual(s.icmp_pct, 10.0, places=0)

    def test_tcp_flags(self):
        """TCP flags should be tracked per destination IP."""
        counter = PerIPCounter()
        counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_TCP, 100,
                              tcp_flags=0x02)  # SYN
        counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_TCP, 100,
                              tcp_flags=0x02)  # SYN
        counter.record_packet("10.0.0.1", "1.1.1.1", PROTO_TCP, 100,
                              tcp_flags=0x10)  # ACK
        snap = counter.snapshot_and_reset()
        self.assertEqual(snap["10.0.0.1"].tcp_flags["SYN"], 2)
        self.assertEqual(snap["10.0.0.1"].tcp_flags["ACK"], 1)


# ═══════════════════════════════════════════════════════════════════════
# B. PerIPBaselineManager Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPerIPBaselineManager(unittest.TestCase):

    def test_independent_baselines(self):
        """Different IPs should get independent thresholds."""
        mgr = PerIPBaselineManager(window=10)
        # IP-A: low traffic (100 PPS)
        for _ in range(20):
            mgr.add("10.0.0.1", 100)
        # IP-B: high traffic (50000 PPS)
        for _ in range(20):
            mgr.add("10.0.0.2", 50000)

        bl_a = mgr.get_baseline("10.0.0.1")
        bl_b = mgr.get_baseline("10.0.0.2")
        # Thresholds should differ significantly
        self.assertLess(bl_a["threshold"], bl_b["threshold"])
        self.assertGreater(bl_b["threshold"], 10000)

    def test_lru_eviction(self):
        """Manager should evict oldest IPs when at capacity."""
        mgr = PerIPBaselineManager(window=10, max_ips=50)
        for i in range(60):
            mgr.add(f"10.0.0.{i}", 100)
        self.assertLessEqual(mgr.ip_count, 50)
        # First IPs should be evicted
        bl = mgr.get_baseline("10.0.0.0")
        self.assertFalse(bl["ready"])  # evicted, so no baseline

    def test_stale_eviction(self):
        """IPs with no traffic for stale_seconds should be evicted."""
        mgr = PerIPBaselineManager(window=10, stale_seconds=0.1)
        mgr.add("10.0.0.1", 100)
        self.assertEqual(mgr.ip_count, 1)
        time.sleep(0.2)
        # Trigger prune by adding another IP
        mgr._last_prune = 0  # force prune check
        mgr.add("10.0.0.2", 200)
        # IP 1 should be pruned
        bl = mgr.get_baseline("10.0.0.1")
        self.assertFalse(bl["ready"])

    def test_floor_threshold_new_ip(self):
        """New IP with no baseline should trigger at absolute floor (10K PPS)."""
        mgr = PerIPBaselineManager(window=300)
        # No samples added yet
        self.assertTrue(mgr.check("10.0.0.1", 15000))
        self.assertFalse(mgr.check("10.0.0.1", 5000))

    def test_baseline_isolation(self):
        """Attack traffic on IP-A should not be fed to IP-B's baseline."""
        mgr = PerIPBaselineManager(window=10)
        # Build baseline for both IPs
        for _ in range(15):
            mgr.add("10.0.0.1", 100)
            mgr.add("10.0.0.2", 100)

        # Simulate: stop feeding IP-A (under attack), keep feeding IP-B
        for _ in range(10):
            mgr.add("10.0.0.2", 100)

        # IP-B baseline should be stable
        bl_b = mgr.get_baseline("10.0.0.2")
        self.assertAlmostEqual(bl_b["avg_pps"], 100, delta=10)

    def test_check_with_baseline(self):
        """After baseline is established, check should use max(p99 x 3, 5000)."""
        mgr = PerIPBaselineManager(window=10)
        # Build a baseline at 100 PPS
        for _ in range(15):
            mgr.add("10.0.0.1", 100)

        bl = mgr.get_baseline("10.0.0.1")
        self.assertTrue(bl["ready"])
        # threshold = max(100 * 3, 5000) = 5000, so 10000 should trigger
        self.assertTrue(mgr.check("10.0.0.1", 10000))
        # 3000 should not trigger (below 5000 floor)
        self.assertFalse(mgr.check("10.0.0.1", 3000))


# ═══════════════════════════════════════════════════════════════════════
# C. Detection Logic Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDetectionLogic(unittest.TestCase):

    def test_per_ip_not_aggregate(self):
        """50 IPs each at 2000 PPS = 100K aggregate, but no single IP should trigger."""
        mgr = PerIPBaselineManager(window=10)
        # Build baselines at 2000 PPS
        for _ in range(15):
            for i in range(50):
                mgr.add(f"10.0.0.{i}", 2000)
        # Check: no IP should trigger at 2000 PPS
        for i in range(50):
            self.assertFalse(mgr.check(f"10.0.0.{i}", 2000))
        # But one IP at 20000 PPS should trigger (above max(6000, 5000) = 6000)
        self.assertTrue(mgr.check("10.0.0.0", 20000))

    def test_concurrent_incidents(self):
        """Two IPs under attack should get separate detection states."""
        mgr = PerIPBaselineManager(window=10)
        for _ in range(15):
            mgr.add("10.0.0.1", 100)
            mgr.add("10.0.0.2", 200)
        # Both should trigger independently (threshold floor = 5000)
        self.assertTrue(mgr.check("10.0.0.1", 10000))
        self.assertTrue(mgr.check("10.0.0.2", 15000))

    def test_resolution_independence(self):
        """IP-A resolving should not affect IP-B's state."""
        # This is inherently true since PerIPBaselineManager tracks
        # baselines independently, but let's verify
        mgr = PerIPBaselineManager(window=10)
        for _ in range(15):
            mgr.add("10.0.0.1", 100)
            mgr.add("10.0.0.2", 100)

        # Both under attack (must exceed 5000 floor)
        self.assertTrue(mgr.check("10.0.0.1", 10000))
        self.assertTrue(mgr.check("10.0.0.2", 10000))

        # IP-A drops back to normal
        for _ in range(5):
            mgr.add("10.0.0.1", 100)

        # IP-A should no longer trigger
        self.assertFalse(mgr.check("10.0.0.1", 100))
        # IP-B should still trigger
        self.assertTrue(mgr.check("10.0.0.2", 10000))


# ═══════════════════════════════════════════════════════════════════════
# D. Packet Parsing Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestPacketParsing(unittest.TestCase):

    def test_basic_ipv4(self):
        """Parse a basic Ethernet + IPv4 + TCP frame."""
        counter = PerIPCounter()
        frame = _make_eth_ipv4("1.2.3.4", "10.0.0.1", PROTO_TCP, 100, dst_port=80)
        _parse_ethernet(frame, counter)
        snap = counter.snapshot_and_reset()
        self.assertIn("10.0.0.1", snap)
        self.assertEqual(snap["10.0.0.1"].packets, 1)
        self.assertEqual(snap["10.0.0.1"].tcp_pct, 100.0)

    def test_vlan_tagged(self):
        """Parse 802.1Q VLAN-tagged frame."""
        counter = PerIPCounter()
        frame = _make_eth_ipv4("1.2.3.4", "10.0.0.1", PROTO_UDP, 100,
                               dst_port=53, vlan=100)
        _parse_ethernet(frame, counter)
        snap = counter.snapshot_and_reset()
        self.assertIn("10.0.0.1", snap)
        self.assertEqual(snap["10.0.0.1"].udp_pct, 100.0)

    def test_qinq_double_tagged(self):
        """Parse QinQ double-tagged frame."""
        counter = PerIPCounter()
        frame = _make_eth_ipv4("1.2.3.4", "10.0.0.1", PROTO_TCP, 100,
                               vlan=200, qinq=100)
        _parse_ethernet(frame, counter)
        snap = counter.snapshot_and_reset()
        self.assertIn("10.0.0.1", snap)

    def test_ipv6(self):
        """Parse IPv6 frame."""
        counter = PerIPCounter()
        frame = _make_eth_ipv6("2001:db8::1", "2001:db8::2", PROTO_TCP, 60)
        _parse_ethernet(frame, counter)
        snap = counter.snapshot_and_reset()
        self.assertIn("2001:db8::2", snap)

    def test_non_ip_ignored(self):
        """ARP/LLDP frames should be silently ignored."""
        counter = PerIPCounter()
        # ARP frame (ethertype 0x0806)
        arp = b"\x00" * 12 + struct.pack("!H", 0x0806) + b"\x00" * 28
        _parse_ethernet(arp, counter)
        snap = counter.snapshot_and_reset()
        self.assertEqual(len(snap), 0)

    def test_truncated_frame(self):
        """Truncated frames should not crash."""
        counter = PerIPCounter()
        # Too short for Ethernet
        _parse_ethernet(b"\x00" * 5, counter)
        # Ethernet header but too short for IP
        _parse_ethernet(b"\x00" * 14, counter)
        snap = counter.snapshot_and_reset()
        self.assertEqual(len(snap), 0)

    def test_gre_decapsulation(self):
        """GRE-encapsulated packets should be decapsulated when gre_strip=True."""
        counter = PerIPCounter()
        frame = _make_gre_frame("172.16.0.1", "172.16.0.2",
                                "10.0.0.5", "10.0.0.6",
                                inner_proto=PROTO_UDP)
        _parse_ethernet(frame, counter, gre_strip=True)
        snap = counter.snapshot_and_reset()
        # Should see inner dst IP, not outer
        self.assertIn("10.0.0.6", snap)
        self.assertNotIn("172.16.0.2", snap)

    def test_gre_without_strip(self):
        """Without gre_strip, GRE packets count the outer IPs."""
        counter = PerIPCounter()
        frame = _make_gre_frame("172.16.0.1", "172.16.0.2",
                                "10.0.0.5", "10.0.0.6")
        _parse_ethernet(frame, counter, gre_strip=False)
        snap = counter.snapshot_and_reset()
        # Should see outer dst IP
        self.assertIn("172.16.0.2", snap)

    def test_subnet_filter(self):
        """Only packets to monitored subnets should be counted."""
        import ipaddress
        subnets = [ipaddress.ip_network("10.0.0.0/24")]
        counter = PerIPCounter()

        # In-subnet
        frame1 = _make_eth_ipv4("1.1.1.1", "10.0.0.5", PROTO_TCP, 100)
        _parse_ethernet(frame1, counter, subnets=subnets)
        # Out-of-subnet
        frame2 = _make_eth_ipv4("1.1.1.1", "192.168.1.5", PROTO_TCP, 100)
        _parse_ethernet(frame2, counter, subnets=subnets)

        snap = counter.snapshot_and_reset()
        self.assertIn("10.0.0.5", snap)
        self.assertNotIn("192.168.1.5", snap)


# ═══════════════════════════════════════════════════════════════════════
# E. Flow Collector Per-Dst-IP Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFlowAggregatorPerDstIP(unittest.TestCase):

    def test_per_dst_ip_tracking(self):
        """Flow aggregator should track per-destination-IP when enabled."""
        agg = FlowAggregator(per_dst_ip_mode=True)
        agg.ingest([
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1", protocol=PROTO_TCP,
                       packets=100, octets=10000),
            FlowRecord(src_ip="1.1.1.2", dst_ip="10.0.0.2", protocol=PROTO_UDP,
                       packets=50, octets=5000),
            FlowRecord(src_ip="1.1.1.3", dst_ip="10.0.0.1", protocol=PROTO_TCP,
                       packets=200, octets=20000),
        ])
        agg.read(dt=1.0)

        per_ip = agg.per_dst_ip_data
        self.assertIn("10.0.0.1", per_ip)
        self.assertIn("10.0.0.2", per_ip)
        self.assertEqual(per_ip["10.0.0.1"]["packets"], 300)
        self.assertEqual(per_ip["10.0.0.2"]["packets"], 50)

    def test_per_dst_ip_disabled(self):
        """Per-dst-IP should be empty when mode is disabled."""
        agg = FlowAggregator(per_dst_ip_mode=False)
        agg.ingest([
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1", protocol=PROTO_TCP,
                       packets=100, octets=10000),
        ])
        agg.read(dt=1.0)
        self.assertEqual(len(agg.per_dst_ip_data), 0)

    def test_per_dst_ip_protocol_breakdown(self):
        """Per-IP data should track protocol breakdown correctly."""
        agg = FlowAggregator(per_dst_ip_mode=True)
        agg.ingest([
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1", protocol=PROTO_TCP,
                       packets=6, octets=600),
            FlowRecord(src_ip="1.1.1.2", dst_ip="10.0.0.1", protocol=PROTO_UDP,
                       packets=3, octets=300),
            FlowRecord(src_ip="1.1.1.3", dst_ip="10.0.0.1", protocol=PROTO_ICMP,
                       packets=1, octets=100),
        ])
        agg.read(dt=1.0)
        data = agg.per_dst_ip_data["10.0.0.1"]
        self.assertEqual(data["tcp"], 6)
        self.assertEqual(data["udp"], 3)
        self.assertEqual(data["icmp"], 1)

    def test_per_dst_ip_pps_method(self):
        """per_dst_ip_pps() should return correct PPS mapping."""
        agg = FlowAggregator(per_dst_ip_mode=True)
        agg.ingest([
            FlowRecord(dst_ip="10.0.0.1", packets=100, octets=1000),
            FlowRecord(dst_ip="10.0.0.2", packets=200, octets=2000),
        ])
        agg.read(dt=1.0)
        pps = agg.per_dst_ip_pps()
        self.assertEqual(pps["10.0.0.1"], 100.0)
        self.assertEqual(pps["10.0.0.2"], 200.0)

    def test_per_dst_ip_memory_cap(self):
        """Per-dst-IP tracking should respect MAX_DST_IPS."""
        agg = FlowAggregator(per_dst_ip_mode=True)
        # Override cap for testing
        agg.MAX_DST_IPS = 50
        records = [
            FlowRecord(dst_ip=f"10.0.{i//256}.{i%256}", packets=1, octets=100)
            for i in range(200)
        ]
        agg.ingest(records)
        agg.read(dt=1.0)
        self.assertLessEqual(len(agg.per_dst_ip_data), 50)


# ═══════════════════════════════════════════════════════════════════════
# F. Collision / Backward Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCollisionChecks(unittest.TestCase):

    def test_default_config_no_mirror(self):
        """Default config should have mirror_mode=False."""
        self.assertFalse(DEFAULT_CONFIG.get("mirror_mode"))
        self.assertEqual(DEFAULT_CONFIG.get("mirror_interface"), "")
        self.assertEqual(DEFAULT_CONFIG.get("mirror_subnets"), [])

    def test_baseline_manager_unchanged(self):
        """BaselineManager should work exactly as before (no regression)."""
        bl = BaselineManager(window=10)
        self.assertFalse(bl.baseline_ready)
        for _ in range(12):
            bl.add(100)
        self.assertTrue(bl.baseline_ready)
        self.assertGreater(bl.threshold, 0)
        self.assertAlmostEqual(bl.avg_pps, 100, delta=5)

    def test_flow_aggregator_backward_compat(self):
        """FlowAggregator without per_dst_ip_mode should work as before."""
        agg = FlowAggregator()
        agg.ingest([
            FlowRecord(src_ip="1.1.1.1", dst_ip="10.0.0.1", protocol=PROTO_TCP,
                       packets=100, octets=10000),
        ])
        agg.read(dt=1.0)
        self.assertEqual(agg.pps, 100.0)
        self.assertEqual(agg.bps, 80000.0)
        self.assertEqual(agg.tcp_pct, 100.0)
        # per_dst_ip_data should be empty
        self.assertEqual(len(agg.per_dst_ip_data), 0)

    def test_classify_attack_unchanged(self):
        """Attack classification should produce same results as before."""
        self.assertEqual(classify_attack(20, 60, 10), "udp_flood")
        self.assertEqual(classify_attack(60, 10, 10, syn_ratio=0.7), "syn_flood")
        self.assertEqual(classify_attack(10, 10, 50), "icmp_flood")
        self.assertEqual(classify_attack(30, 30, 30), "multi_vector")

    def test_classify_subtype_unchanged(self):
        """Subtype classification should produce same results."""
        self.assertEqual(classify_subtype("udp_flood", [{"port": 53}]), "dns_amplification")
        self.assertEqual(classify_subtype("udp_flood", [{"port": 123}]), "ntp_amplification")
        self.assertEqual(classify_subtype("icmp_flood", avg_pkt_len=2000), "ping_of_death")

    def test_ipsnapshot_from_ipstats(self):
        """IPSnapshot should correctly compute fields from IPStats."""
        stats = IPStats()
        stats.packets = 100
        stats.octets = 10000
        stats.tcp_packets = 60
        stats.udp_packets = 30
        stats.icmp_packets = 10
        stats.src_ips = {"1.1.1.1": 50, "2.2.2.2": 50}
        stats.dst_ports = {80: 60, 53: 30, 443: 10}
        stats.pkt_sizes = [100, 200, 300]

        snap = IPSnapshot("10.0.0.1", stats)
        self.assertEqual(snap.dst_ip, "10.0.0.1")
        self.assertEqual(snap.pps, 100.0)
        self.assertEqual(snap.bps, 80000.0)
        self.assertEqual(snap.tcp_pct, 60.0)
        self.assertEqual(snap.udp_pct, 30.0)
        self.assertEqual(snap.icmp_pct, 10.0)
        self.assertEqual(snap.src_ip_count, 2)
        self.assertEqual(len(snap.top_src_ips), 2)
        self.assertEqual(len(snap.top_dst_ports), 3)
        self.assertAlmostEqual(snap.avg_pkt_size, 200.0)


# ═══════════════════════════════════════════════════════════════════════
# Performance Benchmarks
# ═══════════════════════════════════════════════════════════════════════

class TestPerformance(unittest.TestCase):

    def test_per_ip_counter_throughput(self):
        """PerIPCounter should handle high packet rates efficiently."""
        counter = PerIPCounter()
        start = time.monotonic()
        # Simulate 100K packets across 1000 IPs
        for i in range(100_000):
            ip_idx = i % 1000
            counter.record_packet(
                f"10.0.{ip_idx//256}.{ip_idx%256}",
                f"1.0.{(i//256)%256}.{i%256}",
                PROTO_TCP if i % 3 == 0 else PROTO_UDP,
                100,
            )
        elapsed = time.monotonic() - start
        snap = counter.snapshot_and_reset()
        self.assertEqual(len(snap), 1000)
        # Should complete in under 2 seconds (usually <0.5s)
        self.assertLess(elapsed, 2.0,
                        f"100K packets took {elapsed:.2f}s (should be <2s)")

    def test_snapshot_performance(self):
        """snapshot_and_reset should be fast even with many IPs."""
        counter = PerIPCounter()
        for i in range(10_000):
            counter.record_packet(f"10.{i//65536}.{(i//256)%256}.{i%256}",
                                  "1.1.1.1", PROTO_TCP, 100)
        start = time.monotonic()
        snap = counter.snapshot_and_reset()
        elapsed = time.monotonic() - start
        self.assertEqual(len(snap), 10_000)
        self.assertLess(elapsed, 0.1,
                        f"Snapshot of 10K IPs took {elapsed:.3f}s (should be <100ms)")

    def test_per_ip_baseline_throughput(self):
        """PerIPBaselineManager should handle many IPs efficiently."""
        mgr = PerIPBaselineManager(window=10, max_ips=5000)
        start = time.monotonic()
        for _ in range(20):
            for i in range(1000):
                mgr.add(f"10.0.{i//256}.{i%256}", 100 + i)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0,
                        f"20K baseline updates took {elapsed:.2f}s (should be <2s)")
        self.assertEqual(mgr.ip_count, 1000)


if __name__ == "__main__":
    unittest.main()
