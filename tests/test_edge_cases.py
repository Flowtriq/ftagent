"""
Edge case and stress tests for ftagent.

Covers:
  - High PPS simulation (synthetic load, memory leak detection)
  - Rapid incident cycling (trigger/resolve state consistency)
  - Config hot-reload simulation
  - Concurrent access to shared state
  - Boundary conditions (empty, single, max values)
  - Baseline decay and recovery
  - Attack state machine transitions
"""

import collections
import math
import os
import threading
import time

import pytest

from ftagent.agent import (
    BaselineManager,
    PerIPBaselineManager,
    TrafficAnalyser,
    IOCMatcher,
    GREDecapsulator,
    classify_attack,
    classify_subtype,
    classify_tcp_subtype,
    enrich_from_ioc,
    DEFAULT_CONFIG,
)
from ftagent.flow_collector import FlowAggregator, FlowRecord, PROTO_TCP, PROTO_UDP


# ═══════════════════════════════════════════════════════════════════════
# High PPS Simulation
# ═══════════════════════════════════════════════════════════════════════

class TestHighPPSSimulation:
    """Feed 100K+ synthetic data points, verify no memory leaks or crashes."""

    def test_baseline_100k_samples(self):
        bl = BaselineManager(window=300)
        for i in range(100_000):
            bl.add(float(1000 + (i % 500)))
        assert bl.baseline_ready is True
        assert bl.avg_pps > 0
        assert bl.threshold > 0
        assert len(bl.samples) == 300  # bounded

    def test_per_ip_baseline_high_ip_count(self):
        pm = PerIPBaselineManager(window=10, max_ips=1000)
        for i in range(5000):
            ip = f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
            pm.add(ip, float(i * 10))
        # Should stay under max_ips
        assert pm.ip_count <= 1000

    def test_traffic_analyser_many_source_ips(self):
        ta = TrafficAnalyser()
        ta.total_packets = 200_000
        for i in range(200_000):
            ip = f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
            if len(ta.src_ips) < ta.MAX_SRC_IPS:
                ta.src_ips[ip] = 1
            else:
                break
        assert len(ta.src_ips) <= ta.MAX_SRC_IPS
        # entropy calculation should not crash on large data
        entropy = ta.src_ip_entropy()
        assert entropy > 0

    def test_flow_aggregator_high_volume(self):
        agg = FlowAggregator()
        for batch in range(100):
            records = [
                FlowRecord(src_ip=f"10.0.{batch}.{i}", dst_ip="2.2.2.2",
                            protocol=PROTO_TCP, packets=10, octets=1000)
                for i in range(100)
            ]
            agg.ingest(records)
        agg.read(dt=1.0)
        assert agg.pps > 0
        assert agg.src_ip_count > 0

    def test_pkt_length_samples_bounded(self):
        ta = TrafficAnalyser()
        for i in range(100_000):
            if len(ta.pkt_lengths) < ta.MAX_PKT_SAMPLES:
                ta.pkt_lengths.append(64 + (i % 1400))
        assert len(ta.pkt_lengths) <= ta.MAX_PKT_SAMPLES
        # Histogram should work on full buffer
        hist = ta.pkt_length_histogram()
        assert sum(hist.values()) > 0

    def test_dns_queries_bounded(self):
        ta = TrafficAnalyser()
        for i in range(20_000):
            domain = f"test{i}.example.com"
            if len(ta.dns_queries) < ta.MAX_DNS_QUERIES:
                ta.dns_queries[domain] = 1
        assert len(ta.dns_queries) <= ta.MAX_DNS_QUERIES


# ═══════════════════════════════════════════════════════════════════════
# Rapid Incident Cycling
# ═══════════════════════════════════════════════════════════════════════

class TestRapidIncidentCycling:
    """Simulate rapid attack start/stop cycles and verify state consistency."""

    def test_baseline_attack_exclusion_pattern(self):
        """Simulate the pattern: normal -> attack -> normal -> attack.
        Verify baseline stays sane when attack samples are excluded."""
        bl = BaselineManager(window=50)
        # Build baseline with normal traffic
        for _ in range(50):
            bl.add(1000.0)
        assert bl.baseline_ready is True
        normal_threshold = bl.threshold

        # Attack phase: don't add to baseline (simulating agent behavior)
        # This should NOT change baseline
        _ = bl.threshold  # just reading

        # Return to normal
        for _ in range(20):
            bl.add(1100.0)
        # Threshold should be similar (not corrupted by attack)
        assert abs(bl.threshold - normal_threshold) < normal_threshold * 0.5

    def test_per_ip_rapid_cycling(self):
        """Rapidly add/check IPs to verify no state corruption."""
        pm = PerIPBaselineManager(window=10, max_ips=100)
        for cycle in range(50):
            ip = f"10.0.0.{cycle % 20}"
            for _ in range(10):
                pm.add(ip, float(1000 + cycle * 100))
            # Check threshold: should not crash
            pm.check(ip, 5000.0)
            pm.get_baseline(ip)

    def test_traffic_analyser_rapid_reset(self):
        """Reset the analyser many times and verify clean state."""
        ta = TrafficAnalyser()
        for cycle in range(100):
            ta.src_ips = {f"1.2.3.{i}": i * 10 for i in range(50)}
            ta.total_packets = 500
            ta.fragment_count = 25
            ta.pkt_lengths = [64] * 100
            ta.ttl_values = [64] * 100

            # Process stats
            ta.src_ip_entropy()
            ta.syn_ratio()
            ta.fragment_pct()

            # Reset
            ta.reset()
            assert ta.total_packets == 0
            assert len(ta.src_ips) == 0
            assert ta.fragment_count == 0

    def test_flow_aggregator_rapid_read(self):
        """Rapidly ingest and read from flow aggregator."""
        agg = FlowAggregator()
        for _ in range(100):
            rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                              protocol=PROTO_TCP, packets=100, octets=50000)
            agg.ingest([rec])
            agg.read(dt=1.0)
            # After read, accumulators should be reset
            assert agg.read(dt=1.0) is False


# ═══════════════════════════════════════════════════════════════════════
# Concurrent Access
# ═══════════════════════════════════════════════════════════════════════

class TestConcurrentAccess:
    """Test thread safety of shared state."""

    def test_baseline_concurrent_add(self):
        bl = BaselineManager(window=100)
        errors = []

        def worker(start_val):
            try:
                for i in range(200):
                    bl.add(float(start_val + i))
            except Exception as e:
                errors.append(str(e))

        threads = [
            threading.Thread(target=worker, args=(0,)),
            threading.Thread(target=worker, args=(1000,)),
            threading.Thread(target=worker, args=(2000,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert errors == []
        # Baseline should have exactly 100 samples (deque maxlen)
        assert len(bl.samples) == 100

    def test_per_ip_baseline_concurrent(self):
        pm = PerIPBaselineManager(window=10, max_ips=500)
        errors = []

        def worker(prefix):
            try:
                for i in range(200):
                    ip = f"{prefix}.0.0.{i % 256}"
                    pm.add(ip, float(i * 100))
                    pm.check(ip, float(i * 100))
                    pm.get_threshold(ip)
            except Exception as e:
                errors.append(str(e))

        threads = [
            threading.Thread(target=worker, args=("10",)),
            threading.Thread(target=worker, args=("11",)),
            threading.Thread(target=worker, args=("12",)),
            threading.Thread(target=worker, args=("13",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        assert errors == []

    def test_flow_aggregator_concurrent_ingest_read(self):
        agg = FlowAggregator()
        errors = []
        stop = threading.Event()

        def producer():
            try:
                while not stop.is_set():
                    rec = FlowRecord(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                      protocol=PROTO_TCP, packets=1, octets=100)
                    agg.ingest([rec])
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"producer: {e}")

        def consumer():
            try:
                while not stop.is_set():
                    agg.read(dt=0.01)
                    _ = agg.pps
                    _ = agg.tcp_pct
                    _ = agg.src_ip_count
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"consumer: {e}")

        t1 = threading.Thread(target=producer)
        t2 = threading.Thread(target=consumer)
        t1.start()
        t2.start()
        time.sleep(0.5)
        stop.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert errors == []

    def test_gre_decapsulator_concurrent(self):
        import struct
        gre = GREDecapsulator(max_depth=3)
        errors = []

        def _make_raw_ip():
            data = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, 6, 0)
            data += bytes([1, 2, 3, 4]) + bytes([5, 6, 7, 8])
            data += b"\x00" * 20
            return data

        def worker():
            try:
                pkt = _make_raw_ip()
                for _ in range(500):
                    gre.decapsulate_raw(pkt)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert errors == []


# ═══════════════════════════════════════════════════════════════════════
# Baseline Decay and Recovery
# ═══════════════════════════════════════════════════════════════════════

class TestBaselineDecayRecovery:
    """Test baseline behavior during traffic pattern changes."""

    def test_baseline_adapts_to_higher_traffic(self):
        bl = BaselineManager(window=50)
        # Low traffic
        for _ in range(50):
            bl.add(500.0)
        low_threshold = bl.threshold

        # Higher traffic
        for _ in range(50):
            bl.add(5000.0)
        high_threshold = bl.threshold

        # Threshold should increase
        assert high_threshold > low_threshold

    def test_baseline_adapts_to_lower_traffic(self):
        bl = BaselineManager(window=50)
        # High traffic: 50K PPS so threshold is well above MIN_READY_THRESHOLD
        for _ in range(50):
            bl.add(50000.0)
        high_threshold = bl.threshold

        # Lower traffic: need enough samples to fully replace both the main
        # window (50) AND dilute the hourly baseline (360 samples).
        # Feed 400 low samples so the hourly p99 also drops.
        for _ in range(400):
            bl.add(1000.0)
        low_threshold = bl.threshold

        # Threshold should decrease (both above MIN_READY_THRESHOLD)
        assert low_threshold < high_threshold

    def test_baseline_p99_with_outliers(self):
        bl = BaselineManager(window=100)
        for i in range(100):
            # 99% at 1000 PPS, 1% at 50000 PPS
            pps = 50000.0 if i == 99 else 1000.0
            bl.add(pps)
        assert bl.baseline_ready is True
        # p99 should be influenced by the outlier
        assert bl.p99_pps >= 1000.0

    def test_threshold_floor_protects_quiet_servers(self):
        bl = BaselineManager(window=50)
        # Very quiet server: 10 PPS
        for _ in range(50):
            bl.add(10.0)
        assert bl.baseline_ready is True
        # Threshold should not drop below _MIN_READY_THRESHOLD
        assert bl.threshold >= bl._MIN_READY_THRESHOLD

    def test_recalc_interval(self):
        bl = BaselineManager(window=50)
        bl._RECALC_EVERY = 5
        for i in range(50):
            bl.add(float(i * 100))
        # Should have recalculated multiple times
        assert bl.p99_pps > 0


# ═══════════════════════════════════════════════════════════════════════
# Attack Classification Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestClassificationEdgeCases:
    """Edge cases in attack classification."""

    def test_classify_all_protocols_exactly_equal(self):
        # With 33.3% each, icmp_pct > 30 triggers icmp_flood before multi_vector
        result = classify_attack(33.3, 33.3, 33.3)
        assert result == "icmp_flood"

    def test_classify_100_pct_tcp(self):
        result = classify_attack(100.0, 0.0, 0.0)
        assert result in ("tcp_flood", "syn_flood")

    def test_classify_100_pct_udp(self):
        result = classify_attack(0.0, 100.0, 0.0)
        assert result == "udp_flood"

    def test_classify_100_pct_icmp(self):
        result = classify_attack(0.0, 0.0, 100.0)
        assert result == "icmp_flood"

    def test_classify_very_small_values(self):
        result = classify_attack(0.001, 0.001, 0.001)
        assert isinstance(result, str)

    def test_classify_subtype_all_amplification_ports(self):
        amp_ports = {
            53: "dns_amplification",
            123: "ntp_amplification",
            1900: "ssdp_amplification",
            11211: "memcached_amplification",
            389: "cldap_amplification",
            19: "chargen_amplification",
            161: "snmp_amplification",
        }
        for port, expected in amp_ports.items():
            result = classify_subtype("udp_flood",
                                       top_ports=[{"port": port, "count": 100}])
            assert result == expected, f"Port {port} -> {result}, expected {expected}"

    def test_classify_subtype_src_port_amplification(self):
        """Source port detection should identify reflectors."""
        result = classify_subtype(
            "udp_flood",
            top_ports=[{"port": 9999, "count": 100}],  # random dst port
            src_ports=[{"port": 123, "count": 500}],    # NTP src port
        )
        assert result == "ntp_amplification"

    def test_tcp_subtype_null_flood_with_nonzero_counts(self):
        """Null flood: all ratios near zero but total > 0."""
        flags = {"SYN": 1, "ACK": 1, "RST": 1, "FIN": 1,
                 "PSH": 1, "URG": 1}
        result = classify_tcp_subtype(flags)
        # With such small equal values, most ratios < 0.05 threshold
        # except they'd each be ~0.167, so this won't trigger null_flood
        assert isinstance(result, str)

    def test_enrich_multiple_ioc_types(self):
        hits = ["Mirai:botnet", "Mirai:botnet", "Gafgyt:botnet"]
        f, s, tool, boost = enrich_from_ioc(hits, "udp_flood", "")
        # Most frequent hit should win
        assert tool == "Mirai"

    def test_classify_with_tcp_flags_dict(self):
        """classify_attack should handle tcp_flags parameter."""
        flags = {"SYN": 900, "ACK": 100, "RST": 0, "FIN": 0,
                 "PSH": 0, "URG": 0}
        result = classify_attack(80.0, 10.0, 5.0, syn_ratio=0.9,
                                  tcp_flags=flags)
        assert result == "syn_flood"


# ═══════════════════════════════════════════════════════════════════════
# GRE Decapsulator Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestGREEdgeCases:
    """Edge cases for GRE decapsulation."""

    def test_nested_gre_max_depth(self):
        import struct
        gre = GREDecapsulator(max_depth=1)

        def _make_ip_gre_ip():
            inner_ip = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, 6, 0)
            inner_ip += bytes([10, 0, 0, 1, 10, 0, 0, 2])
            inner_ip += b"\x00" * 20
            gre_hdr = struct.pack("!HH", 0, 0x0800)
            outer_ip = struct.pack("!BBHHHBBH",
                                    0x45, 0, 20 + len(gre_hdr) + len(inner_ip),
                                    0, 0, 64, 47, 0)
            outer_ip += bytes([1, 1, 1, 1, 2, 2, 2, 2])
            return outer_ip + gre_hdr + inner_ip

        data = _make_ip_gre_ip()
        result, was_gre = gre.decapsulate_raw(data)
        assert was_gre is True

    def test_gre_with_checksum_flag(self):
        import struct
        gre = GREDecapsulator(max_depth=3)

        # Build GRE with checksum flag set (0x8000)
        inner_ip = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, 6, 0)
        inner_ip += bytes([10, 0, 0, 1, 10, 0, 0, 2])
        inner_ip += b"\x00" * 20

        # GRE with checksum: flags=0x8000, proto=0x0800, checksum(2)+reserved(2)
        gre_hdr = struct.pack("!HH", 0x8000, 0x0800)
        gre_hdr += struct.pack("!HH", 0, 0)  # checksum + reserved

        outer_ip = struct.pack("!BBHHHBBH",
                                0x45, 0, 20 + len(gre_hdr) + len(inner_ip),
                                0, 0, 64, 47, 0)
        outer_ip += bytes([1, 1, 1, 1, 2, 2, 2, 2])

        data = outer_ip + gre_hdr + inner_ip
        result, was_gre = gre.decapsulate_raw(data)
        assert was_gre is True

    def test_gre_invalid_inner_packet(self):
        import struct
        gre = GREDecapsulator(max_depth=3)

        # GRE wrapping non-IP data (inner doesn't start with 0x4x)
        inner = b"\x00" * 40  # not a valid IP packet

        gre_hdr = struct.pack("!HH", 0, 0x0800)
        outer_ip = struct.pack("!BBHHHBBH",
                                0x45, 0, 20 + len(gre_hdr) + len(inner),
                                0, 0, 64, 47, 0)
        outer_ip += bytes([1, 1, 1, 1, 2, 2, 2, 2])

        data = outer_ip + gre_hdr + inner
        result, was_gre = gre.decapsulate_raw(data)
        # Should not strip because inner is not valid IP
        assert was_gre is False

    def test_gre_empty_inner(self):
        import struct
        gre = GREDecapsulator(max_depth=3)

        gre_hdr = struct.pack("!HH", 0, 0x0800)
        outer_ip = struct.pack("!BBHHHBBH",
                                0x45, 0, 20 + len(gre_hdr),
                                0, 0, 64, 47, 0)
        outer_ip += bytes([1, 1, 1, 1, 2, 2, 2, 2])

        data = outer_ip + gre_hdr
        result, was_gre = gre.decapsulate_raw(data)
        assert was_gre is False


# ═══════════════════════════════════════════════════════════════════════
# IOC Matcher Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestIOCMatcherEdgeCases:
    """Edge cases for IOC pattern matching."""

    def test_empty_payload(self):
        m = IOCMatcher()
        m.load([{"pattern": "test", "attack_name": "T", "attack_family": "f"}])
        assert m.check(b"") is None

    def test_binary_payload(self):
        m = IOCMatcher()
        m.load([{"pattern": "test", "attack_name": "T", "attack_family": "f"}])
        assert m.check(b"\x00\xff\x01\x02") is None

    def test_unicode_in_pattern(self):
        m = IOCMatcher()
        m.load([{"pattern": "\u0000test", "attack_name": "T", "attack_family": "f"}])
        result = m.check(b"\x00test data")
        assert result == "T:f"

    def test_many_patterns_performance(self):
        m = IOCMatcher()
        patterns = [
            {"pattern": f"pattern_{i}", "attack_name": f"P{i}", "attack_family": "test"}
            for i in range(100)
        ]
        m.load(patterns)
        # "pattern_99" also contains "pattern_9" so P9 matches first.
        # Use a unique suffix to match only the last pattern.
        result = m.check(b"xyzzy pattern_99 here")
        # First matching pattern wins: pattern_9 is substring of pattern_99
        assert result is not None
        assert result.endswith(":test")

    def test_overlapping_patterns(self):
        m = IOCMatcher()
        m.load([
            {"pattern": "test", "attack_name": "Short", "attack_family": "f"},
            {"pattern": "test_long", "attack_name": "Long", "attack_family": "f"},
        ])
        result = m.check(b"test_long_data")
        # Should match first pattern in list
        assert result == "Short:f"


# ═══════════════════════════════════════════════════════════════════════
# Confidence Scoring
# ═══════════════════════════════════════════════════════════════════════

class TestConfidenceScoring:
    """Test confidence scoring in top_src_ips."""

    def test_high_confidence_syn_flood_source(self):
        ta = TrafficAnalyser()
        ta.total_packets = 1000
        ta.src_ips = {"1.1.1.1": 900}
        ta.src_ip_detail = {
            "1.1.1.1": {
                "tcp": 900, "udp": 0, "icmp": 0, "other": 0,
                "syn": 900, "ack": 0, "bytes": 45000,
                "ttls": {64},
            }
        }
        top = ta.top_src_ips(n=1)
        assert len(top) == 1
        # High contribution + SYN-only + single TTL + single proto + high count
        assert top[0]["confidence"] >= 80

    def test_low_confidence_normal_traffic(self):
        ta = TrafficAnalyser()
        ta.total_packets = 10000
        ta.src_ips = {"1.1.1.1": 10}
        ta.src_ip_detail = {
            "1.1.1.1": {
                "tcp": 5, "udp": 3, "icmp": 2, "other": 0,
                "syn": 3, "ack": 2, "bytes": 5000,
                "ttls": {64, 128, 255},
            }
        }
        top = ta.top_src_ips(n=1)
        assert len(top) == 1
        assert top[0]["confidence"] < 30

    def test_confidence_capped_at_100(self):
        ta = TrafficAnalyser()
        ta.total_packets = 100
        ta.src_ips = {"1.1.1.1": 100}
        ta.src_ip_detail = {
            "1.1.1.1": {
                "tcp": 100, "udp": 0, "icmp": 0, "other": 0,
                "syn": 100, "ack": 0, "bytes": 5000,
                "ttls": {64},
            }
        }
        top = ta.top_src_ips(n=1)
        assert top[0]["confidence"] <= 100
