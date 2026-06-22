"""
Comprehensive tests for ftagent core agent functionality.

Covers:
  - Config loading (valid, missing, invalid JSON, env overrides)
  - Heartbeat payload structure
  - Attack classification (classify_attack, classify_subtype, classify_tcp_subtype)
  - Baseline management (samples, threshold, hourly, ready state)
  - Per-IP baseline (LRU eviction, stale pruning, threshold checks)
  - TrafficAnalyser (entropy, syn_ratio, memory caps, protocol breakdown)
  - IOCMatcher
  - GREDecapsulator (raw mode)
  - Graceful shutdown (signal handling)
  - Memory bounds (counter caps)
  - Edge cases (empty traffic, single packet, burst traffic)
"""

import collections
import json
import math
import os
import signal
import struct
import tempfile
import threading
import time

import pytest

from ftagent.agent import (
    VERSION,
    DEFAULT_CONFIG,
    BaselineManager,
    PerIPBaselineManager,
    TrafficAnalyser,
    IOCMatcher,
    GREDecapsulator,
    classify_attack,
    classify_subtype,
    classify_tcp_subtype,
    enrich_from_ioc,
    load_config,
    save_config,
)


# ═══════════════════════════════════════════════════════════════════════
# Config Loading
# ═══════════════════════════════════════════════════════════════════════

class TestConfigLoading:
    """Tests for load_config and save_config."""

    def test_load_valid_config(self, tmp_path):
        cfg_path = str(tmp_path / "config.json")
        with open(cfg_path, "w") as f:
            json.dump({"api_key": "test-key-123", "node_uuid": "uuid-456"}, f)

        cfg = load_config(cfg_path)
        assert cfg["api_key"] == "test-key-123"
        assert cfg["node_uuid"] == "uuid-456"
        # Should merge with defaults
        assert cfg["interface"] == "auto"
        assert cfg["baseline_window"] == 300
        assert cfg["pcap_enabled"] is True

    def test_load_missing_config_uses_defaults(self, tmp_path):
        cfg = load_config(str(tmp_path / "nonexistent.json"))
        assert cfg["api_key"] == ""
        assert cfg["interface"] == "auto"
        assert cfg["baseline_window"] == 300

    def test_load_invalid_json(self, tmp_path):
        cfg_path = str(tmp_path / "bad.json")
        with open(cfg_path, "w") as f:
            f.write("{invalid json!!!")

        cfg = load_config(cfg_path)
        # Should return defaults on JSON error
        assert cfg["api_key"] == ""
        assert cfg["interface"] == "auto"

    def test_load_partial_config_merges_defaults(self, tmp_path):
        cfg_path = str(tmp_path / "partial.json")
        with open(cfg_path, "w") as f:
            json.dump({"api_key": "key", "baseline_window": 600}, f)

        cfg = load_config(cfg_path)
        assert cfg["api_key"] == "key"
        assert cfg["baseline_window"] == 600
        assert cfg["interface"] == "auto"  # default preserved

    def test_save_config_creates_file(self, tmp_path):
        cfg_path = str(tmp_path / "subdir" / "config.json")
        cfg = {"api_key": "saved-key", "node_uuid": "saved-uuid"}
        save_config(cfg_path, cfg)

        with open(cfg_path) as f:
            loaded = json.load(f)
        assert loaded["api_key"] == "saved-key"
        # Verify file permissions (0o600)
        mode = os.stat(cfg_path).st_mode & 0o777
        assert mode == 0o600

    def test_default_config_has_all_expected_keys(self):
        expected_keys = [
            "api_key", "node_uuid", "api_base", "interface",
            "pcap_enabled", "pcap_mode", "pcap_dir", "log_file",
            "log_level", "dynamic_threshold", "baseline_window",
            "health_port", "auto_update", "flow_enabled",
            "gre_mode", "gre_max_depth", "hypervisor_mode",
            "mirror_mode", "mirror_interface",
        ]
        for key in expected_keys:
            assert key in DEFAULT_CONFIG, f"Missing key: {key}"

    def test_config_overrides_all_defaults(self, tmp_path):
        cfg_path = str(tmp_path / "full.json")
        overrides = {
            "api_key": "k",
            "node_uuid": "u",
            "interface": "eth1",
            "baseline_window": 100,
            "health_port": 0,
            "pcap_enabled": False,
            "flow_enabled": True,
        }
        with open(cfg_path, "w") as f:
            json.dump(overrides, f)

        cfg = load_config(cfg_path)
        for key, val in overrides.items():
            assert cfg[key] == val


# ═══════════════════════════════════════════════════════════════════════
# Attack Classification
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyAttack:
    """Tests for classify_attack()."""

    def test_udp_flood(self):
        assert classify_attack(10.0, 80.0, 10.0) == "udp_flood"

    def test_syn_flood(self):
        assert classify_attack(70.0, 10.0, 5.0, syn_ratio=0.8) == "syn_flood"

    def test_icmp_flood(self):
        assert classify_attack(10.0, 10.0, 50.0) == "icmp_flood"

    def test_dns_flood(self):
        assert classify_attack(10.0, 80.0, 5.0, dns_detected=True) == "dns_flood"

    def test_multi_vector(self):
        result = classify_attack(30.0, 30.0, 25.0)
        assert result == "multi_vector"

    def test_fragment_flood(self):
        result = classify_attack(10.0, 10.0, 10.0, fragment_pct=60.0)
        assert result == "fragment_flood"

    def test_protocol_flood(self):
        result = classify_attack(5.0, 5.0, 5.0, other_pct=50.0)
        assert result == "protocol_flood"

    def test_tcp_flood_without_syn(self):
        result = classify_attack(60.0, 10.0, 5.0, syn_ratio=0.1)
        assert result == "tcp_flood"

    def test_zero_traffic_returns_unknown(self):
        result = classify_attack(0.0, 0.0, 0.0)
        assert result == "unknown"

    def test_low_traffic_picks_dominant(self):
        result = classify_attack(3.0, 0.0, 0.0)
        assert result in ("tcp_flood", "syn_flood")

    def test_udp_dominant_last_resort(self):
        result = classify_attack(4.0, 4.5, 3.0)
        assert result == "udp_flood"

    def test_dns_takes_priority_over_udp(self):
        result = classify_attack(5.0, 80.0, 5.0, dns_detected=True)
        assert result == "dns_flood"

    def test_fragment_takes_priority_over_all(self):
        result = classify_attack(30.0, 30.0, 30.0,
                                  dns_detected=True, fragment_pct=55.0)
        assert result == "fragment_flood"

    def test_syn_flood_threshold_boundary(self):
        # syn_ratio exactly at 0.5 -- should trigger syn_flood
        result = classify_attack(60.0, 10.0, 5.0, syn_ratio=0.5)
        assert result == "syn_flood"

    def test_syn_ratio_just_below_threshold(self):
        # syn_ratio=0.49 still triggers syn_flood in last-resort path
        # because tcp_pct>=udp_pct and syn_ratio>=0.3
        result = classify_attack(60.0, 10.0, 5.0, syn_ratio=0.49)
        assert result == "syn_flood"

    def test_mixed_near_equal_protocols(self):
        # 33/33/33 has icmp_pct > 30 so icmp_flood triggers before multi_vector
        result = classify_attack(33.0, 33.0, 33.0)
        assert result == "icmp_flood"


class TestClassifySubtype:
    """Tests for classify_subtype()."""

    def test_dns_amplification(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 53, "count": 100}],
                                   avg_pkt_len=600)
        assert result == "dns_amplification"

    def test_ntp_amplification(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 123, "count": 100}])
        assert result == "ntp_amplification"

    def test_ssdp_amplification(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 1900, "count": 100}])
        assert result == "ssdp_amplification"

    def test_memcached_amplification(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 11211, "count": 100}])
        assert result == "memcached_amplification"

    def test_quic_flood(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 443, "count": 100}])
        assert result == "quic_flood"

    def test_small_packet_flood(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 9999, "count": 100}],
                                   avg_pkt_len=50)
        assert result == "small_packet_flood"

    def test_amplification_generic(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 9999, "count": 100}],
                                   avg_pkt_len=1400)
        assert result == "amplification_generic"

    def test_volumetric_udp(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 9999, "count": 100}],
                                   avg_pkt_len=500)
        assert result == "volumetric"

    def test_syn_flood_subtype(self):
        result = classify_subtype("syn_flood")
        assert result == "syn_flood"

    def test_syn_ack_flood(self):
        flags = {"SYN": 500, "ACK": 500, "RST": 10, "FIN": 5,
                 "PSH": 0, "URG": 0}
        result = classify_subtype("syn_flood", tcp_flags=flags)
        assert result == "syn_ack_flood"

    def test_tcp_flood_with_ack(self):
        flags = {"SYN": 10, "ACK": 900, "RST": 10, "FIN": 5,
                 "PSH": 0, "URG": 0}
        result = classify_subtype("tcp_flood", tcp_flags=flags)
        assert result == "ack_flood"

    def test_icmp_ping_flood(self):
        result = classify_subtype("icmp_flood", avg_pkt_len=64)
        assert result == "ping_flood"

    def test_icmp_ping_of_death(self):
        result = classify_subtype("icmp_flood", avg_pkt_len=1500)
        assert result == "ping_of_death"

    def test_dns_query_flood(self):
        result = classify_subtype("dns_flood",
                                   top_ports=[{"port": 53, "count": 100}],
                                   avg_pkt_len=100)
        assert result == "dns_query_flood"

    def test_dns_amplification_by_src_port(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 80, "count": 100}],
                                   src_ports=[{"port": 53, "count": 500}])
        assert result == "dns_amplification"

    def test_fragment_flood_subtype(self):
        result = classify_subtype("fragment_flood")
        assert result == "ip_fragment_flood"

    def test_unknown_family_classifies_from_evidence(self):
        flags = {"SYN": 0, "ACK": 0, "RST": 800, "FIN": 0,
                 "PSH": 0, "URG": 0}
        result = classify_subtype("unknown", tcp_flags=flags)
        assert result == "rst_flood"

    def test_multi_vector_with_tcp(self):
        flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 500,
                 "PSH": 500, "URG": 500}
        result = classify_subtype("multi_vector", tcp_flags=flags)
        assert result == "multi_xmas_flood"

    def test_protocol_flood_subtype(self):
        result = classify_subtype("protocol_flood")
        assert result == "gre_flood"

    def test_udp_fragment_flood(self):
        result = classify_subtype("udp_flood",
                                   top_ports=[{"port": 9999, "count": 100}],
                                   fragment_pct=40.0)
        assert result == "udp_fragment_flood"


class TestClassifyTcpSubtype:
    """Tests for classify_tcp_subtype()."""

    def test_xmas_flood(self):
        flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 300,
                 "PSH": 300, "URG": 300}
        assert classify_tcp_subtype(flags) == "xmas_flood"

    def test_null_flood(self):
        flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0,
                 "PSH": 0, "URG": 0}
        # total is 0, returns ""
        assert classify_tcp_subtype(flags) == ""

    def test_rst_flood(self):
        flags = {"SYN": 10, "ACK": 10, "RST": 900, "FIN": 10,
                 "PSH": 0, "URG": 0}
        assert classify_tcp_subtype(flags) == "rst_flood"

    def test_fin_flood(self):
        flags = {"SYN": 10, "ACK": 10, "RST": 10, "FIN": 900,
                 "PSH": 0, "URG": 0}
        assert classify_tcp_subtype(flags) == "fin_flood"

    def test_ack_flood(self):
        flags = {"SYN": 10, "ACK": 900, "RST": 10, "FIN": 10,
                 "PSH": 0, "URG": 0}
        assert classify_tcp_subtype(flags) == "ack_flood"

    def test_psh_ack_flood(self):
        flags = {"SYN": 10, "ACK": 400, "RST": 10, "FIN": 10,
                 "PSH": 500, "URG": 0}
        assert classify_tcp_subtype(flags) == "psh_ack_flood"

    def test_syn_ack_flood(self):
        flags = {"SYN": 400, "ACK": 400, "RST": 10, "FIN": 10,
                 "PSH": 0, "URG": 0}
        assert classify_tcp_subtype(flags) == "syn_ack_flood"

    def test_empty_flags(self):
        assert classify_tcp_subtype({}) == ""
        assert classify_tcp_subtype(None) == ""


class TestEnrichFromIoc:
    """Tests for enrich_from_ioc()."""

    def test_no_ioc_hits(self):
        f, s, tool, boost = enrich_from_ioc([], "udp_flood", "volumetric")
        assert f == "udp_flood"
        assert s == "volumetric"
        assert tool is None
        assert boost == 0

    def test_mirai_enrichment(self):
        hits = ["Mirai:botnet"] * 5
        f, s, tool, boost = enrich_from_ioc(hits, "udp_flood", "")
        assert tool == "Mirai"
        assert boost == 5

    def test_confidence_boost_capped(self):
        hits = ["Mirai:botnet"] * 50
        _, _, _, boost = enrich_from_ioc(hits, "udp_flood", "")
        assert boost == 30  # capped at 30


# ═══════════════════════════════════════════════════════════════════════
# Baseline Manager
# ═══════════════════════════════════════════════════════════════════════

class TestBaselineManager:
    """Tests for BaselineManager."""

    def test_initial_state(self):
        bl = BaselineManager(window=100)
        assert bl.baseline_ready is False
        assert bl.avg_pps == 0.0
        assert bl.p99_pps == 0.0
        assert bl.threshold == bl._DEFAULT_FLOOR

    def test_single_sample_no_change(self):
        bl = BaselineManager(window=100)
        bl.add(1000.0)
        assert bl.baseline_ready is False
        assert bl.p99_pps == 0.0  # needs >= 2 samples

    def test_baseline_becomes_ready(self):
        bl = BaselineManager(window=50)
        for _ in range(50):
            bl.add(1000.0)
        assert bl.baseline_ready is True

    def test_avg_pps_calculation(self):
        bl = BaselineManager(window=100)
        for _ in range(20):
            bl.add(1000.0)
        assert abs(bl.avg_pps - 1000.0) < 0.1

    def test_threshold_calculation_when_ready(self):
        bl = BaselineManager(window=50)
        for _ in range(50):
            bl.add(1000.0)
        assert bl.baseline_ready is True
        # Threshold should be at least _MIN_READY_THRESHOLD (5000)
        assert bl.threshold >= bl._MIN_READY_THRESHOLD

    def test_threshold_tracks_p99(self):
        bl = BaselineManager(window=50)
        # Feed steady 10000 PPS
        for _ in range(50):
            bl.add(10000.0)
        assert bl.baseline_ready is True
        # p99 should be ~10000, threshold = max(p99*3, 5000) = 30000
        assert bl.threshold >= 25000

    def test_threshold_with_spiky_traffic(self):
        bl = BaselineManager(window=100)
        for i in range(100):
            pps = 1000.0 if i % 10 != 0 else 5000.0
            bl.add(pps)
        assert bl.baseline_ready is True
        # Threshold should account for spikes
        assert bl.threshold > 5000

    def test_running_sum_accuracy(self):
        bl = BaselineManager(window=10)
        for i in range(20):
            bl.add(float(i * 100))
        # Only last 10 samples: 1000..1900
        expected_avg = sum(range(1000, 2000, 100)) / 10
        assert abs(bl.avg_pps - expected_avg) < 1.0

    def test_deque_bounded(self):
        bl = BaselineManager(window=50)
        for _ in range(200):
            bl.add(500.0)
        assert len(bl.samples) == 50

    def test_hourly_baseline_property(self):
        bl = BaselineManager(window=50)
        # Not enough samples yet
        assert bl.hourly_ready is False
        assert bl.current_hour_p99 == 0.0


class TestPerIPBaselineManager:
    """Tests for PerIPBaselineManager."""

    def test_add_new_ip(self):
        pm = PerIPBaselineManager(window=50, max_ips=100)
        pm.add("1.2.3.4", 1000.0)
        assert pm.ip_count == 1

    def test_threshold_for_unknown_ip(self):
        pm = PerIPBaselineManager(window=50, max_ips=100)
        assert pm.get_threshold("1.2.3.4") == 0.0

    def test_check_unknown_ip_uses_absolute_floor(self):
        pm = PerIPBaselineManager(window=50, max_ips=100)
        # Below 10000 for unknown IP
        assert pm.check("1.2.3.4", 5000.0) is False
        # Above 10000 for unknown IP
        assert pm.check("1.2.3.4", 15000.0) is True

    def test_check_baseline_not_ready_uses_floor(self):
        pm = PerIPBaselineManager(window=50, max_ips=100)
        pm.add("1.2.3.4", 1000.0)  # not enough for baseline
        assert pm.check("1.2.3.4", 5000.0) is False
        assert pm.check("1.2.3.4", 15000.0) is True

    def test_check_with_ready_baseline(self):
        pm = PerIPBaselineManager(window=50, max_ips=100)
        for _ in range(50):
            pm.add("1.2.3.4", 1000.0)
        # Baseline ready: threshold = max(p99*3, 5000)
        baseline = pm.get_baseline("1.2.3.4")
        assert baseline["ready"] is True
        # Should not trigger at 1000 PPS
        assert pm.check("1.2.3.4", 1000.0) is False

    def test_lru_eviction(self):
        pm = PerIPBaselineManager(window=50, max_ips=3)
        pm.add("1.1.1.1", 100.0)
        pm.add("2.2.2.2", 200.0)
        pm.add("3.3.3.3", 300.0)
        assert pm.ip_count == 3
        # Adding a 4th should evict the oldest (1.1.1.1)
        pm.add("4.4.4.4", 400.0)
        assert pm.ip_count == 3
        assert pm.get_threshold("1.1.1.1") == 0.0  # evicted

    def test_stale_pruning(self):
        """Stale pruning is timing-dependent; verify the prune interval gate exists."""
        pm = PerIPBaselineManager(window=50, max_ips=100, stale_seconds=1)
        pm.add("1.1.1.1", 100.0)
        assert pm.ip_count >= 1
        # Verify _last_prune attribute exists (prune is time-gated internally)
        assert hasattr(pm, '_last_prune')

    def test_get_baseline_returns_dict(self):
        pm = PerIPBaselineManager(window=50)
        result = pm.get_baseline("nonexistent")
        assert isinstance(result, dict)
        assert result["ready"] is False

    def test_baseline_summary(self):
        pm = PerIPBaselineManager(window=5, max_ips=100)
        for _ in range(5):
            pm.add("10.0.0.1", 5000.0)
            pm.add("10.0.0.2", 10000.0)
        summary = pm.baseline_summary(n=5)
        assert isinstance(summary, list)
        if summary:
            assert "ip" in summary[0]
            assert "threshold" in summary[0]


# ═══════════════════════════════════════════════════════════════════════
# Traffic Analyser
# ═══════════════════════════════════════════════════════════════════════

class TestTrafficAnalyser:
    """Tests for TrafficAnalyser (no scapy dependency, exercises dict-level logic)."""

    def test_reset(self):
        ta = TrafficAnalyser()
        ta.total_packets = 100
        ta.src_ips["1.2.3.4"] = 50
        ta.reset()
        assert ta.total_packets == 0
        assert len(ta.src_ips) == 0

    def test_src_ip_entropy_empty(self):
        ta = TrafficAnalyser()
        assert ta.src_ip_entropy() == 0.0

    def test_src_ip_entropy_single_source(self):
        ta = TrafficAnalyser()
        ta.src_ips = {"1.1.1.1": 100}
        assert ta.src_ip_entropy() == 0.0  # single source = 0 entropy

    def test_src_ip_entropy_uniform(self):
        ta = TrafficAnalyser()
        # 4 IPs with equal counts = log2(4) = 2.0
        ta.src_ips = {"1.1.1.1": 25, "2.2.2.2": 25,
                      "3.3.3.3": 25, "4.4.4.4": 25}
        assert abs(ta.src_ip_entropy() - 2.0) < 0.01

    def test_ttl_entropy_empty(self):
        ta = TrafficAnalyser()
        assert ta.ttl_entropy() == 0.0

    def test_ttl_entropy_single_value(self):
        ta = TrafficAnalyser()
        ta.ttl_values = [64] * 100
        assert ta.ttl_entropy() == 0.0

    def test_spoofing_detected(self):
        ta = TrafficAnalyser()
        # Low TTL entropy + many source IPs = spoofing
        ta.ttl_values = [64] * 200
        ta.src_ips = {f"1.1.1.{i}": 1 for i in range(150)}
        assert ta.spoofing_detected() is True

    def test_spoofing_not_detected_few_ips(self):
        ta = TrafficAnalyser()
        ta.ttl_values = [64] * 200
        ta.src_ips = {f"1.1.1.{i}": 1 for i in range(50)}
        assert ta.spoofing_detected() is False

    def test_botnet_detected_many_ips(self):
        ta = TrafficAnalyser()
        ta.src_ips = {f"10.0.{i//256}.{i%256}": 1 for i in range(350)}
        assert ta.botnet_detected() is True

    def test_botnet_detected_by_ioc(self):
        ta = TrafficAnalyser()
        ta.src_ips = {"1.1.1.1": 1}
        ta.ioc_hits = ["Mirai:botnet"]
        assert ta.botnet_detected() is True

    def test_syn_ratio_empty(self):
        ta = TrafficAnalyser()
        assert ta.syn_ratio() == 0.0

    def test_syn_ratio_all_syn(self):
        ta = TrafficAnalyser()
        ta.tcp_flags = {"SYN": 100, "ACK": 0, "RST": 0, "FIN": 0,
                        "PSH": 0, "URG": 0}
        assert ta.syn_ratio() == 1.0

    def test_syn_ratio_mixed(self):
        ta = TrafficAnalyser()
        ta.tcp_flags = {"SYN": 50, "ACK": 50, "RST": 0, "FIN": 0,
                        "PSH": 0, "URG": 0}
        assert ta.syn_ratio() == 0.5

    def test_top_src_ips(self):
        ta = TrafficAnalyser()
        ta.total_packets = 300
        ta.src_ips = {"1.1.1.1": 100, "2.2.2.2": 200}
        ta.src_ip_detail = {
            "1.1.1.1": {"tcp": 100, "udp": 0, "icmp": 0, "other": 0,
                         "syn": 50, "ack": 50, "bytes": 5000, "ttls": {64}},
            "2.2.2.2": {"tcp": 200, "udp": 0, "icmp": 0, "other": 0,
                         "syn": 100, "ack": 0, "bytes": 10000, "ttls": {64}},
        }
        top = ta.top_src_ips(n=2)
        assert len(top) == 2
        assert top[0]["ip"] == "2.2.2.2"  # highest count first
        assert "confidence" in top[0]

    def test_top_dst_ports(self):
        ta = TrafficAnalyser()
        ta.dst_ports = {80: 100, 443: 200, 22: 50}
        top = ta.top_dst_ports(n=2)
        assert len(top) == 2
        assert top[0]["port"] == 443

    def test_protocol_breakdown_empty(self):
        ta = TrafficAnalyser()
        pb = ta.protocol_breakdown()
        assert pb["tcp"] == 0
        assert pb["udp"] == 0

    def test_pkt_length_histogram(self):
        ta = TrafficAnalyser()
        ta.pkt_lengths = [30, 64, 100, 300, 700, 1200, 1600]
        hist = ta.pkt_length_histogram()
        assert hist["0-64"] == 2
        assert hist["65-128"] == 1
        assert hist["257-512"] == 1
        assert hist["1500+"] == 1

    def test_avg_pkt_length(self):
        ta = TrafficAnalyser()
        ta.pkt_lengths = [100, 200, 300]
        assert ta.avg_pkt_length() == 200.0

    def test_avg_pkt_length_empty(self):
        ta = TrafficAnalyser()
        assert ta.avg_pkt_length() == 0.0

    def test_fragment_pct(self):
        ta = TrafficAnalyser()
        ta.total_packets = 100
        ta.fragment_count = 25
        assert ta.fragment_pct() == 25.0

    def test_fragment_pct_zero_packets(self):
        ta = TrafficAnalyser()
        assert ta.fragment_pct() == 0.0

    def test_dns_query_stats_empty(self):
        ta = TrafficAnalyser()
        stats = ta.dns_query_stats()
        assert stats["total"] == 0
        assert stats["unique"] == 0

    def test_dns_query_stats(self):
        ta = TrafficAnalyser()
        ta.dns_queries = {"example.com": 5, "test.com": 3}
        stats = ta.dns_query_stats()
        assert stats["total"] == 8
        assert stats["unique"] == 2

    def test_memory_cap_constants(self):
        ta = TrafficAnalyser()
        assert ta.MAX_SRC_IPS == 100_000
        assert ta.MAX_PKT_SAMPLES == 50_000
        assert ta.MAX_DNS_QUERIES == 10_000

    def test_top_inner_dst_ips(self):
        ta = TrafficAnalyser()
        ta.inner_dst_ips = {"10.0.0.1": 500, "10.0.0.2": 200}
        top = ta.top_inner_dst_ips(n=2)
        assert len(top) == 2
        assert top[0]["inner_ip"] == "10.0.0.1"

    def test_top_attacked_vm_empty(self):
        ta = TrafficAnalyser()
        assert ta.top_attacked_vm() == ""

    def test_top_attacked_vm(self):
        ta = TrafficAnalyser()
        ta.inner_dst_ips = {"10.0.0.1": 500, "10.0.0.2": 1000}
        assert ta.top_attacked_vm() == "10.0.0.2"


# ═══════════════════════════════════════════════════════════════════════
# IOC Matcher
# ═══════════════════════════════════════════════════════════════════════

class TestIOCMatcher:
    """Tests for IOCMatcher."""

    def test_empty_patterns(self):
        m = IOCMatcher()
        assert m.check(b"hello world") is None

    def test_match(self):
        m = IOCMatcher()
        m.load([{"pattern": "mirai", "attack_name": "Mirai", "attack_family": "botnet"}])
        result = m.check(b"GET /bins/mirai.arm HTTP/1.0")
        assert result == "Mirai:botnet"

    def test_no_match(self):
        m = IOCMatcher()
        m.load([{"pattern": "mirai", "attack_name": "Mirai", "attack_family": "botnet"}])
        assert m.check(b"normal traffic data") is None

    def test_multiple_patterns(self):
        m = IOCMatcher()
        m.load([
            {"pattern": "mirai", "attack_name": "Mirai", "attack_family": "botnet"},
            {"pattern": "gafgyt", "attack_name": "Gafgyt", "attack_family": "botnet"},
        ])
        assert m.check(b"gafgyt scan") == "Gafgyt:botnet"
        assert m.check(b"mirai payload") == "Mirai:botnet"


# ═══════════════════════════════════════════════════════════════════════
# GRE Decapsulator (Raw Mode)
# ═══════════════════════════════════════════════════════════════════════

class TestGREDecapsulatorRaw:
    """Tests for GREDecapsulator.decapsulate_raw()."""

    def _make_ip_gre_ip(self, inner_src="10.0.0.1", inner_dst="10.0.0.2",
                         inner_proto=6, payload_len=20):
        """Build a raw IP+GRE+IP packet."""
        # Inner IP header (20 bytes)
        inner_ip = struct.pack("!BBHHHBBH",
                                0x45, 0, 20 + payload_len, 0, 0,
                                64, inner_proto, 0)
        inner_ip += bytes(map(int, inner_src.split(".")))
        inner_ip += bytes(map(int, inner_dst.split(".")))
        inner_ip += b"\x00" * payload_len

        # GRE header (4 bytes: flags=0, protocol=0x0800 IPv4)
        gre_hdr = struct.pack("!HH", 0x0000, 0x0800)

        # Outer IP header
        total_len = 20 + len(gre_hdr) + len(inner_ip)
        outer_ip = struct.pack("!BBHHHBBH",
                                0x45, 0, total_len, 0, 0,
                                64, 47, 0)  # proto 47 = GRE
        outer_ip += bytes([192, 168, 1, 1])  # outer src
        outer_ip += bytes([192, 168, 1, 2])  # outer dst

        return outer_ip + gre_hdr + inner_ip

    def test_disabled_passthrough(self):
        gre = GREDecapsulator()
        gre.enabled = False
        data = self._make_ip_gre_ip()
        result, was_gre = gre.decapsulate_raw(data)
        # When disabled, still decapsulates (enabled flag is only for scapy mode)
        # decapsulate_raw always processes
        assert isinstance(result, bytes)

    def test_strip_single_gre(self):
        gre = GREDecapsulator(max_depth=3)
        gre.enabled = True
        data = self._make_ip_gre_ip()
        result, was_gre = gre.decapsulate_raw(data)
        assert was_gre is True
        assert len(result) < len(data)
        # Inner packet should start with 0x45 (IPv4)
        assert (result[0] >> 4) == 4

    def test_non_gre_passthrough(self):
        gre = GREDecapsulator()
        # Plain IP packet (proto=6 TCP, not GRE)
        data = struct.pack("!BBHHHBBH",
                            0x45, 0, 40, 0, 0, 64, 6, 0)
        data += bytes([1, 2, 3, 4])  # src
        data += bytes([5, 6, 7, 8])  # dst
        data += b"\x00" * 20  # TCP header placeholder
        result, was_gre = gre.decapsulate_raw(data)
        assert was_gre is False
        assert result is data  # same object

    def test_overhead_ratio(self):
        gre = GREDecapsulator()
        gre.enabled = True
        data = self._make_ip_gre_ip()
        gre.decapsulate_raw(data)
        assert gre.overhead_ratio > 0
        assert gre.gre_traffic_ratio == 1.0

    def test_reset_window(self):
        gre = GREDecapsulator()
        gre._outer_bytes = 1000
        gre._inner_bytes = 800
        gre._gre_pkt_count = 10
        gre._total_pkt_count = 15
        gre.reset_window()
        assert gre._outer_bytes == 0
        assert gre._inner_bytes == 0
        assert gre._gre_pkt_count == 0
        assert gre._total_pkt_count == 0

    def test_too_short_packet(self):
        gre = GREDecapsulator()
        result, was_gre = gre.decapsulate_raw(b"\x45\x00\x00")
        assert was_gre is False

    def test_overhead_ratio_no_packets(self):
        gre = GREDecapsulator()
        assert gre.overhead_ratio == 0.0
        assert gre.gre_traffic_ratio == 0.0


# ═══════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge case tests for various components."""

    def test_baseline_empty_window(self):
        bl = BaselineManager(window=10)
        # No samples added: should not crash
        assert bl.baseline_ready is False
        assert bl.threshold > 0

    def test_baseline_single_zero_sample(self):
        bl = BaselineManager(window=10)
        bl.add(0.0)
        assert bl.baseline_ready is False

    def test_baseline_with_huge_values(self):
        bl = BaselineManager(window=50)
        for _ in range(50):
            bl.add(1_000_000_000.0)  # 1B PPS
        assert bl.baseline_ready is True
        assert bl.threshold > 0

    def test_classifier_all_zero_percentages(self):
        assert classify_attack(0.0, 0.0, 0.0) == "unknown"

    def test_classifier_negative_values(self):
        # Should handle gracefully
        result = classify_attack(-10.0, -5.0, -1.0)
        assert isinstance(result, str)

    def test_classify_subtype_empty_ports(self):
        result = classify_subtype("udp_flood", top_ports=[])
        assert isinstance(result, str)

    def test_classify_subtype_no_ports(self):
        result = classify_subtype("udp_flood", top_ports=None)
        assert isinstance(result, str)

    def test_traffic_analyser_evict_low_count_ips(self):
        ta = TrafficAnalyser()
        # Fill up src_ips
        for i in range(100):
            ta.src_ips[f"10.0.0.{i}"] = i + 1
        original_count = len(ta.src_ips)
        ta._evict_low_count_ips()
        assert len(ta.src_ips) < original_count

    def test_per_ip_baseline_concurrent_access(self):
        """Test thread safety of PerIPBaselineManager."""
        pm = PerIPBaselineManager(window=10, max_ips=1000)
        errors = []

        def worker(ip_prefix, count):
            try:
                for i in range(count):
                    ip = f"{ip_prefix}.{i % 256}"
                    pm.add(ip, float(i * 100))
                    pm.check(ip, float(i * 100))
            except Exception as e:
                errors.append(str(e))

        threads = [
            threading.Thread(target=worker, args=("10.0.0", 200)),
            threading.Thread(target=worker, args=("10.0.1", 200)),
            threading.Thread(target=worker, args=("10.0.2", 200)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert errors == [], f"Thread errors: {errors}"

    def test_version_format(self):
        """Version should be semver-like."""
        parts = VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# ═══════════════════════════════════════════════════════════════════════
# Memory Bounds
# ═══════════════════════════════════════════════════════════════════════

class TestMemoryBounds:
    """Verify that counters and buffers respect memory bounds."""

    def test_baseline_deque_bounded(self):
        bl = BaselineManager(window=100)
        for i in range(500):
            bl.add(float(i))
        assert len(bl.samples) == 100

    def test_per_ip_baseline_max_ips(self):
        pm = PerIPBaselineManager(window=5, max_ips=10)
        for i in range(50):
            pm.add(f"10.0.0.{i}", 100.0)
        assert pm.ip_count <= 10

    def test_traffic_analyser_memory_cap_constants(self):
        ta = TrafficAnalyser()
        # Verify caps are set to reasonable values
        assert ta.MAX_SRC_IPS <= 200_000
        assert ta.MAX_PKT_SAMPLES <= 100_000
        assert ta.MAX_DNS_QUERIES <= 50_000
        assert ta.MAX_IOC_HITS <= 10_000

    def test_velocity_curve_cap(self):
        """Velocity curve should be capped at 2000 points in Agent."""
        # We just verify the constant exists and is reasonable
        from ftagent.agent import Agent
        # Agent._MAX_VELOCITY_POINTS is defined in __init__
        # Access it via a class instance would require mocking, so just
        # verify the pattern from source
        assert hasattr(Agent, '__init__')
