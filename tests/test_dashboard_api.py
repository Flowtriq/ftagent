"""
Dashboard API integration tests for ftagent.

These tests validate that the agent can construct correct payloads for
all API endpoints. In CI, the "live" tests only run on the self-hosted
runner with network access to the staging API.

Covered:
  - Heartbeat payload structure and required fields
  - Incident open/update/resolve payload structure
  - Metrics payload structure
  - PCAP upload payload construction
  - Service port metrics payload
  - GRE tunnel report payload
  - VM stats payload
"""

import json
import time
import uuid

import pytest
from unittest.mock import MagicMock, patch, call

from ftagent.agent import (
    VERSION,
    APIClient,
    BaselineManager,
    TrafficAnalyser,
    GREDecapsulator,
    classify_attack,
    classify_subtype,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_mock_client():
    """Create an APIClient with fully mocked HTTP layer."""
    cfg = {
        "api_base": "https://staging.flowtriq.com/api/v1",
        "api_key": "test-key",
        "node_uuid": "test-uuid",
    }
    with patch("ftagent.agent.requests") as mock_requests:
        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        # Default: all POSTs succeed
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"ok":true}'
        mock_resp.json.return_value = {"ok": True}
        mock_session.post.return_value = mock_resp

        # Default: all GETs succeed
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {}
        mock_session.get.return_value = mock_get_resp

        client = APIClient(cfg)
    return client


# ═══════════════════════════════════════════════════════════════════════
# Heartbeat Payload
# ═══════════════════════════════════════════════════════════════════════

class TestHeartbeatPayload:
    """Verify heartbeat payload has all required fields."""

    def test_heartbeat_sends_correct_path(self):
        client = _make_mock_client()
        hb_data = {
            "version": VERSION,
            "baseline_ready": True,
            "baseline_avg_pps": 1500.0,
            "baseline_p99_pps": 3000.0,
            "baseline_hourly_ready": False,
            "baseline_current_hour_p99": 0.0,
            "circuit_breaker": "closed",
            "retry_queue_size": 0,
            "gre_dedup_enabled": False,
            "hypervisor_mode": False,
            "pcap_active": True,
            "flow_active": False,
        }
        client.heartbeat(hb_data)
        call_url = client.session.post.call_args[0][0]
        assert call_url.endswith("/agent/heartbeat")

    def test_heartbeat_payload_structure(self):
        client = _make_mock_client()
        hb_data = {
            "version": VERSION,
            "baseline_ready": True,
            "baseline_avg_pps": 1500.0,
            "baseline_p99_pps": 3000.0,
            "baseline_hourly_ready": True,
            "baseline_current_hour_p99": 2800.0,
            "circuit_breaker": "closed",
            "retry_queue_size": 0,
            "gre_dedup_enabled": True,
            "hypervisor_mode": False,
            "pcap_active": True,
            "flow_active": True,
        }
        client.heartbeat(hb_data)
        call_kwargs = client.session.post.call_args[1]
        payload = call_kwargs["json"]

        assert payload["version"] == VERSION
        assert isinstance(payload["baseline_ready"], bool)
        assert isinstance(payload["baseline_avg_pps"], float)
        assert isinstance(payload["baseline_p99_pps"], float)

    def test_heartbeat_with_flow_stats(self):
        client = _make_mock_client()
        hb_data = {
            "version": VERSION,
            "baseline_ready": False,
            "baseline_avg_pps": 0.0,
            "baseline_p99_pps": 0.0,
            "baseline_hourly_ready": False,
            "baseline_current_hour_p99": 0.0,
            "circuit_breaker": "closed",
            "retry_queue_size": 0,
            "gre_dedup_enabled": False,
            "hypervisor_mode": False,
            "pcap_active": True,
            "flow_active": True,
            "flow_collector": {
                "datagrams_received": 1000,
                "records_parsed": 5000,
                "protocol": "sflow",
                "port": 6343,
                "running": True,
            },
        }
        client.heartbeat(hb_data)
        payload = client.session.post.call_args[1]["json"]
        assert "flow_collector" in payload
        assert payload["flow_collector"]["protocol"] == "sflow"


# ═══════════════════════════════════════════════════════════════════════
# Incident Open Payload
# ═══════════════════════════════════════════════════════════════════════

class TestIncidentPayload:
    """Verify incident open/update/resolve payloads."""

    def test_open_incident_payload(self):
        client = _make_mock_client()
        # Make the mock return a UUID
        client.session.post.return_value.content = b'{"uuid":"inc-test-123"}'
        client.session.post.return_value.json.return_value = {"uuid": "inc-test-123"}

        inc_data = {
            "peak_pps": 50000.0,
            "peak_bps": 400000000.0,
            "started_at": "2026-06-21T12:00:00+00:00",
            "attack_family": "udp_flood",
            "attack_subtype": "dns_amplification",
            "baseline_pps": 1500.0,
            "duration": 0,
            "gre_dedup_active": False,
        }
        result = client.open_incident(inc_data)
        assert result["uuid"] == "inc-test-123"

        call_url = client.session.post.call_args[0][0]
        assert "/agent/incidents" in call_url
        payload = client.session.post.call_args[1]["json"]
        assert payload["peak_pps"] == 50000.0
        assert payload["attack_family"] == "udp_flood"

    def test_update_incident_payload(self):
        client = _make_mock_client()
        update_data = {
            "peak_pps": 75000.0,
            "peak_bps": 600000000.0,
            "attack_family": "udp_flood",
            "attack_subtype": "dns_amplification",
            "protocol_breakdown": {"tcp": 5.0, "udp": 90.0, "icmp": 5.0},
            "source_ip_count": 500,
            "total_packets": 150000,
            "top_src_ips": [{"ip": "1.2.3.4", "count": 5000}],
            "top_dst_ports": [{"port": 53, "count": 100000}],
        }
        client.update_incident("inc-test-123", update_data)

        call_url = client.session.post.call_args[0][0]
        assert "/agent/incidents/inc-test-123" in call_url

    def test_resolve_incident_payload(self):
        client = _make_mock_client()
        resolve_data = {
            "duration_seconds": 120.5,
            "peak_pps": 75000.0,
            "peak_bps": 600000000.0,
            "attack_family": "udp_flood",
            "attack_subtype": "dns_amplification",
            "protocol_breakdown": {"tcp": 5.0, "udp": 90.0, "icmp": 5.0},
            "source_ip_count": 500,
            "total_packets": 300000,
            "top_src_ips": [{"ip": "1.2.3.4", "count": 10000}],
            "top_dst_ports": [{"port": 53, "count": 200000}],
            "velocity_curve": [
                {"t": 0, "pps": 50000},
                {"t": 60, "pps": 75000},
                {"t": 120, "pps": 2000},
            ],
            "spoofing_detected": True,
            "botnet_detected": False,
        }
        client.resolve_incident("inc-test-123", resolve_data)

        call_url = client.session.post.call_args[0][0]
        assert "/agent/incidents/inc-test-123/resolve" in call_url
        payload = client.session.post.call_args[1]["json"]
        assert payload["duration_seconds"] == 120.5
        assert len(payload["velocity_curve"]) == 3


# ═══════════════════════════════════════════════════════════════════════
# Metrics Payload
# ═══════════════════════════════════════════════════════════════════════

class TestMetricsPayload:
    """Verify metrics payload structure."""

    def test_send_metrics(self):
        client = _make_mock_client()
        metrics = {
            "pps": 1500.0,
            "bps": 12000000.0,
            "tcp_pct": 60.0,
            "udp_pct": 30.0,
            "icmp_pct": 10.0,
            "conn_count": 5000,
            "threshold": 15000.0,
            "avg_pps": 1400.0,
            "samples": 5,
        }
        client.send_metrics(metrics)
        call_url = client.session.post.call_args[0][0]
        assert "/agent/metrics" in call_url


# ═══════════════════════════════════════════════════════════════════════
# Service Port Metrics
# ═══════════════════════════════════════════════════════════════════════

class TestServicePortPayload:
    """Verify service port metrics payload."""

    def test_sp_metrics_payload(self):
        client = _make_mock_client()
        sp_data = {
            "service_pps": 5000,
            "service_bps": 40000000,
            "non_service_pps": 200,
            "non_service_bps": 1600000,
            "blocked_pps": 50,
            "active_blocks": 3,
        }
        client._post("/agent/sp/metrics", sp_data, timeout=5)
        payload = client.session.post.call_args[1]["json"]
        assert payload["service_pps"] == 5000
        assert payload["active_blocks"] == 3

    def test_sp_blocks_payload(self):
        client = _make_mock_client()
        blocks_data = {
            "incident_uuid": "inc-123",
            "blocks": [
                {
                    "source_ip": "1.2.3.4",
                    "block_scope": "non_service",
                    "src_pps": 150,
                    "dst_ports": [22, 3389],
                    "cooldown": 300,
                },
            ],
        }
        client._post("/agent/sp/blocks", blocks_data, timeout=10)
        payload = client.session.post.call_args[1]["json"]
        assert len(payload["blocks"]) == 1
        assert payload["blocks"][0]["source_ip"] == "1.2.3.4"


# ═══════════════════════════════════════════════════════════════════════
# GRE Tunnel Report
# ═══════════════════════════════════════════════════════════════════════

class TestGRETunnelPayload:
    """Verify GRE tunnel report payload."""

    def test_gre_tunnel_report(self):
        client = _make_mock_client()
        tunnel_data = {
            "tunnels": [
                {
                    "name": "gre1",
                    "type": "ip/gre",
                    "remote_ip": "203.0.113.1",
                    "local_ip": "192.0.2.1",
                },
            ],
            "gre_dedup_active": True,
        }
        client._post("/agent/gre-tunnels", tunnel_data, timeout=10)
        payload = client.session.post.call_args[1]["json"]
        assert len(payload["tunnels"]) == 1
        assert payload["tunnels"][0]["remote_ip"] == "203.0.113.1"

    def test_gre_tunnel_report_empty(self):
        client = _make_mock_client()
        tunnel_data = {
            "tunnels": [],
            "gre_dedup_active": False,
        }
        client._post("/agent/gre-tunnels", tunnel_data, timeout=10)
        payload = client.session.post.call_args[1]["json"]
        assert payload["tunnels"] == []


# ═══════════════════════════════════════════════════════════════════════
# VM Stats Payload
# ═══════════════════════════════════════════════════════════════════════

class TestVMStatsPayload:
    """Verify per-VM stats payload."""

    def test_vm_stats_payload(self):
        client = _make_mock_client()
        vm_data = {
            "vms": [
                {
                    "inner_ip": "10.0.0.5",
                    "pps": 5000,
                    "bps": 40000000,
                    "tcp_pct": 80.0,
                    "udp_pct": 15.0,
                    "icmp_pct": 5.0,
                    "src_ip_count": 200,
                    "label": "Web Server",
                },
            ],
            "gre_dedup_active": True,
        }
        client._post("/agent/vm-stats", vm_data, timeout=5)
        payload = client.session.post.call_args[1]["json"]
        assert len(payload["vms"]) == 1
        assert payload["vms"][0]["inner_ip"] == "10.0.0.5"


# ═══════════════════════════════════════════════════════════════════════
# Config Fetch
# ═══════════════════════════════════════════════════════════════════════

class TestConfigFetch:
    """Verify config fetch response handling."""

    def test_get_config_with_threshold(self):
        client = _make_mock_client()
        client.session.get.return_value.json.return_value = {
            "pps_threshold": 25000,
            "dynamic_threshold": False,
        }
        result = client.get_config()
        assert result["pps_threshold"] == 25000

    def test_get_config_with_ioc_patterns(self):
        client = _make_mock_client()
        client.session.get.return_value.json.return_value = {
            "ioc_patterns": [
                {"pattern": "mirai", "attack_name": "Mirai", "attack_family": "botnet"},
            ],
        }
        result = client.get_config()
        assert len(result["ioc_patterns"]) == 1

    def test_get_config_with_service_ports(self):
        client = _make_mock_client()
        client.session.get.return_value.json.return_value = {
            "service_ports": {
                "enabled": True,
                "ports": [
                    {"protocol": "tcp", "port_value": "80,443"},
                    {"protocol": "udp", "port_value": "53"},
                ],
                "sensitivity": "standard",
                "pps_threshold": 100,
                "response_mode": "full",
            },
        }
        result = client.get_config()
        sp = result["service_ports"]
        assert sp["enabled"] is True
        assert len(sp["ports"]) == 2

    def test_get_config_with_pending_commands(self):
        client = _make_mock_client()
        client.session.get.return_value.json.return_value = {
            "pending_commands": [
                {
                    "id": 1,
                    "action": "iptables_block",
                    "source_ip": "1.2.3.4",
                    "protocol": "all",
                    "duration": 3600,
                },
            ],
        }
        result = client.get_config()
        assert len(result["pending_commands"]) == 1
        assert result["pending_commands"][0]["action"] == "iptables_block"

    def test_get_config_suspended(self):
        client = _make_mock_client()
        client.session.get.return_value.json.return_value = {
            "suspended": True,
        }
        result = client.get_config()
        assert result["suspended"] is True

    def test_get_config_network_error(self):
        client = _make_mock_client()
        import requests
        client.session.get.side_effect = requests.ConnectionError("refused")
        result = client.get_config()
        assert result is None


# ═══════════════════════════════════════════════════════════════════════
# End-to-End Payload Flow
# ═══════════════════════════════════════════════════════════════════════

class TestEndToEndPayloadFlow:
    """Test the complete attack lifecycle payload sequence."""

    def test_attack_lifecycle_payloads(self):
        """Simulate: metrics -> incident open -> update -> resolve."""
        client = _make_mock_client()
        client.session.post.return_value.content = b'{"uuid":"inc-lifecycle"}'
        client.session.post.return_value.json.return_value = {"uuid": "inc-lifecycle"}

        # 1. Send metrics
        client.send_metrics({"pps": 50000.0, "bps": 400000000.0,
                              "tcp_pct": 10.0, "udp_pct": 80.0, "icmp_pct": 10.0,
                              "conn_count": 1000, "threshold": 15000.0})

        # 2. Open incident
        result = client.open_incident({
            "peak_pps": 50000.0,
            "peak_bps": 400000000.0,
            "started_at": "2026-06-21T12:00:00+00:00",
            "attack_family": "udp_flood",
            "baseline_pps": 1500.0,
            "duration": 0,
            "gre_dedup_active": False,
        })
        assert result["uuid"] == "inc-lifecycle"

        # 3. Update incident
        client.update_incident("inc-lifecycle", {
            "peak_pps": 75000.0,
            "attack_family": "udp_flood",
        })

        # 4. Resolve incident
        client.resolve_incident("inc-lifecycle", {
            "duration_seconds": 60.0,
            "peak_pps": 75000.0,
        })

        # Verify 4 POST calls were made
        assert client.session.post.call_count == 4
