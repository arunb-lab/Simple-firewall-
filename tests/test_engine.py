"""Tests for the decision engine: ordering, default policy, and logging."""

from __future__ import annotations

import pytest

from firewall.engine import Decision, FirewallEngine
from firewall.errors import FirewallError
from firewall.logger import NullLogger
from firewall.packets import Packet
from firewall.rules import Rule


def rules(*specs) -> list:
    return [Rule.from_dict(spec) for spec in specs]


@pytest.fixture
def any_packet() -> Packet:
    return Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", 5000, 80)


class TestDefaultPolicy:
    def test_an_unmatched_packet_falls_to_the_default(self, any_packet):
        decision = FirewallEngine([], default_policy="DENY").decide(any_packet)
        assert decision.action == "DENY"
        assert decision.matched_rule is None
        assert decision.reason == "default policy"

    def test_the_default_can_be_allow(self, any_packet):
        assert FirewallEngine([], default_policy="ALLOW").decide(any_packet).allowed

    def test_the_default_policy_is_deny(self, any_packet):
        assert not FirewallEngine([]).decide(any_packet).allowed

    @pytest.mark.parametrize("bad", ["MAYBE", "", None, 5])
    def test_an_invalid_default_policy_is_rejected(self, bad):
        with pytest.raises(FirewallError, match="default_policy"):
            FirewallEngine([], default_policy=bad)

    def test_the_default_policy_is_case_insensitive(self, any_packet):
        assert FirewallEngine([], default_policy="allow").decide(any_packet).allowed


class TestFirstMatchWins:
    def test_the_first_matching_rule_decides(self, any_packet):
        engine = FirewallEngine(
            rules(
                {"name": "deny all", "action": "DENY"},
                {"name": "allow all", "action": "ALLOW"},
            )
        )
        decision = engine.decide(any_packet)
        assert decision.action == "DENY"
        assert decision.matched_rule == "deny all"
        assert decision.rule_index == 0

    def test_reversing_the_order_reverses_the_verdict(self, any_packet):
        engine = FirewallEngine(
            rules(
                {"name": "allow all", "action": "ALLOW"},
                {"name": "deny all", "action": "DENY"},
            )
        )
        assert engine.decide(any_packet).action == "ALLOW"

    def test_a_specific_rule_placed_first_beats_a_broad_one(self):
        engine = FirewallEngine(
            rules(
                {"name": "block ssh", "action": "DENY", "protocol": "TCP", "dst_port": 22},
                {"name": "allow tcp", "action": "ALLOW", "protocol": "TCP"},
            )
        )
        ssh = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", 5000, 22)
        web = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", 5000, 80)
        assert engine.decide(ssh).action == "DENY"
        assert engine.decide(web).action == "ALLOW"

    def test_a_disabled_rule_is_skipped_over(self, any_packet):
        engine = FirewallEngine(
            rules(
                {"name": "off", "action": "DENY", "enabled": False},
                {"name": "on", "action": "ALLOW"},
            )
        )
        assert engine.decide(any_packet).matched_rule == "on"


class TestEvaluate:
    def test_decisions_come_back_in_packet_order(self):
        engine = FirewallEngine(rules({"name": "web", "action": "ALLOW", "dst_port": 80}))
        packets = [Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", 5000, port) for port in (80, 22, 80)]
        assert [d.action for d in engine.evaluate(packets)] == ["ALLOW", "DENY", "ALLOW"]

    def test_evaluation_is_lazy(self):
        engine = FirewallEngine([])
        consumed = []

        def source():
            for port in (80, 443):
                consumed.append(port)
                yield Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", 5000, port)

        stream = engine.evaluate(source())
        next(stream)
        assert consumed == [80]  # the second packet has not been read yet


class TestDecision:
    def test_a_matched_decision_names_its_rule(self, any_packet):
        engine = FirewallEngine(rules({"name": "allow all", "action": "ALLOW"}))
        decision = engine.decide(any_packet)
        assert decision.reason == "rule #1 'allow all'"

    def test_to_dict_is_json_shaped(self, any_packet):
        decision = FirewallEngine([]).decide(any_packet)
        record = decision.to_dict()
        assert record["decision"] == "DENY"
        assert record["matched_rule"] is None
        assert record["packet"]["dst_port"] == 80

    def test_allowed_reflects_the_action(self):
        packet = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN")
        assert Decision(packet, "ALLOW").allowed
        assert not Decision(packet, "DENY").allowed


class TestLoggingHook:
    def test_every_decision_is_handed_to_the_logger(self, any_packet):
        seen = []

        class Recorder(NullLogger):
            def log(self, decision):
                seen.append(decision)
                return decision.to_dict()

        engine = FirewallEngine([], logger=Recorder())
        engine.decide(any_packet)
        engine.decide(any_packet)
        assert len(seen) == 2

    def test_logging_is_off_unless_a_logger_is_given(self, any_packet, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        FirewallEngine([]).decide(any_packet)
        assert not (tmp_path / "firewall.log").exists()


class TestConstruction:
    def test_from_file_loads_the_shipped_ruleset(self, sample_rules_path):
        engine = FirewallEngine.from_file(sample_rules_path)
        assert len(engine) > 0

    def test_rules_are_copied_not_aliased(self):
        source = rules({"name": "a", "action": "DENY"})
        engine = FirewallEngine(source)
        source.clear()
        assert len(engine) == 1
