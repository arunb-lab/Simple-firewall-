"""Tests for rule parsing, matching, and the rule file loader."""

from __future__ import annotations

import pytest

from firewall.errors import RuleError
from firewall.packets import Packet
from firewall.rules import PortSpec, Rule, load_rules, parse_rules


def rule(**overrides) -> Rule:
    """Build a rule from its JSON form with sensible defaults."""
    data = {"name": "test", "action": "DENY"}
    data.update(overrides)
    return Rule.from_dict(data)


class TestPortSpec:
    @pytest.mark.parametrize(
        "value,inside,outside",
        [
            (22, [22], [21, 23]),
            ("22", [22], [23]),
            ("80,443", [80, 443], [81, 8080]),
            ("8000-8100", [8000, 8050, 8100], [7999, 8101]),
            ([80, "443", "8000-8100"], [80, 443, 8000], [22]),
            ("0-65535", [0, 65535], []),
        ],
    )
    def test_accepted_forms(self, value, inside, outside):
        spec = PortSpec.parse(value, "dst_port")
        assert all(spec.contains(port) for port in inside)
        assert not any(spec.contains(port) for port in outside)

    def test_none_means_any_port(self):
        assert PortSpec.parse(None, "dst_port") is None

    def test_a_portless_packet_never_matches_a_port_spec(self):
        assert not PortSpec.parse("0-65535", "dst_port").contains(None)

    @pytest.mark.parametrize(
        "value,message",
        [
            ("8100-8000", "starts above"),
            ("70000", "outside"),
            ("-1", "not a valid port range"),
            ("8000-", "not a valid port range"),
            ("http", "not a number"),
            (True, "not a valid port"),
            ("", "empty"),
        ],
    )
    def test_rejected_forms(self, value, message):
        with pytest.raises(RuleError, match=message):
            PortSpec.parse(value, "dst_port")

    def test_renders_back_to_its_source_form(self):
        assert str(PortSpec.parse("80,443,8000-8100", "dst_port")) == "80,443,8000-8100"


class TestRuleParsing:
    def test_minimal_rule_matches_everything(self):
        assert rule().matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))

    def test_action_and_protocol_are_case_insensitive(self):
        parsed = rule(action="allow", protocol="udp", direction="out")
        assert (parsed.action, parsed.protocol, parsed.direction) == ("ALLOW", "UDP", "OUT")

    @pytest.mark.parametrize("bad", [{}, {"name": ""}, {"name": "  "}, {"name": 5}])
    def test_name_is_required(self, bad):
        with pytest.raises(RuleError, match="name"):
            Rule.from_dict({"action": "DENY", **bad})

    def test_action_is_required(self):
        with pytest.raises(RuleError, match="'action' is required"):
            Rule.from_dict({"name": "test"})

    def test_misspelled_action_is_rejected(self):
        # The original code silently produced a decision of "ALOW".
        with pytest.raises(RuleError, match="expected one of"):
            rule(action="ALOW")

    def test_misspelled_field_is_reported_with_the_valid_names(self):
        with pytest.raises(RuleError, match="dest_port"):
            rule(dest_port=22)

    def test_invalid_cidr_is_reported(self):
        with pytest.raises(RuleError, match="not a valid CIDR"):
            rule(src_cidr="192.168.1.0/33")

    def test_host_bits_in_a_cidr_are_tolerated(self):
        assert str(rule(src_cidr="192.168.1.5/24").src_cidr[0]) == "192.168.1.0/24"

    def test_enabled_must_be_a_boolean(self):
        with pytest.raises(RuleError, match="true or false"):
            rule(enabled="yes")


class TestMatching:
    def test_direction_must_agree(self):
        inbound = rule(direction="IN")
        assert inbound.matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))
        assert not inbound.matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "OUT"))

    def test_protocol_must_agree(self):
        tcp = rule(protocol="TCP")
        assert tcp.matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))
        assert not tcp.matches(Packet("10.0.0.1", "10.0.0.2", "UDP", "IN"))

    def test_source_network_must_contain_the_source(self):
        lan = rule(src_cidr="192.168.1.0/24")
        assert lan.matches(Packet("192.168.1.50", "10.0.0.2", "TCP", "OUT"))
        assert not lan.matches(Packet("192.168.2.50", "10.0.0.2", "TCP", "OUT"))

    def test_a_list_of_networks_matches_any_of_them(self):
        multi = rule(src_cidr=["192.168.1.0/24", "10.0.0.0/8"])
        assert multi.matches(Packet("10.1.2.3", "8.8.8.8", "TCP", "OUT"))
        assert multi.matches(Packet("192.168.1.7", "8.8.8.8", "TCP", "OUT"))
        assert not multi.matches(Packet("172.16.0.1", "8.8.8.8", "TCP", "OUT"))

    def test_mixing_ip_families_does_not_crash(self):
        # ip_address(v4) in ip_network(v6) raises TypeError; it must simply not match.
        v4_rule = rule(src_cidr="0.0.0.0/0")
        assert not v4_rule.matches(Packet("2001:db8::1", "2001:db8::2", "TCP", "IN"))

    def test_ipv6_networks_match_ipv6_packets(self):
        v6_rule = rule(src_cidr="2001:db8::/32")
        assert v6_rule.matches(Packet("2001:db8::1", "2001:db8::2", "TCP", "IN"))
        assert not v6_rule.matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))

    def test_no_cidr_matches_both_families(self):
        catch_all = rule()
        assert catch_all.matches(Packet("2001:db8::1", "2001:db8::2", "TCP", "IN"))
        assert catch_all.matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))

    def test_a_disabled_rule_never_matches(self):
        assert not rule(enabled=False).matches(Packet("10.0.0.1", "10.0.0.2", "TCP", "IN"))

    def test_all_conditions_must_hold_together(self):
        ssh = rule(direction="IN", protocol="TCP", dst_port=22, dst_cidr="192.168.1.0/24")
        assert ssh.matches(Packet("10.0.0.5", "192.168.1.10", "TCP", "IN", 5000, 22))
        # Right port, wrong destination network.
        assert not ssh.matches(Packet("10.0.0.5", "172.16.0.10", "TCP", "IN", 5000, 22))
        # Right destination, wrong port.
        assert not ssh.matches(Packet("10.0.0.5", "192.168.1.10", "TCP", "IN", 5000, 23))


class TestLoading:
    def test_the_shipped_ruleset_loads(self, sample_rules_path):
        rules = load_rules(sample_rules_path)
        assert rules
        assert all(r.action in ("ALLOW", "DENY") for r in rules)

    def test_a_bare_list_of_rules_is_accepted(self):
        assert len(parse_rules([{"name": "a", "action": "DENY"}])) == 1

    def test_rules_keep_their_file_order(self, write_rules):
        path = write_rules(
            {"rules": [{"name": "first", "action": "DENY"}, {"name": "second", "action": "ALLOW"}]}
        )
        assert [r.name for r in load_rules(path)] == ["first", "second"]

    def test_an_empty_ruleset_is_valid(self, write_rules):
        assert load_rules(write_rules({"rules": []})) == []

    def test_a_missing_file_says_so(self, tmp_path):
        with pytest.raises(RuleError, match="cannot read rule file"):
            load_rules(tmp_path / "nope.json")

    def test_malformed_json_says_so(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(RuleError, match="not valid JSON"):
            load_rules(path)

    def test_a_missing_rules_key_says_so(self, write_rules):
        with pytest.raises(RuleError, match="no 'rules' key"):
            load_rules(write_rules({"policies": []}))

    def test_a_bad_rule_is_reported_with_its_position(self, write_rules):
        path = write_rules({"rules": [{"name": "ok", "action": "DENY"}, {"action": "DENY"}]})
        with pytest.raises(RuleError, match="rule #2"):
            load_rules(path)

    def test_an_error_names_the_file_the_position_and_the_rule(self, write_rules):
        path = write_rules({"rules": [{"name": "Block SSH", "action": "ALOW"}]})
        with pytest.raises(RuleError) as exc:
            load_rules(path)
        message = str(exc.value)
        assert str(path) in message
        assert "rule #1" in message
        assert "Block SSH" in message
