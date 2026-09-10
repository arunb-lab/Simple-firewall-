"""A rule-based firewall simulator.

This package models how a packet filter decides: ordered ALLOW/DENY rules,
first-match-wins, and a default policy for anything left over. It reasons about
packet *descriptions*, so it neither captures nor blocks real traffic — it is a
teaching and rule-testing tool, not a kernel firewall.

    >>> from firewall import FirewallEngine, Packet
    >>> engine = FirewallEngine.from_file("rules.json")
    >>> engine.decide(Packet("10.0.0.5", "192.168.1.10", "TCP", "IN", dst_port=22)).action
    'DENY'
"""

from __future__ import annotations

__version__ = "1.0.0"

from firewall.engine import Decision, FirewallEngine
from firewall.errors import FirewallError, PacketError, RuleError
from firewall.logger import DecisionLogger, NullLogger
from firewall.packets import Packet
from firewall.rules import PortSpec, Rule, load_rules, parse_rules
from firewall.traffic import packets_from_jsonl, simulated_traffic

__all__ = [
    "Decision",
    "DecisionLogger",
    "FirewallEngine",
    "FirewallError",
    "NullLogger",
    "Packet",
    "PacketError",
    "PortSpec",
    "Rule",
    "RuleError",
    "__version__",
    "load_rules",
    "packets_from_jsonl",
    "parse_rules",
    "simulated_traffic",
]
