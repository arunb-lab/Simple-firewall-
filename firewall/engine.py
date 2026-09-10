"""The decision engine: match a packet against ordered rules and act.

The engine implements *first-match-wins*, the behaviour of real packet
filters: rules are tested in file order and the first match decides. A packet
matching no rule falls through to the default policy, which should normally be
``DENY`` so that anything not explicitly permitted is refused.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from firewall.errors import FirewallError
from firewall.logger import NullLogger
from firewall.packets import Packet
from firewall.rules import ACTIONS, Rule, load_rules

#: Policy applied to a packet that matches no rule.
DEFAULT_POLICIES = ACTIONS


class SupportsLog(Protocol):
    """The slice of a logger the engine depends on."""

    def log(self, decision: Decision) -> dict[str, Any]: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class Decision:
    """The verdict on a single packet, and why it was reached."""

    packet: Packet
    action: str
    matched_rule: str | None = None
    rule_index: int | None = None

    @property
    def allowed(self) -> bool:
        """Whether the packet may pass."""
        return self.action == "ALLOW"

    @property
    def reason(self) -> str:
        """Human-readable explanation of which rule decided, or the fallback."""
        if self.matched_rule is None:
            return "default policy"
        return f"rule #{self.rule_index + 1} {self.matched_rule!r}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable record of this decision."""
        return {
            "decision": self.action,
            "matched_rule": self.matched_rule,
            "rule_index": self.rule_index,
            "packet": self.packet.to_dict(),
        }

    def __str__(self) -> str:
        return f"{self.action:<5} {self.packet}  ({self.reason})"


class FirewallEngine:
    """Evaluates packets against an ordered rule list."""

    def __init__(
        self,
        rules: Iterable[Rule],
        default_policy: str = "DENY",
        logger: SupportsLog | None = None,
    ) -> None:
        policy = str(default_policy).strip().upper()
        if policy not in DEFAULT_POLICIES:
            raise FirewallError(
                f"default_policy must be one of {', '.join(DEFAULT_POLICIES)}, "
                f"got {default_policy!r}"
            )
        self.rules: list[Rule] = list(rules)
        self.default_policy = policy
        self.logger: SupportsLog = logger if logger is not None else NullLogger()

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        default_policy: str = "DENY",
        logger: SupportsLog | None = None,
    ) -> FirewallEngine:
        """Build an engine from a JSON rule file."""
        return cls(load_rules(path), default_policy=default_policy, logger=logger)

    def decide(self, packet: Packet) -> Decision:
        """Return the verdict for one packet, logging it on the way out."""
        for index, rule in enumerate(self.rules):
            if rule.matches(packet):
                decision = Decision(
                    packet=packet,
                    action=rule.action,
                    matched_rule=rule.name,
                    rule_index=index,
                )
                break
        else:
            decision = Decision(packet=packet, action=self.default_policy)

        self.logger.log(decision)
        return decision

    def evaluate(self, packets: Iterable[Packet]) -> Iterator[Decision]:
        """Decide a stream of packets lazily, in order."""
        for packet in packets:
            yield self.decide(packet)

    def __len__(self) -> int:
        return len(self.rules)


__all__ = ["DEFAULT_POLICIES", "Decision", "FirewallEngine"]
