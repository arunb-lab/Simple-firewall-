import json
from pathlib import Path
from typing import List, Literal, Optional
from firewall.rules import Rule
from firewall.logger import FirewallLogger

DefaultPolicy = Literal["ALLOW", "DENY"]

class FirewallEngine:
    def __init__(self, rules: List[Rule], default_policy: DefaultPolicy = "DENY", logger: Optional[FirewallLogger] = None):
        self.rules = rules
        self.default_policy = default_policy
        self.logger = logger or FirewallLogger()

    @staticmethod
    def load_rules(path: str) -> List[Rule]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rules = []
        for item in data["rules"]:
            rules.append(Rule(**item))
        return rules

    def decide(self, packet: dict) -> dict:
        # First-match wins (common firewall behavior)
        matched_rule = None
        action = self.default_policy

        for rule in self.rules:
            if rule.matches(packet):
                matched_rule = rule.name
                action = rule.action
                break

        decision = {
            "packet": packet,
            "decision": action,
            "matched_rule": matched_rule,
        }
        self.logger.log(decision)
        return decision
