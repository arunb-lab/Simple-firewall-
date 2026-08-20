"""Tests for JSON Lines audit logging."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from firewall.engine import Decision, FirewallEngine
from firewall.logger import DecisionLogger, NullLogger
from firewall.packets import Packet
from firewall.rules import Rule


@pytest.fixture
def decision() -> Decision:
    packet = Packet("10.0.0.5", "192.168.1.10", "TCP", "IN", 51515, 22)
    return Decision(packet, "DENY", matched_rule="block ssh", rule_index=0)


def read_lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class TestDecisionLogger:
    def test_each_decision_becomes_one_json_line(self, tmp_path, decision):
        path = tmp_path / "firewall.log"
        with DecisionLogger(path) as logger:
            logger.log(decision)
            logger.log(decision)

        records = read_lines(path)
        assert len(records) == 2
        assert records[0]["decision"] == "DENY"
        assert records[0]["matched_rule"] == "block ssh"
        assert records[0]["packet"]["dst_port"] == 22

    def test_the_timestamp_is_timezone_aware_utc(self, tmp_path, decision):
        path = tmp_path / "firewall.log"
        with DecisionLogger(path) as logger:
            logger.log(decision)

        stamp = datetime.fromisoformat(read_lines(path)[0]["timestamp"])
        assert stamp.tzinfo is not None
        assert stamp.utcoffset().total_seconds() == 0

    def test_a_new_run_appends_rather_than_truncating(self, tmp_path, decision):
        path = tmp_path / "firewall.log"
        for _ in range(2):
            with DecisionLogger(path) as logger:
                logger.log(decision)
        assert len(read_lines(path)) == 2

    def test_missing_parent_directories_are_created(self, tmp_path, decision):
        path = tmp_path / "logs" / "nested" / "firewall.log"
        with DecisionLogger(path) as logger:
            logger.log(decision)
        assert path.exists()

    def test_records_survive_a_crash_mid_run(self, tmp_path, decision):
        # Entries are flushed as they are written, so an abrupt exit keeps them.
        path = tmp_path / "firewall.log"
        logger = DecisionLogger(path)
        logger.log(decision)
        assert len(read_lines(path)) == 1
        logger.close()

    def test_close_is_idempotent(self, tmp_path):
        logger = DecisionLogger(tmp_path / "firewall.log")
        logger.close()
        logger.close()

    def test_log_returns_the_written_record(self, tmp_path, decision):
        with DecisionLogger(tmp_path / "firewall.log") as logger:
            record = logger.log(decision)
        assert record["decision"] == "DENY"
        assert "timestamp" in record


class TestNullLogger:
    def test_it_writes_nothing(self, tmp_path, decision, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with NullLogger() as logger:
            logger.log(decision)
        assert list(tmp_path.iterdir()) == []


class TestEngineIntegration:
    def test_an_engine_run_produces_a_readable_audit_trail(self, tmp_path):
        path = tmp_path / "audit.log"
        rules = [Rule.from_dict({"name": "block ssh", "action": "DENY", "dst_port": 22})]
        packets = [
            Packet("10.0.0.5", "192.168.1.10", "TCP", "IN", 51515, 22),
            Packet("192.168.1.10", "8.8.8.8", "UDP", "OUT", 51516, 53),
        ]
        with DecisionLogger(path) as logger:
            engine = FirewallEngine(rules, default_policy="ALLOW", logger=logger)
            list(engine.evaluate(packets))

        records = read_lines(path)
        assert [r["decision"] for r in records] == ["DENY", "ALLOW"]
        assert records[0]["matched_rule"] == "block ssh"
        assert records[1]["matched_rule"] is None
