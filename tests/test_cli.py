"""End-to-end tests for the command line interface."""

from __future__ import annotations

import json

import pytest

from firewall.cli import main


@pytest.fixture
def rules_file(write_rules):
    return write_rules(
        {
            "rules": [
                {"name": "block ssh", "action": "DENY", "protocol": "TCP", "dst_port": 22},
                {"name": "allow web", "action": "ALLOW", "protocol": "TCP", "dst_port": "80,443"},
            ]
        }
    )


class TestSimulate:
    def test_it_prints_one_line_per_packet_plus_a_summary(self, rules_file, tmp_path, capsys):
        code = main(
            [
                "simulate",
                "-r",
                str(rules_file),
                "-n",
                "5",
                "--seed",
                "1",
                "-l",
                str(tmp_path / "fw.log"),
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert len([line for line in out.splitlines() if line.startswith("[")]) == 5
        assert "Evaluated 5 packet(s)" in out

    def test_the_same_seed_gives_the_same_output(self, rules_file, tmp_path, capsys):
        args = ["simulate", "-r", str(rules_file), "-n", "8", "--seed", "3", "--no-log"]
        main(args)
        first = capsys.readouterr().out
        main(args)
        assert capsys.readouterr().out == first

    def test_json_output_is_one_object_per_packet(self, rules_file, capsys):
        main(["simulate", "-r", str(rules_file), "-n", "4", "--seed", "1", "--json", "--no-log"])
        lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
        assert len(lines) == 4
        assert all(json.loads(line)["decision"] in ("ALLOW", "DENY") for line in lines)

    def test_quiet_prints_only_the_summary(self, rules_file, capsys):
        main(["simulate", "-r", str(rules_file), "-n", "5", "--seed", "1", "-q", "--no-log"])
        out = capsys.readouterr().out.strip().splitlines()
        assert len(out) == 1
        assert out[0].startswith("Evaluated 5 packet(s)")

    def test_it_writes_the_audit_log(self, rules_file, tmp_path):
        log = tmp_path / "audit.log"
        main(["simulate", "-r", str(rules_file), "-n", "6", "--seed", "1", "-l", str(log)])
        records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        assert len(records) == 6
        assert all("timestamp" in record for record in records)

    def test_no_log_writes_nothing(self, rules_file, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        main(["simulate", "-r", str(rules_file), "-n", "3", "--seed", "1", "--no-log"])
        assert not (tmp_path / "firewall.log").exists()

    @pytest.mark.parametrize(
        "policy,expected", [("DENY", "0 allowed, 5 denied"), ("ALLOW", "5 allowed, 0 denied")]
    )
    def test_the_default_policy_decides_unmatched_traffic(
        self, write_rules, capsys, policy, expected
    ):
        # An empty ruleset means every packet falls through to the default.
        empty = write_rules({"rules": []})
        main(
            ["simulate", "-r", str(empty), "-n", "5", "--seed", "1", "-p", policy, "--no-log", "-q"]
        )
        assert expected in capsys.readouterr().out

    def test_it_replays_packets_from_a_file(self, rules_file, tmp_path, capsys):
        traffic = tmp_path / "traffic.jsonl"
        traffic.write_text(
            '{"src_ip":"10.0.0.5","dst_ip":"192.168.1.10","protocol":"TCP",'
            '"direction":"IN","dst_port":22}\n'
            '{"src_ip":"10.0.0.5","dst_ip":"192.168.1.10","protocol":"TCP",'
            '"direction":"IN","dst_port":443}\n',
            encoding="utf-8",
        )
        main(["simulate", "-r", str(rules_file), "-i", str(traffic), "--no-log"])
        out = capsys.readouterr().out
        assert "block ssh" in out
        assert "allow web" in out
        assert "Evaluated 2 packet(s): 1 allowed, 1 denied." in out


class TestCheck:
    def test_a_denied_packet_exits_nonzero(self, rules_file, capsys):
        code = main(
            [
                "check",
                "-r",
                str(rules_file),
                "--src-ip",
                "10.0.0.5",
                "--dst-ip",
                "192.168.1.10",
                "--dst-port",
                "22",
            ]
        )
        assert code == 1
        assert "DENY" in capsys.readouterr().out

    def test_an_allowed_packet_exits_zero(self, rules_file, capsys):
        code = main(
            [
                "check",
                "-r",
                str(rules_file),
                "--src-ip",
                "10.0.0.5",
                "--dst-ip",
                "192.168.1.10",
                "--dst-port",
                "443",
            ]
        )
        assert code == 0
        assert "ALLOW" in capsys.readouterr().out

    def test_it_names_the_rule_that_decided(self, rules_file, capsys):
        main(
            [
                "check",
                "-r",
                str(rules_file),
                "--src-ip",
                "10.0.0.5",
                "--dst-ip",
                "192.168.1.10",
                "--dst-port",
                "22",
            ]
        )
        assert "block ssh" in capsys.readouterr().out

    def test_json_output_is_a_single_object(self, rules_file, capsys):
        main(
            [
                "check",
                "-r",
                str(rules_file),
                "--src-ip",
                "10.0.0.5",
                "--dst-ip",
                "192.168.1.10",
                "--dst-port",
                "22",
                "--json",
            ]
        )
        assert json.loads(capsys.readouterr().out)["decision"] == "DENY"

    def test_check_does_not_write_to_the_audit_log(self, rules_file, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        main(
            [
                "check",
                "-r",
                str(rules_file),
                "--src-ip",
                "10.0.0.5",
                "--dst-ip",
                "192.168.1.10",
                "--dst-port",
                "22",
            ]
        )
        assert not (tmp_path / "firewall.log").exists()

    def test_an_invalid_address_is_a_clean_error(self, rules_file, capsys):
        code = main(["check", "-r", str(rules_file), "--src-ip", "nope", "--dst-ip", "10.0.0.2"])
        assert code == 2
        assert "error:" in capsys.readouterr().err


class TestValidate:
    def test_it_lists_the_rules_in_order(self, rules_file, capsys):
        assert main(["validate", "-r", str(rules_file)]) == 0
        out = capsys.readouterr().out
        assert "2 rule(s)" in out
        assert out.index("block ssh") < out.index("allow web")

    def test_the_shipped_ruleset_validates(self, sample_rules_path, capsys):
        assert main(["validate", "-r", str(sample_rules_path)]) == 0

    def test_a_broken_rule_file_reports_a_clean_error(self, write_rules, capsys):
        path = write_rules({"rules": [{"name": "bad", "action": "ALOW"}]})
        assert main(["validate", "-r", str(path)]) == 2
        err = capsys.readouterr().err
        assert "error:" in err
        assert "ALOW" in err

    def test_it_warns_about_unreachable_rules(self, write_rules, capsys):
        path = write_rules(
            {
                "rules": [
                    {"name": "catch all", "action": "DENY"},
                    {"name": "never reached", "action": "ALLOW", "dst_port": 80},
                ]
            }
        )
        main(["validate", "-r", str(path)])
        assert "can never apply" in capsys.readouterr().err

    def test_it_warns_about_duplicate_names(self, write_rules, capsys):
        path = write_rules(
            {
                "rules": [
                    {"name": "same", "action": "DENY", "dst_port": 22},
                    {"name": "same", "action": "ALLOW", "dst_port": 80},
                ]
            }
        )
        main(["validate", "-r", str(path)])
        assert "used more than once" in capsys.readouterr().err

    def test_an_empty_ruleset_is_explained(self, write_rules, capsys):
        path = write_rules({"rules": []})
        assert main(["validate", "-r", str(path)]) == 0
        assert "no rules defined" in capsys.readouterr().out


class TestParser:
    def test_a_missing_rule_file_is_a_clean_error(self, tmp_path, capsys):
        assert main(["validate", "-r", str(tmp_path / "absent.json")]) == 2
        assert "cannot read rule file" in capsys.readouterr().err

    def test_no_subcommand_is_a_usage_error(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 2

    def test_version_is_reported(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip()
