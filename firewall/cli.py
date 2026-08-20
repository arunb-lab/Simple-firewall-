"""Command line interface for the firewall simulator.

Three subcommands:

``simulate``
    Generate synthetic traffic and show what the rules would do with it.
``check``
    Ask about one specific packet, for testing a rule you just wrote.
``validate``
    Parse the rule file and report problems without evaluating anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path

from firewall import __version__
from firewall.engine import DEFAULT_POLICIES, FirewallEngine, SupportsLog
from firewall.errors import FirewallError
from firewall.logger import DecisionLogger, NullLogger
from firewall.packets import DIRECTIONS, PROTOCOLS, Packet
from firewall.rules import Rule, load_rules
from firewall.traffic import packets_from_jsonl, simulated_traffic

DEFAULT_RULES = "rules.json"
DEFAULT_LOG = "firewall.log"


def build_parser() -> argparse.ArgumentParser:
    """Assemble the argument parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog="firewall",
        description="A rule-based firewall simulator: evaluate traffic against "
        "ordered ALLOW/DENY rules using first-match-wins.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("simulate", "evaluate generated or replayed traffic"),
        ("check", "evaluate one packet given on the command line"),
        ("validate", "check the rule file for errors and print it back"),
    ):
        sub = subparsers.add_parser(name, help=help_text, description=help_text)
        sub.add_argument(
            "-r",
            "--rules",
            default=DEFAULT_RULES,
            metavar="PATH",
            help=f"JSON rule file (default: {DEFAULT_RULES})",
        )

    simulate = subparsers.choices["simulate"]
    _add_policy_args(simulate)
    _add_log_args(simulate)
    simulate.add_argument(
        "-n",
        "--count",
        type=int,
        default=10,
        metavar="N",
        help="number of packets to generate (default: 10)",
    )
    simulate.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="N",
        help="seed the generator so the run is reproducible",
    )
    simulate.add_argument(
        "-i",
        "--input",
        default=None,
        metavar="PATH",
        help="replay packets from a JSON Lines file instead of generating them "
        "('-' reads standard input)",
    )
    simulate.add_argument(
        "--json",
        action="store_true",
        help="print decisions as JSON Lines instead of a table",
    )
    simulate.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print only the summary",
    )

    check = subparsers.choices["check"]
    _add_policy_args(check)
    check.add_argument("--src-ip", required=True, metavar="IP", help="source address")
    check.add_argument("--dst-ip", required=True, metavar="IP", help="destination address")
    check.add_argument("--src-port", type=int, default=None, metavar="PORT")
    check.add_argument("--dst-port", type=int, default=None, metavar="PORT")
    check.add_argument(
        "--protocol",
        default="TCP",
        choices=PROTOCOLS,
        type=str.upper,
        help="default: TCP",
    )
    check.add_argument(
        "--direction",
        default="IN",
        choices=DIRECTIONS,
        type=str.upper,
        help="default: IN",
    )
    check.add_argument("--json", action="store_true", help="print the decision as JSON")

    return parser


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-p",
        "--default-policy",
        default="DENY",
        choices=DEFAULT_POLICIES,
        type=str.upper,
        help="verdict for packets matching no rule (default: DENY)",
    )


def _add_log_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-l",
        "--log",
        default=DEFAULT_LOG,
        metavar="PATH",
        help=f"JSON Lines audit log (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="do not write an audit log",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit status."""
    args = build_parser().parse_args(argv)
    handlers = {
        "simulate": _run_simulate,
        "check": _run_check,
        "validate": _run_validate,
    }
    try:
        return handlers[args.command](args)
    except FirewallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # e.g. piping into `head`
        return 0
    except KeyboardInterrupt:
        return 130


def _run_simulate(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    packets = _packet_source(args)

    logger = NullLogger() if args.no_log else DecisionLogger(args.log)
    tally: Counter = Counter()
    try:
        engine = FirewallEngine(rules, default_policy=args.default_policy, logger=logger)
        for index, decision in enumerate(engine.evaluate(packets), start=1):
            tally[decision.action] += 1
            if args.quiet:
                continue
            if args.json:
                print(json.dumps(decision.to_dict()))
            else:
                print(f"[{index:>3}] {decision}")
    finally:
        logger.close()

    _print_summary(tally, logger, args)
    return 0


def _packet_source(args: argparse.Namespace) -> Iterator[Packet]:
    if args.input:
        return packets_from_jsonl(args.input)
    if args.count < 0:
        raise FirewallError(f"--count must not be negative, got {args.count}")
    return simulated_traffic(args.count, seed=args.seed)


def _print_summary(tally: Counter, logger: SupportsLog, args: argparse.Namespace) -> None:
    total = sum(tally.values())
    allowed = tally.get("ALLOW", 0)
    denied = tally.get("DENY", 0)
    if not args.quiet:
        print()
    print(f"Evaluated {total} packet(s): {allowed} allowed, {denied} denied.")
    if isinstance(logger, DecisionLogger) and total:
        print(f"Audit log written to {logger.path} (JSON Lines).")


def _run_check(args: argparse.Namespace) -> int:
    packet = Packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        protocol=args.protocol,
        direction=args.direction,
        src_port=args.src_port,
        dst_port=args.dst_port,
    )
    engine = FirewallEngine(
        load_rules(args.rules),
        default_policy=args.default_policy,
        logger=NullLogger(),
    )
    decision = engine.decide(packet)

    if args.json:
        print(json.dumps(decision.to_dict()))
    else:
        print(decision)
    # A denied packet is a normal, expected outcome, so it is not an error;
    # exit 1 lets scripts branch on the verdict.
    return 0 if decision.allowed else 1


def _run_validate(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    path = Path(args.rules)

    if not rules:
        print(f"{path}: no rules defined; every packet falls to the default policy.")
        return 0

    print(f"{path}: {len(rules)} rule(s), evaluated top to bottom.")
    for index, rule in enumerate(rules, start=1):
        print(f"  {index:>2}. {rule}")
        if rule.description:
            print(f"      {rule.description}")

    warnings = _lint(rules)
    if warnings:
        print()
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def _lint(rules: list[Rule]) -> list[str]:
    """Report rules that are suspicious but not invalid."""
    warnings = []

    duplicates = [name for name, n in Counter(r.name for r in rules).items() if n > 1]
    for name in sorted(duplicates):
        warnings.append(f"rule name {name!r} is used more than once; logs will be ambiguous")

    for index, rule in enumerate(rules):
        if _is_catch_all(rule) and index < len(rules) - 1:
            warnings.append(
                f"rule #{index + 1} {rule.name!r} matches every packet, so the "
                f"{len(rules) - index - 1} rule(s) after it can never apply"
            )
            break
    return warnings


def _is_catch_all(rule: Rule) -> bool:
    return (
        rule.enabled
        and rule.protocol == "ANY"
        and rule.direction == "ANY"
        and not rule.src_cidr
        and not rule.dst_cidr
        and rule.src_port is None
        and rule.dst_port is None
    )
