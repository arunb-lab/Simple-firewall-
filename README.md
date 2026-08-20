# Simple Firewall

A rule-based firewall simulator in Python, written to make packet-filtering
decisions easy to see and reason about.

It models the part of a firewall that matters conceptually — ordered ALLOW/DENY
rules, first-match-wins, and a default policy — and prints exactly which rule
decided each packet's fate.

> **This is a simulator.** It reasons about *descriptions* of packets. It does
> not capture, forward, or block real traffic, and it is not a substitute for
> `iptables`, `nftables`, or `ufw`. Use it to learn how filtering logic works
> and to test a ruleset before writing the real thing.

```console
$ python -m firewall simulate -n 6 --seed 12
[  1] ALLOW OUT TCP 192.168.1.15:61657 -> 1.1.1.1:443  (rule #7 'Allow outbound web browsing')
[  2] DENY  IN TCP 203.0.113.10:64232 -> 192.168.1.15:8080  (default policy)
[  3] DENY  IN UDP 198.51.100.7:63571 -> 192.168.1.11:53  (default policy)
[  4] ALLOW OUT TCP 192.168.1.11:55693 -> 8.8.8.8:443  (rule #7 'Allow outbound web browsing')
[  5] DENY  IN UDP 10.0.0.5:52014 -> 192.168.1.20:53  (default policy)
[  6] DENY  IN TCP 198.51.100.7:52133 -> 192.168.1.11:3389  (rule #2 'Block inbound database and remote desktop')

Evaluated 6 packet(s): 2 allowed, 4 denied.
Audit log written to firewall.log (JSON Lines).
```

## How a decision is made

Rules are tested **in file order**, and the **first one that matches wins** —
the same way a real packet filter behaves. A packet that matches no rule falls
through to the **default policy**, which is `DENY` unless you say otherwise.

This makes rule order significant. A broad `ALLOW` placed above a narrow `DENY`
silently defeats it, which is one of the most common real-world firewall
mistakes. `firewall validate` warns when a rule can never be reached.

Every field you leave out of a rule means *"match anything"*, so a rule with no
conditions at all matches every packet.

## Install

Requires Python 3.10 or newer. There are no runtime dependencies.

```bash
git clone https://github.com/arunb-lab/Simple-firewall-.git
cd Simple-firewall-
```

That is enough to run it with `python main.py`. To get the `firewall` command on
your `PATH`:

```bash
pip install -e .
```

## Usage

Three subcommands. Every one takes `-r/--rules` to point at a rule file
(default `rules.json`).

### `simulate` — run traffic past the rules

```bash
firewall simulate -n 20                     # 20 generated packets
firewall simulate -n 20 --seed 42           # reproducible run
firewall simulate --input sample_traffic.jsonl   # replay from a file
firewall simulate -n 100 --json --quiet     # machine-readable, summary only
firewall simulate -n 10 -p ALLOW            # default-allow instead of default-deny
```

| Option | Meaning |
| --- | --- |
| `-n`, `--count` | how many packets to generate (default 10) |
| `--seed` | fix the generator's seed so the run repeats exactly |
| `-i`, `--input` | replay packets from a JSON Lines file (`-` for stdin) |
| `-p`, `--default-policy` | `ALLOW` or `DENY` for unmatched packets (default `DENY`) |
| `-l`, `--log` | audit log path (default `firewall.log`) |
| `--no-log` | don't write an audit log |
| `--json` | print decisions as JSON Lines |
| `-q`, `--quiet` | print only the summary |

### `check` — ask about one packet

Useful for testing a rule you just wrote. It exits `0` if the packet is allowed
and `1` if it is denied, so scripts can branch on the answer.

```bash
$ firewall check --src-ip 203.0.113.10 --dst-ip 192.168.1.10 --dst-port 22
DENY  IN TCP 203.0.113.10 -> 192.168.1.10:22  (rule #1 'Block inbound SSH')
```

### `validate` — check the rule file

Parses the rules, prints them in evaluation order, and warns about problems
that aren't outright errors — duplicate names, and rules that can never be
reached.

```bash
firewall validate -r rules.json
```

## Writing rules

Rules live in a JSON file as an ordered list:

```json
{
  "rules": [
    {
      "name": "Block inbound SSH",
      "description": "Administration happens over the VPN, never from the internet.",
      "action": "DENY",
      "direction": "IN",
      "protocol": "TCP",
      "dst_port": 22
    },
    {
      "name": "Allow outbound web browsing",
      "action": "ALLOW",
      "direction": "OUT",
      "protocol": "TCP",
      "dst_port": "80,443"
    }
  ]
}
```

| Field | Required | Accepts | Default |
| --- | --- | --- | --- |
| `name` | yes | any non-empty string; appears in logs | — |
| `action` | yes | `ALLOW` or `DENY` | — |
| `direction` | no | `IN`, `OUT`, `ANY` | `ANY` |
| `protocol` | no | `TCP`, `UDP`, `ICMP`, `ANY` | `ANY` |
| `src_cidr` / `dst_cidr` | no | one CIDR string or a list of them; IPv4 and IPv6 | any address |
| `src_port` / `dst_port` | no | `22`, `"80,443"`, `"8000-8100"`, or a list mixing those | any port |
| `enabled` | no | `false` to keep a rule on file but inactive | `true` |
| `description` | no | a note for humans; shown by `validate` | — |

A few things worth knowing:

- **Ports and protocols are independent.** A rule with `dst_port` but no
  `protocol` matches TCP and UDP alike.
- **ICMP has no ports.** A rule that specifies a port will never match an ICMP
  packet.
- **Address families don't mix.** An IPv4 packet is never matched by an IPv6
  CIDR, and `0.0.0.0/0` means "any IPv4 address", not "any address" — omit the
  field entirely for that.
- **Host bits are tolerated.** `192.168.1.5/24` is read as `192.168.1.0/24`.

Mistakes are reported with the rule that caused them rather than a stack trace:

```console
$ firewall validate -r broken.json
error: broken.json: rule #1 'Block SSH': 'action' is 'ALOW', expected one of ALLOW, DENY
```

## Describing traffic

`--input` reads JSON Lines — one packet object per line. Blank lines and lines
starting with `#` are ignored. See `sample_traffic.jsonl`.

```json
{"src_ip": "203.0.113.10", "dst_ip": "192.168.1.10", "protocol": "TCP", "direction": "IN", "src_port": 51515, "dst_port": 22}
```

`src_ip`, `dst_ip`, `protocol`, and `direction` are required; ports are optional
because ICMP has none. `direction` is relative to the network you are
protecting: `IN` is arriving, `OUT` is leaving.

## The audit log

Every decision in a `simulate` run is appended to `firewall.log` as one JSON
object per line, so it can be read back with standard tools:

```console
$ jq -r '"\(.decision)\t\(.matched_rule // "default policy")"' firewall.log | sort | uniq -c
```

```json
{"decision": "DENY", "matched_rule": "Block inbound SSH", "rule_index": 0,
 "packet": {"src_ip": "203.0.113.10", "dst_ip": "192.168.1.10", "protocol": "TCP",
            "direction": "IN", "src_port": 51515, "dst_port": 22},
 "timestamp": "2026-08-20T09:14:22.481293+00:00"}
```

Timestamps are timezone-aware UTC. Entries are flushed as they are written, so
an interrupted run keeps everything decided up to that point.

## Using it as a library

```python
from firewall import FirewallEngine, Packet

engine = FirewallEngine.from_file("rules.json", default_policy="DENY")

decision = engine.decide(
    Packet("203.0.113.10", "192.168.1.10", "TCP", "IN", dst_port=22)
)

print(decision.action)        # 'DENY'
print(decision.matched_rule)  # 'Block inbound SSH'
print(decision.allowed)       # False
print(decision.reason)        # "rule #1 'Block inbound SSH'"
```

`engine.evaluate(packets)` does the same lazily over an iterable, so a large
capture is never held in memory all at once.

To keep an audit trail, pass a logger:

```python
from firewall import DecisionLogger, FirewallEngine

with DecisionLogger("audit.log") as logger:
    engine = FirewallEngine.from_file("rules.json", logger=logger)
    for decision in engine.evaluate(packets):
        ...
```

Everything the package raises derives from `FirewallError`, so a single
`except FirewallError` catches bad rules (`RuleError`) and bad packets
(`PacketError`) alike.

## Project layout

```
firewall/
  __init__.py     public API
  __main__.py     enables `python -m firewall`
  cli.py          argument parsing and the three subcommands
  engine.py       FirewallEngine and Decision — first-match-wins evaluation
  rules.py        Rule, PortSpec, and the JSON rule loader
  packets.py      Packet — validation and normalisation
  logger.py       JSON Lines audit logging
  traffic.py      generated and replayed packet sources
  errors.py       the exception hierarchy
tests/            the test suite
rules.json        the example ruleset
sample_traffic.jsonl
main.py           convenience launcher for `python main.py`
```

## Development

```bash
pip install -e ".[dev]"
pytest              # run the tests
ruff check .        # lint
ruff format .       # format
```

## License

MIT — see [LICENSE](LICENSE).
