"""Stage 1: safety policy. Decides *what the agent is allowed to ask for*.

It's an allowlist, not a syntax checker. The kernel sandbox (stage 4) decides whether a rule is
valid iptables. This stage decides whether it's acceptable: a single append/insert into the filter
table, a DROP/REJECT target, scoped to an explicit address, with no shell metacharacters, no
negation, and no flush/policy/delete operations.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network

FORBIDDEN_CHARS = set(";|&$`<>(){}\\\n\r!*?")
COMMANDS = {"iptables", "iptables-nft", "iptables-legacy", "/sbin/iptables", "/usr/sbin/iptables"}
DESTRUCTIVE = {"-F", "--flush", "-X", "--delete-chain", "-P", "--policy", "-D", "--delete", "-R", "--replace",
               "-Z", "--zero", "-N", "--new-chain", "-E", "--rename-chain", "-L", "--list", "-S", "--list-rules"}
CHAINS = {"INPUT", "FORWARD", "OUTPUT"}
BLOCK_TARGETS = {"DROP", "REJECT"}
MATCHES = {"tcp", "udp", "icmp", "multiport", "conntrack", "state", "limit", "comment"}
# option -> number of values it takes
OPTIONS: dict[str, int] = {
    "-s": 1, "--source": 1, "--src": 1, "-d": 1, "--destination": 1, "--dst": 1,
    "-p": 1, "--protocol": 1, "--dport": 1, "--destination-port": 1, "--sport": 1, "--source-port": 1,
    "-m": 1, "--match": 1, "--dports": 1, "--sports": 1, "--state": 1, "--ctstate": 1, "--syn": 0,
    "-i": 1, "--in-interface": 1, "-o": 1, "--out-interface": 1, "-j": 1, "--jump": 1,
    "--reject-with": 1, "--comment": 1, "--limit": 1, "--limit-burst": 1, "--icmp-type": 1,
    "-t": 1, "--table": 1,
}
_COMMENT_OK = re.compile(r"^[A-Za-z0-9 _.:/-]{0,64}$")


class PolicyError(ValueError):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class ParsedRule:
    op: str                      # -A | -I
    chain: str
    position: int | None
    target: str
    sources: list[IPv4Network] = field(default_factory=list)
    destinations: list[IPv4Network] = field(default_factory=list)
    protocol: str | None = None
    dports: set[int] | None = None
    in_iface: str | None = None
    out_iface: str | None = None
    tokens: list[str] = field(default_factory=list)   # argv after the command

    @property
    def argv(self) -> list[str]:
        return ["iptables", *self.tokens]

    @property
    def restore_line(self) -> str:
        """Same rule in iptables-restore syntax (no command, no -t)."""
        out, skip = [], False
        for i, tok in enumerate(self.tokens):
            if skip:
                skip = False
                continue
            if tok in ("-t", "--table"):
                skip = True
                continue
            out.append(f'"{tok}"' if " " in tok else tok)
        return " ".join(out)


def _networks(value: str) -> list[IPv4Network]:
    nets = []
    for part in value.split(","):
        try:
            net = ip_network(part.strip(), strict=False)
        except ValueError as exc:
            raise PolicyError(f"'{part}' is not a valid IPv4 address or CIDR block") from exc
        if net.version != 4:
            raise PolicyError("only IPv4 rules are supported")
        nets.append(net)
    return nets


def _ports(value: str) -> set[int] | None:
    ports: set[int] = set()
    for part in value.split(","):
        lo, _, hi = part.partition(":")
        try:
            a, b = int(lo), int(hi or lo)
        except ValueError:
            return None  # let the kernel stage produce the real error
        ports.update(range(a, min(b, 65535) + 1))
    return ports


def tokenize(rule: str) -> list[str]:
    rule = (rule or "").strip()
    if not rule:
        raise PolicyError("empty rule")
    bad = sorted(set(rule) & FORBIDDEN_CHARS)
    if bad:
        raise PolicyError(f"rule contains forbidden shell/negation characters {bad}; output a single plain iptables command")
    try:
        tokens = shlex.split(rule)
    except ValueError as exc:
        raise PolicyError(f"could not tokenize rule: {exc}") from exc
    if tokens and tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens or tokens[0] not in COMMANDS:
        raise PolicyError("rule must be a single 'iptables' command")
    return tokens[1:]


def parse(rule: str, block_only: bool = True) -> ParsedRule:
    tokens = tokenize(rule)
    return parse_tokens(tokens, block_only)


def parse_tokens(tokens: list[str], block_only: bool = True) -> ParsedRule:
    op = chain = target = None
    position = None
    table = "filter"
    sources: list[IPv4Network] = []
    dests: list[IPv4Network] = []
    protocol = None
    dports: set[int] | None = None
    in_iface = out_iface = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in DESTRUCTIVE:
            raise PolicyError(f"operation '{tok}' is not allowed (only -A/-I of a single block rule)", retryable=True)
        if tok in ("-A", "--append", "-I", "--insert"):
            if op is not None:
                raise PolicyError("rule must contain exactly one -A or -I")
            if i + 1 >= len(tokens):
                raise PolicyError(f"{tok} needs a chain name")
            op, chain = ("-A" if tok in ("-A", "--append") else "-I"), tokens[i + 1]
            i += 2
            if op == "-I" and i < len(tokens) and tokens[i].isdigit():
                position = int(tokens[i])
                i += 1
            continue
        if not tok.startswith("-"):
            raise PolicyError(f"unexpected token '{tok}'")
        if tok not in OPTIONS:
            raise PolicyError(f"option '{tok}' is not in the allowed option set")
        arity = OPTIONS[tok]
        if i + arity >= len(tokens) + (0 if arity else 1):
            raise PolicyError(f"option '{tok}' is missing its value")
        value = tokens[i + 1] if arity else ""
        if tok in ("-t", "--table"):
            table = value
        elif tok in ("-s", "--source", "--src"):
            sources += _networks(value)
        elif tok in ("-d", "--destination", "--dst"):
            dests += _networks(value)
        elif tok in ("-p", "--protocol"):
            protocol = value.lower()
        elif tok in ("--dport", "--destination-port", "--dports"):
            dports = _ports(value)
        elif tok in ("-i", "--in-interface"):
            in_iface = value
        elif tok in ("-o", "--out-interface"):
            out_iface = value
        elif tok in ("-m", "--match") and value not in MATCHES:
            raise PolicyError(f"match module '{value}' is not allowed")
        elif tok in ("-j", "--jump"):
            target = value
        elif tok == "--comment" and not _COMMENT_OK.match(value):
            raise PolicyError("comment may only contain letters, digits, spaces and . _ : / -")
        i += 1 + arity
    if op is None:
        raise PolicyError("rule must append (-A) or insert (-I) into a chain")
    if table != "filter":
        raise PolicyError(f"table '{table}' is not allowed; use the filter table")
    if chain not in CHAINS:
        raise PolicyError(f"chain '{chain}' is not allowed; use INPUT, FORWARD or OUTPUT")
    if target is None:
        raise PolicyError("rule has no -j target")
    if block_only:
        if target not in BLOCK_TARGETS:
            raise PolicyError(f"target '{target}' is not allowed; mitigation rules must DROP or REJECT")
        scoped = dests if chain == "OUTPUT" else sources
        if not scoped:
            flag = "-d <attacker>" if chain == "OUTPUT" else "-s <attacker>"
            raise PolicyError(f"rule is not scoped to the attacker; add {flag}")
    return ParsedRule(op=op, chain=chain, position=position, target=target, sources=sources,
                      destinations=dests, protocol=protocol, dports=dports, in_iface=in_iface,
                      out_iface=out_iface, tokens=tokens)
