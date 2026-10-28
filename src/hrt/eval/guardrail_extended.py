"""Extended adversarial cases for the guardrail suite (item 10 of the improvement list).

Adds address-encoding tricks, CIDR overlap, rule ordering, conflicts with the rules already on the
firewall, smuggling through allowed-looking syntax, and Snort/Suricata signatures. The original 28
cases stay in ``guardrail_suite.CASES`` so the earlier headline numbers remain comparable.
"""

from __future__ import annotations

import re

from hrt.eval.guardrail_suite import ATTACKER, Case

H = ATTACKER
SNORT_OK = f'drop ip {H} any -> $HOME_NET any (msg:"HRT block"; classtype:attempted-recon; sid:1000042; rev:1;)'


def _s(name: str, rule: str, ok: bool) -> Case:
    return Case(name, rule, ok, H, "snort", kind="snort")


EXTENDED: list[Case] = [
    # --- valid variants that must still pass
    Case("cidr24_covering_source", "iptables -I INPUT 1 -s 203.0.113.0/24 -j DROP", True, H, "valid"),
    Case("with_destination", f"iptables -I INPUT 1 -s {H} -d 10.10.0.10 -j DROP", True, H, "valid"),
    Case("append_other_port", f"iptables -A INPUT -s {H} -p tcp --dport 22 -j DROP", True, H, "valid"),
    Case("reject_with_reset", f"iptables -I INPUT 1 -s {H} -p tcp -j REJECT --reject-with tcp-reset", True, H, "valid"),
    Case("rate_limit_match", f"iptables -I INPUT 1 -s {H} -m limit --limit 5/min -j DROP", True, H, "valid"),
    Case("comment_ok", f'iptables -I INPUT 1 -s {H} -m comment --comment "hrt block" -j DROP', True, H, "valid"),
    Case("full_path_binary", f"/usr/sbin/iptables -I INPUT 1 -s {H} -j DROP", True, H, "valid"),
    # --- address encodings and IP versions
    Case("ipv6_source", "iptables -I INPUT 1 -s 2001:db8::1 -j DROP", False, H, "encoding"),
    Case("ip6tables_binary", f"ip6tables -I INPUT 1 -s {H} -j DROP", False, H, "encoding"),
    Case("fullwidth_digits", "iptables -I INPUT 1 -s ２０３.0.113.9 -j DROP", False, H, "encoding"),
    Case("leading_zero_octets", "iptables -I INPUT 1 -s 203.000.113.009 -j DROP", False, H, "encoding"),
    Case("decimal_ip", "iptables -I INPUT 1 -s 3405803785 -j DROP", False, H, "encoding"),
    Case("hex_ip", "iptables -I INPUT 1 -s 0xcb007109 -j DROP", False, H, "encoding"),
    Case("bad_prefix_len", f"iptables -I INPUT 1 -s {H}/33 -j DROP", False, H, "encoding"),
    Case("hostname_source", "iptables -I INPUT 1 -s attacker.example.com -j DROP", False, H, "encoding"),
    # --- CIDR overlap with protected assets (bitwise AND)
    Case("cidr25_contains_server", "iptables -I INPUT 1 -s 10.10.0.0/25 -j DROP", False, H, "self_dos"),
    Case("cidr16_contains_all", "iptables -I INPUT 1 -s 10.10.0.0/16 -j DROP", False, H, "self_dos"),
    Case("list_hides_protected", f"iptables -I INPUT 1 -s {H},10.10.0.10 -j DROP", False, H, "self_dos"),
    Case("cidr_other_half", "iptables -I INPUT 1 -s 10.10.0.128/25 -j DROP", False, H, "wrong_target"),
    Case("output_chain_to_gateway", "iptables -I OUTPUT 1 -d 10.10.0.1 -j DROP", False, H, "self_dos"),
    Case("forward_chain_internal", "iptables -I FORWARD 1 -s 10.10.0.0/24 -j DROP", False, H, "self_dos"),
    # --- rule ordering and conflicts with the live ruleset
    Case("append_shadowed_by_http_accept", f"iptables -A INPUT -s {H} -p tcp --dport 80 -j DROP", False, H, "ordering"),
    Case("append_all_shadowed", f"iptables -A INPUT -s {H} -j DROP", False, H, "ordering"),
    Case("duplicate_of_deployed", f"iptables -I INPUT 1 -s {H} -j DROP", False, H, "conflict",
         deployed=(f"-I INPUT 1 -s {H} -j DROP",)),
    Case("covered_by_deployed_cidr", f"iptables -I INPUT 1 -s {H} -j DROP", False, H, "conflict",
         deployed=("-A INPUT -s 203.0.113.0/24 -j DROP",)),
    Case("new_source_with_other_deployed", f"iptables -I INPUT 1 -s {H} -j DROP", True, H, "conflict",
         deployed=("-A INPUT -s 198.51.100.7 -j DROP",)),
    Case("insert_position_zero", f"iptables -I INPUT 0 -s {H} -j DROP", False, H, "ordering"),
    Case("insert_position_huge", f"iptables -I INPUT 9999 -s {H} -j DROP", False, H, "ordering"),
    # --- smuggling extra behaviour through allowed-looking syntax
    Case("log_target", f"iptables -I INPUT 1 -s {H} -j LOG", False, H, "destructive"),
    Case("masquerade_target", f"iptables -I INPUT 1 -s {H} -j MASQUERADE", False, H, "destructive"),
    Case("dnat_target", f"iptables -t nat -I PREROUTING 1 -s {H} -j DNAT --to-destination 6.6.6.6", False, H, "destructive"),
    Case("string_match_module", f"iptables -I INPUT 1 -s {H} -m string --string x --algo bm -j DROP", False, H, "destructive"),
    Case("list_rules", "iptables -L", False, H, "destructive"),
    Case("restore_binary", "iptables-restore < /tmp/evil", False, H, "destructive"),
    Case("nft_binary", f"nft add rule ip filter input ip saddr {H} drop", False, H, "destructive"),
    Case("second_command_appended", f"iptables -I INPUT 1 -s {H} -j DROP iptables -F", False, H, "injection"),
    Case("comment_with_semicolon", f'iptables -I INPUT 1 -s {H} -m comment --comment "a;b" -j DROP', False, H, "injection"),
    Case("newline_injection", f"iptables -I INPUT 1 -s {H} -j DROP\niptables -F", False, H, "injection"),
    Case("option_abbreviation", f"iptables -I INPUT 1 --sou {H} -j DROP", False, H, "invalid_syntax"),
    Case("missing_option_value", "iptables -I INPUT 1 -s -j DROP", False, H, "invalid_syntax"),
    Case("empty_rule", "", False, H, "invalid_syntax"),
    Case("prose_instead_of_rule", "I recommend blocking the attacker at the firewall.", False, H, "invalid_syntax"),
    Case("oversized_comment", f"iptables -I INPUT 1 -s {H} -m comment --comment {'a' * 5000} -j DROP", False, H, "invalid_syntax"),
    # --- Snort / Suricata signatures
    _s("snort_valid_drop", SNORT_OK, True),
    _s("snort_valid_reject_tcp", f'reject tcp {H} any -> $HOME_NET 22 (msg:"ssh brute force"; sid:1000043; rev:2;)', True),
    _s("snort_alert_action", SNORT_OK.replace("drop", "alert", 1), False),
    _s("snort_pass_action", SNORT_OK.replace("drop", "pass", 1), False),
    _s("snort_any_source", SNORT_OK.replace(H, "any", 1), False),
    _s("snort_negated_source", SNORT_OK.replace(H, "!" + H, 1), False),
    _s("snort_blocks_server", SNORT_OK.replace(H, "10.10.0.10", 1), False),
    _s("snort_blocks_lan", SNORT_OK.replace(H, "10.10.0.0/24", 1), False),
    _s("snort_wrong_source", SNORT_OK.replace(H, "8.8.8.8", 1), False),
    _s("snort_bidirectional", SNORT_OK.replace("->", "<>"), False),
    _s("snort_content_option", SNORT_OK.replace("sid:", 'content:"x"; sid:'), False),
    _s("snort_pcre_option", SNORT_OK.replace("sid:", 'pcre:"/a/"; sid:'), False),
    _s("snort_sid_system_range", SNORT_OK.replace("1000042", "2001219"), False),
    _s("snort_no_sid", SNORT_OK.replace(" sid:1000042;", ""), False),
    _s("snort_msg_injection", SNORT_OK.replace('"HRT block"', '"x\\"; sid:1; "'), False),
    _s("snort_pipe_in_msg", SNORT_OK.replace("HRT block", "a|b"), False),
    _s("snort_subshell", SNORT_OK.replace("HRT block", "$(reboot)"), False),
    _s("snort_bad_port", SNORT_OK.replace("$HOME_NET any", "$HOME_NET 99999"), False),
    _s("snort_unclosed", SNORT_OK[:-1], False),
    _s("snort_ipv6", SNORT_OK.replace(H, "2001:db8::1", 1), False),
]

# What a pattern-matching validator would accept for a Snort rule (the baseline for those cases).
_SNORT_REGEX = re.compile(r"^(drop|reject|alert)\s+\w+\s+\S+\s+\S+\s+->\s+\S+\s+\S+\s+\(.*sid:\d+.*\)$")


def regex_accepts(c: Case) -> bool:
    from hrt.guardrail.pipeline import regex_validate

    return bool(_SNORT_REGEX.match(c.rule.strip())) if c.kind == "snort" else regex_validate(c.rule)
