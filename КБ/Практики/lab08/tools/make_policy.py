#!/usr/bin/env python3
"""Print a scoped nftables policy. Does not load rules or alter the system."""
import argparse
import ipaddress
import re
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--variant', type=int, required=True)
p.add_argument('--iface', required=True)
p.add_argument('--astra', required=True)
p.add_argument('--kali', required=True)
a = p.parse_args()
if not 1 <= a.variant <= 27:
    p.error('variant must be 1..27')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', a.iface):
    p.error('use the real interface name, without @suffix')
ast = ipaddress.IPv4Address(a.astra)
kal = ipaddress.IPv4Address(a.kali)
if ast == kal or ast.is_unspecified or kal.is_unspecified or ast.is_multicast or kal.is_multicast or ast.is_loopback or kal.is_loopback:
    p.error('use two distinct unicast addresses from the stand passport')
b = 18000 + 10 * a.variant
allowed = b if a.variant % 2 else b + 1
udp_action = 'accept' if a.variant % 2 else 'drop'
print('''table inet pr8_%d {
    chain lab_input {
        ct state invalid counter drop comment "invalid"
        ip saddr %s ip daddr %s tcp dport %d ct state { new, established } counter accept comment "allowed_http"
        ip saddr %s ip daddr %s udp dport %d counter %s comment "variant_udp"
        ip saddr %s ip daddr %s icmp type echo-request counter accept comment "diagnostic_ping"
        counter drop comment "deny_other_lab_input"
    }
    chain input {
        type filter hook input priority 10; policy accept;
        iifname "%s" jump lab_input
    }
}''' % (a.variant, kal, ast, allowed, kal, ast, b + 2, udp_action, kal, ast, a.iface))
