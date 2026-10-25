#!/usr/bin/env python3
"""Print an unreferenced IPv4 filter chain for iptables-restore --noflush."""
import argparse
import ipaddress
import re


def parameters(variant, iface, astra, kali):
    if not 1 <= variant <= 27:
        raise ValueError('variant must be 1..27')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', iface) or iface == 'lo':
        raise ValueError('use the actual internal interface name, without @suffix')
    addresses = [ipaddress.IPv4Address(x) for x in (astra, kali)]
    if addresses[0] == addresses[1] or any(x.is_unspecified or x.is_multicast or x.is_loopback or int(x) == 0xffffffff for x in addresses):
        raise ValueError('use two distinct unicast IPv4 addresses from the passport')
    return str(addresses[0]), str(addresses[1])


def policy(variant, iface, astra, kali):
    astra, kali = parameters(variant, iface, astra, kali)
    chain = 'PR8_%d' % variant
    base = 18000 + 10 * variant
    allowed = base if variant % 2 else base + 1
    udp_action = 'RETURN' if variant % 2 else 'DROP'
    return '\n'.join([
        '# Attach ONLY after successful check, timer setup and chain load.',
        '# Interface %s; destination %s/32; source %s/32' % (iface, astra, kali),
        '*filter',
        ':%s - [0:0]' % chain,
        '-A %s -m conntrack --ctstate INVALID -m comment --comment invalid -j DROP' % chain,
        '-A %s -s %s/32 -d %s/32 -p tcp --dport %d -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment allowed_http -j RETURN' % (chain, kali, astra, allowed),
        '-A %s -s %s/32 -d %s/32 -p udp --dport %d -m comment --comment variant_udp -j %s' % (chain, kali, astra, base + 2, udp_action),
        '-A %s -s %s/32 -d %s/32 -p icmp --icmp-type echo-request -m comment --comment diagnostic_ping -j RETURN' % (chain, kali, astra),
        '-A %s -m comment --comment deny_other_lab_input -j DROP' % chain,
        'COMMIT', ''])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variant', type=int, required=True)
    p.add_argument('--iface', required=True)
    p.add_argument('--astra', required=True)
    p.add_argument('--kali', required=True)
    a = p.parse_args()
    try:
        print(policy(a.variant, a.iface, a.astra, a.kali), end='')
    except ValueError as e:
        p.error(str(e))


if __name__ == '__main__':
    main()
