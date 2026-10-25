#!/usr/bin/env python3
"""Remove only the PR8 jump and its private chain. No full ruleset restore."""
import argparse
import ipaddress
import re
import subprocess


def rollback(binary, variant, iface, astra, run=subprocess.call):
    if not 1 <= variant <= 27 or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', iface) or iface == 'lo':
        raise ValueError('invalid variant or interface')
    address = ipaddress.IPv4Address(astra)
    if address.is_loopback or address.is_unspecified or address.is_multicast or int(address) == 0xffffffff:
        raise ValueError('use the stand IPv4 address')
    if not binary.startswith('/'):
        raise ValueError('absolute iptables binary path required')
    chain = 'PR8_%d' % variant
    jump = ['INPUT', '-i', iface, '-d', str(address) + '/32', '-j', chain]

    def command(args):
        return run([binary, '-w', '5', '-t', 'filter'] + args)

    status = command(['-S', chain])
    if status == 1:
        # A nonexistent chain cannot have live references. Avoid parsing a
        # nonexistent jump target with -C, which may report a different error.
        print('PR8 chain already absent')
        return
    if status != 0:
        raise RuntimeError('cannot inspect the private chain')
    # Remove only exact matching references, never INPUT by line number.
    while True:
        status = command(['-C'] + jump)
        if status == 1:
            break
        if status != 0 or command(['-D'] + jump) != 0:
            raise RuntimeError('cannot inspect/remove the private jump')
    if command(['-F', chain]) != 0 or command(['-X', chain]) != 0:
        raise RuntimeError('cannot remove the private chain; inspect references from console')
    print('Removed only %s and its scoped INPUT jump' % chain)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--iptables', required=True)
    p.add_argument('--variant', type=int, required=True)
    p.add_argument('--iface', required=True)
    p.add_argument('--astra', required=True)
    a = p.parse_args()
    try:
        rollback(a.iptables, a.variant, a.iface, a.astra)
    except (ValueError, RuntimeError, OSError) as e:
        p.exit(1, 'Rollback error: %s\n' % e)


if __name__ == '__main__':
    main()
