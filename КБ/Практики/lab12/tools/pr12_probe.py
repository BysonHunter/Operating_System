#!/usr/bin/env python3
"""PR12 (Kali): matrix of control SSH connections to the own Astra.

One host, port 22, seven single connections per phase, BatchMode (no password prompts, no guessing),
a verified known_hosts file and the lab key only. Private keys and passwords are never stored.
Standard library only, Python 3.5 syntax.
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys

PHASES = ['before', 'after', 'restored']


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def plan(v, phase):
    a, b = 'ssha%02d' % v, 'sshb%02d' % v
    marker = 'pr12-restricted-v%02d' % v
    deny_b = v % 2 == 1
    hard = phase == 'after'
    t = [
        ('T1', a, 'user A, lab key', [], 'id -un', ('ALLOW', a)),
        ('T2', a, 'user A, password only (no prompt)', ['-o', 'PubkeyAuthentication=no',
                                                         '-o', 'PreferredAuthentications=password,keyboard-interactive'],
         'id -un', ('DENY', 'publickey' if hard else 'password')),
        ('T3', b, 'user B, lab key', [], 'id -un',
         (('DENY', None) if deny_b else ('ALLOW', marker)) if hard else ('ALLOW', b)),
        ('T4', 'root', 'root, lab key', [], 'id -un', ('DENY', None)),
        ('T5', 'nouser%02d' % v, 'nonexistent user', [], 'id -un', ('DENY', None)),
        ('T6', a, 'user A, remote forwarding request', ['-o', 'ExitOnForwardFailure=yes', '-R', '127.0.0.1:0:127.0.0.1:9'],
         'true', ('FORWARD_REFUSED', None) if hard else ('ALLOW', None)),
        ('T7', a, 'user A, only aes128-ctr + hmac-sha1', ['-o', 'Ciphers=aes128-ctr', '-o', 'MACs=hmac-sha1'],
         'id -un', ('NEGOTIATION_FAILED', None) if hard else ('ALLOW', a)),
    ]
    return t


def classify(rc, out, err):
    methods = ''
    for line in err.splitlines():
        m = re.search(r'Authentications that can continue: (\S+)', line)
        if m:
            methods = m.group(1)
        m = re.search(r'Permission denied \(([^)]*)\)', line)
        if m:
            methods = m.group(1)
    if re.search(r'Unable to negotiate|no matching (cipher|mac|key exchange|host key)', err, re.I):
        return 'NEGOTIATION_FAILED', methods
    if re.search(r'remote port forwarding failed', err, re.I):
        return 'FORWARD_REFUSED', methods
    if re.search(r'Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED', err):
        return 'HOSTKEY_ERROR', methods
    if rc == 0:
        return 'ALLOW', methods
    if 'Permission denied' in err:
        return 'DENY', methods
    if re.search(r'Connection (refused|timed out)|No route to host|Connection closed', err):
        return 'NETWORK_ERROR', methods
    return 'ERROR', methods


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host', required=True)
    ap.add_argument('--variant', type=int, required=True)
    ap.add_argument('--phase', required=True, choices=PHASES)
    ap.add_argument('--key', required=True, help='path to the PRIVATE lab key (loaded into ssh-agent)')
    ap.add_argument('--known-hosts', required=True)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('variant must be 1..27')
    host = ipaddress.IPv4Address(a.host)
    if not host.is_private or host.is_loopback:
        raise SystemExit('target must be the own Astra address in the isolated segment')
    if str(host) != '10.50.%d.10' % v:
        print('WARNING: %s differs from the default passport 10.50.%d.10' % (host, v), file=sys.stderr)
    for p in (a.key, a.known_hosts):
        if not os.path.isfile(p):
            raise SystemExit('file not found: ' + p)
    if os.path.exists(a.output):
        raise SystemExit('refusing to overwrite ' + a.output)
    base = ['ssh', '-F', '/dev/null', '-v', '-p', '22', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + os.path.abspath(a.known_hosts),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no', '-o', 'IdentitiesOnly=yes',
            '-i', os.path.abspath(a.key), '-o', 'ServerAliveInterval=5']
    rows = []
    for tid, user, desc, extra, cmd, (exp, detail) in plan(v, a.phase):
        argv = base + extra + ['%s@%s' % (user, host), cmd]
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
            rc, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = None, '', 'timeout'
        outcome, methods = classify(rc, out, err)
        stdout = out.strip().splitlines()[0] if out.strip() else ''
        ok = outcome == exp
        if ok and exp == 'ALLOW' and detail:
            ok = stdout == detail
        if ok and exp == 'DENY' and detail:
            ok = (methods == 'publickey') if detail == 'publickey' else ('password' in methods or 'keyboard-interactive' in methods)
        err_tail = [l for l in err.splitlines() if not l.startswith('debug')][-3:]
        rows.append(dict(kind='test', variant=v, phase=a.phase, test=tid, user=user, description=desc,
                         expected=exp + ('' if not detail else ':' + detail), outcome=outcome, exit_code=rc,
                         methods=methods, stdout=stdout[:120], stderr_tail=err_tail, pass_=None, client_utc=utc(),
                         options=' '.join(extra)))
        rows[-1]['pass'] = ok
        del rows[-1]['pass_']
    with open(a.output, 'w', encoding='utf-8') as s:
        for r in rows:
            s.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n')
        s.write(json.dumps(dict(kind='summary', variant=v, phase=a.phase, target='%s:22' % host, tests=len(rows),
                                passed=sum(r['pass'] for r in rows), client_utc=utc()), sort_keys=True) + '\n')
    for r in rows:
        print('%s %-9s %-36s exp=%-24s got=%-18s methods=%-22s %s %s' % (
            r['test'], r['user'], r['description'][:36], r['expected'], r['outcome'], r['methods'] or '-',
            r['stdout'][:24], 'PASS' if r['pass'] else 'FAIL'))
    print('%d/%d as expected; saved %s' % (sum(r['pass'] for r in rows), len(rows), a.output))
    return 0 if all(r['pass'] for r in rows) else 3


if __name__ == '__main__':
    sys.exit(main())
