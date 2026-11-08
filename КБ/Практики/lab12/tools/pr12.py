#!/usr/bin/env python3
"""PR12 (Astra): session, audit of the effective sshd configuration, journal summary, test table, clean check.

Standard library only, Python 3.5 syntax. Run as the ordinary training user; root-only data
(sshd -T output, journal) is saved by the commands of the task and passed here as files.
"""
import argparse
import csv
import datetime
import grp
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import time
import uuid

PHASES = ['before', 'after', 'restored']
WEAK_CIPHER = re.compile(r'(cbc|3des|arcfour|blowfish|cast128|rijndael)', re.I)
WEAK_MAC = re.compile(r'(md5|sha1|ripemd|umac-64)', re.I)
WEAK_KEX = re.compile(r'(sha1|group1-|group-exchange-sha1)', re.I)


def utc(epoch=None):
    t = time.time() if epoch is None else epoch
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def variant_params(v):
    return dict(variant=v, group='sshlab%02d' % v, user_a='ssha%02d' % v, user_b='sshb%02d' % v,
                policy_b='deny' if v % 2 == 1 else 'restricted', marker='pr12-restricted-v%02d' % v,
                maxauthtries=2 + (v - 1) % 3, logingracetime=(20, 30, 45, 60)[(v - 1) % 4],
                alive=120 + 60 * ((v - 1) % 4), alivecount=2)


def write_new(path, text):
    if os.path.exists(path):
        raise SystemExit('refusing to overwrite existing evidence: ' + path)
    with open(path, 'w', encoding='utf-8') as s:
        s.write(text)


def load(work):
    work = os.path.abspath(work)
    with open(os.path.join(work, 'session.json'), encoding='utf-8') as s:
        ses = json.load(s)
    if not 1 <= int(ses['variant']) <= 27 or not re.match(r'^v\d\d-[a-f0-9]{12}$', ses['run']):
        raise SystemExit('invalid session.json')
    ses['work'] = work
    return ses


def init(a):
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('variant must be 1..27')
    work = os.path.abspath(a.work)
    if os.path.exists(os.path.join(work, 'session.json')) or os.path.exists(os.path.join(work, 'evidence')):
        raise SystemExit('session/evidence already exist in %s; save the previous work under another name' % work)
    for d in ['evidence', 'backup', 'config']:
        os.makedirs(os.path.join(work, d), exist_ok=True)
    os.chmod(os.path.join(work, 'backup'), 0o700)
    ses = variant_params(v)
    ses.update(run='v%02d-%s' % (v, uuid.uuid4().hex[:12]), astra=a.astra or '10.50.%d.10' % v,
               kali=a.kali or '10.50.%d.20' % v, started_epoch=time.time(),
               since=datetime.datetime.fromtimestamp(time.time() - 1).strftime('%Y-%m-%d %H:%M:%S'))
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True)
    print(json.dumps(ses, indent=2, sort_keys=True))


def info(a):
    print(load(a.work)[a.field])


# ------------------------------------------------------------- effective configuration
def parse_effective(path):
    conf = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line or ' ' not in line:
            continue
        k, v = line.split(' ', 1)
        conf.setdefault(k.lower(), []).append(v.strip())
    return conf


def first(conf, *keys):
    for k in keys:
        if k in conf:
            return conf[k][0]
    return None


def audit_config(a):
    ses = load(a.work)
    conf = parse_effective(a.file)
    role = a.role
    req = []

    def need(name, ok, actual, expected):
        req.append(dict(item=name, ok=bool(ok), actual=actual, expected=expected))

    def eq(key, expected, *alias):
        val = first(conf, key, *alias)
        need(key, val is not None and val.lower() == str(expected).lower(), val, str(expected))

    eq('permitrootlogin', 'no')
    eq('passwordauthentication', 'no')
    eq('challengeresponseauthentication', 'no', 'kbdinteractiveauthentication')
    eq('permitemptypasswords', 'no')
    eq('pubkeyauthentication', 'yes')
    eq('authenticationmethods', 'publickey')
    eq('allowgroups', ses['group'])
    eq('maxauthtries', ses['maxauthtries'])
    eq('logingracetime', ses['logingracetime'])
    eq('clientaliveinterval', ses['alive'])
    eq('clientalivecountmax', ses['alivecount'])
    eq('x11forwarding', 'no')
    eq('allowtcpforwarding', 'no')
    eq('allowagentforwarding', 'no')
    eq('permittunnel', 'no')
    eq('permituserenvironment', 'no')
    eq('loglevel', 'VERBOSE')
    for key, rx in [('ciphers', WEAK_CIPHER), ('macs', WEAK_MAC), ('kexalgorithms', WEAK_KEX)]:
        val = first(conf, key) or ''
        weak = [x for x in val.split(',') if x and rx.search(x)]
        need(key + ' without weak algorithms', bool(val) and not weak, ','.join(weak) or val[:60], 'no weak entries')
    if role == 'b' and ses['policy_b'] == 'restricted':
        eq('forcecommand', '/bin/echo ' + ses['marker'])
        eq('permittty', 'no')
    if role == 'b' and ses['policy_b'] == 'deny':
        try:
            groups = [g.gr_name for g in grp.getgrall() if ses['user_b'] in g.gr_mem]
            groups.append(grp.getgrgid(pwd.getpwnam(ses['user_b']).pw_gid).gr_name)
        except KeyError:
            groups = ['(user absent)']
        need('user B not in ' + ses['group'], ses['group'] not in groups, ','.join(sorted(set(groups))), 'not a member')
    if role == 'a':
        try:
            ga = [g.gr_name for g in grp.getgrall() if ses['user_a'] in g.gr_mem]
        except KeyError:
            ga = []
        need('user A in ' + ses['group'], ses['group'] in ga, ','.join(ga), 'member')
    rep = dict(run=ses['run'], variant=ses['variant'], role=role, source=os.path.abspath(a.file),
               source_sha256=hashlib.sha256(open(a.file, 'rb').read()).hexdigest(), checked_utc=utc(),
               items=req, passed=sum(r['ok'] for r in req), total=len(req))
    out = os.path.join(ses['work'], 'evidence', 'audit-config-%s.json' % role)
    write_new(out, json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    for r in req:
        print('%-4s %-38s actual=%s expected=%s' % ('OK' if r['ok'] else 'FAIL', r['item'], r['actual'], r['expected']))
    print('%d/%d requirements met; saved %s' % (rep['passed'], rep['total'], out))
    return 0 if rep['passed'] == rep['total'] else 3


# ------------------------------------------------------------- journal summary
PATTERNS = [
    ('accepted_publickey', re.compile(r'Accepted publickey for (\S+) from (\S+)')),
    ('key_fingerprint', re.compile(r'(ED25519|RSA|ECDSA) SHA256:\S+')),
    ('not_allowed', re.compile(r'User (\S+) from (\S+) not allowed because ([^\n]+)')),
    ('root_refused', re.compile(r'ROOT LOGIN REFUSED')),
    ('invalid_user', re.compile(r'Invalid user (\S+) from (\S+)')),
    ('failed', re.compile(r'Failed (\S+) for (invalid user )?(\S+) from (\S+)')),
    ('no_matching', re.compile(r'(Unable to negotiate|no matching \w+ found)', re.I)),
    ('forward_refused', re.compile(r'(refused|denied).*(forward|tcpip)', re.I)),
    ('reload', re.compile(r'Received SIGHUP|Reloading|Reloaded', re.I)),
]


def logs(a):
    ses = load(a.work)
    text = open(a.file, encoding='utf-8', errors='replace').read()
    lines = text.splitlines()
    counts, examples = {}, {}
    for line in lines:
        for name, rx in PATTERNS:
            if rx.search(line):
                counts[name] = counts.get(name, 0) + 1
                examples.setdefault(name, line.strip()[-220:])
    rep = dict(run=ses['run'], phase=a.phase, source=os.path.abspath(a.file), lines=len(lines),
               counts=counts, examples=examples, checked_utc=utc())
    out = os.path.join(ses['work'], 'evidence', 'journal-summary-%s.json' % a.phase)
    write_new(out, json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    for name, _ in PATTERNS:
        print('%-20s %3d  %s' % (name, counts.get(name, 0), examples.get(name, '')[:110]))
    print('saved', out)


# ------------------------------------------------------------- table
def table(a):
    ses = load(a.work)
    ev = os.path.join(ses['work'], 'evidence')
    rows = []
    for ph in PHASES:
        p = os.path.join(ev, 'kali-%s.jsonl' % ph)
        if not os.path.exists(p):
            print('phase %s: %s absent' % (ph, p))
            continue
        for line in open(p, encoding='utf-8'):
            r = json.loads(line)
            if r.get('kind') != 'test':
                continue
            if r.get('variant') != ses['variant'] or r.get('phase') != ph:
                raise SystemExit('file %s belongs to another variant or phase' % p)
            rows.append(dict(phase=ph, test=r['test'], user=r['user'], check=r['description'], expected=r['expected'],
                             outcome=r['outcome'], methods=r.get('methods', ''), output=r.get('stdout', ''),
                             verdict='PASS' if r['pass'] else 'FAIL'))
    out = os.path.join(ev, 'tests.csv')
    if os.path.exists(out):
        raise SystemExit('refusing to overwrite ' + out)
    with open(out, 'w', encoding='utf-8', newline='') as s:
        w = csv.DictWriter(s, fieldnames=['phase', 'test', 'user', 'check', 'expected', 'outcome', 'methods', 'output', 'verdict'])
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print('%-8s %-3s %-9s %-15s %-15s %-18s %s' % (r['phase'], r['test'], r['user'], r['expected'], r['outcome'],
                                                      r['methods'], r['verdict']))
    bad = [r for r in rows if r['verdict'] != 'PASS']
    print('%d tests, %d not as expected; saved %s' % (len(rows), len(bad), out))
    return 0 if rows and not bad else 3


# ------------------------------------------------------------- clean check
def clean_check(a):
    ses = load(a.work)
    def absent_user(u):
        try:
            pwd.getpwnam(u)
            return False
        except KeyError:
            return True
    try:
        grp.getgrnam(ses['group'])
        group_absent = False
    except KeyError:
        group_absent = True
    orig = os.path.join(ses['work'], 'backup', 'sshd_config.orig')
    cur = '/etc/ssh/sshd_config'
    h = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest() if os.path.exists(p) else None
    rc = subprocess.run(['systemctl', 'is-active', 'ssh'], stdout=subprocess.PIPE, universal_newlines=True)
    rep = dict(run=ses['run'], checked_utc=utc(), user_a_absent=absent_user(ses['user_a']),
               user_b_absent=absent_user(ses['user_b']), group_absent=group_absent,
               home_a_absent=not os.path.exists('/home/' + ses['user_a']), home_b_absent=not os.path.exists('/home/' + ses['user_b']),
               config_sha256=h(cur), original_sha256=h(orig), ssh_service=rc.stdout.strip())
    rep['config_restored'] = rep['config_sha256'] is not None and rep['config_sha256'] == rep['original_sha256']
    rep['clean'] = all(rep[k] for k in rep if k.endswith('_absent')) and rep['config_restored']
    write_new(os.path.join(ses['work'], 'evidence', 'clean-check.json'),
              json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    for k in sorted(rep):
        print('%s: %s' % (k, rep[k]))
    return 0 if rep['clean'] else 4


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sp = ap.add_subparsers(dest='cmd')
    p = sp.add_parser('init'); p.add_argument('--work', required=True); p.add_argument('--variant', type=int, required=True)
    p.add_argument('--astra'); p.add_argument('--kali')
    p = sp.add_parser('info'); p.add_argument('--work', required=True)
    p.add_argument('--field', required=True, choices=['run', 'variant', 'group', 'user_a', 'user_b', 'policy_b', 'marker',
                                                      'maxauthtries', 'logingracetime', 'alive', 'alivecount', 'astra', 'kali', 'since'])
    p = sp.add_parser('audit-config'); p.add_argument('--work', required=True); p.add_argument('--file', required=True)
    p.add_argument('--role', required=True, choices=['a', 'b'])
    p = sp.add_parser('logs'); p.add_argument('--work', required=True); p.add_argument('--file', required=True)
    p.add_argument('--phase', required=True, choices=PHASES)
    p = sp.add_parser('table'); p.add_argument('--work', required=True)
    p = sp.add_parser('clean-check'); p.add_argument('--work', required=True)
    a = ap.parse_args()
    fn = {'init': init, 'info': info, 'audit-config': audit_config, 'logs': logs, 'table': table,
          'clean-check': clean_check}.get(a.cmd)
    if not fn:
        ap.print_help()
        return 2
    return fn(a) or 0


if __name__ == '__main__':
    sys.exit(main())
