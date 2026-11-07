#!/usr/bin/env python3
"""PR11 (Astra): session, trust chain of the teaching repository, local confirmation, findings table, clean check.

Standard library only, Python 3.5 syntax. Run as the ordinary training user; sudo is not needed for this script.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
import urllib.request
import urllib.error

TRUSTED_FPR = '5DFE88895F0C7932597E6B4D770FAA1FBFFF93BE'
PKG = 'pr11-demo'
CONF = '/etc/pr11-demo/pr11-demo.conf'
DPKG_LIST = '/var/lib/dpkg/info/pr11-demo.list'
REPO_ROOT = '/srv/oslab11'
PHASES = ['before', 'updated', 'restarted']


def utc(epoch=None):
    t = time.time() if epoch is None else epoch
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def write_json(path, obj):
    if os.path.exists(path):
        raise SystemExit('refusing to overwrite existing evidence: ' + path)
    with open(path, 'w', encoding='utf-8') as s:
        json.dump(obj, s, ensure_ascii=False, indent=2, sort_keys=True)
        s.write('\n')


# ---------------------------------------------------------------- session
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
    for d in ['evidence', 'state', 'apt']:
        os.makedirs(os.path.join(work, d), exist_ok=True)
    start = time.time()
    group = 'A' if v % 2 == 1 else 'B'
    run_id = 'v%02d-%s' % (v, uuid.uuid4().hex[:12])
    ses = dict(variant=v, run=run_id, port=22000 + v, probes=1 + (v - 1) % 3, group=group,
               start_version='1.0-1', target_version='1.0-2' if group == 'A' else '1.1-1',
               policy='minimal security backport' if group == 'A' else 'move to supported branch 1.1',
               astra=a.astra or '10.50.%d.10' % v, kali=a.kali or '10.50.%d.20' % v,
               unit='pr11-demo-' + run_id, since=datetime.datetime.fromtimestamp(
                   start - 1, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), started_epoch=start)
    with open(os.path.join(work, 'apt', 'oslab11.list'), 'w', encoding='ascii') as s:
        s.write('deb [signed-by=%s/keys/oslab11-archive.gpg] file:%s/orel-lab orel-lab main\n' % (REPO_ROOT, REPO_ROOT))
    with open(os.path.join(work, 'apt', 'hotfix.list'), 'w', encoding='ascii') as s:
        s.write('deb [signed-by=%s/keys/oslab11-archive.gpg] file:%s/untrusted orel-hotfix main\n' % (REPO_ROOT, REPO_ROOT))
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True)
    print(json.dumps(ses, indent=2, sort_keys=True))


def info(a):
    ses = load(a.work)
    print(ses[a.field])


# ---------------------------------------------------------------- trust chain
def gpgv(keyring, sig, data=None):
    cmd = ['gpgv', '--status-fd', '1', '--keyring', os.path.abspath(keyring), sig]
    if data:
        cmd.append(data)
    rc, out, err = run(cmd)
    fpr = ''
    for line in out.splitlines():
        if line.startswith('[GNUPG:] VALIDSIG '):
            fpr = line.split()[2]
    return dict(rc=rc, validsig=fpr, status=[l for l in out.splitlines() if l.startswith('[GNUPG:] ')][:6],
                stderr=err.strip().splitlines()[-3:])


def clearsigned_text(path):
    lines = open(path, encoding='utf-8').read().split('\n')
    i = lines.index('-----BEGIN PGP SIGNED MESSAGE-----') + 1
    while lines[i].strip():
        i += 1
    j = lines.index('-----BEGIN PGP SIGNATURE-----')
    body = [l[2:] if l.startswith('- ') else l for l in lines[i + 1:j]]
    return '\n'.join(body).rstrip('\n')


def parse_stanzas(text):
    out, cur, key = [], {}, None
    for line in text.split('\n'):
        if not line.strip():
            if cur:
                out.append(cur)
            cur, key = {}, None
        elif line[0] in ' \t' and key:
            cur[key] += '\n' + line.strip()
        else:
            key, _, val = line.partition(':')
            cur[key] = val.strip()
    if cur:
        out.append(cur)
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as s:
        for block in iter(lambda: s.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def repo_verify(a):
    top = os.path.abspath(a.repo)
    dist = os.path.join(top, 'dists', a.suite)
    expected = (a.fingerprint or TRUSTED_FPR).replace(' ', '').upper()
    rep = dict(repo=top, suite=a.suite, keyring=os.path.abspath(a.keyring), expected_fingerprint=expected,
               checked_utc=utc(), checks=[])

    def check(name, ok, **detail):
        row = dict(check=name, ok=bool(ok))
        row.update(detail)
        rep['checks'].append(row)
        return ok

    inrel = gpgv(a.keyring, os.path.join(dist, 'InRelease'))
    check('InRelease signature by expected key', inrel['rc'] == 0 and inrel['validsig'] == expected, gpgv=inrel)
    det = gpgv(a.keyring, os.path.join(dist, 'Release.gpg'), os.path.join(dist, 'Release'))
    check('Release.gpg detached signature by expected key', det['rc'] == 0 and det['validsig'] == expected, gpgv=det)
    release = open(os.path.join(dist, 'Release'), encoding='utf-8').read().rstrip('\n')
    check('InRelease text equals Release', clearsigned_text(os.path.join(dist, 'InRelease')) == release)
    meta = parse_stanzas(release)[0]
    rep['release'] = dict((k, meta.get(k, '')) for k in ['Origin', 'Label', 'Suite', 'Codename', 'Date'])
    listed = {}
    for line in meta.get('SHA256', '').split('\n'):
        f = line.split()
        if len(f) == 3:
            listed[f[2]] = (f[0], int(f[1]))
    for rel in ['main/binary-amd64/Packages', 'main/binary-amd64/Packages.gz']:
        p = os.path.join(dist, rel)
        ok = rel in listed and os.path.isfile(p) and sha256(p) == listed[rel][0] and os.path.getsize(p) == listed[rel][1]
        check('index %s matches SHA256 in Release' % rel, ok)
    rep['packages'] = []
    for st in parse_stanzas(open(os.path.join(dist, 'main/binary-amd64/Packages'), encoding='utf-8').read()):
        p = os.path.join(top, st['Filename'])
        ok = os.path.isfile(p) and sha256(p) == st['SHA256'] and os.path.getsize(p) == int(st['Size'])
        check('%s %s .deb matches SHA256 in Packages' % (st['Package'], st['Version']), ok, file=st['Filename'])
        rep['packages'].append(dict(package=st['Package'], version=st['Version'], file=st['Filename'], sha256=st['SHA256']))
    rep['trusted'] = all(c['ok'] for c in rep['checks'])
    if a.output:
        write_json(a.output, rep)
    for c in rep['checks']:
        print('%-4s %s' % ('OK' if c['ok'] else 'FAIL', c['check']))
    print('TRUSTED' if rep['trusted'] else 'NOT TRUSTED: do not use this source')
    return 0 if rep['trusted'] else 3


def advisory(a):
    res = gpgv(a.keyring, a.file + '.asc', a.file)
    ok = res['rc'] == 0 and res['validsig'] == (a.fingerprint or TRUSTED_FPR)
    print('%-4s bulletin signature by expected key' % ('OK' if ok else 'FAIL'))
    if not ok:
        print('\n'.join(res['stderr']))
        return 3
    b = json.load(open(a.file, encoding='utf-8'))
    for adv in b['advisories']:
        print('%s | affected %s | fixed %s | %s' % (adv['id'], ','.join(adv['affected_versions']),
                                                   ','.join(adv['fixed_versions']) or '-', adv['title']))
    return 0


# ---------------------------------------------------------------- local confirmation
def read_conf(path):
    conf = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            conf[k.strip()] = v.strip()
    return conf


def listening(port):
    """IPv4/IPv6 TCP sockets in LISTEN state on the port, read from /proc (no dependency on ss options)."""
    found = []
    for name in ['/proc/net/tcp', '/proc/net/tcp6']:
        if not os.path.exists(name):
            continue
        for line in open(name, encoding='ascii').readlines()[1:]:
            f = line.split()
            addr, _, hport = f[1].partition(':')
            if f[3] == '0A' and int(hport, 16) == port:
                if len(addr) == 8:
                    ip = '.'.join(str(int(addr[i:i + 2], 16)) for i in (6, 4, 2, 0))
                else:
                    ip = 'ipv6:' + addr
                found.append('%s:%d' % (ip, port))
    return found


def http_status(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        r = opener.open(url, timeout=4)
        return r.status, r.headers.get('Server', ''), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Server', ''), b''
    except Exception as e:  # noqa
        return None, '', str(e).encode()


def audit(a):
    ses = load(a.work)
    if a.phase not in PHASES:
        raise SystemExit('phase must be one of ' + ', '.join(PHASES))
    b = json.load(open(a.advisory, encoding='utf-8'))
    rep = dict(run=ses['run'], variant=ses['variant'], phase=a.phase, checked_utc=utc())
    rc, out, err = run(['dpkg-query', '-W', '-f', '${Status}\t${Version}\n', PKG])
    status, _, version = out.strip().partition('\t')
    rep['dpkg'] = dict(status=status or 'not found', version=version if status.endswith(' installed') else '')
    rep['dpkg']['install_epoch'] = os.stat(DPKG_LIST).st_mtime if os.path.exists(DPKG_LIST) else None
    conf = {}
    if os.path.exists(CONF):
        st = os.stat(CONF)
        conf = read_conf(CONF)
        rep['conffile'] = dict(path=CONF, mode='%04o' % stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                               world_readable=bool(st.st_mode & stat.S_IROTH), keys=sorted(conf),
                               token_present='token' in conf, debug=conf.get('debug', '(absent)'),
                               upload=conf.get('upload', '(absent)'))
    else:
        rep['conffile'] = dict(path=CONF, exists=False)
    rt_path = os.path.join(ses['work'], 'state', 'runtime.json')
    rt = json.load(open(rt_path, encoding='utf-8')) if os.path.exists(rt_path) else {}
    alive = False
    if rt.get('pid'):
        try:
            cmd = open('/proc/%d/cmdline' % rt['pid'], 'rb').read().replace(b'\0', b' ').decode()
            alive = 'pr11_demo.py' in cmd and ses['run'] in cmd
        except OSError:
            alive = False
    inst = rep['dpkg']['install_epoch']
    rep['runtime'] = dict(present=bool(rt), alive=alive, build=rt.get('build'), pid=rt.get('pid'),
                          started_utc=utc(rt['started_epoch']) if rt else None,
                          debug_active=rt.get('debug_active'), upload_active=rt.get('upload_active'),
                          restart_required=bool(alive and (rt.get('build') != rep['dpkg']['version'] or
                                                           (inst and rt['started_epoch'] < inst))))
    rep['listen'] = listening(ses['port'])
    base = 'http://%s:%d' % (ses['astra'], ses['port'])
    h_code, server, _ = http_status(base + '/health?rid=%s-%s-local-health' % (ses['run'], a.phase))
    d_code, _, body = http_status(base + '/debug?rid=%s-%s-local-debug' % (ses['run'], a.phase))
    dkeys = []
    if d_code == 200:
        try:
            dkeys = sorted(json.loads(body.decode()).get('config', {}))
        except ValueError:
            dkeys = ['(not json)']
    rep['local_http'] = dict(health=h_code, server_header=server, debug=d_code, debug_config_keys=dkeys)
    running = rt.get('build') if alive else None
    res = []
    for adv in b['advisories']:
        aid = adv['id']
        if aid.endswith('1101'):
            if running in adv['affected_versions'] and rt.get('debug_active'):
                st_, why = 'CONFIRMED', 'running build %s with debug_active; local GET /debug -> %s' % (running, d_code)
            elif running is None:
                st_, why = 'NOT_RUNNING', 'service process not running'
            else:
                st_, why = 'NOT_CONFIRMED', 'running build %s, debug_active=%s, local GET /debug -> %s' % (
                    running, rt.get('debug_active'), d_code)
        elif aid.endswith('1102'):
            c = rep['conffile']
            if c.get('world_readable') and c.get('token_present'):
                st_, why = 'CONFIRMED', 'conffile mode %s readable by others and contains key token' % c['mode']
            elif c.get('exists') is False:
                st_, why = 'NOT_APPLICABLE', 'conffile absent'
            else:
                st_, why = 'NOT_CONFIRMED', 'mode %s, token_present=%s' % (c.get('mode'), c.get('token_present'))
        else:
            if running in adv['affected_versions'] and rt.get('upload_active'):
                st_, why = 'CONFIRMED', 'running build %s with upload_active' % running
            elif running in adv['affected_versions']:
                st_, why = 'NOT_CONFIRMED', 'version %s affected only when upload = on; upload_active=%s, config upload=%s' % (
                    running, rt.get('upload_active'), rep['conffile'].get('upload'))
            else:
                st_, why = 'NOT_APPLICABLE', 'running build %s is not %s' % (running, ','.join(adv['affected_versions']))
        res.append(dict(id=aid, local_status=st_, basis=why))
    rep['findings'] = res
    out_path = os.path.join(ses['work'], 'evidence', 'audit-%s.json' % a.phase)
    write_json(out_path, rep)
    print('dpkg: %s %s | running: %s alive=%s restart_required=%s' % (
        rep['dpkg']['status'], rep['dpkg']['version'] or '-', rep['runtime']['build'], alive, rep['runtime']['restart_required']))
    print('conffile: %s | listen: %s | local /debug -> %s' % (
        {k: rep['conffile'].get(k) for k in ['mode', 'token_present', 'debug', 'upload']}, rep['listen'], d_code))
    for r in res:
        print('%s %-14s %s' % (r['id'], r['local_status'], r['basis']))
    print('saved', out_path)


# ---------------------------------------------------------------- findings table
CONCLUSION = {
    ('CONFIRMED', 'OBSERVED'): 'CONFIRMED',
    ('CONFIRMED', 'POSSIBLE_BY_VERSION'): 'CONFIRMED',
    ('CONFIRMED', 'NOT_FLAGGED'): 'CONFIRMED_LOCALLY_ONLY',
    ('NOT_CONFIRMED', 'POSSIBLE_BY_VERSION'): 'FALSE_POSITIVE_BY_VERSION',
    ('NOT_CONFIRMED', 'OBSERVED'): 'CONTRADICTION_CHECK_AGAIN',
    ('NOT_CONFIRMED', 'NOT_FLAGGED'): 'NOT_DETECTED',
    ('NOT_APPLICABLE', 'NOT_FLAGGED'): 'NOT_APPLICABLE',
    ('NOT_APPLICABLE', 'POSSIBLE_BY_VERSION'): 'FALSE_POSITIVE_BY_VERSION',
}


def table(a):
    ses = load(a.work)
    ev = os.path.join(ses['work'], 'evidence')
    rows = []
    first = {}
    for ph in PHASES:
        kali = os.path.join(ev, 'kali-%s.jsonl' % ph)
        aud = os.path.join(ev, 'audit-%s.json' % ph)
        if not (os.path.exists(kali) and os.path.exists(aud)):
            print('phase %s: missing %s' % (ph, kali if not os.path.exists(kali) else aud))
            continue
        summary = None
        for line in open(kali, encoding='utf-8'):
            r = json.loads(line)
            if r.get('kind') == 'summary':
                summary = r
        if not summary or summary.get('run') != ses['run'] or summary.get('phase') != ph:
            print('phase %s: Kali summary absent or for another run/phase' % ph)
            continue
        remote = dict((f['id'], f) for f in summary['findings'])
        local = json.load(open(aud, encoding='utf-8'))
        for f in local['findings']:
            r = remote.get(f['id'], dict(remote_status='NOT_FLAGGED', basis=''))
            rs = r['remote_status']
            rs_key = 'NOT_FLAGGED' if rs == 'NO_REMOTE_CHECK' else rs
            concl = CONCLUSION.get((f['local_status'], rs_key), 'REVIEW')
            if f['local_status'] == 'NOT_RUNNING':
                concl = 'SERVICE_NOT_RUNNING'
            first.setdefault(f['id'], f['local_status'])
            if ph != 'before' and first[f['id']] == 'CONFIRMED' and f['local_status'] == 'NOT_CONFIRMED':
                concl += '+FIXED_SINCE_BEFORE'
            rows.append(dict(phase=ph, advisory=f['id'], banner=summary.get('banner', ''),
                             installed=local['dpkg']['version'], running=local['runtime']['build'] or '',
                             restart_required=local['runtime']['restart_required'], remote_status=rs,
                             remote_basis=r.get('basis', ''), local_status=f['local_status'],
                             local_basis=f['basis'], conclusion=concl))
    out = os.path.join(ev, 'findings.csv')
    if os.path.exists(out):
        raise SystemExit('refusing to overwrite ' + out)
    with open(out, 'w', encoding='utf-8', newline='') as s:
        w = csv.DictWriter(s, fieldnames=['phase', 'advisory', 'banner', 'installed', 'running', 'restart_required',
                                          'remote_status', 'remote_basis', 'local_status', 'local_basis', 'conclusion'])
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print('%-9s %s banner=%-14s inst=%-5s run=%-5s remote=%-19s local=%-14s -> %s' % (
            r['phase'], r['advisory'], r['banner'], r['installed'], r['running'], r['remote_status'],
            r['local_status'], r['conclusion']))
    print('saved', out)


# ---------------------------------------------------------------- clean check
def clean_check(a):
    ses = load(a.work)
    rc, out, err = run(['dpkg-query', '-W', '-f', '${Status}\n', PKG])
    status = out.strip() or 'not found'
    rt_path = os.path.join(ses['work'], 'state', 'runtime.json')
    alive = False
    if os.path.exists(rt_path):
        pid = json.load(open(rt_path, encoding='utf-8')).get('pid')
        alive = bool(pid) and os.path.exists('/proc/%d' % pid) and b'pr11_demo.py' in open('/proc/%d/cmdline' % pid, 'rb').read()
    rep = dict(run=ses['run'], checked_utc=utc(), dpkg_status=status,
               package_absent=(status == 'not found' or 'not-installed' in status),
               conf_dir_absent=not os.path.exists('/etc/pr11-demo'), repo_absent=not os.path.exists(REPO_ROOT),
               service_process_absent=not alive, port_free=not listening(ses['port']))
    rep['clean'] = all(v for k, v in rep.items() if k.endswith(('_absent', '_free')))
    write_json(os.path.join(ses['work'], 'evidence', 'clean-check.json'), rep)
    for k in sorted(rep):
        print('%s: %s' % (k, rep[k]))
    return 0 if rep['clean'] else 4


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sp = ap.add_subparsers(dest='cmd')
    p = sp.add_parser('init'); p.add_argument('--work', required=True); p.add_argument('--variant', type=int, required=True)
    p.add_argument('--astra'); p.add_argument('--kali')
    p = sp.add_parser('info'); p.add_argument('--work', required=True)
    p.add_argument('--field', required=True, choices=['run', 'port', 'probes', 'group', 'start_version', 'target_version',
                                                      'policy', 'astra', 'kali', 'unit', 'since', 'variant'])
    p = sp.add_parser('repo-verify'); p.add_argument('--repo', required=True); p.add_argument('--suite', required=True)
    p.add_argument('--keyring', default=REPO_ROOT + '/keys/oslab11-archive.gpg'); p.add_argument('--fingerprint')
    p.add_argument('--output')
    p = sp.add_parser('advisory'); p.add_argument('--file', required=True)
    p.add_argument('--keyring', default=REPO_ROOT + '/keys/oslab11-archive.gpg'); p.add_argument('--fingerprint')
    p = sp.add_parser('audit'); p.add_argument('--work', required=True); p.add_argument('--phase', required=True)
    p.add_argument('--advisory', default=REPO_ROOT + '/advisories/OSLAB-2026-11.json')
    p = sp.add_parser('table'); p.add_argument('--work', required=True)
    p = sp.add_parser('clean-check'); p.add_argument('--work', required=True)
    a = ap.parse_args()
    fn = {'init': init, 'info': info, 'repo-verify': repo_verify, 'advisory': advisory, 'audit': audit,
          'table': table, 'clean-check': clean_check}.get(a.cmd)
    if not fn:
        ap.print_help()
        return 2
    return fn(a) or 0


if __name__ == '__main__':
    sys.exit(main())
