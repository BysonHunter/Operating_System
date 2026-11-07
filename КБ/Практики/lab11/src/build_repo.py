#!/usr/bin/env python3
"""Rebuild the teaching repositories of practical work 11 (run by the teacher, not by students).

Requires: dpkg-deb, dpkg-scanpackages (dpkg-dev), gpg with the secret keys in GNUPGHOME.
Usage:
  GNUPGHOME=/path/to/keys python3 build_repo.py --key FPR_TRUSTED --hotfix-key FPR_UNTRUSTED --out ../repo
After rebuilding with a new key, update TRUSTED_FPR in tools/pr11.py and the fingerprint in Lab11.md.
The secret keys are not part of the student kit.
"""
import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from email.utils import formatdate

HERE = os.path.dirname(os.path.abspath(__file__))
DATE = 'Sat, 01 Nov 2025 09:00:00 +0000'
MAINT = 'OS Lab Teaching Archive <oslab@example.invalid>'

BUILDS = {
    '1.0-1': dict(upstream='1.0', debug=True, upload=False, suite='orel-lab',
                  conf=('# pr11-demo 1.0 default configuration (teaching)\n'
                        'debug = on\n'
                        'token = OSLAB-DEMO-TOKEN-NOT-A-SECRET\n'),
                  log=[('1.0-1', 'Initial teaching release 1.0. Diagnostic endpoint /debug enabled by default.')]),
    '1.0-2': dict(upstream='1.0', debug=False, upload=False, suite='orel-lab',
                  conf=('# pr11-demo 1.0 default configuration (teaching)\n'
                        '# OSLAB-2026-1101/1102: debug endpoint removed, no token in configuration\n'),
                  log=[('1.0-2', 'Security backport for OSLAB-2026-1101 and OSLAB-2026-1102:\n'
                                 '    remove /debug endpoint; remove token from the default configuration.\n'
                                 '    Upstream version and Server header stay 1.0.'),
                       ('1.0-1', 'Initial teaching release 1.0. Diagnostic endpoint /debug enabled by default.')]),
    '1.1-1': dict(upstream='1.1', debug=False, upload=True, suite='orel-lab',
                  conf=('# pr11-demo 1.1 default configuration (teaching)\n'
                        '# optional file upload feature; see OSLAB-2026-1104\n'
                        'upload = off\n'),
                  log=[('1.1-1', 'New upstream release 1.1: /debug removed (OSLAB-2026-1101),\n'
                                 '    no token in configuration (OSLAB-2026-1102),\n'
                                 '    new optional upload feature, disabled by default.'),
                       ('1.0-1', 'Initial teaching release 1.0. Diagnostic endpoint /debug enabled by default.')]),
    '9.9-1': dict(upstream='9.9', debug=False, upload=False, suite='orel-hotfix',
                  conf='# pr11-demo hotfix from an unknown source\n',
                  log=[('9.9-1', 'Urgent hotfix. Install immediately.')]),
}


def sh(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def build_deb(version, b, pool):
    root = tempfile.mkdtemp()
    try:
        tpl = open(os.path.join(HERE, 'pr11_demo.py.in'), encoding='utf-8').read()
        code = (tpl.replace('@UPSTREAM@', b['upstream']).replace('@BUILD@', version)
                .replace('@HAS_DEBUG@', str(b['debug'])).replace('@HAS_UPLOAD@', str(b['upload'])))
        files = {
            'usr/lib/pr11-demo/pr11_demo.py': (code, 0o755),
            'etc/pr11-demo/pr11-demo.conf': (b['conf'], 0o644),
            'usr/share/doc/pr11-demo/copyright': ('Teaching package for the course "Operating systems".\n'
                                                  'Not a real product. No warranty.\n', 0o644),
        }
        for rel, (text, mode) in files.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'w', encoding='utf-8') as s:
                s.write(text)
            os.chmod(p, mode)
        log = ''
        for ver, text in b['log']:
            log += ('pr11-demo (%s) %s; urgency=medium\n\n  * %s\n\n -- %s  %s\n\n'
                    % (ver, b['suite'], text, MAINT, DATE))
        cl = os.path.join(root, 'usr/share/doc/pr11-demo/changelog.Debian.gz')
        with gzip.GzipFile(cl, 'wb', mtime=0) as s:
            s.write(log.encode())
        os.chmod(cl, 0o644)
        for d, _, fs in os.walk(root):
            os.chmod(d, 0o755)
        size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(root) for f in fs)
        os.makedirs(os.path.join(root, 'DEBIAN'))
        ctl = ('Package: pr11-demo\nVersion: %s\nArchitecture: all\nMaintainer: %s\nInstalled-Size: %d\n'
               'Depends: python3 (>= 3.5)\nSection: misc\nPriority: optional\n'
               'Description: teaching HTTP service for OS practical work 11\n'
               ' Bounded service with artificial findings OSLAB-2026-11xx. Not a real product.\n'
               % (version, MAINT, max(1, size // 1024)))
        open(os.path.join(root, 'DEBIAN/control'), 'w').write(ctl)
        open(os.path.join(root, 'DEBIAN/conffiles'), 'w').write('/etc/pr11-demo/pr11-demo.conf\n')
        md5 = ''
        for d, _, fs in sorted(os.walk(root)):
            for f in sorted(fs):
                p = os.path.join(d, f)
                rel = os.path.relpath(p, root)
                if rel.startswith('DEBIAN') or rel.startswith('etc/'):
                    continue
                md5 += '%s  %s\n' % (hashlib.md5(open(p, 'rb').read()).hexdigest(), rel)
        open(os.path.join(root, 'DEBIAN/md5sums'), 'w').write(md5)
        for f in os.listdir(os.path.join(root, 'DEBIAN')):
            os.chmod(os.path.join(root, 'DEBIAN', f), 0o644)
        os.makedirs(pool, exist_ok=True)
        out = os.path.join(pool, 'pr11-demo_%s_all.deb' % version)
        env = dict(os.environ, SOURCE_DATE_EPOCH='1761987600')
        sh('dpkg-deb', '--root-owner-group', '-Zgzip', '--build', root, out, env=env, stdout=subprocess.DEVNULL)
        return out
    finally:
        shutil.rmtree(root)


def release(dist_dir, suite, label):
    entries = []
    for rel in ['main/binary-amd64/Packages', 'main/binary-amd64/Packages.gz']:
        data = open(os.path.join(dist_dir, rel), 'rb').read()
        entries.append((rel, len(data), hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()))
    text = ('Origin: OS Lab\nLabel: %s\nSuite: %s\nCodename: %s\nDate: %s\nArchitectures: amd64\n'
            'Components: main\nDescription: teaching repository of practical work 11\n' % (label, suite, suite, DATE))
    text += 'MD5Sum:\n' + ''.join(' %s %8d %s\n' % (m, n, r) for r, n, m, s in entries)
    text += 'SHA256:\n' + ''.join(' %s %8d %s\n' % (s, n, r) for r, n, m, s in entries)
    open(os.path.join(dist_dir, 'Release'), 'w').write(text)


def sign(path_in, key, clear_out=None, detached_out=None):
    base = ['gpg', '--batch', '--yes', '--quiet', '--local-user', key, '--digest-algo', 'SHA256']
    if clear_out:
        sh(*(base + ['--clearsign', '--output', clear_out, path_in]))
    if detached_out:
        sh(*(base + ['--armor', '--detach-sign', '--output', detached_out, path_in]))


def repo(out, name, suite, label, versions, key):
    top = os.path.join(out, name)
    pool = os.path.join(top, 'pool/main/p/pr11-demo')
    for v in versions:
        build_deb(v, BUILDS[v], pool)
    dist = os.path.join(top, 'dists', suite)
    bdir = os.path.join(dist, 'main/binary-amd64')
    os.makedirs(bdir, exist_ok=True)
    pk = subprocess.run(['dpkg-scanpackages', '--multiversion', 'pool', '/dev/null'], cwd=top, check=True,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    open(os.path.join(bdir, 'Packages'), 'wb').write(pk)
    with gzip.GzipFile(os.path.join(bdir, 'Packages.gz'), 'wb', mtime=0) as s:
        s.write(pk)
    release(dist, suite, label)
    sign(os.path.join(dist, 'Release'), key, os.path.join(dist, 'InRelease'), os.path.join(dist, 'Release.gpg'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', required=True)
    ap.add_argument('--hotfix-key', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    if os.path.exists(out):
        raise SystemExit('output exists: ' + out)
    os.makedirs(os.path.join(out, 'keys'))
    repo(out, 'orel-lab', 'orel-lab', 'OS Lab trusted', ['1.0-1', '1.0-2', '1.1-1'], a.key)
    repo(out, 'untrusted', 'orel-hotfix', 'Unknown hotfix', ['9.9-1'], a.hotfix_key)
    kr = subprocess.run(['gpg', '--batch', '--export', a.key], check=True, stdout=subprocess.PIPE).stdout
    open(os.path.join(out, 'keys/oslab11-archive.gpg'), 'wb').write(kr)
    open(os.path.join(out, 'keys/FINGERPRINT.txt'), 'w').write(a.key + '\n')
    adv_dir = os.path.join(out, 'advisories')
    os.makedirs(adv_dir)
    shutil.copy(os.path.join(HERE, 'OSLAB-2026-11.json'), adv_dir)
    sign(os.path.join(adv_dir, 'OSLAB-2026-11.json'), a.key, detached_out=os.path.join(adv_dir, 'OSLAB-2026-11.json.asc'))
    print('built', out)


if __name__ == '__main__':
    main()
