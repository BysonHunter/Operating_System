#!/usr/bin/env python3
"""PR13 (Kali): trusted storage of the AIDE baseline outside the controlled host.

Pulls the export of the own Astra over SSH (key, BatchMode, verified known_hosts), keeps read-only
copies by tag, compares the current export with a stored tag, pushes trusted copies back for
restoration and sends the storage log to the Astra evidence. Standard library only.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REMOTE_EXPORT = '/var/lib/pr13-export'


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as s:
        for b in iter(lambda: s.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest()


def ssh_opts(a, scp=False):
    extra = ['-O'] if (scp and a.scp_legacy) else []
    return extra + ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', a.key, '-o', 'UserKnownHostsFile=' + a.known_hosts,
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', '-o', 'LogLevel=ERROR']


def call(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        raise SystemExit('ошибка (%d): %s\n%s' % (p.returncode, ' '.join(cmd), err.decode('utf-8', 'replace').strip()))
    return out.decode('utf-8', 'replace')


def log_path(a):
    return os.path.join(a.vault, 'log.json')


def log_add(a, entry):
    path = log_path(a)
    data = {'entries': []}
    if os.path.exists(path):
        with open(path, encoding='utf-8') as s:
            data = json.load(s)
    entry['time'] = utc()
    data['entries'].append(entry)
    with open(path, 'w', encoding='utf-8') as s:
        json.dump(data, s, indent=2, ensure_ascii=False)


def read_manifest(d):
    res = {}
    with open(os.path.join(d, 'MANIFEST.sha256')) as s:
        for line in s:
            h, name = line.split()
            if '/' in name or name.startswith('.'):
                raise SystemExit('недопустимое имя в манифесте: ' + name)
            res[name] = h
    return res


def fetch(a, dest):
    call(['scp', '-q'] + ssh_opts(a, True) + ['%s@%s:%s/*' % (a.user, a.host, REMOTE_EXPORT), dest + '/'])
    man = read_manifest(dest)
    present = set(os.listdir(dest)) - {'MANIFEST.sha256'}
    if present != set(man):
        raise SystemExit('состав выгрузки не совпадает с манифестом: %s' % sorted(present ^ set(man)))
    got = dict((n, sha256_file(os.path.join(dest, n))) for n in man)
    return man, got


def cmd_trust(a):
    if os.path.exists(a.known_hosts) and not a.replace:
        raise SystemExit('%s уже существует; используйте --replace только после сверки нового отпечатка' % a.known_hosts)
    out = call(['ssh-keyscan', '-t', 'ed25519', a.host])
    lines = [x for x in out.splitlines() if x and not x.startswith('#')]
    if not lines:
        raise SystemExit('ключ ed25519 не получен от %s' % a.host)
    with open(a.known_hosts, 'w') as s:
        s.write('\n'.join(lines) + '\n')
    fp = call(['ssh-keygen', '-lf', a.known_hosts]).strip()
    print(fp)
    print('Сверьте отпечаток с выводом на консоли Astra. При несовпадении удалите %s и остановитесь.' % a.known_hosts)


def cmd_store(a):
    dst = os.path.join(a.vault, a.tag)
    if os.path.exists(dst):
        raise SystemExit('метка %s уже есть в хранилище; эталоны не перезаписываются' % a.tag)
    os.makedirs(a.vault, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='.fetch-', dir=a.vault)
    man, got = fetch(a, tmp)
    bad = [n for n in man if man[n] != got[n]]
    if bad:
        shutil.rmtree(tmp)
        raise SystemExit('контрольные суммы не совпали при получении: %s' % bad)
    os.rename(tmp, dst)
    for n in os.listdir(dst):
        os.chmod(os.path.join(dst, n), 0o444)
    os.chmod(dst, 0o555)
    msha = sha256_file(os.path.join(dst, 'MANIFEST.sha256'))
    for n in sorted(man):
        print('%s  %s' % (man[n], n))
    print('Метка: %s' % a.tag)
    print('MANIFEST SHA256: %s' % msha)
    log_add(a, dict(action='store', tag=a.tag, host=a.host, manifest_sha256=msha, files=man, note=a.note or ''))


def cmd_compare(a):
    ref = os.path.join(a.vault, a.tag)
    rman = read_manifest(ref)
    tmp = tempfile.mkdtemp(prefix='.cmp-', dir=a.vault)
    try:
        man, got = fetch(a, tmp)
    finally:
        shutil.rmtree(tmp)
    rows = []
    for n in sorted(set(rman) | set(got)):
        if n not in got:
            st = 'MISSING'
        elif n not in rman:
            st = 'EXTRA'
        else:
            st = 'MATCH' if rman[n] == got[n] else 'DIFF'
        rows.append(dict(name=n, status=st, stored=rman.get(n), current=got.get(n)))
        print('%-8s %s' % (st, n))
    ok = all(r['status'] == 'MATCH' for r in rows)
    log_add(a, dict(action='compare', tag=a.tag, host=a.host, ok=ok, rows=rows))
    print('Итог: %s' % ('совпадает с эталоном %s' % a.tag if ok else 'ОТЛИЧИЯ от эталона %s' % a.tag))
    sys.exit(0 if ok else 3)


def cmd_push(a):
    ref = os.path.join(a.vault, a.tag)
    man = read_manifest(ref)
    for n, h in man.items():
        if sha256_file(os.path.join(ref, n)) != h:
            raise SystemExit('копия %s в хранилище повреждена' % n)
    target = a.dest.rstrip('/')
    call(['ssh'] + ssh_opts(a) + ['%s@%s' % (a.user, a.host),
                                  'mkdir -p %s && find %s -maxdepth 1 -type f -delete' % (target, target)])
    files = [os.path.join(ref, n) for n in sorted(man)] + [os.path.join(ref, 'MANIFEST.sha256')]
    call(['scp', '-q'] + ssh_opts(a, True) + files + ['%s@%s:%s/' % (a.user, a.host, target)])
    msha = sha256_file(os.path.join(ref, 'MANIFEST.sha256'))
    print('Отправлено в %s@%s:%s' % (a.user, a.host, target))
    print('MANIFEST SHA256: %s' % msha)
    log_add(a, dict(action='push', tag=a.tag, host=a.host, dest=target, manifest_sha256=msha))


def cmd_list(a):
    if not os.path.isdir(a.vault):
        print('хранилище пусто')
        return
    for t in sorted(os.listdir(a.vault)):
        d = os.path.join(a.vault, t)
        if os.path.isdir(d) and not t.startswith('.'):
            print('%-24s %s' % (t, sha256_file(os.path.join(d, 'MANIFEST.sha256'))))


def cmd_report(a):
    log_add(a, dict(action='report', host=a.host, dest=a.dest))
    call(['scp', '-q'] + ssh_opts(a, True) + [log_path(a), '%s@%s:%s' % (a.user, a.host, a.dest)])
    print('Журнал хранилища отправлен: %s@%s:%s' % (a.user, a.host, a.dest))


def main():
    ap = argparse.ArgumentParser(description='PR13: доверенное хранилище эталона (Kali)')
    ap.add_argument('--vault', default=os.path.expanduser('~/pr13/vault'))
    ap.add_argument('--host', required=True)
    ap.add_argument('--user')
    ap.add_argument('--key', default=os.path.expanduser('~/pr13/keys/id_pr13'))
    ap.add_argument('--known-hosts', default=os.path.expanduser('~/pr13/known_hosts'))
    ap.add_argument('--scp-legacy', action='store_true', help='scp -O: старый протокол, если на сервере нет SFTP')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('trust')
    s.add_argument('--replace', action='store_true')
    s = sub.add_parser('store')
    s.add_argument('--tag', required=True)
    s.add_argument('--note')
    s = sub.add_parser('compare')
    s.add_argument('--tag', required=True)
    s = sub.add_parser('push')
    s.add_argument('--tag', required=True)
    s.add_argument('--dest', default='pr13/incoming')
    sub.add_parser('list')
    s = sub.add_parser('report')
    s.add_argument('--dest', default='pr13/evidence/kali-vault.json')
    a = ap.parse_args()
    fn = {'trust': cmd_trust, 'store': cmd_store, 'compare': cmd_compare, 'push': cmd_push, 'list': cmd_list,
          'report': cmd_report}.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    if a.cmd not in ('trust', 'list') and not a.user:
        raise SystemExit('укажите --user: учебная запись на Astra')
    if getattr(a, 'tag', None) and not all(c.isalnum() or c in '._-' for c in a.tag):
        raise SystemExit('метка: только буквы, цифры, точка, дефис и подчёркивание')
    a.vault = os.path.abspath(a.vault)
    fn(a)


if __name__ == '__main__':
    main()
