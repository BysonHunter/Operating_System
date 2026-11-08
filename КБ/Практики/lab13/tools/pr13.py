#!/usr/bin/env python3
"""PR13 (Astra): test objects, AIDE policy check, export of the baseline, training event,
staging of trusted copies, classification, reveal and clean check.

Standard library only, Python 3.5 syntax. Commands that touch system objects are run with sudo
from the ordinary training account: the account becomes the operator of the session.
"""
import argparse
import csv
import datetime
import grp
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

STATE = '/var/lib/pr13'
AIDE_DIR = STATE + '/aide'
TRUSTED = STATE + '/trusted'
QUAR = STATE + '/quarantine'
EXPORT = '/var/lib/pr13-export'
SRV = '/srv/pr13'
PKG = 'pr13-agent'
LIB = '/usr/lib/pr13-agent'
ETC = '/etc/pr13-agent'
CONFFILE = ETC + '/agent.conf'
CRIT_ALL = ['/etc/passwd', '/etc/group', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
            '/etc/crontab', '/etc/hosts', '/etc/fstab']
EPOCH = 1793491200  # 2026-11-01T00:00:00Z, fixed mtime of the trusted objects
VERDICTS = ('authorized', 'unauthorized', 'normal')


# ------------------------------------------------------------------ helpers
def utc(t=None):
    t = time.time() if t is None else t
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as s:
        for b in iter(lambda: s.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def run(cmd, check=False):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    out = out.decode('utf-8', 'replace')
    err = err.decode('utf-8', 'replace')
    if check and p.returncode != 0:
        raise SystemExit('ошибка команды %s (rc=%d): %s' % (' '.join(cmd), p.returncode, err.strip()[:400]))
    return p.returncode, out, err


def need_root():
    if os.geteuid() != 0:
        raise SystemExit('эта команда выполняется через sudo')


def operator():
    uid = os.environ.get('SUDO_UID')
    if not uid or uid == '0':
        raise SystemExit('запустите команду через sudo из обычной учебной записи (SUDO_UID не задан)')
    pw = pwd.getpwuid(int(uid))
    return dict(uid=pw.pw_uid, gid=pw.pw_gid, name=pw.pw_name, home=pw.pw_dir)


def give(path, op):
    os.chown(path, op['uid'], op['gid'])


def variant_params(v):
    kind = ('interval', 'log_level', 'upload_host')[(v - 1) % 3]
    old = {'interval': '60', 'log_level': 'info', 'upload_host': '10.50.%d.30' % v}
    if kind == 'interval':
        new = str(15 + 5 * (((v - 1) // 3) % 9))
    elif kind == 'log_level':
        new = ('debug', 'warning')[((v - 1) // 3) % 2]
    else:
        new = '10.50.%d.%d' % (v, 31 + (v - 1) % 5)
    start = (v - 1) % len(CRIT_ALL)
    order = CRIT_ALL[start:] + CRIT_ALL[:start]
    return dict(variant=v, astra='10.50.%d.10' % v, kali='10.50.%d.20' % v, ticket='CHG-13-%02d' % v,
                ticket_key=kind, ticket_old=old[kind], ticket_new=new, defaults=old, critical_order=order)


def ticket_text(p):
    return ('Заявка %s: в %s изменить параметр %s с %s на %s. Иные изменения объектов '
            'контроля заявкой не разрешены.' % (p['ticket'], CONFFILE, p['ticket_key'], p['ticket_old'], p['ticket_new']))


def load_state():
    path = STATE + '/state.json'
    if not os.path.exists(path):
        raise SystemExit('сессия не инициализирована: sudo python3 pr13.py init ...')
    with open(path, encoding='utf-8') as s:
        return json.load(s)


def save_state(st):
    path = STATE + '/state.json'
    with open(path + '.tmp', 'w', encoding='utf-8') as s:
        json.dump(st, s, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o600)
    os.rename(path + '.tmp', path)


def load_session(work):
    with open(os.path.join(os.path.abspath(work), 'session.json'), encoding='utf-8') as s:
        return json.load(s)


def evidence(work, name, obj, op=None):
    d = os.path.join(os.path.abspath(work), 'evidence')
    if not os.path.isdir(d):
        os.makedirs(d)
        if op:
            give(d, op)
    path = os.path.join(d, name)
    with open(path, 'w', encoding='utf-8') as s:
        json.dump(obj, s, indent=2, sort_keys=True, ensure_ascii=False)
        s.write('\n')
    if op:
        give(path, op)
    return path


def next_name(work, prefix):
    d = os.path.join(os.path.abspath(work), 'evidence')
    n = 1
    while os.path.exists(os.path.join(d, '%s-%d.json' % (prefix, n))):
        n += 1
    return '%s-%d.json' % (prefix, n)


def file_meta(path):
    st = os.lstat(path)
    m = dict(path=path, mode='%04o' % stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
             size=st.st_size, inode=st.st_ino, mtime=utc(st.st_mtime), ctime=utc(st.st_ctime))
    if stat.S_ISREG(st.st_mode):
        m['sha256'] = sha256_file(path)
    return m


# ------------------------------------------------------------------ trusted objects
def trusted_files(v, p):
    nn = '%02d' % v
    agent = ('#!/bin/sh\n'
             '# pr13-agent: training status agent, variant %s\n'
             '. /usr/lib/pr13-agent/functions.sh\n'
             'CONF=/etc/pr13-agent/agent.conf\n'
             'ALLOW_REMOTE_DEBUG=no \n'
             'pr13_status "$CONF"\n') % nn
    func = ('# helper functions of pr13-agent, variant %s\n'
            'pr13_status() {\n'
            '    printf \'pr13-agent v%%s: config %%s\\n\' "%s" "$1"\n'
            '}\n') % (nn, nn)
    d = p['defaults']
    conf = ('# pr13-agent configuration, package pr13-agent 1.0-v%s\n'
            'interval=%s\nlog_level=%s\nupload_host=%s\nreport_dir=/srv/pr13/log\n') % (
        nn, d['interval'], d['log_level'], d['upload_host'])
    allow = ('# hosts allowed to read reports, variant %s\n10.50.%d.10\n10.50.%d.20\n') % (nn, v, v)
    accounts = ('login,role,department\nsvc_report,service,it\nivanova,analyst,security\n'
                'petrov,operator,it\nsidorova,auditor,audit\n# variant %s\n') % nn
    pkgfiles = [(LIB + '/agent.sh', agent, 0o755), (LIB + '/functions.sh', func, 0o644),
                (CONFFILE, conf, 0o644)]
    srvfiles = [(SRV + '/policy/allowlist.txt', allow, 0o640, 'root', 'root'),
                (SRV + '/data/accounts.csv', accounts, 0o640, 'root', 'root')]
    return pkgfiles, srvfiles


def build_package(v, p, workdir):
    nn = '%02d' % v
    tree = os.path.join(workdir, 'tree')
    pkgfiles, _ = trusted_files(v, p)
    md5 = []
    for path, text, mode in pkgfiles:
        dst = tree + path
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'w', encoding='utf-8') as s:
            s.write(text)
        os.chmod(dst, mode)
        os.utime(dst, (EPOCH, EPOCH))
        if path != CONFFILE:
            md5.append('%s  %s\n' % (hashlib.md5(text.encode('utf-8')).hexdigest(), path.lstrip('/')))
    for root, dirs, _ in os.walk(tree):
        for dd in dirs:
            os.chmod(os.path.join(root, dd), 0o755)
    deb = os.path.join(tree, 'DEBIAN')
    os.makedirs(deb, exist_ok=True)
    os.chmod(deb, 0o755)
    control = ('Package: %s\nVersion: 1.0-v%s\nArchitecture: all\nMaintainer: OS course lab <oslab@localhost.invalid>\n'
               'Section: misc\nPriority: optional\nDescription: training agent for practical work 13\n'
               ' Variant %s. The files are test objects of integrity control.\n') % (PKG, nn, nn)
    for name, text in (('control', control), ('conffiles', CONFFILE + '\n'), ('md5sums', ''.join(sorted(md5)))):
        with open(os.path.join(deb, name), 'w', encoding='utf-8') as s:
            s.write(text)
        os.chmod(os.path.join(deb, name), 0o644)
    out = os.path.join(workdir, '%s_1.0-v%s_all.deb' % (PKG, nn))
    run(['dpkg-deb', '-Zgzip', '--build', tree, out], check=True)
    return out


def make_backup(path):
    with tarfile.open(path, 'w', format=tarfile.GNU_FORMAT) as t:
        for sub in ('policy', 'data'):
            t.add(SRV + '/' + sub, arcname='srv/pr13/' + sub, recursive=True)
    os.chmod(path, 0o600)


def deb_members(debpath):
    """Return {path: (sha256, mode)} for regular files in the data part of a .deb."""
    p = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', debpath], stdout=subprocess.PIPE)
    data, _ = p.communicate()
    if p.returncode != 0:
        raise SystemExit('dpkg-deb --fsys-tarfile завершился с ошибкой')
    res = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            if m.isfile():
                res['/' + m.name.lstrip('./')] = (sha256_bytes(t.extractfile(m).read()), m.mode & 0o7777)
    return res


def tar_members(path):
    res = {}
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if m.isfile():
                res['/' + m.name] = (sha256_bytes(t.extractfile(m).read()), m.mode & 0o7777, m.uname, m.gname)
    return res


# ------------------------------------------------------------------ AIDE configuration
OPTIONS = {'database', 'database_in', 'database_out', 'database_new', 'report_url', 'gzip_dbout', 'verbose',
           'warn_dead_symlinks', 'grouped', 'summarize_changes', 'acl_no_symlink_follow', 'database_attrs',
           'report_detailed_init', 'report_base16', 'report_quiet', 'root_prefix', 'report_level',
           'report_format', 'log_level', 'num_workers', 'report_ignore_e2fsattrs', 'config_version',
           'report_force_attrs', 'report_ignore_added_attrs', 'report_ignore_removed_attrs',
           'report_ignore_changed_attrs', 'report_append', 'report_grouped', 'report_summarize_changes',
           'database_add_metadata', 'report_detailed_init', 'config_check_warn_unrestricted_rules'}
ATTRS = {'p', 'i', 'n', 'u', 'g', 's', 'b', 'm', 'a', 'c', 'S', 'I', 'l', 'md5', 'sha1', 'sha256', 'sha512',
         'rmd160', 'tiger', 'haval', 'gost', 'crc32', 'whirlpool', 'acl', 'xattrs', 'selinux', 'e2fsattrs',
         'ftype', 'caps', 'stribog256', 'stribog512', 'sha512_256', 'sha3_256', 'sha3_512', 'H', 'X'}
BUILTIN = {'R': 'p+i+n+u+g+s+m+c+acl+selinux+xattrs+md5', 'L': 'p+i+n+u+g+acl+selinux+xattrs',
           '>': 'p+u+g+i+n+S+acl+selinux+xattrs', 'E': '', 'X': ''}
STRONG = {'sha256', 'sha512', 'sha512_256', 'sha3_256', 'sha3_512', 'stribog256', 'stribog512'}
CONTENT = {'s', 'b', 'm', 'c', 'a', 'md5', 'sha1', 'rmd160', 'tiger', 'haval', 'gost', 'crc32', 'whirlpool'} | STRONG


def expand(expr, groups, depth=0):
    if depth > 10:
        raise ValueError('слишком глубокая вложенность групп')
    res = set()
    expr = expr.strip()
    if not expr:
        return res
    for sign, tok in re.findall(r'([+-]?)\s*([A-Za-z0-9_>]+)', expr):
        if tok in groups:
            val = expand(groups[tok], groups, depth + 1)
        elif tok in BUILTIN:
            val = expand(BUILTIN[tok], groups, depth + 1)
        elif tok in ATTRS:
            val = {tok}
        else:
            raise ValueError('неизвестный атрибут или группа: %s' % tok)
        if sign == '-':
            res -= val
        else:
            res |= val
    return res


def parse_aide(path):
    text = open(path, encoding='utf-8').read()
    defines = {}
    opts, groups, rules, errors = {}, {}, [], []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'@@define\s+(\w+)\s+(.*)$', line)
        if m:
            defines[m.group(1)] = m.group(2).strip()
            continue
        if line.startswith('@@'):
            continue
        line = re.sub(r'@@\{(\w+)\}', lambda x: defines.get(x.group(1), ''), line)
        m = re.match(r'^([=!]?)(/\S*)\s*(.*)$', line)
        if m:
            rules.append(dict(line=no, type=m.group(1) or '+', pattern=m.group(2), expr=m.group(3).strip()))
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key in OPTIONS:
                opts[key] = val
            else:
                groups[key] = val
            continue
        errors.append('строка %d не разобрана: %s' % (no, raw))
    for r in rules:
        if r['type'] != '!':
            try:
                r['attrs'] = sorted(expand(r['expr'], groups))
            except ValueError as e:
                errors.append('строка %d: %s' % (r['line'], e))
                r['attrs'] = []
    return dict(options=opts, groups=groups, rules=rules, errors=errors)


def literal_len(pattern):
    n = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == '\\' and i + 1 < len(pattern):
            n += 1
            i += 2
            continue
        if ch in '*+?[](){}|^$':
            break
        n += 1
        i += 1
    return n


def rule_matches(r, path):
    pat = r['pattern']
    try:
        if r['type'] == '=':
            return re.match('(?:%s)/?$' % pat, path) is not None
        return re.match(pat, path) is not None
    except re.error:
        return False


def applicable(cfg, path):
    """AIDE-like decision: a matching negative rule excludes; otherwise the most specific positive rule."""
    for r in cfg['rules']:
        if r['type'] == '!' and rule_matches(r, path):
            return None, r
    best = None
    for r in cfg['rules']:
        if r['type'] != '!' and rule_matches(r, path):
            if best is None or literal_len(r['pattern']) >= literal_len(best['pattern']):
                best = r
    return best, None


def db_path(cfg, key):
    v = cfg['options'].get(key)
    if v is None and key == 'database':
        v = cfg['options'].get('database_in')
    if v is None:
        return None
    return v[5:] if v.startswith('file:') else v


# ------------------------------------------------------------------ commands
def cmd_init(a):
    need_root()
    op = operator()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('вариант должен быть от 1 до 27')
    if os.path.exists(STATE) or os.path.exists(SRV):
        raise SystemExit('объекты ПР13 уже существуют; вернитесь к снимку или выполните cleanup --yes')
    for c in ('aide', 'dpkg-deb', 'dpkg'):
        if not shutil.which(c):
            raise SystemExit('нет программы %s: см. раздел 2.2' % c)
    work = os.path.abspath(a.work)
    for d in (work, os.path.join(work, 'evidence'), os.path.join(work, 'incoming')):
        if not os.path.isdir(d):
            os.makedirs(d)
        give(d, op)
    p = variant_params(v)
    crit = [x for x in p['critical_order'] if os.path.isfile(x)][:3]
    if len(crit) < 3:
        raise SystemExit('не найдено трёх критичных файлов из списка %s' % CRIT_ALL)
    adm = 'adm'
    try:
        adm_gid = grp.getgrnam(adm).gr_gid
    except KeyError:
        adm_gid = 0
    for d in (STATE, AIDE_DIR, STATE + '/pkg', STATE + '/backup', QUAR):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    os.makedirs(EXPORT, exist_ok=True)
    os.chown(EXPORT, 0, op['gid'])
    os.chmod(EXPORT, 0o750)
    # package
    build = tempfile.mkdtemp(prefix='build-', dir=STATE)
    debtmp = build_package(v, p, build)
    deb = os.path.join(STATE, 'pkg', os.path.basename(debtmp))
    shutil.copy2(debtmp, deb)
    shutil.rmtree(build)
    rc, out, err = run(['dpkg', '-i', deb])
    if rc != 0:
        raise SystemExit('dpkg -i не выполнен: ' + (err or out)[-600:])
    # non-package objects
    _, srvfiles = trusted_files(v, p)
    for d, mode in ((SRV, 0o755), (SRV + '/policy', 0o750), (SRV + '/data', 0o750), (SRV + '/log', 0o750),
                    (SRV + '/tmp', 0o750)):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, mode)
    for path, text, mode, _u, _g in srvfiles:
        with open(path, 'w', encoding='utf-8') as s:
            s.write(text)
        os.chmod(path, mode)
        os.chown(path, 0, 0)
        os.utime(path, (EPOCH, EPOCH))
    log = SRV + '/log/agent.log'
    with open(log, 'w', encoding='utf-8') as s:
        s.write('%s pr13-agent v%02d started\n' % (utc(), v))
    os.chmod(log, 0o640)
    os.chown(log, 0, adm_gid)
    with open(SRV + '/tmp/cache-0001.tmp', 'w') as s:
        s.write('cache\n')
    backup = STATE + '/backup/srv-pr13.tar'
    make_backup(backup)
    nonce = os.urandom(16).hex()
    h = hashlib.sha256((nonce + str(v)).encode()).digest()
    st = dict(variant=v, operator=op, work=work, nonce=nonce, created=utc(), critical=crit,
              drill=dict(pkg=('stealth', 'mode', 'newfile')[h[0] % 3], srv=('append', 'owner')[h[1] % 2]),
              deb=deb, backup=backup, exports=[], conf=None, drill_done=None, stages=[], revealed=None)
    save_state(st)
    ses = dict(variant=v, astra=p['astra'], kali=p['kali'], ticket=p['ticket'], ticket_key=p['ticket_key'],
               ticket_old=p['ticket_old'], ticket_new=p['ticket_new'], ticket_text=ticket_text(p),
               critical=crit, critical_list=' '.join(crit), conffile=CONFFILE, lib=LIB, srv=SRV,
               aide_dir=AIDE_DIR, export=EXPORT, trusted=TRUSTED, quarantine=QUAR, package=PKG,
               deb_name=os.path.basename(deb), work=work, created=st['created'])
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True, ensure_ascii=False)
    give(os.path.join(work, 'session.json'), op)
    rc, aver, aerr = run(['aide', '--version'])
    objs = [file_meta(x) for x in (LIB + '/agent.sh', LIB + '/functions.sh', CONFFILE, SRV + '/policy/allowlist.txt',
                                   SRV + '/data/accounts.csv', log)]
    evidence(work, 'init.json', dict(session=ses, aide_version=(aver + aerr).strip().splitlines()[:1],
                                     dpkg_status=run(['dpkg-query', '-W', '-f=${Package} ${Version} ${Status}', PKG])[1],
                                     deb_sha256=sha256_file(deb), backup_sha256=sha256_file(backup), objects=objs), op)
    print('Вариант %02d: объекты ПР13 созданы, пакет %s установлен.' % (v, os.path.basename(deb)))
    print(ses['ticket_text'])
    print('Критичные системные файлы варианта (только чтение): ' + ses['critical_list'])


def cmd_info(a):
    ses = load_session(a.work)
    if a.field:
        val = ses[a.field]
        print(' '.join(val) if isinstance(val, list) else val)
    else:
        print(json.dumps(ses, indent=2, sort_keys=True, ensure_ascii=False))


def check_policy(conf, st):
    cfg = parse_aide(conf)
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))

    rc, out, err = run(['aide', '--config=' + conf, '--config-check'])
    add('config-check', rc == 0 and not cfg['errors'],
        'aide --config-check rc=%d %s %s' % (rc, (out + err).strip()[:300], '; '.join(cfg['errors'])))
    dbin, dbout = db_path(cfg, 'database'), db_path(cfg, 'database_out')
    add('database', bool(dbin and dbout and dbin != dbout and dbin.startswith(AIDE_DIR + '/') and dbout.startswith(AIDE_DIR + '/')),
        'database=%s database_out=%s (оба в %s, разные)' % (dbin, dbout, AIDE_DIR))
    whole = [r['pattern'] for r in cfg['rules'] if r['type'] != '!' and r['pattern'] in ('/', '/.*', '/etc', '/usr', '/srv', '/var')]
    add('scope', not whole, 'слишком широкие правила: %s' % (whole or 'нет'))
    groups = [('BIN', [LIB, LIB + '/agent.sh', LIB + '/functions.sh', LIB + '/new-file-probe'], {'p', 'u', 'g', 's', 'c'}, True),
              ('CONF', [CONFFILE, SRV + '/policy/allowlist.txt', SRV + '/data/accounts.csv'] + st['critical'],
               {'p', 'u', 'g'}, True)]
    for cat, paths, need, strong in groups:
        for path in paths:
            r, neg = applicable(cfg, path)
            attrs = set(r['attrs']) if r else set()
            miss = sorted(need - attrs)
            hasstrong = bool(attrs & STRONG)
            add('%s %s' % (cat, path), r is not None and not miss and (hasstrong or not strong),
                'правило: %s; не хватает: %s; стойкий хеш: %s' % (
                    ('строка %d %s %s' % (r['line'], r['pattern'], r['expr'])) if r else ('исключено' if neg else 'не покрыто'),
                    ','.join(miss) or '—', 'да' if hasstrong else 'нет'))
    r, neg = applicable(cfg, SRV + '/log/agent.log')
    attrs = set(r['attrs']) if r else set()
    bad = sorted(attrs & CONTENT)
    add('LOG %s/log/agent.log' % SRV, r is not None and {'p', 'u', 'g'} <= attrs and not bad,
        'правило: %s; лишние для растущего файла: %s' % (('строка %d %s %s' % (r['line'], r['pattern'], r['expr'])) if r else 'не покрыто',
                                                     ','.join(bad) or '—'))
    for path in (SRV + '/tmp', SRV + '/tmp/cache-0001.tmp'):
        r, neg = applicable(cfg, path)
        add('EXCL %s' % path, r is None, 'исключено' if r is None else 'покрыто строкой %d' % r['line'])
    for path in (AIDE_DIR + '/aide.db', EXPORT + '/aide.db'):
        r, neg = applicable(cfg, path)
        add('EXCL %s' % path, r is None, 'база не входит в объект контроля' if r is None else 'покрыто строкой %d' % r['line'])
    return cfg, checks


def cmd_policy_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    conf = os.path.abspath(a.conf)
    cfg, checks = check_policy(conf, st)
    ok = all(c['ok'] for c in checks)
    for c in checks:
        print('%-4s %-48s %s' % ('OK' if c['ok'] else 'FAIL', c['id'], c['detail']))
    shutil.copy2(conf, os.path.join(st['work'], 'evidence', 'aide.conf'))
    give(os.path.join(st['work'], 'evidence', 'aide.conf'), op)
    evidence(st['work'], 'policy-check.json', dict(time=utc(), conf=conf, conf_sha256=sha256_file(conf), ok=ok,
                                                   checks=checks, rules=cfg['rules']), op)
    if ok:
        st['conf'] = conf
        save_state(st)
        print('Политика принята и зарегистрирована: %s' % conf)
    else:
        print('Политика не принята: исправьте строки FAIL и повторите проверку.')
        sys.exit(2)


def registered(st):
    if not st.get('conf') or not os.path.exists(st['conf']):
        raise SystemExit('нет принятой политики: выполните policy-check')
    cfg = parse_aide(st['conf'])
    return cfg, db_path(cfg, 'database'), db_path(cfg, 'database_out')


def cmd_export(a):
    need_root()
    st = load_state()
    op = st['operator']
    cfg, db, dbout = registered(st)
    if not os.path.exists(db):
        raise SystemExit('нет базы %s: выполните aide --init и переименуйте aide.db.new' % db)
    for name in os.listdir(EXPORT):
        os.unlink(os.path.join(EXPORT, name))
    items = [('aide.db', db), ('aide.conf', st['conf']), (os.path.basename(st['deb']), st['deb']),
             ('srv-pr13.tar', st['backup'])]
    lines = []
    for name, src in items:
        dst = os.path.join(EXPORT, name)
        shutil.copyfile(src, dst)
        os.chown(dst, 0, op['gid'])
        os.chmod(dst, 0o640)
        lines.append('%s  %s\n' % (sha256_file(dst), name))
    man = os.path.join(EXPORT, 'MANIFEST.sha256')
    with open(man, 'w') as s:
        s.write(''.join(sorted(lines, key=lambda x: x.split()[1])))
    os.chown(man, 0, op['gid'])
    os.chmod(man, 0o640)
    msha = sha256_file(man)
    rec = dict(time=utc(), epoch=time.time(), manifest_sha256=msha, db_sha256=sha256_file(db), note=a.note or '')
    st['exports'].append(rec)
    save_state(st)
    evidence(st['work'], next_name(st['work'], 'export'), dict(rec, manifest=open(man).read().splitlines()), op)
    print(open(man).read().rstrip())
    print('MANIFEST SHA256: %s' % msha)


def ticket_state(st):
    p = variant_params(st['variant'])
    pkgfiles, _ = trusted_files(st['variant'], p)
    want = [x for x in pkgfiles if x[0] == CONFFILE][0][1]
    want = want.replace('%s=%s\n' % (p['ticket_key'], p['ticket_old']), '%s=%s\n' % (p['ticket_key'], p['ticket_new']))
    cur = open(CONFFILE, encoding='utf-8').read()
    return cur == want, p


def cmd_drill(a):
    need_root()
    st = load_state()
    op = st['operator']
    if st.get('drill_done'):
        raise SystemExit('учебное событие уже выполнено в %s' % st['drill_done'])
    cfg, db, dbout = registered(st)
    if not os.path.exists(db) or not st['exports']:
        raise SystemExit('сначала создайте эталон и выполните export (шаг 3)')
    ok, p = ticket_state(st)
    if not ok:
        raise SystemExit('файл %s не соответствует заявке %s: выполните ровно разрешённое изменение (шаг 4)' % (CONFFILE, p['ticket']))
    v = st['variant']
    # ordinary activity of the service
    with open(SRV + '/log/agent.log', 'a', encoding='utf-8') as s:
        s.write('%s pr13-agent v%02d report sent\n%s pr13-agent v%02d interval tick\n' % (utc(), v, utc(), v))
    for name in os.listdir(SRV + '/tmp'):
        os.unlink(os.path.join(SRV + '/tmp', name))
    with open(SRV + '/tmp/cache-0002.tmp', 'w') as s:
        s.write('cache %s\n' % utc())
    # unannounced changes
    k = st['drill']['pkg']
    if k == 'stealth':
        path = LIB + '/agent.sh'
        s0 = os.stat(path)
        data = open(path, 'rb').read().replace(b'ALLOW_REMOTE_DEBUG=no ', b'ALLOW_REMOTE_DEBUG=yes')
        with open(path, 'r+b') as s:
            s.write(data)
        os.utime(path, (s0.st_atime, s0.st_mtime))
    elif k == 'mode':
        os.chmod(LIB + '/functions.sh', 0o666)
    else:
        path = LIB + '/hook.sh'
        with open(path, 'w') as s:
            s.write('#!/bin/sh\n# unexpected hook\nexit 0\n')
        os.chmod(path, 0o755)
        m = os.stat(LIB + '/agent.sh').st_mtime
        os.utime(path, (m, m))
    k = st['drill']['srv']
    if k == 'append':
        path = SRV + '/policy/allowlist.txt'
        s0 = os.stat(path)
        with open(path, 'a') as s:
            s.write('10.50.%d.66\n' % v)
        os.utime(path, (s0.st_atime, s0.st_mtime))
    else:
        try:
            uid = pwd.getpwnam('nobody').pw_uid
        except KeyError:
            uid = 65534
        try:
            gid = grp.getgrnam('nogroup').gr_gid
        except KeyError:
            gid = 65534
        os.chown(SRV + '/data/accounts.csv', uid, gid)
    # the intruder rebuilds the local baseline to hide the changes
    rc, out, err = run(['aide', '--config=' + st['conf'], '--init'])
    if rc != 0 or not os.path.exists(dbout):
        raise SystemExit('служебная ошибка учения (aide --init rc=%d)' % rc)
    os.rename(dbout, db)
    st['drill_done'] = utc()
    st['drill_epoch'] = time.time()
    save_state(st)
    evidence(st['work'], 'drill.json', dict(time=st['drill_done'], message='учебное событие выполнено'), op)
    print('Учебное событие выполнено в %s. Что изменено, не сообщается: найдите это сами.' % st['drill_done'])


def cmd_stage(a):
    need_root()
    st = load_state()
    op = st['operator']
    src = os.path.abspath(a.src)
    man = os.path.join(src, 'MANIFEST.sha256')
    exp = a.expect.strip().lower()
    if not re.match(r'^[0-9a-f]{16,64}$', exp):
        raise SystemExit('--expect: укажите SHA256 манифеста, выведенный на Kali (не менее 16 символов)')
    msha = sha256_file(man)
    if not msha.startswith(exp):
        raise SystemExit('ОТКАЗ: SHA256 манифеста %s не совпадает с ожидаемым %s' % (msha, exp))
    files = []
    for line in open(man):
        h, name = line.split()
        if '/' in name:
            raise SystemExit('недопустимое имя в манифесте: ' + name)
        got = sha256_file(os.path.join(src, name))
        if got != h:
            raise SystemExit('ОТКАЗ: %s: %s вместо %s' % (name, got, h))
        files.append(dict(name=name, sha256=h))
    if os.path.exists(TRUSTED):
        shutil.rmtree(TRUSTED)
    os.makedirs(TRUSTED)
    os.chmod(TRUSTED, 0o700)
    for f in files + [dict(name='MANIFEST.sha256')]:
        dst = os.path.join(TRUSTED, f['name'])
        shutil.copyfile(os.path.join(src, f['name']), dst)
        os.chmod(dst, 0o600)
    rec = dict(time=utc(), manifest_sha256=msha, files=files)
    st['stages'].append(rec)
    save_state(st)
    evidence(st['work'], next_name(st['work'], 'stage'), rec, op)
    for f in files:
        print('OK   %s  %s' % (f['sha256'][:16], f['name']))
    print('Доверенные копии размещены в %s' % TRUSTED)


def read_classification(work):
    path = os.path.join(os.path.abspath(work), 'classification.csv')
    if not os.path.exists(path):
        raise SystemExit('нет файла classification.csv (шаг 5)')
    rows, errors = [], []
    with open(path, encoding='utf-8') as s:
        rd = csv.DictReader(s)
        need = ['object', 'attributes', 'verdict', 'reason']
        if rd.fieldnames is None or [x.strip() for x in rd.fieldnames] != need:
            raise SystemExit('заголовок classification.csv должен быть: ' + ','.join(need))
        for i, r in enumerate(rd, 2):
            r = dict((k.strip(), (v or '').strip()) for k, v in r.items())
            if not r['object'].startswith('/'):
                errors.append('строка %d: объект должен быть абсолютным путём' % i)
            if r['verdict'] not in VERDICTS:
                errors.append('строка %d: verdict — одно из %s' % (i, ', '.join(VERDICTS)))
            if not r['reason']:
                errors.append('строка %d: пустое обоснование' % i)
            rows.append(r)
    return rows, errors


def cmd_classify(a):
    rows, errors = read_classification(a.work)
    for r in rows:
        print('%-13s %-40s %s' % (r['verdict'], r['object'], r['attributes']))
    if errors:
        print('\n'.join(errors))
        sys.exit(2)
    out = os.path.join(os.path.abspath(a.work), 'evidence', 'classification.json')
    with open(out, 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), rows=rows), s, indent=2, ensure_ascii=False)
    print('Формат таблицы верен: %d строк.' % len(rows))


def truth(st):
    t = {CONFFILE: 'authorized'}
    t[{'stealth': LIB + '/agent.sh', 'mode': LIB + '/functions.sh', 'newfile': LIB + '/hook.sh'}[st['drill']['pkg']]] = 'unauthorized'
    t[{'append': SRV + '/policy/allowlist.txt', 'owner': SRV + '/data/accounts.csv'}[st['drill']['srv']]] = 'unauthorized'
    return t


def cmd_reveal(a):
    need_root()
    st = load_state()
    op = st['operator']
    if not st.get('drill_done'):
        raise SystemExit('учебное событие ещё не выполнялось')
    rows, errors = read_classification(st['work'])
    if errors:
        raise SystemExit('исправьте classification.csv: ' + '; '.join(errors))
    t = truth(st)
    got = dict((os.path.normpath(r['object']), r['verdict']) for r in rows)
    res = []
    for obj, verdict in sorted(t.items()):
        res.append(dict(object=obj, expected=verdict, given=got.get(obj), ok=got.get(obj) == verdict))
    extra = []
    for obj, verdict in sorted(got.items()):
        if obj not in t:
            ok = verdict == 'normal' and obj.startswith(SRV + '/log')
            extra.append(dict(object=obj, given=verdict, ok=ok))
    desc = {'stealth': 'подмена содержимого agent.sh при сохранённых размере и mtime',
            'mode': 'права functions.sh изменены на 0666', 'newfile': 'добавлен файл hook.sh',
            'append': 'в allowlist.txt дописан адрес, mtime возвращён', 'owner': 'владелец accounts.csv изменён на nobody'}
    rep = dict(time=utc(), drill=[desc[st['drill']['pkg']], desc[st['drill']['srv']]],
               local_baseline_rebuilt=True, results=res, extra=extra,
               score='%d/%d' % (sum(1 for r in res if r['ok']), len(res)))
    st['revealed'] = utc()
    save_state(st)
    evidence(st['work'], 'reveal.json', rep, op)
    print('Учебное событие: ' + '; '.join(rep['drill']) + '; затем локальная база AIDE перестроена.')
    for r in res:
        print('%-4s %-40s ожидалось %-12s указано %s' % ('OK' if r['ok'] else 'MISS', r['object'], r['expected'], r['given']))
    for r in extra:
        print('%-4s %-40s дополнительно: %s' % ('OK' if r['ok'] else 'CHECK', r['object'], r['given']))
    print('Совпадение: ' + rep['score'])


def cmd_clean_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-44s %s' % ('OK' if ok else 'FAIL', cid, detail))

    p = variant_params(st['variant'])
    ok, _ = ticket_state(st)
    add('ticket', ok, '%s: %s=%s, остальное без изменений' % (p['ticket'], p['ticket_key'], p['ticket_new']))
    members = deb_members(st['deb'])
    for path, (h, mode) in sorted(members.items()):
        if path == CONFFILE:
            continue
        if not os.path.exists(path):
            add('pkg ' + path, False, 'файл отсутствует')
            continue
        s = os.lstat(path)
        add('pkg ' + path, sha256_file(path) == h and stat.S_IMODE(s.st_mode) == mode and s.st_uid == 0 and s.st_gid == 0,
            'содержимое, права %04o и владелец root как в доверенном пакете' % mode)
    for d, allowed in ((LIB, {'agent.sh', 'functions.sh'}), (ETC, {'agent.conf'})):
        extra = sorted(set(os.listdir(d)) - allowed)
        add('extra ' + d, not extra, 'лишние объекты: %s' % (', '.join(extra) or 'нет'))
    if st.get('drill_done') and st['drill']['pkg'] == 'newfile':
        q = os.path.exists(QUAR) and any(n.startswith('hook.sh') for n in os.listdir(QUAR))
        add('quarantine', q, 'неожиданный файл сохранён в %s для разбора' % QUAR)
    tm = tar_members(st['backup'])
    for path, (h, mode, un, gn) in sorted(tm.items()):
        if not os.path.exists(path):
            add('srv ' + path, False, 'файл отсутствует')
            continue
        s = os.lstat(path)
        add('srv ' + path, sha256_file(path) == h and stat.S_IMODE(s.st_mode) == mode and
            pwd.getpwuid(s.st_uid).pw_name == un and grp.getgrgid(s.st_gid).gr_name == gn,
            'содержимое, права %04o, владелец %s:%s как в резервной копии' % (mode, un, gn))
    rc, out, err = run(['dpkg', '--verify', PKG])
    lines = [x for x in out.splitlines() if x.strip()]
    add('dpkg --verify', len(lines) == 1 and lines[0].endswith(' c ' + CONFFILE),
        'ожидается одна строка conffile: %s' % ('; '.join(lines) or 'пусто'))
    cfg, db, dbout = registered(st)
    rc, out, err = run(['aide', '--config=' + st['conf'], '--check'])
    add('aide --check', rc == 0, 'код возврата %d с действующей базой' % rc)
    last = st['exports'][-1] if st['exports'] else None
    after = bool(last and st.get('drill_epoch') and last['epoch'] > st['drill_epoch'])
    add('new baseline exported', after and last['db_sha256'] == sha256_file(db),
        'последний export после учения и совпадает с действующей базой')
    kv = os.path.join(st['work'], 'evidence', 'kali-vault.json')
    kok, kdet = False, 'нет evidence/kali-vault.json (шаг 7, report на Kali)'
    if os.path.exists(kv) and last:
        try:
            log = json.load(open(kv, encoding='utf-8'))
            stored = [e for e in log.get('entries', []) if e.get('action') == 'store']
            kok = bool(stored) and stored[-1].get('manifest_sha256') == last['manifest_sha256']
            kdet = 'последний эталон в хранилище Kali: %s' % (stored[-1].get('tag') if stored else 'нет')
        except ValueError:
            kdet = 'kali-vault.json не разобран'
    add('kali vault', kok, kdet)
    add('reveal', bool(st.get('revealed')), 'самопроверка классификации выполнена')
    allok = all(c['ok'] for c in checks)
    evidence(st['work'], 'clean-check.json', dict(time=utc(), clean=allok, checks=checks), op)
    print('clean: %s' % allok)
    if not allok:
        sys.exit(2)


def cmd_cleanup(a):
    need_root()
    if not a.yes:
        raise SystemExit('удаление учебных объектов: повторите с --yes')
    st = load_state() if os.path.exists(STATE + '/state.json') else None
    run(['dpkg', '--purge', PKG])
    for d in (SRV, STATE, EXPORT):
        if os.path.exists(d):
            shutil.rmtree(d)
    rc, out, err = run(['dpkg-query', '-W', '-f=${Status}', PKG])
    res = dict(time=utc(), package_status=(out or err).strip(),
               removed=dict((d, not os.path.exists(d)) for d in (SRV, STATE, EXPORT, LIB, ETC)))
    keys = []
    if st:
        ak = os.path.join(st['operator']['home'], '.ssh', 'authorized_keys')
        if os.path.exists(ak):
            keys = [x.split()[-1] for x in open(ak, encoding='utf-8', errors='replace') if 'pr13-vault' in x]
    res['vault_keys_left'] = keys
    res['clean'] = all(res['removed'].values()) and 'installed' not in out.replace('not-installed', '') and not keys
    if st:
        evidence(st['work'], 'cleanup.json', res, st['operator'])
    print(json.dumps(res, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description='PR13: контроль целостности критичных файлов (Astra)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('init')
    s.add_argument('--work', required=True)
    s.add_argument('--variant', type=int, required=True)
    s = sub.add_parser('info')
    s.add_argument('--work', required=True)
    s.add_argument('--field')
    s = sub.add_parser('policy-check')
    s.add_argument('--conf', required=True)
    s = sub.add_parser('export')
    s.add_argument('--note')
    sub.add_parser('drill')
    s = sub.add_parser('stage')
    s.add_argument('--from', dest='src', required=True)
    s.add_argument('--expect', required=True)
    s = sub.add_parser('classify')
    s.add_argument('--work', required=True)
    sub.add_parser('reveal')
    sub.add_parser('clean-check')
    s = sub.add_parser('cleanup')
    s.add_argument('--yes', action='store_true')
    a = ap.parse_args()
    fn = {'init': cmd_init, 'info': cmd_info, 'policy-check': cmd_policy_check, 'export': cmd_export,
          'drill': cmd_drill, 'stage': cmd_stage, 'classify': cmd_classify, 'reveal': cmd_reveal,
          'clean-check': cmd_clean_check, 'cleanup': cmd_cleanup}.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(a)


if __name__ == '__main__':
    main()
