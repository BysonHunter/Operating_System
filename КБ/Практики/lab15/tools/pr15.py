#!/usr/bin/env python3
"""PR15 (Astra): учебное реагирование на инцидент.

Скрипт подкладывает на учебную Astra готовый инцидент: журналы SSH с серией неуспешных входов,
изменённые файлы службы pr15-agent и доверенный эталон этих файлов, снятый до инцидента. Студент
сохраняет журналы (chain of custody), локализует источник, отличает вредоносные изменения от
санкционированных, восстанавливает конфигурацию из эталона и готовит краткий отчёт.

Самодостаточно: ни настоящий sshd, ни Kali для разбора не нужны — инцидент воспроизводим и
детерминирован для данной инициализации. Содержание инцидента (какой源, какой аккаунт, какие файлы)
до команды reveal не раскрывается (какой источник, какой аккаунт, какие файлы); файл
/var/lib/pr15/state.json до reveal не открывают.

Только стандартная библиотека Python 3.5. Команды, затрагивающие системные объекты, выполняются
через sudo из обычной учебной записи.
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import sys
import time


def _utf8_stdio():
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()

STATE = '/var/lib/pr15'
INCIDENT = STATE + '/incident'
BASELINE = STATE + '/baseline'
BASEFILES = BASELINE + '/files'
CASE = STATE + '/case'
QUAR = STATE + '/quarantine'
SRV = '/srv/pr15'
AUTHLOG = INCIDENT + '/auth.log'
JOURNAL = INCIDENT + '/journal.txt'
HOSTNAME = None  # set per variant

TZ = '+0300'
TZOFF = 3 * 3600
MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
# базовый момент инцидента: 2026-11-07 в местном времени стенда (Europe/Moscow, +03:00)
BASE = 1794033000  # 2026-11-07T09:30:00+03:00
EPOCH_TRUST = 1793860200  # 2026-11-05T09:30:00+03:00 — время эталонных файлов (до инцидента)

ACCOUNTS = ['svc_report', 'operator', 'backup', 'deploy', 'monitor', 'gitlab', 'webadmin', 'dbadmin', 'courier']
OBJECTS = [SRV + '/conf/agent.conf', SRV + '/conf/allow.hosts', SRV + '/data/report.csv',
           SRV + '/data/notes.txt', SRV + '/log/agent.log']
VERDICTS = ('malicious', 'authorized', 'normal')
ACTIONS = ('restore', 'keep', 'quarantine')
FINDING_FIELDS = ['source_ip', 'benign_source_ip', 'target_account', 'failed_count', 'first_failed',
                  'last_failed', 'breached', 'success_time']
REPORT_SECTIONS = ['Идентификация', 'Источник', 'Хронология', 'Последствия', 'Восстановление', 'Выводы']


# ------------------------------------------------------------------ helpers
def utc(t=None):
    t = time.time() if t is None else t
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def syslog_ts(epoch):
    g = time.gmtime(epoch + TZOFF)
    return '%s %2d %02d:%02d:%02d' % (MON[g.tm_mon - 1], g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec)


def iso_ts(epoch):
    g = time.gmtime(epoch + TZOFF)
    return '%04d-%02d-%02dT%02d:%02d:%02d%s' % (g.tm_year, g.tm_mon, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec, TZ)


def norm(s):
    return re.sub(r'\s+', ' ', (s or '').strip())


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as s:
        for b in iter(lambda: s.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


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


def wfile(path, text, mode=0o644, when=None):
    with open(path, 'w', encoding='utf-8') as s:
        s.write(text)
    os.chmod(path, mode)
    if when is not None:
        os.utime(path, (when, when))


def rfile(path, default=None):
    try:
        with open(path, encoding='utf-8', errors='replace') as s:
            return s.read()
    except (IOError, OSError):
        return default


def load_state():
    path = STATE + '/state.json'
    if not os.path.exists(path):
        raise SystemExit('сессия не инициализирована: sudo python3 pr15.py init ...')
    with open(path, encoding='utf-8') as s:
        return json.load(s)


def save_state(st):
    path = STATE + '/state.json'
    with open(path + '.tmp', 'w', encoding='utf-8') as s:
        json.dump(st, s, indent=2, sort_keys=True, ensure_ascii=False)
    os.chmod(path + '.tmp', 0o600)
    os.rename(path + '.tmp', path)


def load_session(work):
    path = os.path.join(os.path.abspath(work), 'session.json')
    if not os.path.exists(path):
        raise SystemExit('нет %s: выполните init' % path)
    with open(path, encoding='utf-8') as s:
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


def load_evidence(work, name):
    path = os.path.join(os.path.abspath(work), 'evidence', name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as s:
            return json.load(s)
    except ValueError:
        return None


def file_meta(path):
    st = os.lstat(path)
    m = dict(path=path, mode='%04o' % stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
             size=st.st_size, mtime=utc(st.st_mtime), mtime_local=iso_ts(st.st_mtime))
    if stat.S_ISREG(st.st_mode):
        m['sha256'] = sha256_file(path)
    return m


# ------------------------------------------------------------------ variant and scenario
def variant_params(v):
    nn = '%02d' % v
    return dict(variant=v, nn=nn, astra='10.50.%d.10' % v, kali='10.50.%d.20' % v,
                benign='10.50.%d.40' % v, inc='INC-15-%s' % nn, chg='CHG-15-%s' % nn,
                hostname='astra-v' + nn)


def plan_incident(v, p, nonce):
    """Детерминированный по (variant, nonce) план инцидента. Возвращает истину (truth)."""
    h = hashlib.sha256((nonce + str(v)).encode()).digest()
    target = ACCOUNTS[h[0] % len(ACCOUNTS)]
    invalid_user = ['admin', 'test', 'oracle', 'user', 'git'][h[1] % 5]
    fails = 16 + h[2] % 18
    use_invalid = h[3] % 2 == 0   # пробует сначала несуществующего пользователя
    # какой конфиг и какой файл данных испорчены; второй файл данных — санкционированное изменение
    mal_conf = (SRV + '/conf/agent.conf', SRV + '/conf/allow.hosts')[h[4] % 2]
    other_conf = SRV + '/conf/allow.hosts' if mal_conf.endswith('agent.conf') else SRV + '/conf/agent.conf'
    mal_data = (SRV + '/data/report.csv', SRV + '/data/notes.txt')[h[5] % 2]
    auth_data = SRV + '/data/notes.txt' if mal_data.endswith('report.csv') else SRV + '/data/report.csv'
    # времена
    first_fail = BASE + 20 + h[6] % 40
    step = 3 + h[7] % 4
    last_fail = first_fail + (fails - 1) * step
    success = last_fail + 6 + h[8] % 10
    mal1_mt = success + 30 + h[9] % 30           # испорченный конфиг
    mal2_mt = mal1_mt + 20 + h[10] % 30          # испорченный файл данных
    auth_mt = BASE - (2 * 3600 + 600 * (h[11] % 6))   # санкционированное изменение — за 2+ часа до атаки
    benign_fail = BASE - 300 - h[12] % 120       # разовый промах легитимного пользователя
    benign_ok = benign_fail + 25 + h[13] % 20
    return dict(target=target, invalid_user=invalid_user if use_invalid else None, fails=fails, step=step,
                attacker_ip=p['kali'], benign_ip=p['benign'], benign_user='operator' if target != 'operator' else 'backup',
                first_fail=first_fail, last_fail=last_fail, success=success,
                benign_fail=benign_fail, benign_ok=benign_ok,
                mal_conf=mal_conf, other_conf=other_conf, mal_data=mal_data, auth_data=auth_data,
                mal1_mt=mal1_mt, mal2_mt=mal2_mt, auth_mt=auth_mt)


def baseline_text(v, p):
    nn = p['nn']
    return {
        SRV + '/conf/agent.conf': ('# pr15-agent configuration, variant %s\n'
                                   'interval=60\nlog_level=info\nreport_dir=/srv/pr15/data\n'
                                   'upload_host=10.50.%d.30\nallow_file=/srv/pr15/conf/allow.hosts\n'
                                   'debug_shell=no\n') % (nn, v),
        SRV + '/conf/allow.hosts': ('# hosts allowed to collect reports, variant %s\n'
                                    '10.50.%d.10\n10.50.%d.30\n') % (nn, v, v),
        SRV + '/data/report.csv': ('host,role,status\n10.50.%d.10,astra,ok\n10.50.%d.30,collector,ok\n'
                                   '# pr15-agent report, variant %s\n') % (v, v, nn),
        SRV + '/data/notes.txt': ('Заметки обслуживания службы pr15-agent, вариант %s\n'
                                  '2026-11-01 развёртывание службы\n') % nn,
    }


def render_logs(v, p, t):
    """Строит auth.log (syslog) и journal.txt (journalctl -o short-iso) из плана инцидента."""
    host = p['hostname']
    ev = []  # (epoch, 'sshd'|'agent'|'cron'|'sudo', pid, auth_text, journal_text_override)

    def add(epoch, comp, pid, text, jtext=None):
        ev.append((epoch, comp, pid, text, jtext))

    # фоновая активность: плановый вход администратора с консоли/локальной сети раньше
    add(BASE - 3600, 'sshd', 1510, 'Accepted publickey for %s from %s port 51000 ssh2: ED25519 SHA256:abc'
        % (t['benign_user'], p['astra']))
    add(BASE - 3600 + 1, 'sshd', 1510, 'pam_unix(sshd:session): session opened for user %s by (uid=0)' % t['benign_user'])
    # санкционированное изменение файла данных (заявка CHG) — с консоли, задолго до атаки
    add(t['auth_mt'] - 5, 'sudo', 1602, '%s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/tee -a %s'
        % (t['benign_user'], t['benign_user'], t['auth_data']))
    add(t['auth_mt'], 'agent', 1572, 'config maintenance per %s: appended line to %s'
        % (p['chg'], os.path.basename(t['auth_data'])))
    # разовый промах легитимного пользователя с другого внутреннего узла — шум, НЕ атакующий
    add(t['benign_fail'], 'sshd', 1880, 'Failed password for %s from %s port 44120 ssh2'
        % (t['benign_user'], t['benign_ip']))
    add(t['benign_ok'], 'sshd', 1884, 'Accepted password for %s from %s port 44123 ssh2'
        % (t['benign_user'], t['benign_ip']))
    # серия неуспешных входов от атакующего (Kali)
    pid = 2100
    port = 50500
    n = t['fails']
    inv = t['invalid_user']
    for i in range(n):
        epoch = t['first_fail'] + i * t['step']
        pid += 1
        port += 7
        if inv and i < max(3, n // 4):
            add(epoch, 'sshd', pid, 'Invalid user %s from %s port %d' % (inv, t['attacker_ip'], port))
            add(epoch, 'sshd', pid, 'Failed password for invalid user %s from %s port %d ssh2'
                % (inv, t['attacker_ip'], port))
        else:
            add(epoch, 'sshd', pid, 'Failed password for %s from %s port %d ssh2' % (t['target'], t['attacker_ip'], port))
    # успешный вход атакующего и сессия
    pid += 1
    add(t['success'], 'sshd', pid, 'Accepted password for %s from %s port %d ssh2' % (t['target'], t['attacker_ip'], port + 7))
    add(t['success'] + 1, 'sshd', pid, 'pam_unix(sshd:session): session opened for user %s by (uid=0)' % t['target'])
    # действия в сессии атакующего (видно в journal), правка файлов
    add(t['mal1_mt'], 'agent', pid, 'file changed: %s (sshd session from %s)'
        % (os.path.basename(t['mal_conf']), t['attacker_ip']))
    add(t['mal2_mt'], 'agent', pid, 'file changed: %s (sshd session from %s)'
        % (os.path.basename(t['mal_data']), t['attacker_ip']))
    add(t['mal2_mt'] + 20, 'sshd', pid, 'pam_unix(sshd:session): session closed for user %s' % t['target'])
    # штатная работа службы — рост журнала
    add(BASE + 2000, 'agent', 1572, 'report cycle complete')
    ev.sort(key=lambda x: x[0])
    auth_lines, jrn_lines = [], []
    comp_name = {'sshd': 'sshd', 'agent': 'pr15-agent', 'cron': 'CRON', 'sudo': 'sudo'}
    for epoch, comp, pid, text, jtext in ev:
        name = comp_name[comp]
        auth_lines.append('%s %s %s[%d]: %s' % (syslog_ts(epoch), host, name, pid, text))
        jrn_lines.append('%s %s %s[%d]: %s' % (iso_ts(epoch), host, name, pid, jtext or text))
    return '\n'.join(auth_lines) + '\n', '\n'.join(jrn_lines) + '\n', ev


def apply_incident(v, p, t):
    """Портит файлы службы согласно плану и проставляет им mtime из журнала."""
    # испорченный конфиг
    if t['mal_conf'].endswith('agent.conf'):
        data = rfile(t['mal_conf'])
        data = data.replace('debug_shell=no\n', 'debug_shell=yes\n')
        wfile(t['mal_conf'], data, 0o644, t['mal1_mt'])
    else:  # allow.hosts — атакующий добавил свой адрес
        with open(t['mal_conf'], 'a', encoding='utf-8') as s:
            s.write('%s\n' % t['attacker_ip'])
        os.chmod(t['mal_conf'], 0o644)
        os.utime(t['mal_conf'], (t['mal1_mt'], t['mal1_mt']))
    # испорченный файл данных
    if t['mal_data'].endswith('report.csv'):
        with open(t['mal_data'], 'a', encoding='utf-8') as s:
            s.write('%s,attacker,ok\n' % t['attacker_ip'])
    else:
        with open(t['mal_data'], 'a', encoding='utf-8') as s:
            s.write('%s доступ получен\n' % utc(t['success']))
    os.chmod(t['mal_data'], 0o644)
    os.utime(t['mal_data'], (t['mal2_mt'], t['mal2_mt']))
    # санкционированное изменение второго файла данных (заявка CHG) — раньше атаки
    with open(t['auth_data'], 'a', encoding='utf-8') as s:
        s.write('%s %s плановое обслуживание\n' % (utc(t['auth_mt']), p['chg']))
    os.chmod(t['auth_data'], 0o644)
    os.utime(t['auth_data'], (t['auth_mt'], t['auth_mt']))


def chg_text(p, t):
    return ('%s: санкционированное изменение %s — добавление строки планового обслуживания, выполнено '
            'учётной записью %s с консоли %s. Иные изменения файлов службы заявками не предусмотрены.' % (
                p['chg'], t['auth_data'], t['benign_user'], iso_ts(t['auth_mt'])))


def truth_files(t):
    res = {}
    res[t['mal_conf']] = dict(verdict='malicious', action='restore')
    res[t['mal_data']] = dict(verdict='malicious', action='restore')
    res[t['auth_data']] = dict(verdict='authorized', action='keep')
    res[SRV + '/log/agent.log'] = dict(verdict='normal', action='keep')
    return res


# ------------------------------------------------------------------ commands
def cmd_init(a):
    need_root()
    op = operator()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('вариант должен быть от 1 до 27')
    if os.path.exists(STATE) or os.path.exists(SRV):
        raise SystemExit('объекты ПР15 уже существуют; вернитесь к снимку или выполните cleanup --yes')
    p = variant_params(v)
    work = os.path.abspath(a.work)
    for d in (work, os.path.join(work, 'evidence')):
        if not os.path.isdir(d):
            os.makedirs(d)
        give(d, op)
    for d in (STATE, INCIDENT, BASELINE, BASEFILES, QUAR):
        os.makedirs(d)
        os.chmod(d, 0o755)
    os.chmod(STATE, 0o755)
    os.chmod(QUAR, 0o700)
    for d, mode in ((SRV, 0o755), (SRV + '/conf', 0o755), (SRV + '/data', 0o755), (SRV + '/log', 0o755)):
        os.makedirs(d)
        os.chmod(d, mode)
    # эталонные (доверенные) файлы службы — до инцидента
    base = baseline_text(v, p)
    manifest = {}
    for path, text in sorted(base.items()):
        wfile(path, text, 0o644, EPOCH_TRUST)
        os.chown(path, 0, 0)
        rel = path[len(SRV) + 1:]
        bdst = os.path.join(BASEFILES, rel)
        os.makedirs(os.path.dirname(bdst), exist_ok=True)
        shutil.copyfile(path, bdst)
        os.chmod(bdst, 0o444)
        os.utime(bdst, (EPOCH_TRUST, EPOCH_TRUST))
        manifest[path] = dict(sha256=sha256_file(bdst), mode='0644', mtime=iso_ts(EPOCH_TRUST))
    log = SRV + '/log/agent.log'
    wfile(log, '%s pr15-agent v%s started\n' % (iso_ts(EPOCH_TRUST), p['nn']), 0o644, EPOCH_TRUST)
    os.chown(log, 0, 0)
    with open(BASELINE + '/manifest.json', 'w', encoding='utf-8') as s:
        json.dump(dict(created=utc(), note='доверенный эталон файлов службы до инцидента', files=manifest), s,
                  indent=2, ensure_ascii=False)
    os.chmod(BASELINE + '/manifest.json', 0o444)
    # план инцидента и его применение
    nonce = os.urandom(16).hex()
    t = plan_incident(v, p, nonce)
    authtext, jrntext, ev = render_logs(v, p, t)
    wfile(AUTHLOG, authtext, 0o644, BASE + 2100)
    wfile(JOURNAL, jrntext, 0o644, BASE + 2100)
    apply_incident(v, p, t)
    # рост журнала службы (штатная активность) — после атаки
    with open(log, 'a', encoding='utf-8') as s:
        s.write('%s pr15-agent v%s report sent\n%s pr15-agent v%s report sent\n'
                % (iso_ts(BASE + 1800), p['nn'], iso_ts(BASE + 2000), p['nn']))
    os.utime(log, (BASE + 2000, BASE + 2000))
    # истина (скрыта до reveal)
    tf = truth_files(t)
    for path, info in tf.items():
        if path in base:
            info['baseline_sha256'] = manifest[path]['sha256']
        if os.path.exists(path):
            info['incident_sha256'] = sha256_file(path)
            info['mtime_local'] = iso_ts(os.stat(path).st_mtime)
    st = dict(variant=v, operator=op, work=work, nonce=nonce, created=utc(), hostname=p['hostname'],
              truth=dict(attacker_ip=t['attacker_ip'], benign_ip=t['benign_ip'], target=t['target'],
                         invalid_user=t['invalid_user'], failed_count=t['fails'], breached=True,
                         first_failed=syslog_ts(t['first_fail']), last_failed=syslog_ts(t['last_fail']),
                         success_time=syslog_ts(t['success']), files=tf),
              preserved=None, restored=None, revealed=None, chg=p['chg'], auth_data=t['auth_data'])
    save_state(st)
    ses = dict(variant=v, nn=p['nn'], astra=p['astra'], kali=p['kali'], benign_hint='внутренний узел стенда',
               inc=p['inc'], chg=p['chg'], chg_text=chg_text(p, t), hostname=p['hostname'],
               incident_dir=INCIDENT, auth_log=AUTHLOG, journal=JOURNAL, baseline=BASELINE,
               baseline_manifest=BASELINE + '/manifest.json', srv=SRV, case_dir=CASE, quarantine=QUAR,
               objects=OBJECTS, accounts=ACCOUNTS, work=work, created=st['created'])
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True, ensure_ascii=False)
    give(os.path.join(work, 'session.json'), op)
    evidence(work, 'init.json', dict(session=ses, baseline=manifest), op)
    print('Вариант %s: инцидент подготовлен.' % p['nn'])
    print(p['inc'] + ': зафиксирована серия неуспешных входов по SSH на ' + p['astra'] +
          ' и подозрение на изменение файлов службы pr15-agent.')
    print('Журналы инцидента: %s, %s (только чтение).' % (AUTHLOG, JOURNAL))
    print('Доверенный эталон файлов службы до инцидента: %s.' % BASELINE)
    print('Санкционированное изменение: ' + chg_text(p, t))
    print('Задача: сохранить журналы (preserve), локализовать источник, восстановить конфигурацию, '
          'подготовить краткий отчёт.')


def cmd_info(a):
    ses = load_session(a.work)
    if a.field:
        if a.field not in ses:
            raise SystemExit('нет поля %s; есть: %s' % (a.field, ', '.join(sorted(ses))))
        val = ses[a.field]
        print(' '.join(map(str, val)) if isinstance(val, list) else val)
    else:
        print(json.dumps(ses, indent=2, sort_keys=True, ensure_ascii=False))


def cmd_preserve(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    if not os.path.exists(AUTHLOG):
        raise SystemExit('нет журналов инцидента: выполните init')
    for d in (CASE, os.path.join(work, 'evidence', 'case')):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)
    collected = utc()
    manifest = {}
    # журналы инцидента
    items = [('auth.log', AUTHLOG), ('journal.txt', JOURNAL), ('baseline-manifest.json', BASELINE + '/manifest.json')]
    # текущее состояние файлов службы (стат + хеш) — снимок на момент сбора
    states = {}
    for pth in OBJECTS:
        if os.path.exists(pth):
            states[pth] = file_meta(pth)
    state_text = json.dumps(dict(collected=collected, files=states), indent=2, ensure_ascii=False, sort_keys=True)
    for name, src in items:
        dst = os.path.join(CASE, name)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o444)
    with open(os.path.join(CASE, 'file-state.json'), 'w', encoding='utf-8') as s:
        s.write(state_text + '\n')
    os.chmod(os.path.join(CASE, 'file-state.json'), 0o444)
    lines = []
    for name in sorted(os.listdir(CASE)):
        if name == 'CASE-MANIFEST.sha256':
            continue
        h = sha256_file(os.path.join(CASE, name))
        manifest[name] = h
        lines.append('%s  %s\n' % (h, name))
    man = os.path.join(CASE, 'CASE-MANIFEST.sha256')
    with open(man, 'w') as s:
        s.write(''.join(sorted(lines, key=lambda x: x.split()[1])))
    os.chmod(man, 0o444)
    msha = sha256_file(man)
    # копия дела в рабочий каталог студента (для отчёта), тоже только чтение
    wcase = os.path.join(work, 'evidence', 'case')
    for name in os.listdir(CASE):
        shutil.copyfile(os.path.join(CASE, name), os.path.join(wcase, name))
    for name in os.listdir(wcase):
        os.chmod(os.path.join(wcase, name), 0o444)
    for root, dirs, files in os.walk(wcase):
        for d in dirs:
            give(os.path.join(root, d), op)
    give(wcase, op)
    for name in os.listdir(wcase):
        give(os.path.join(wcase, name), op)
    st['preserved'] = dict(time=collected, manifest_sha256=msha, files=manifest)
    save_state(st)
    evidence(work, 'preserve.json', dict(time=collected, case_dir=CASE, manifest_sha256=msha, files=manifest,
                                         file_state=states), op)
    print('Журналы и состояние файлов сохранены в %s (только чтение).' % CASE)
    print('Собрано: %s' % collected)
    for name in sorted(manifest):
        print('  %s  %s' % (manifest[name][:16], name))
    print('CASE-MANIFEST SHA256: %s' % msha)


# ------------------------------------------------------------------ анализ журналов
def parse_auth(text):
    """Разбирает строки sshd из auth.log. Возвращает список событий."""
    events = []
    rx = re.compile(r'^(?P<ts>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$')
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        msg = m.group('msg')
        ev = dict(ts=m.group('ts'), host=m.group('host'), pid=int(m.group('pid')), msg=msg, kind=None, ip=None, user=None)
        mm = re.search(r'Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)', msg)
        if mm:
            ev['kind'] = 'fail'
            ev['user'] = mm.group(2)
            ev['ip'] = mm.group(3)
            ev['invalid'] = bool(mm.group(1))
        mm = re.match(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)', msg)
        if mm:
            ev['kind'] = 'invalid'
            ev['user'] = mm.group(1)
            ev['ip'] = mm.group(2)
        mm = re.search(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)', msg)
        if mm:
            ev['kind'] = 'accept'
            ev['user'] = mm.group(1)
            ev['ip'] = mm.group(2)
        if ev['kind']:
            events.append(ev)
    return events


def baseline_manifest():
    path = BASELINE + '/manifest.json'
    if not os.path.exists(path):
        return {}
    with open(path, encoding='utf-8') as s:
        return json.load(s).get('files', {})


def cmd_timeline(a):
    work = os.path.abspath(a.work)
    text = rfile(AUTHLOG)
    if text is None:
        raise SystemExit('нет %s (журнал читается без sudo; проверьте init)' % AUTHLOG)
    events = parse_auth(text)
    bysrc = {}
    for e in events:
        s = bysrc.setdefault(e['ip'], dict(fail=0, invalid=0, accept=0, users=set(), first=None, last=None, accepted_users=set()))
        if e['kind'] in ('fail', 'invalid'):
            s['fail' if e['kind'] == 'fail' else 'invalid'] += 1
            s['users'].add(e['user'])
            if s['first'] is None:
                s['first'] = e['ts']
            s['last'] = e['ts']
        elif e['kind'] == 'accept':
            s['accept'] += 1
            s['accepted_users'].add(e['user'])
    print('Источники по журналу %s:' % AUTHLOG)
    print('%-16s %6s %8s %7s  %-14s %-14s %s' % ('IP', 'Failed', 'Invalid', 'Accept', 'первый неуспех',
                                                 'последний', 'аккаунты'))
    rows = []
    for ip in sorted(bysrc, key=lambda x: -(bysrc[x]['fail'] + bysrc[x]['invalid'])):
        s = bysrc[ip]
        print('%-16s %6d %8d %7d  %-14s %-14s %s' % (ip, s['fail'], s['invalid'], s['accept'],
                                                     s['first'] or '-', s['last'] or '-',
                                                     ','.join(sorted(s['users']))))
        rows.append(dict(ip=ip, failed=s['fail'], invalid=s['invalid'], accept=s['accept'], first=s['first'],
                         last=s['last'], users=sorted(s['users']), accepted_users=sorted(s['accepted_users'])))
    # сравнение файлов службы с эталоном
    man = baseline_manifest()
    print('\nОтличия файлов службы от эталона (%s):' % (BASELINE + '/manifest.json'))
    diffs = []
    for pth in OBJECTS:
        cur = sha256_file(pth) if os.path.exists(pth) else None
        bsha = man.get(pth, {}).get('sha256')
        if bsha is None:
            status = 'нет в эталоне (рост/вне эталона)'
            changed = cur is not None
        elif cur == bsha:
            status = 'совпадает'
            changed = False
        else:
            status = 'ИЗМЕНЁН'
            changed = True
        mt = iso_ts(os.stat(pth).st_mtime) if os.path.exists(pth) else '-'
        if changed or bsha is not None:
            print('  %-32s %-28s mtime=%s' % (pth, status, mt))
        diffs.append(dict(path=pth, status=status, changed=changed, mtime_local=mt, current_sha256=cur,
                          baseline_sha256=bsha))
    out = dict(time=utc(), sources=rows, file_diffs=diffs, accepted=[dict(ip=e['ip'], user=e['user'], ts=e['ts'])
                                                                      for e in events if e['kind'] == 'accept'])
    evidence(work, 'timeline.json', out)
    print('\nСохранено: evidence/timeline.json. Выводы по источнику и файлам сделайте сами.')


# ------------------------------------------------------------------ findings / files
def read_findings(work):
    path = os.path.join(os.path.abspath(work), 'findings.csv')
    if not os.path.exists(path):
        raise SystemExit('нет файла findings.csv (шаг 4)')
    rows, errors = {}, []
    with open(path, encoding='utf-8') as s:
        rd = csv.DictReader(s)
        need = ['field', 'value']
        if rd.fieldnames is None or [x.strip() for x in rd.fieldnames] != need:
            raise SystemExit('заголовок findings.csv должен быть: field,value')
        for i, r in enumerate(rd, 2):
            r = dict((k.strip(), (v or '').strip()) for k, v in r.items())
            if r['field'] not in FINDING_FIELDS:
                errors.append('строка %d: поле должно быть одним из: %s' % (i, ', '.join(FINDING_FIELDS)))
                continue
            rows[r['field']] = r['value']
    miss = [f for f in FINDING_FIELDS if f not in rows]
    if miss:
        errors.append('не заполнены поля: %s' % ', '.join(miss))
    if 'breached' in rows and rows['breached'] not in ('yes', 'no'):
        errors.append('breached: yes или no')
    if 'failed_count' in rows and not rows['failed_count'].isdigit():
        errors.append('failed_count: целое число')
    return rows, errors


def read_files_csv(work):
    path = os.path.join(os.path.abspath(work), 'files.csv')
    if not os.path.exists(path):
        raise SystemExit('нет файла files.csv (шаг 4)')
    rows, errors = [], []
    with open(path, encoding='utf-8') as s:
        rd = csv.DictReader(s)
        need = ['object', 'verdict', 'action', 'reason']
        if rd.fieldnames is None or [x.strip() for x in rd.fieldnames] != need:
            raise SystemExit('заголовок files.csv должен быть: ' + ','.join(need))
        for i, r in enumerate(rd, 2):
            r = dict((k.strip(), (v or '').strip()) for k, v in r.items())
            if not r['object'].startswith('/'):
                errors.append('строка %d: object — абсолютный путь' % i)
            if r['verdict'] not in VERDICTS:
                errors.append('строка %d: verdict — одно из %s' % (i, ', '.join(VERDICTS)))
            if r['action'] not in ACTIONS:
                errors.append('строка %d: action — одно из %s' % (i, ', '.join(ACTIONS)))
            if not r['reason']:
                errors.append('строка %d: пустое обоснование' % i)
            rows.append(r)
    return rows, errors


def cmd_localize(a):
    work = os.path.abspath(a.work)
    frows, ferr = read_findings(work)
    crows, cerr = read_files_csv(work)
    errors = ferr + cerr
    for f in FINDING_FIELDS:
        print('  %-18s %s' % (f, frows.get(f, '—')))
    print('Файлы:')
    for r in crows:
        print('  %-11s %-10s %s' % (r['verdict'], r['action'], r['object']))
    if errors:
        print('\n'.join(errors))
        sys.exit(2)
    out = os.path.join(work, 'evidence', 'localize.json')
    with open(out, 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), findings=frows, files=crows), s, indent=2, ensure_ascii=False)
    print('Формат findings.csv и files.csv верен.')


def cmd_restore(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    if not st.get('preserved'):
        raise SystemExit('сначала сохраните журналы: preserve (журналы восстановлением затираются не должны)')
    crows, errors = read_files_csv(work)
    if errors:
        raise SystemExit('исправьте files.csv: ' + '; '.join(errors))
    man = baseline_manifest()
    actions = []
    for r in crows:
        pth = os.path.normpath(r['object'])
        if r['action'] == 'restore':
            if pth not in man:
                actions.append(dict(object=pth, action='restore', result='ОШИБКА: файла нет в эталоне'))
                continue
            rel = pth[len(SRV) + 1:]
            src = os.path.join(BASEFILES, rel)
            shutil.copyfile(src, pth)
            os.chmod(pth, int(man[pth]['mode'], 8))
            os.chown(pth, 0, 0)
            ok = sha256_file(pth) == man[pth]['sha256']
            actions.append(dict(object=pth, action='restore', result='восстановлен из эталона' if ok else 'НЕ совпал с эталоном',
                                ok=ok))
        elif r['action'] == 'quarantine':
            if os.path.exists(pth):
                dst = os.path.join(QUAR, os.path.basename(pth) + '.' + str(int(time.time())))
                sha = sha256_file(pth)
                shutil.move(pth, dst)
                actions.append(dict(object=pth, action='quarantine', result='в карантин %s' % dst, sha256=sha))
            else:
                actions.append(dict(object=pth, action='quarantine', result='файл отсутствует'))
        else:
            actions.append(dict(object=pth, action='keep', result='оставлен без изменений'))
    # проверка результата относительно эталона
    verify = []
    for pth, info in sorted(man.items()):
        cur = sha256_file(pth) if os.path.exists(pth) else None
        verify.append(dict(object=pth, matches_baseline=cur == info['sha256'], current_sha256=cur))
    st['restored'] = dict(time=utc(), actions=actions)
    save_state(st)
    evidence(work, 'restore.json', dict(time=utc(), actions=actions, verify=verify), op)
    for aobj in actions:
        print('%-10s %-34s %s' % (aobj['action'], aobj['object'], aobj['result']))
    print('Сверка с эталоном:')
    for vobj in verify:
        print('  %-34s %s' % (vobj['object'], 'совпадает' if vobj['matches_baseline'] else 'отличается'))
    print('Сохранено: evidence/restore.json')


def cmd_report(a):
    work = os.path.abspath(a.work)
    path = os.path.join(work, 'report.md')
    if not os.path.exists(path):
        raise SystemExit('нет файла report.md (шаг 6): напишите краткий отчёт')
    text = rfile(path) or ''
    low = text.lower()
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-22s %s' % ('OK' if ok else 'FAIL', cid, detail))

    for sec in REPORT_SECTIONS:
        add('раздел:' + sec, sec.lower() in low, 'есть раздел «%s»' % sec)
    frows = {}
    try:
        frows = read_findings(work)[0]
    except SystemExit:
        frows = {}
    src = frows.get('source_ip', '')
    add('источник указан', bool(src) and src in text, 'в отчёте назван источник %s' % (src or '—'))
    ses = load_session(work)
    add('номер инцидента', ses['inc'] in text, 'указан %s' % ses['inc'])
    words = len(text.split())
    add('объём', 40 <= words <= 1200, 'слов: %d (краткий отчёт)' % words)
    ok = all(c['ok'] for c in checks)
    out = os.path.join(work, 'evidence', 'report-check.json')
    with open(out, 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), ok=ok, words=words, checks=checks), s, indent=2, ensure_ascii=False)
    shutil.copyfile(path, os.path.join(work, 'evidence', 'report.md'))
    if not ok:
        print('Отчёт не принят: добавьте недостающие разделы и сведения.')
        sys.exit(2)
    print('Отчёт принят: все обязательные разделы присутствуют.')


def cmd_reveal(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    tr = st['truth']
    frows, ferr = read_findings(work)
    crows, cerr = read_files_csv(work)
    if ferr or cerr:
        raise SystemExit('исправьте findings.csv/files.csv: ' + '; '.join(ferr + cerr))
    res = []

    def cmp(field, given, expected, match=None):
        ok = (norm(given).lower() == norm(str(expected)).lower()) if match is None else match
        res.append(dict(field=field, given=given, expected=expected, ok=ok))

    cmp('source_ip', frows['source_ip'], tr['attacker_ip'])
    cmp('benign_source_ip', frows['benign_source_ip'], tr['benign_ip'])
    cmp('target_account', frows['target_account'], tr['target'])
    cmp('failed_count', frows['failed_count'], tr['failed_count'],
        match=frows['failed_count'].isdigit() and int(frows['failed_count']) == tr['failed_count'])
    cmp('first_failed', frows['first_failed'], tr['first_failed'])
    cmp('last_failed', frows['last_failed'], tr['last_failed'])
    cmp('breached', frows['breached'], 'yes' if tr['breached'] else 'no')
    cmp('success_time', frows['success_time'], tr['success_time'])
    # файлы
    tf = tr['files']
    given = dict((os.path.normpath(r['object']), r) for r in crows)
    fres = []
    for pth, info in sorted(tf.items()):
        g = given.get(pth)
        ok = bool(g) and g['verdict'] == info['verdict'] and g['action'] == info['action']
        fres.append(dict(object=pth, expected='%s/%s' % (info['verdict'], info['action']),
                         given='%s/%s' % (g['verdict'], g['action']) if g else '—', ok=ok))
    extra = []
    for pth, g in sorted(given.items()):
        if pth not in tf:
            ok = g['verdict'] == 'normal' and g['action'] == 'keep'
            extra.append(dict(object=pth, given='%s/%s' % (g['verdict'], g['action']), ok=ok))
    score = sum(1 for r in res if r['ok']) + sum(1 for r in fres if r['ok'])
    total = len(res) + len(fres)
    rep = dict(time=utc(), findings=res, files=fres, extra=extra, score='%d/%d' % (score, total),
               incident=dict(attacker_ip=tr['attacker_ip'], target=tr['target'], invalid_user=tr['invalid_user'],
                             breached=tr['breached'], success_time=tr['success_time']))
    st['revealed'] = utc()
    save_state(st)
    evidence(work, 'reveal.json', rep, op)
    print('Истина инцидента: источник %s, целевой аккаунт %s%s, вход %s в %s.' % (
        tr['attacker_ip'], tr['target'], (', до этого перебор несуществующего пользователя %s' % tr['invalid_user'])
        if tr['invalid_user'] else '', 'выполнен' if tr['breached'] else 'не выполнен', tr['success_time']))
    for r in res:
        print('%-4s %-18s указано «%s» ожидалось «%s»' % ('OK' if r['ok'] else 'MISS', r['field'], r['given'], r['expected']))
    for r in fres:
        print('%-4s %-34s указано %-20s ожидалось %s' % ('OK' if r['ok'] else 'MISS', r['object'], r['given'], r['expected']))
    for r in extra:
        print('%-4s %-34s дополнительно: %s' % ('OK' if r['ok'] else 'CHECK', r['object'], r['given']))
    print('Совпадение: ' + rep['score'])


def cmd_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    tr = st['truth']
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-26s %s' % ('OK' if ok else 'FAIL', cid, detail))

    # 1. журналы сохранены и целы
    pres = st.get('preserved')
    case_ok = False
    if pres and os.path.isdir(CASE):
        man = os.path.join(CASE, 'CASE-MANIFEST.sha256')
        case_ok = os.path.exists(man) and sha256_file(man) == pres['manifest_sha256']
        for name, h in pres['files'].items():
            if not (os.path.exists(os.path.join(CASE, name)) and sha256_file(os.path.join(CASE, name)) == h):
                case_ok = False
    add('preserve', case_ok, 'журналы и состояние файлов сохранены, манифест цел' if case_ok else 'нет целого дела (preserve)')
    # 2. локализация верна
    frows, ferr = ({}, ['нет findings.csv'])
    try:
        frows, ferr = read_findings(work)
    except SystemExit as e:
        ferr = [str(e)]
    loc_ok = not ferr and norm(frows.get('source_ip')) == tr['attacker_ip'] and \
        norm(frows.get('target_account')).lower() == tr['target'].lower() and \
        frows.get('failed_count', '').isdigit() and int(frows['failed_count']) == tr['failed_count'] and \
        frows.get('breached') == ('yes' if tr['breached'] else 'no') and \
        norm(frows.get('benign_source_ip')) == tr['benign_ip']
    add('localize', loc_ok, 'источник %s, аккаунт %s, попыток %s, взлом %s' % (
        frows.get('source_ip'), frows.get('target_account'), frows.get('failed_count'), frows.get('breached')))
    # 3. времена из журнала совпадают
    times_ok = not ferr and norm(frows.get('first_failed')) == norm(tr['first_failed']) and \
        norm(frows.get('last_failed')) == norm(tr['last_failed']) and \
        norm(frows.get('success_time')) == norm(tr['success_time'])
    add('timeline', times_ok, 'первый/последний неуспех и время входа соответствуют журналу')
    # 4. классификация файлов верна
    crows, cerr = ([], ['нет files.csv'])
    try:
        crows, cerr = read_files_csv(work)
    except SystemExit as e:
        cerr = [str(e)]
    given = dict((os.path.normpath(r['object']), r) for r in crows)
    files_ok = not cerr
    for pth, info in tr['files'].items():
        g = given.get(pth)
        if not (g and g['verdict'] == info['verdict'] and g['action'] == info['action']):
            files_ok = False
    for pth, g in given.items():
        if pth not in tr['files'] and not (g['verdict'] == 'normal' and g['action'] == 'keep'):
            files_ok = False
    add('classify', files_ok, 'вредоносные/санкционированные/штатные изменения определены верно')
    # 5. восстановление: вредоносные совпали с эталоном, санкционированный не тронут
    man = baseline_manifest()
    restore_ok = bool(st.get('restored'))
    detail = []
    for pth, info in tr['files'].items():
        if pth not in man:
            continue
        cur = sha256_file(pth) if os.path.exists(pth) else None
        if info['verdict'] == 'malicious':
            good = cur == man[pth]['sha256']
            detail.append('%s=%s' % (os.path.basename(pth), 'эталон' if good else 'НЕ эталон'))
            restore_ok = restore_ok and good
        elif info['verdict'] == 'authorized':
            good = cur is not None and cur != man[pth]['sha256']
            detail.append('%s=%s' % (os.path.basename(pth), 'сохранён' if good else 'ОШИБКА'))
            restore_ok = restore_ok and good
    add('restore', restore_ok, ', '.join(detail) or 'нет данных')
    # 6. отчёт
    rc = load_evidence(work, 'report-check.json')
    add('report', bool(rc and rc.get('ok')), 'краткий отчёт со всеми разделами' if rc and rc.get('ok')
        else 'отчёт не принят (report)')
    # 7. самопроверка reveal
    add('reveal', bool(st.get('revealed')), 'разбор инцидента выполнен (reveal)')
    # 8. необязательный живой захват
    live = rfile(os.path.join(work, 'evidence', 'live-auth.txt'))
    if live is None:
        add('live capture (опц.)', True, 'необязательный шаг с реальным «стуком» Kali не выполнялся')
    else:
        add('live capture (опц.)', tr['attacker_ip'] in live, 'в реальном журнале виден адрес Kali %s' % tr['attacker_ip'])
    passed = all(c['ok'] for c in checks)
    evidence(work, 'final-check.json', dict(time=utc(), passed=passed, checks=checks), op)
    print('passed: %s' % passed)
    if not passed:
        sys.exit(2)


def cmd_capture(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    src = st['truth']['attacker_ip']
    lines = []
    authpath = '/var/log/auth.log'
    if os.path.exists(authpath):
        for line in rfile(authpath, '').splitlines():
            if 'sshd' in line and (src in line or 'Failed password' in line or 'Invalid user' in line):
                lines.append(line)
        source = authpath
    else:
        import subprocess
        try:
            p = subprocess.Popen(['journalctl', '-u', 'ssh', '-u', 'sshd', '--no-pager', '-n', '400'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out = p.communicate()[0].decode('utf-8', 'replace')
            lines = [x for x in out.splitlines() if 'Failed password' in x or 'Invalid user' in x or src in x]
            source = 'journalctl -u ssh'
        except OSError:
            source = 'нет /var/log/auth.log и journalctl'
    tail = lines[-200:]
    path = os.path.join(work, 'evidence', 'live-auth.txt')
    with open(path, 'w', encoding='utf-8') as s:
        s.write('# источник: %s; захвачено %s\n' % (source, utc()))
        s.write('\n'.join(tail) + ('\n' if tail else ''))
    give(path, op)
    print('Захвачено строк: %d из %s -> evidence/live-auth.txt' % (len(tail), source))
    if not tail:
        print('Реальных записей не найдено: шаг необязательный, инцидент разбирается по журналам из init.')


def cmd_cleanup(a):
    need_root()
    if not a.yes:
        raise SystemExit('удаление учебных объектов: повторите с --yes')
    st = load_state() if os.path.exists(STATE + '/state.json') else None
    for d in (SRV, STATE):
        if os.path.exists(d):
            shutil.rmtree(d)
    res = dict(time=utc(), removed=dict((d, not os.path.exists(d)) for d in (SRV, STATE)))
    res['clean'] = all(res['removed'].values())
    if st:
        try:
            evidence(st['work'], 'cleanup.json', res, st['operator'])
        except OSError:
            pass
    print(json.dumps(res, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description='PR15: учебное реагирование на инцидент (Astra)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('init')
    s.add_argument('--work', required=True)
    s.add_argument('--variant', type=int, required=True)
    s = sub.add_parser('info')
    s.add_argument('--work', required=True)
    s.add_argument('--field')
    sub.add_parser('preserve')
    s = sub.add_parser('timeline')
    s.add_argument('--work', required=True)
    s = sub.add_parser('localize')
    s.add_argument('--work', required=True)
    sub.add_parser('restore')
    s = sub.add_parser('report')
    s.add_argument('--work', required=True)
    sub.add_parser('capture')
    sub.add_parser('reveal')
    sub.add_parser('check')
    s = sub.add_parser('cleanup')
    s.add_argument('--yes', action='store_true')
    a = ap.parse_args()
    # команды, не требующие доступа к рабочему каталогу из состояния
    fns = {'init': cmd_init, 'info': cmd_info, 'preserve': cmd_preserve, 'timeline': cmd_timeline,
           'localize': cmd_localize, 'restore': cmd_restore, 'report': cmd_report, 'capture': cmd_capture,
           'reveal': cmd_reveal, 'check': cmd_check, 'cleanup': cmd_cleanup}
    fn = fns.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(a)


if __name__ == '__main__':
    main()
