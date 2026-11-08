#!/usr/bin/env python3
"""PR16 (Astra): итоговое упражнение «красная и синяя команды».

На учебной Astra разворачивается учебная служба pr16-svc с набором слабостей (по варианту). Красная
команда (Kali, скрипт pr16_red.py) выполняет ТОЛЬКО разрешённые проверки из опубликованного каталога
— безопасные, доступные только на чтение. Синяя команда (Astra) обнаруживает эти проверки по журналу
службы и устраняет слабости, приводя конфигурацию к целевому состоянию. Затем роли меняются:
выполняется повторная проверка, подтверждающая, что слабости закрыты, и проводится разбор.

Служба отдаёт по сети только факты о своей текущей конфигурации (баннер, значения параметров,
открыт ли порт по учебному набору правил, права учебного секрета); каждый запрос записывается в
журнал. Все объекты учебные (в /srv/pr16 и /var/lib/pr16); настоящие службы, /var/log и системный
межсетевой экран не затрагиваются. Набор присутствующих слабостей и целевые значения до команды
reveal не раскрываются; файл /var/lib/pr16/state.json до reveal не открывают.

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
import socket
import stat
import sys
import time


def _utf8_stdio():
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()

STATE = '/var/lib/pr16'
SRV = '/srv/pr16'
CONF = SRV + '/service.conf'
RULES = SRV + '/firewall.rules'
ALLOW = SRV + '/conf/allow.hosts'
SECRET = SRV + '/data/token.secret'
LOG = SRV + '/log/service.log'
DEFAULT_PORT = 7016

# Каталог разрешённых проверок. id -> (заголовок, ключ факта, как «слабо»).
CATALOG = [
    ('c1_banner', 'Раскрытие версии в баннере', 'баннер службы содержит номер версии'),
    ('c2_anon', 'Анонимный доступ', 'allow_anonymous=yes'),
    ('c3_tls', 'Передача без шифрования', 'require_tls=no'),
    ('c4_debug', 'Открыт отладочный порт', 'отладочный порт разрешён для всех'),
    ('c5_secret', 'Секрет доступен другим на чтение', 'права секрета дают доступ группе/прочим'),
    ('c6_lockout', 'Нет ограничения неуспешных входов', 'login_max_fail=0 или меньше 5'),
    ('c7_admin', 'Админ-порт открыт для всех', 'админ-порт разрешён «from any»'),
    ('c8_allow', 'Устаревшая запись в списке доступа', 'в allow.hosts есть устаревший узел'),
    ('c9_errors', 'Подробные ошибки раскрывают пути', 'verbose_errors=yes'),
]
CAT_IDS = [c[0] for c in CATALOG]
CAT_TITLE = dict((c[0], c[1]) for c in CATALOG)


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


def wfile(path, text, mode=0o644):
    with open(path, 'w', encoding='utf-8') as s:
        s.write(text)
    os.chmod(path, mode)


def rfile(path, default=None):
    try:
        with open(path, encoding='utf-8', errors='replace') as s:
            return s.read()
    except (IOError, OSError):
        return default


def load_state():
    path = STATE + '/state.json'
    if not os.path.exists(path):
        raise SystemExit('сессия не инициализирована: sudo python3 pr16.py init ...')
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


# ------------------------------------------------------------------ variant
def variant_params(v):
    nn = '%02d' % v
    return dict(variant=v, nn=nn, astra='10.50.%d.10' % v, kali='10.50.%d.20' % v,
                ex='EX-16-%s' % nn, debug_port=9000 + v, admin_port=8000 + v,
                version='1.%d.%d' % (v % 5 + 1, v % 9), stale_host='203.0.113.%d' % v, port=DEFAULT_PORT)


def present_set(v, nonce):
    h = hashlib.sha256((nonce + str(v)).encode()).digest()
    ids = list(CAT_IDS)
    # детерминированная перестановка по хешу, берём первые 6
    order = sorted(range(len(ids)), key=lambda i: h[i])
    chosen = sorted((ids[i] for i in order[:6]), key=CAT_IDS.index)
    return chosen


# ------------------------------------------------------------------ config read / facts
def read_conf(path=CONF):
    d = {}
    for line in (rfile(path) or '').splitlines():
        line = line.split('#', 1)[0].strip()
        if '=' in line:
            k, val = line.split('=', 1)
            d[k.strip()] = val.strip()
    return d


def port_state(port, rules_text=None):
    """open — есть незакомментированное 'allow tcp <port> from any'; иначе denied."""
    rules_text = rfile(RULES) if rules_text is None else rules_text
    openp = False
    for line in (rules_text or '').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        m = re.match(r'(allow|deny)\s+tcp\s+(\d+)\s+from\s+(\S+)', line)
        if m and int(m.group(2)) == port:
            if m.group(1) == 'deny' and m.group(3) in ('any', '0.0.0.0/0'):
                return 'denied'
            if m.group(1) == 'allow' and m.group(3) in ('any', '0.0.0.0/0'):
                openp = True
    return 'open' if openp else 'denied'


def secret_mode():
    try:
        return '%04o' % stat.S_IMODE(os.lstat(SECRET).st_mode)
    except OSError:
        return '----'


def stale_present(p):
    for line in (rfile(ALLOW) or '').splitlines():
        if line.split('#', 1)[0].strip() == p['stale_host']:
            return True
    return False


def fact(check_id, p):
    conf = read_conf()
    if check_id == 'c1_banner':
        on = conf.get('banner_version', 'off') == 'on'
        return 'banner=pr16-svc/%s' % p['version'] if on else 'banner=pr16-svc'
    if check_id == 'c2_anon':
        return 'allow_anonymous=%s' % conf.get('allow_anonymous', 'no')
    if check_id == 'c3_tls':
        return 'require_tls=%s' % conf.get('require_tls', 'yes')
    if check_id == 'c4_debug':
        return 'port_%d=%s' % (p['debug_port'], port_state(p['debug_port']))
    if check_id == 'c5_secret':
        return 'secret_mode=%s' % secret_mode()
    if check_id == 'c6_lockout':
        return 'login_max_fail=%s' % conf.get('login_max_fail', '5')
    if check_id == 'c7_admin':
        return 'port_%d=%s' % (p['admin_port'], port_state(p['admin_port']))
    if check_id == 'c8_allow':
        return 'stale_host=%s' % ('present' if stale_present(p) else 'absent')
    if check_id == 'c9_errors':
        return 'verbose_errors=%s' % conf.get('verbose_errors', 'no')
    return 'unknown'


def is_weak(check_id, p):
    """Истина для harden-check/reveal (красная команда оценивает независимо по факту)."""
    f = fact(check_id, p)
    val = f.split('=', 1)[1] if '=' in f else f
    if check_id == 'c1_banner':
        return '/' in val
    if check_id == 'c2_anon':
        return val == 'yes'
    if check_id == 'c3_tls':
        return val == 'no'
    if check_id in ('c4_debug', 'c7_admin'):
        return val == 'open'
    if check_id == 'c5_secret':
        try:
            return bool(int(val, 8) & 0o077)
        except ValueError:
            return True
    if check_id == 'c6_lockout':
        try:
            return int(val) < 5
        except ValueError:
            return True
    if check_id == 'c8_allow':
        return val == 'present'
    if check_id == 'c9_errors':
        return val == 'yes'
    return False


# ------------------------------------------------------------------ init
def write_service(v, p, present):
    nn = p['nn']
    for d, mode in ((SRV, 0o755), (SRV + '/conf', 0o755), (SRV + '/data', 0o755), (SRV + '/log', 0o755)):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, mode)
    conf = {
        'banner_version': 'on' if 'c1_banner' in present else 'off',
        'allow_anonymous': 'yes' if 'c2_anon' in present else 'no',
        'require_tls': 'no' if 'c3_tls' in present else 'yes',
        'login_max_fail': '0' if 'c6_lockout' in present else '5',
        'verbose_errors': 'yes' if 'c9_errors' in present else 'no',
    }
    text = '# pr16-svc configuration, variant %s\nservice_name=pr16-svc\n' % nn
    for k in ('banner_version', 'allow_anonymous', 'require_tls', 'login_max_fail', 'verbose_errors'):
        text += '%s=%s\n' % (k, conf[k])
    wfile(CONF, text, 0o644)
    # firewall.rules: 22 и порт службы — всегда из подсети; отладочный/админ порт — слабо «from any»
    sub = '10.50.%d.0/24' % v
    lines = ['# pr16 learning firewall ruleset, variant %s' % nn,
             'allow tcp 22 from %s' % sub,
             'allow tcp %d from %s' % (p['port'], sub)]
    lines.append('allow tcp %d from %s' % (p['debug_port'], 'any' if 'c4_debug' in present else sub))
    lines.append('allow tcp %d from %s' % (p['admin_port'], 'any' if 'c7_admin' in present else sub))
    lines.append('deny tcp 0 from any')
    wfile(RULES, '\n'.join(lines) + '\n', 0o644)
    allow = ['# hosts allowed to administer pr16-svc, variant %s' % nn, p['astra'], p['kali']]
    if 'c8_allow' in present:
        allow.append(p['stale_host'])
    wfile(ALLOW, '\n'.join(allow) + '\n', 0o644)
    wfile(SECRET, 'pr16-token-v%s-%s\n' % (nn, os.urandom(8).hex()), 0o644 if 'c5_secret' in present else 0o600)
    wfile(LOG, '%s pr16-svc v%s started\n' % (utc(), nn), 0o644)
    for pth in (CONF, RULES, ALLOW, SECRET, LOG, SRV + '/conf', SRV + '/data', SRV + '/log'):
        try:
            os.chown(pth, 0, 0)
        except OSError:
            pass


def cmd_init(a):
    need_root()
    op = operator()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('вариант должен быть от 1 до 27')
    if os.path.exists(STATE) or os.path.exists(SRV):
        raise SystemExit('объекты ПР16 уже существуют; вернитесь к снимку или выполните cleanup --yes')
    p = variant_params(v)
    work = os.path.abspath(a.work)
    for d in (work, os.path.join(work, 'evidence')):
        if not os.path.isdir(d):
            os.makedirs(d)
        give(d, op)
    os.makedirs(STATE)
    os.chmod(STATE, 0o755)
    nonce = os.urandom(16).hex()
    present = present_set(v, nonce)
    write_service(v, p, present)
    st = dict(variant=v, operator=op, work=work, nonce=nonce, created=utc(), present=present,
              port=p['port'], debug_port=p['debug_port'], admin_port=p['admin_port'], version=p['version'],
              stale_host=p['stale_host'], revealed=None)
    save_state(st)
    catalog = [dict(id=i, title=CAT_TITLE[i]) for i in CAT_IDS]
    ses = dict(variant=v, nn=p['nn'], astra=p['astra'], kali=p['kali'], ex=p['ex'], service='pr16-svc',
               port=p['port'], debug_port=p['debug_port'], admin_port=p['admin_port'],
               conf=CONF, rules=RULES, allow=ALLOW, secret=SECRET, log=LOG, srv=SRV,
               catalog=catalog, work=work, created=st['created'])
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True, ensure_ascii=False)
    give(os.path.join(work, 'session.json'), op)
    evidence(work, 'init.json', dict(session=ses), op)
    print('Вариант %s: учебная служба pr16-svc развёрнута (%s).' % (p['nn'], SRV))
    print('%s: красная команда выполняет ТОЛЬКО разрешённые проверки каталога (%d шт.);' % (p['ex'], len(CAT_IDS)))
    print('синяя команда обнаруживает их по %s и устраняет слабости.' % LOG)
    print('Endpoint службы: %s:%d. Отладочный порт %d, админ-порт %d.' % (p['astra'], p['port'], p['debug_port'],
                                                                          p['admin_port']))
    print('Каталог: ' + ', '.join('%s (%s)' % (i, CAT_TITLE[i]) for i in CAT_IDS))


def cmd_info(a):
    ses = load_session(a.work)
    if a.field:
        if a.field not in ses:
            raise SystemExit('нет поля %s; есть: %s' % (a.field, ', '.join(sorted(ses))))
        val = ses[a.field]
        if isinstance(val, list):
            print(json.dumps(val, ensure_ascii=False))
        else:
            print(val)
    else:
        print(json.dumps(ses, indent=2, sort_keys=True, ensure_ascii=False))


# ------------------------------------------------------------------ serve (read-only endpoint)
def log_line(ip, text):
    try:
        with open(LOG, 'a', encoding='utf-8') as s:
            s.write('%s %s %s\n' % (utc(), ip, text))
    except (IOError, OSError):
        pass


def cmd_serve(a):
    need_root()
    st = load_state()
    p = variant_params(st['variant'])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((a.bind, a.port))
    except (IOError, OSError) as e:
        raise SystemExit('не удаётся открыть %s:%d — %s' % (a.bind, a.port, e))
    srv.listen(16)
    srv.settimeout(1.0)
    log_line('-', 'SERVE start port=%d' % a.port)
    print('Служба pr16-svc слушает %s:%d, %d с (Ctrl+C — остановить). Журнал: %s' % (a.bind, a.port, a.seconds, LOG))
    deadline = time.time() + a.seconds
    conns = 0
    try:
        while time.time() < deadline:
            try:
                c, addr = srv.accept()
            except socket.timeout:
                continue
            conns += 1
            ip = addr[0]
            c.settimeout(5)
            log_line(ip, 'CONNECT')
            buf = b''
            try:
                while b'\n' not in buf:
                    chunk = c.recv(256)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 4096:
                        break
                for raw in buf.decode('utf-8', 'replace').splitlines():
                    req = raw.strip()
                    if not req:
                        continue
                    if req == 'HELLO':
                        c.sendall(('pr16-svc exercise endpoint, variant %s (read-only)\n' % p['nn']).encode())
                    elif req == 'CATALOG':
                        c.sendall(('catalog=%s\n' % ','.join(CAT_IDS)).encode())
                    elif req.startswith('CHECK '):
                        cid = req[6:].strip()
                        if cid in CAT_IDS:
                            log_line(ip, 'CHECK %s' % cid)
                            c.sendall((fact(cid, p) + '\n').encode())
                        else:
                            c.sendall(b'ERR unknown check\n')
                    else:
                        c.sendall(b'ERR unknown request\n')
            except (IOError, OSError):
                pass
            finally:
                c.close()
    except KeyboardInterrupt:
        print('\nОстановлено.')
    finally:
        srv.close()
        log_line('-', 'SERVE stop connections=%d' % conns)
    print('Соединений обработано: %d.' % conns)


# ------------------------------------------------------------------ detection (blue)
def parse_log():
    """Из журнала службы: по каждому источнику набор проверок CHECK."""
    seen = {}
    rx = re.compile(r'^\S+\s+(\S+)\s+CHECK\s+(\S+)$')
    for line in (rfile(LOG) or '').splitlines():
        m = rx.match(line)
        if m:
            ip, cid = m.group(1), m.group(2)
            seen.setdefault(ip, {}).setdefault(cid, 0)
            seen[ip][cid] += 1
    return seen


def read_detections(work):
    path = os.path.join(os.path.abspath(work), 'detections.csv')
    if not os.path.exists(path):
        raise SystemExit('нет файла detections.csv (шаг 4)')
    rows, errors = [], []
    with open(path, encoding='utf-8') as s:
        rd = csv.DictReader(s)
        need = ['check', 'source_ip', 'count']
        if rd.fieldnames is None or [x.strip() for x in rd.fieldnames] != need:
            raise SystemExit('заголовок detections.csv должен быть: ' + ','.join(need))
        for i, r in enumerate(rd, 2):
            r = dict((k.strip(), (v or '').strip()) for k, v in r.items())
            if r['check'] not in CAT_IDS:
                errors.append('строка %d: check — один из каталога' % i)
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', r['source_ip']):
                errors.append('строка %d: source_ip — IPv4' % i)
            if not r['count'].isdigit():
                errors.append('строка %d: count — целое' % i)
            rows.append(r)
    return rows, errors


def cmd_detect(a):
    work = os.path.abspath(a.work)
    rows, errors = read_detections(work)
    seen = parse_log()
    for r in rows:
        print('  %-10s %-16s %s' % (r['check'], r['source_ip'], r['count']))
    if errors:
        print('\n'.join(errors))
        sys.exit(2)
    out = os.path.join(work, 'evidence', 'detect.json')
    with open(out, 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), detections=rows, log_sources=seen), s, indent=2, ensure_ascii=False)
    print('Формат detections.csv верен; в журнале источников: %d.' % len(seen))


# ------------------------------------------------------------------ harden-check (blue)
def harden_table(st):
    p = variant_params(st['variant'])
    present = st['present']
    rows = []
    for cid in CAT_IDS:
        if cid not in present:
            continue
        weak = is_weak(cid, p)
        rows.append(dict(check=cid, title=CAT_TITLE[cid], fact=fact(cid, p), hardened=not weak))
    return rows


def cmd_harden_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    rows = harden_table(st)
    for r in rows:
        print('%-4s %-10s %-36s %s' % ('OK' if r['hardened'] else 'СЛАБО', r['check'], r['title'], r['fact']))
    ok = all(r['hardened'] for r in rows)
    evidence(st['work'], 'harden-check.json', dict(time=utc(), all_hardened=ok, rows=rows), op)
    if ok:
        print('Все слабости варианта устранены (%d из %d).' % (len(rows), len(rows)))
    else:
        left = [r['check'] for r in rows if not r['hardened']]
        print('Не устранено: %s. Исправьте конфигурацию/правила/права и повторите.' % ', '.join(left))
        sys.exit(2)


# ------------------------------------------------------------------ scoring from red findings
def load_findings(work, name):
    f = load_evidence(work, name)
    if not f:
        return None
    return f


def weak_ids(findings):
    return sorted(r['check'] for r in findings.get('results', []) if r.get('verdict') == 'weak')


def cmd_report(a):
    work = os.path.abspath(a.work)
    path = os.path.join(work, 'report.md')
    if not os.path.exists(path):
        raise SystemExit('нет файла report.md (шаг 6)')
    text = rfile(path) or ''
    low = text.lower()
    sections = ['Сценарий', 'Разведка', 'Обнаружение', 'Усиление', 'Повторная проверка', 'Выводы']
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-22s %s' % ('OK' if ok else 'FAIL', cid, detail))

    for sec in sections:
        add('раздел:' + sec, sec.lower() in low, 'есть раздел «%s»' % sec)
    ses = load_session(work)
    add('номер упражнения', ses['ex'] in text, 'указан %s' % ses['ex'])
    words = len(text.split())
    add('объём', 60 <= words <= 1500, 'слов: %d' % words)
    ok = all(c['ok'] for c in checks)
    with open(os.path.join(work, 'evidence', 'report-check.json'), 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), ok=ok, words=words, checks=checks), s, indent=2, ensure_ascii=False)
    shutil.copyfile(path, os.path.join(work, 'evidence', 'report.md'))
    if not ok:
        print('Отчёт не принят: добавьте недостающие разделы и сведения.')
        sys.exit(2)
    print('Отчёт принят.')


def cmd_reveal(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    p = variant_params(st['variant'])
    present = st['present']
    base = load_findings(work, 'findings-baseline.json')
    rech = load_findings(work, 'findings-recheck.json')
    found = weak_ids(base) if base else []
    rfound = weak_ids(rech) if rech else []
    rows = []
    for cid in CAT_IDS:
        rows.append(dict(check=cid, title=CAT_TITLE[cid], present=cid in present,
                         red_baseline='weak' if cid in found else 'ok',
                         red_recheck='weak' if cid in rfound else 'ok',
                         hardened=not is_weak(cid, p) if cid in present else True))
    missed_find = sorted(set(present) - set(found))
    not_fixed = [cid for cid in present if is_weak(cid, p)]
    still_weak_recheck = sorted(set(rfound) & set(present))
    rep = dict(time=utc(), present=present, red_found_baseline=found, red_found_recheck=rfound,
               missed_by_red=missed_find, not_fixed_by_blue=not_fixed, rows=rows)
    st['revealed'] = utc()
    save_state(st)
    evidence(work, 'reveal.json', rep, op)
    print('Слабости варианта (всего %d): %s' % (len(present), ', '.join(present)))
    print('%-10s %-34s %-8s %-9s %-9s %s' % ('check', 'название', 'в варианте', 'база(red)', 'повтор', 'устранено'))
    for r in rows:
        print('%-10s %-34s %-8s %-9s %-9s %s' % (r['check'], r['title'], 'да' if r['present'] else 'нет',
              r['red_baseline'], r['red_recheck'], 'да' if r['hardened'] else 'НЕТ'))
    print('Красная не нашла из присутствующих: %s' % (', '.join(missed_find) or 'нет'))
    print('Синяя не устранила: %s' % (', '.join(not_fixed) or 'нет'))
    print('В повторной проверке всё ещё слабо: %s' % (', '.join(still_weak_recheck) or 'нет'))


def cmd_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    present = set(st['present'])
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-24s %s' % ('OK' if ok else 'FAIL', cid, detail))

    base = load_findings(work, 'findings-baseline.json')
    rech = load_findings(work, 'findings-recheck.json')
    add('red baseline', bool(base), 'есть findings-baseline.json' if base else 'нет базовой разведки красной команды')
    add('red recheck', bool(rech), 'есть findings-recheck.json' if rech else 'нет повторной разведки')
    if base:
        found = set(weak_ids(base))
        add('red found all', present <= found, 'красная нашла все присутствующие слабости (%d)' % len(present)
            if present <= found else 'не найдены: %s' % ', '.join(sorted(present - found)))
    # detection
    drows, derr = ([], ['нет detections.csv'])
    try:
        drows, derr = read_detections(work)
    except SystemExit as e:
        derr = [str(e)]
    seen = parse_log()
    det_ok = not derr
    seen_checks = set()
    for ip in seen:
        seen_checks |= set(seen[ip])
    given_checks = set(r['check'] for r in drows)
    det_ok = det_ok and given_checks == seen_checks and bool(seen_checks)
    for r in drows:
        s = seen.get(r['source_ip'], {})
        if r['check'] not in s:
            det_ok = False
    add('detection', det_ok, 'таблица обнаружения соответствует журналу (%d проверок)' % len(seen_checks)
        if det_ok else 'detections.csv не совпадает с журналом службы')
    # hardening
    hc = harden_table(st)
    hard_ok = all(r['hardened'] for r in hc) and bool(hc)
    add('hardening', hard_ok, 'все слабости варианта устранены' if hard_ok
        else 'не устранено: %s' % ', '.join(r['check'] for r in hc if not r['hardened']))
    # recheck confirms closed
    if rech:
        rweak = set(weak_ids(rech)) & present
        add('recheck closed', not rweak, 'повторная проверка: слабостей не осталось'
            if not rweak else 'в повторной проверке всё ещё слабо: %s' % ', '.join(sorted(rweak)))
    else:
        add('recheck closed', False, 'нет повторной разведки')
    rc = load_evidence(work, 'report-check.json')
    add('report', bool(rc and rc.get('ok')), 'отчёт со всеми разделами' if rc and rc.get('ok') else 'отчёт не принят')
    add('reveal', bool(st.get('revealed')), 'разбор выполнен (reveal)')
    passed = all(c['ok'] for c in checks)
    evidence(work, 'final-check.json', dict(time=utc(), passed=passed, checks=checks), op)
    print('passed: %s' % passed)
    if not passed:
        sys.exit(2)


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
    ap = argparse.ArgumentParser(description='PR16: упражнение «красная и синяя команды» (Astra)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('init')
    s.add_argument('--work', required=True)
    s.add_argument('--variant', type=int, required=True)
    s = sub.add_parser('info')
    s.add_argument('--work', required=True)
    s.add_argument('--field')
    s = sub.add_parser('serve')
    s.add_argument('--port', type=int, default=DEFAULT_PORT)
    s.add_argument('--bind', default='0.0.0.0')
    s.add_argument('--seconds', type=int, default=900)
    s = sub.add_parser('detect')
    s.add_argument('--work', required=True)
    sub.add_parser('harden-check')
    s = sub.add_parser('report')
    s.add_argument('--work', required=True)
    sub.add_parser('reveal')
    sub.add_parser('check')
    s = sub.add_parser('cleanup')
    s.add_argument('--yes', action='store_true')
    a = ap.parse_args()
    fns = {'init': cmd_init, 'info': cmd_info, 'serve': cmd_serve, 'detect': cmd_detect,
           'harden-check': cmd_harden_check, 'report': cmd_report, 'reveal': cmd_reveal, 'check': cmd_check,
           'cleanup': cmd_cleanup}
    fn = fns.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(a)


if __name__ == '__main__':
    main()
