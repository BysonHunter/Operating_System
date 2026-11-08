#!/usr/bin/env python3
"""PR14 (Astra): training container runtime and checks for the isolation analysis.

The runtime starts a process in Linux namespaces (mnt, uts, ipc, pid, net, user, cgroup) with a
pivot_root into a small image, maps container root to an unprivileged host UID range, drops
capabilities, sets no_new_privs and places the container into a cgroup with memory, pids and cpu
limits (cgroup v1 or v2). Everything is described by an INI profile written by the student.

Standard library only (ctypes for unshare, mount, pivot_root, capset, prctl), Python 3.5 syntax.
Commands that touch system objects are run with sudo from the ordinary training account.
"""
import argparse
import configparser
import csv
import ctypes
import datetime
import errno
import fcntl
import hashlib
import io
import json
import os
import platform
import pwd
import re
import select
import shutil
import signal
import socket
import stat
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pr14_probe as probe  # noqa: E402  (same kit directory)

STATE = '/var/lib/pr14'
ROOTFS = STATE + '/rootfs'
SRV = '/srv/pr14'
DATA = SRV + '/data'
HOSTDIR = SRV + '/host'
RUNDIR = '/run/pr14'
KIT = os.path.dirname(os.path.abspath(__file__))
CGNAME = 'pr14'
EPOCH = 1793491200  # 2026-11-01T00:00:00Z, fixed mtime of the image files
POOL = ['CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'NET_BIND_SERVICE', 'SYS_CHROOT']
MUST_ABSENT = ['NET_RAW', 'SYS_ADMIN', 'NET_ADMIN']
DANGEROUS = {'SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_BOOT', 'SYS_TIME', 'NET_ADMIN', 'NET_RAW',
             'DAC_READ_SEARCH', 'MAC_ADMIN', 'MAC_OVERRIDE', 'BPF', 'PERFMON', 'SYSLOG', 'SETFCAP', 'SETPCAP',
             'LINUX_IMMUTABLE', 'MKNOD', 'AUDIT_CONTROL'}
NS_FLAGS = {'mnt': 0x00020000, 'uts': 0x04000000, 'ipc': 0x08000000, 'user': 0x10000000, 'pid': 0x20000000,
            'net': 0x40000000, 'cgroup': 0x02000000}
REQUIRED_NS = ['mnt', 'uts', 'ipc', 'pid', 'net', 'user']
SYSDIRS = ['bin', 'sbin', 'lib', 'lib32', 'lib64', 'libx32', 'usr']
DEVICES = ['null', 'zero', 'full', 'random', 'urandom']
TESTS = ('probe', 'net', 'mem', 'pids', 'cpu', 'hold')
PROPS = ['kernel', 'pid', 'net', 'mnt', 'uts', 'ipc', 'user', 'host-files', 'privileges', 'resources', 'meminfo']
CONTEXTS = ['vm', 'shared', 'restricted']

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REMOUNT = 1, 2, 4, 8, 32
MS_NOATIME, MS_NODIRATIME, MS_BIND, MS_REC = 1024, 2048, 4096, 16384
MS_PRIVATE, MS_RELATIME, MS_STRICTATIME = 1 << 18, 1 << 21, 1 << 24
ST_RDONLY, ST_NOSUID, ST_NODEV, ST_NOEXEC, ST_NOATIME, ST_NODIRATIME, ST_RELATIME = 1, 2, 4, 8, 1024, 2048, 4096
MNT_DETACH = 2
PR_SET_PDEATHSIG, PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 1, 24, 38, 47, 4
SYS_PIVOT_ROOT = {'x86_64': 155, 'aarch64': 41}


def _utf8_stdio():
    """Python 3.5 under a C/POSIX locale writes ASCII: switch the console streams to UTF-8."""
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()


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
        with open(path, encoding='utf-8') as s:
            return s.read()
    except (IOError, OSError):
        return default


def variant_params(v):
    combos = []
    for i in range(len(POOL)):
        for j in range(i + 1, len(POOL)):
            for k in range(j + 1, len(POOL)):
                combos.append([POOL[i], POOL[j], POOL[k]])
    caps = combos[(v * 7) % len(combos)]
    nn = '%02d' % v
    return dict(variant=v, nn=nn, astra='10.50.%d.10' % v, kali='10.50.%d.20' % v,
                hostname='ct-v' + nn, shared_hostname='sh-v' + nn,
                uid_base=100000 * v, uid_count=65536, caps=caps, caps_text=' '.join(caps),
                memory_mb=48 + 16 * ((v - 1) % 6), pids=16 + 4 * ((v - 1) % 7),
                cpu=(10, 15, 20, 25, 30, 35, 40, 45, 50)[(v * 4) % 9],
                kali_port=14000 + v, bind_port=600 + v, peer='10.50.%d.20:%d' % (v, 14000 + v))


def load_state():
    path = STATE + '/state.json'
    if not os.path.exists(path):
        raise SystemExit('сессия не инициализирована: sudo python3 pr14.py init ...')
    with open(path, encoding='utf-8') as s:
        return json.load(s)


def save_state(st):
    path = STATE + '/state.json'
    with open(path + '.tmp', 'w', encoding='utf-8') as s:
        json.dump(st, s, indent=2, sort_keys=True)
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


def environment():
    """Kernel features needed by the runtime."""
    env = dict(kernel=os.uname().release, machine=os.uname().machine, python=platform.python_version())
    env['ns'] = dict((n, os.path.exists('/proc/self/ns/' + n)) for n in NS_FLAGS)
    env['max_user_namespaces'] = int((rfile('/proc/sys/user/max_user_namespaces') or '-1').strip())
    uc = rfile('/proc/sys/kernel/unprivileged_userns_clone')
    env['unprivileged_userns_clone'] = int(uc.strip()) if uc else None
    env['cgroup'] = Cgroup.detect()
    return env


# ------------------------------------------------------------------ cgroups v1 / v2
class Cgroup(object):
    CONTROLLERS = ('memory', 'pids', 'cpu')

    @staticmethod
    def v1_mounts():
        res = {}
        for line in (rfile('/proc/self/mountinfo') or '').splitlines():
            left, _, right = line.partition(' - ')
            f, r = left.split(), right.split()
            if len(r) >= 3 and r[0] == 'cgroup':
                for opt in r[2].split(','):
                    if opt in ('memory', 'pids', 'cpu', 'cpuacct'):
                        res.setdefault(opt, f[4])
        return res

    @staticmethod
    def detect():
        enabled = {}
        for line in (rfile('/proc/cgroups') or '').splitlines()[1:]:
            f = line.split()
            if len(f) >= 4:
                enabled[f[0]] = f[3] == '1'
        if os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
            ctl = (rfile('/sys/fs/cgroup/cgroup.controllers') or '').split()
            return dict(version=2, controllers=dict((c, c in ctl) for c in Cgroup.CONTROLLERS))
        m = Cgroup.v1_mounts()
        return dict(version=1, controllers=dict((c, c in m and enabled.get(c, False)) for c in Cgroup.CONTROLLERS),
                    mounts=m)

    def __init__(self, label, limits):
        self.label = label
        self.limits = limits
        self.info = Cgroup.detect()
        self.v2 = self.info['version'] == 2
        self.paths = {}
        self.notes = []

    @staticmethod
    def put(path, value):
        with open(path, 'w') as s:
            s.write(str(value))

    def create(self):
        if self.v2:
            root = '/sys/fs/cgroup'
            want = [c for c in self.CONTROLLERS if self.info['controllers'].get(c)]
            for c in want:
                try:
                    self.put(root + '/cgroup.subtree_control', '+' + c)
                except OSError:
                    pass
            parent = root + '/' + CGNAME
            os.makedirs(parent, exist_ok=True)
            for c in want:
                try:
                    self.put(parent + '/cgroup.subtree_control', '+' + c)
                except OSError as e:
                    self.notes.append('контроллер %s не включён: %s' % (c, e))
            p = parent + '/' + self.label
            self.remove_dir(p)
            os.mkdir(p)
            self.paths['unified'] = p
            lim = self.limits
            if lim.get('memory'):
                self.put(p + '/memory.max', lim['memory'])
                if os.path.exists(p + '/memory.swap.max'):
                    self.put(p + '/memory.swap.max', 0)
            if lim.get('pids'):
                self.put(p + '/pids.max', lim['pids'])
            if lim.get('cpu'):
                self.put(p + '/cpu.max', '%d 100000' % (lim['cpu'] * 1000))
        else:
            mounts = self.info['mounts']
            for c in ('memory', 'pids', 'cpu', 'cpuacct'):
                if c not in mounts or c in [k for k, v in self.paths.items()]:
                    continue
                base = mounts[c]
                same = [k for k in self.paths if mounts.get(k) == base]
                if same:
                    self.paths[c] = self.paths[same[0]]
                    continue
                parent = base + '/' + CGNAME
                os.makedirs(parent, exist_ok=True)
                p = parent + '/' + self.label
                self.remove_dir(p)
                os.mkdir(p)
                self.paths[c] = p
            lim = self.limits
            if lim.get('memory'):
                if 'memory' not in self.paths:
                    raise SystemExit('контроллер memory недоступен: см. диагностику (cgroup_enable=memory)')
                p = self.paths['memory']
                self.put(p + '/memory.limit_in_bytes', lim['memory'])
                try:
                    self.put(p + '/memory.swappiness', 0)
                except OSError as e:
                    self.notes.append('memory.swappiness: %s' % e)
                if os.path.exists(p + '/memory.memsw.limit_in_bytes'):
                    try:
                        self.put(p + '/memory.memsw.limit_in_bytes', lim['memory'])
                    except OSError as e:
                        self.notes.append('memory.memsw.limit_in_bytes: %s' % e)
                else:
                    self.notes.append('нет memory.memsw (учёт подкачки выключен): ограничение действует на ОЗУ')
            if lim.get('pids'):
                if 'pids' not in self.paths:
                    raise SystemExit('контроллер pids недоступен')
                self.put(self.paths['pids'] + '/pids.max', lim['pids'])
            if lim.get('cpu'):
                if 'cpu' not in self.paths:
                    raise SystemExit('контроллер cpu недоступен')
                self.put(self.paths['cpu'] + '/cpu.cfs_period_us', 100000)
                self.put(self.paths['cpu'] + '/cpu.cfs_quota_us', lim['cpu'] * 1000)

    def attach(self, pid):
        done = set()
        for p in self.paths.values():
            if p in done:
                continue
            self.put(p + '/cgroup.procs', pid)
            done.add(p)

    @staticmethod
    def kv(path):
        res = {}
        for line in (rfile(path) or '').splitlines():
            f = line.split()
            if len(f) == 2:
                try:
                    res[f[0]] = int(f[1])
                except ValueError:
                    pass
        return res

    @staticmethod
    def num(path):
        v = rfile(path)
        if v is None:
            return None
        v = v.strip().split()[0] if v.strip() else ''
        if v == 'max':
            return 'max'
        try:
            return int(v)
        except ValueError:
            return v

    def stats(self):
        r = dict(version=2 if self.v2 else 1, paths=self.paths, notes=self.notes)
        if self.v2:
            p = self.paths.get('unified')
            if not p:
                return r
            me = self.kv(p + '/memory.events')
            pe = self.kv(p + '/pids.events')
            cs = self.kv(p + '/cpu.stat')
            cpumax = (rfile(p + '/cpu.max') or '').split()
            r.update(memory_limit=self.num(p + '/memory.max'), memory_peak=self.num(p + '/memory.peak'),
                     memory_max_events=me.get('max'), oom_kill=me.get('oom_kill'), pids_limit=self.num(p + '/pids.max'),
                     pids_peak=self.num(p + '/pids.peak'), pids_max_events=pe.get('max'),
                     cpu_quota=cpumax[0] if cpumax else None, cpu_usage_us=cs.get('usage_usec'),
                     nr_periods=cs.get('nr_periods'), nr_throttled=cs.get('nr_throttled'),
                     throttled_us=cs.get('throttled_usec'))
        else:
            p = self.paths
            if 'memory' in p:
                oc = self.kv(p['memory'] + '/memory.oom_control')
                r.update(memory_limit=self.num(p['memory'] + '/memory.limit_in_bytes'),
                         memory_peak=self.num(p['memory'] + '/memory.max_usage_in_bytes'),
                         memory_max_events=self.num(p['memory'] + '/memory.failcnt'), oom_kill=oc.get('oom_kill'))
            if 'pids' in p:
                pe = (rfile(p['pids'] + '/pids.events') or '').split()
                r.update(pids_limit=self.num(p['pids'] + '/pids.max'),
                         pids_max_events=int(pe[1]) if len(pe) == 2 and pe[1].isdigit() else None)
            if 'cpu' in p:
                cs = self.kv(p['cpu'] + '/cpu.stat')
                r.update(cpu_quota=self.num(p['cpu'] + '/cpu.cfs_quota_us'), nr_periods=cs.get('nr_periods'),
                         nr_throttled=cs.get('nr_throttled'),
                         throttled_us=(cs['throttled_time'] // 1000) if 'throttled_time' in cs else None)
            if 'cpuacct' in p:
                u = self.num(p['cpuacct'] + '/cpuacct.usage')
                r['cpu_usage_us'] = u // 1000 if isinstance(u, int) else None
        return r

    @staticmethod
    def remove_dir(p):
        if not os.path.isdir(p):
            return
        for _ in range(50):
            procs = (rfile(p + '/cgroup.procs') or '').split()
            for pid in procs:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
            try:
                os.rmdir(p)
                return
            except OSError:
                time.sleep(0.1)
        raise SystemExit('не удаётся удалить cgroup %s' % p)

    def remove(self):
        for p in sorted(set(self.paths.values())):
            try:
                self.remove_dir(p)
            except SystemExit as e:
                self.notes.append(str(e))

    @staticmethod
    def remove_all():
        res = []
        info = Cgroup.detect()
        bases = ['/sys/fs/cgroup'] if info['version'] == 2 else sorted(set(info['mounts'].values()))
        for b in bases:
            parent = b + '/' + CGNAME
            if not os.path.isdir(parent):
                continue
            for n in os.listdir(parent):
                if os.path.isdir(os.path.join(parent, n)):
                    Cgroup.remove_dir(os.path.join(parent, n))
            Cgroup.remove_dir(parent)
            res.append(parent)
        return res


# ------------------------------------------------------------------ profile
def parse_size(v):
    m = re.match(r'^\s*(\d+)\s*([KkMmGg])?(i?[Bb])?\s*$', v)
    if not m:
        raise ValueError('размер памяти: %s (пример: 64M)' % v)
    return int(m.group(1)) * {None: 1, 'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}[(m.group(2) or '').lower() or None]


def load_profile(path):
    cp = configparser.ConfigParser(inline_comment_prefixes=('#', ';'), interpolation=None)
    cp.optionxform = str
    try:
        with open(path, encoding='utf-8') as s:
            cp.read_file(s)
    except (configparser.Error, IOError, OSError) as e:
        raise ValueError('профиль не прочитан: %s' % e)
    for sec in ('container', 'mounts', 'limits'):
        if not cp.has_section(sec):
            raise ValueError('нет секции [%s]' % sec)
    c = dict(cp.items('container'))
    known = {'hostname', 'namespaces', 'uid_map', 'gid_map', 'user', 'capabilities', 'no_new_privs', 'readonly_root'}
    unknown = sorted(set(c) - known)
    if unknown:
        raise ValueError('неизвестные параметры [container]: %s' % ', '.join(unknown))
    prof = dict(path=os.path.abspath(path), sha256=sha256_file(path))
    prof['hostname'] = c.get('hostname', '').strip()
    if prof['hostname'] and not re.match(r'^[a-z0-9][a-z0-9-]{0,62}$', prof['hostname']):
        raise ValueError('hostname: латинские буквы, цифры и дефис')
    ns = c.get('namespaces', '').split()
    bad = [n for n in ns if n not in NS_FLAGS]
    if bad:
        raise ValueError('неизвестные пространства имён: %s (допустимы: %s)' % (' '.join(bad), ' '.join(sorted(NS_FLAGS))))
    if 'mnt' not in ns:
        raise ValueError('пространство имён mnt обязательно: среда выполнения меняет корень контейнера')
    prof['namespaces'] = [n for n in ['mnt', 'uts', 'ipc', 'pid', 'net', 'user', 'cgroup'] if n in ns]
    for key in ('uid_map', 'gid_map'):
        v = c.get(key, '').split()
        if v:
            if len(v) != 3 or not all(x.isdigit() for x in v):
                raise ValueError('%s: три числа «внутри снаружи количество»' % key)
            v = [int(x) for x in v]
            if v[2] < 1 or v[2] > 1 << 20:
                raise ValueError('%s: количество от 1 до 1048576' % key)
        prof[key] = v or None
    if 'user' in ns and not (prof['uid_map'] and prof['gid_map']):
        raise ValueError('с пространством имён user нужны uid_map и gid_map')
    if 'user' not in ns and (prof['uid_map'] or prof['gid_map']):
        raise ValueError('uid_map/gid_map действуют только с пространством имён user')
    u = c.get('user', '0').strip()
    if not u.isdigit():
        raise ValueError('user: числовой uid внутри контейнера')
    prof['user'] = int(u)
    caps = c.get('capabilities', '').replace(',', ' ').split()
    if [x.upper() for x in caps] == ['ALL']:
        prof['capabilities'] = 'ALL'
    else:
        norm = []
        for x in caps:
            x = x.upper()
            x = x[4:] if x.startswith('CAP_') else x
            if x not in probe.CAPS:
                raise ValueError('неизвестная capability: %s' % x)
            norm.append(x)
        prof['capabilities'] = sorted(set(norm), key=probe.CAPS.index)
    for key in ('no_new_privs', 'readonly_root'):
        v = c.get(key, 'no').strip().lower()
        if v not in ('yes', 'no'):
            raise ValueError('%s: yes или no' % key)
        prof[key] = v == 'yes'
    mounts = []
    for tgt, val in cp.items('mounts'):
        f = val.split()
        if len(f) != 2 or f[1] not in ('ro', 'rw'):
            raise ValueError('монтирование %s: «источник ro|rw»' % tgt)
        src = os.path.realpath(f[0])
        if not (src == SRV or src.startswith(SRV + '/')) or not os.path.isdir(src):
            raise ValueError('монтирование %s: источник должен быть каталогом внутри %s' % (tgt, SRV))
        if tgt not in ('/data', '/hostdata'):
            raise ValueError('монтирование %s: допустимы точки /data и /hostdata' % tgt)
        mounts.append(dict(target=tgt, source=src, mode=f[1]))
    prof['mounts'] = sorted(mounts, key=lambda m: m['target'])
    lim = dict(cp.items('limits'))
    unknown = sorted(set(lim) - {'memory', 'pids', 'cpu'})
    if unknown:
        raise ValueError('неизвестные параметры [limits]: %s' % ', '.join(unknown))
    limits = {}
    if lim.get('memory', '').strip():
        limits['memory'] = parse_size(lim['memory'])
        if limits['memory'] < 16 << 20:
            raise ValueError('memory: не меньше 16M, иначе не запустится интерпретатор')
    if lim.get('pids', '').strip():
        if not lim['pids'].strip().isdigit() or int(lim['pids']) < 4:
            raise ValueError('pids: целое не меньше 4')
        limits['pids'] = int(lim['pids'])
    if lim.get('cpu', '').strip():
        m = re.match(r'^\s*(\d+)\s*%\s*$', lim['cpu'])
        if not m or not 1 <= int(m.group(1)) <= 400:
            raise ValueError('cpu: процент от 1% до 400% (пример: 20%)')
        limits['cpu'] = int(m.group(1))
    prof['limits'] = limits
    return prof


def profile_text_shared(p):
    return ('# PR14 v%s: контейнер со СЛАБОЙ изоляцией (для сравнения). Не исправляйте этот файл.\n'
            '[container]\nhostname = %s\nnamespaces = mnt uts\nuid_map =\ngid_map =\nuser = 0\n'
            'capabilities = ALL\nno_new_privs = no\nreadonly_root = no\n\n'
            '[mounts]\n/data = %s rw\n/hostdata = %s rw\n\n'
            '[limits]\nmemory =\npids =\ncpu =\n') % (p['nn'], p['shared_hostname'], DATA, HOSTDIR)


def check_profile(path, p):
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))

    try:
        prof = load_profile(path)
    except ValueError as e:
        add('syntax', False, str(e))
        return None, checks
    add('syntax', True, 'профиль разобран')
    miss = [n for n in REQUIRED_NS if n not in prof['namespaces']]
    add('namespaces', not miss, 'есть: %s; не хватает: %s%s' % (' '.join(prof['namespaces']), ' '.join(miss) or '—',
                                                               '' if 'cgroup' in prof['namespaces'] else
                                                               ' (cgroup — рекомендуется)'))
    add('hostname', prof['hostname'] == p['hostname'], 'ожидается %s, указано %s' % (p['hostname'], prof['hostname'] or '—'))
    want = [0, p['uid_base'], p['uid_count']]
    add('uid_map', prof['uid_map'] == want, 'ожидается «%s», указано «%s»%s' % (
        ' '.join(map(str, want)), ' '.join(map(str, prof['uid_map'] or [])) or '—',
        '; root контейнера = root хоста!' if prof['uid_map'] and prof['uid_map'][1] == 0 else ''))
    add('gid_map', prof['gid_map'] == want, 'ожидается «%s», указано «%s»' % (
        ' '.join(map(str, want)), ' '.join(map(str, prof['gid_map'] or [])) or '—'))
    add('user', prof['user'] == 0, 'служба работает от uid 0 внутри контейнера (отображённого на %d)' % p['uid_base'])
    caps = prof['capabilities']
    if caps == 'ALL':
        add('capabilities', False, 'ALL: все привилегии root — нарушение минимальных привилегий')
    else:
        extra = [c for c in caps if c not in p['caps']]
        missing = [c for c in p['caps'] if c not in caps]
        add('capabilities', not extra and not missing, 'нужны ровно: %s; лишние: %s%s; не хватает: %s' % (
            ' '.join(p['caps']), ' '.join(extra) or '—',
            ' (опасные: %s)' % ' '.join(c for c in extra if c in DANGEROUS) if any(c in DANGEROUS for c in extra) else '',
            ' '.join(missing) or '—'))
    add('no_new_privs', prof['no_new_privs'], 'no_new_privs = yes: setuid-файлы не повышают права')
    add('readonly_root', prof['readonly_root'], 'readonly_root = yes: образ не изменяется из контейнера')
    m = dict((x['target'], x) for x in prof['mounts'])
    add('mount /data', m.get('/data', {}).get('source') == DATA and m.get('/data', {}).get('mode') == 'rw',
        '/data = %s rw (том данных службы)' % DATA)
    add('mount /hostdata', m.get('/hostdata', {}).get('source') == HOSTDIR and m.get('/hostdata', {}).get('mode') == 'ro',
        '/hostdata = %s ro (справочные данные хоста только для чтения)' % HOSTDIR)
    lim = prof['limits']
    add('memory', lim.get('memory') == p['memory_mb'] << 20, 'ожидается %dM, указано %s' % (
        p['memory_mb'], '%dM' % (lim['memory'] >> 20) if lim.get('memory') else '—'))
    add('pids', lim.get('pids') == p['pids'], 'ожидается %d, указано %s' % (p['pids'], lim.get('pids', '—')))
    add('cpu', lim.get('cpu') == p['cpu'], 'ожидается %d%%, указано %s' % (p['cpu'], '%d%%' % lim['cpu'] if lim.get('cpu') else '—'))
    env = environment()
    add('kernel: namespaces', all(env['ns'][n] for n in REQUIRED_NS),
        'ядро %s: %s' % (env['kernel'], ', '.join('%s=%s' % (n, 'да' if env['ns'][n] else 'нет') for n in REQUIRED_NS)))
    add('kernel: user namespaces', env['max_user_namespaces'] > 0,
        'user.max_user_namespaces = %d' % env['max_user_namespaces'])
    cg = env['cgroup']
    add('kernel: cgroups', all(cg['controllers'].values()), 'cgroup v%d: %s' % (
        cg['version'], ', '.join('%s=%s' % (c, 'да' if v else 'нет') for c, v in sorted(cg['controllers'].items()))))
    return prof, checks


# ------------------------------------------------------------------ libc
_libc = None


def libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL('libc.so.6', use_errno=True)
        _libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
        _libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _libc.unshare.argtypes = [ctypes.c_int]
        _libc.sethostname.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        _libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        _libc.syscall.restype = ctypes.c_long
    return _libc


def _chk(rc, what):
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, '%s: %s' % (what, os.strerror(e)))


def _b(x):
    return None if x is None else x.encode()


def sys_unshare(flags):
    _chk(libc().unshare(flags), 'unshare')


def sys_mount(src, tgt, fstype, flags, data=None):
    _chk(libc().mount(_b(src), _b(tgt), _b(fstype), flags, _b(data)), 'mount %s' % tgt)


def sys_umount(tgt, flags=0):
    _chk(libc().umount2(_b(tgt), flags), 'umount %s' % tgt)


def sys_prctl(opt, a2=0, a3=0, a4=0, a5=0):
    _chk(libc().prctl(opt, a2, a3, a4, a5), 'prctl %d' % opt)


def sys_pivot_root(new, old):
    nr = SYS_PIVOT_ROOT.get(os.uname().machine)
    if nr is None:
        raise OSError(errno.ENOSYS, 'pivot_root: неизвестная архитектура')
    _chk(libc().syscall(ctypes.c_long(nr), ctypes.c_char_p(_b(new)), ctypes.c_char_p(_b(old))), 'pivot_root')


def sys_sethostname(name):
    n = name.encode()
    _chk(libc().sethostname(n, len(n)), 'sethostname')


class CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]


def sys_capset(mask):
    hdr = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    for i in range(2):
        part = (mask >> (32 * i)) & 0xffffffff
        data[i].effective = part
        data[i].permitted = part
        data[i].inheritable = 0
    _chk(libc().capset(ctypes.byref(hdr), data), 'capset')


def remount_bind(target, ro=False, nosuid=False, nodev=False):
    """Bind remount that keeps the locked flags of the source (required inside a user namespace)."""
    f = os.statvfs(target).f_flag
    flags = MS_BIND | MS_REMOUNT
    if ro or f & ST_RDONLY:
        flags |= MS_RDONLY
    if nosuid or f & ST_NOSUID:
        flags |= MS_NOSUID
    if nodev or f & ST_NODEV:
        flags |= MS_NODEV
    if f & ST_NOEXEC:
        flags |= MS_NOEXEC
    if f & ST_NOATIME:
        flags |= MS_NOATIME
    elif f & ST_RELATIME:
        flags |= MS_RELATIME
    else:
        flags |= MS_STRICTATIME
    if f & ST_NODIRATIME:
        flags |= MS_NODIRATIME
    sys_mount(None, target, None, flags)


def lo_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), 0x8913, struct.pack('16sh22s', b'lo', 0, b'\0' * 22))
        flags = struct.unpack('16sh', r[:18])[1]
        fcntl.ioctl(s.fileno(), 0x8914, struct.pack('16sh22s', b'lo', flags | 0x1 | 0x40, b'\0' * 22))
    finally:
        s.close()


# ------------------------------------------------------------------ container start
def setup_mounts(prof, report):
    restricted = 'user' in prof['namespaces'] or prof['capabilities'] != 'ALL'
    r = ROOTFS
    sys_mount(None, '/', None, MS_REC | MS_PRIVATE)
    sys_mount(r, r, None, MS_BIND | MS_REC)
    for d in SYSDIRS:
        host = '/' + d
        if os.path.islink(host) or not os.path.isdir(host) or not os.path.isdir(r + host):
            continue
        sys_mount(host, r + host, None, MS_BIND | MS_REC)
        remount_bind(r + host, ro=True, nosuid=restricted, nodev=True)
    for m in prof['mounts']:
        sys_mount(m['source'], r + m['target'], None, MS_BIND)
        remount_bind(r + m['target'], ro=m['mode'] == 'ro', nosuid=restricted, nodev=True)
    sys_mount('tmpfs', r + '/tmp', 'tmpfs', MS_NOSUID | MS_NODEV, 'mode=1777,size=16m')
    sys_mount('tmpfs', r + '/run', 'tmpfs', MS_NOSUID | MS_NODEV, 'mode=755,size=4m')
    os.makedirs(r + '/run/systemd', exist_ok=True)
    wfile(r + '/run/systemd/container', 'pr14\n')
    sys_mount('tmpfs', r + '/dev', 'tmpfs', MS_NOSUID | MS_NOEXEC, 'mode=755,size=64k')
    for d in DEVICES:
        open(r + '/dev/' + d, 'w').close()
        sys_mount('/dev/' + d, r + '/dev/' + d, None, MS_BIND)
    for name, tgt in (('fd', '/proc/self/fd'), ('stdin', '/proc/self/fd/0'), ('stdout', '/proc/self/fd/1'),
                      ('stderr', '/proc/self/fd/2')):
        os.symlink(tgt, r + '/dev/' + name)
    sys_mount('proc', r + '/proc', 'proc', MS_NOSUID | MS_NODEV | MS_NOEXEC)
    masked = []
    if restricted:
        for sub in ('sys', 'sysrq-trigger', 'irq', 'bus'):
            p = r + '/proc/' + sub
            if os.path.exists(p):
                try:
                    sys_mount(p, p, None, MS_BIND | MS_REC)
                    remount_bind(p, ro=True, nosuid=True, nodev=True)
                    masked.append('/proc/' + sub)
                except OSError as e:
                    report.append('не удалось защитить /proc/%s: %s' % (sub, e))
    report.append('только чтение: ' + (', '.join(masked) or 'нет'))
    os.chdir(r)
    try:
        sys_pivot_root('.', '.oldroot')
        os.chdir('/')
        sys_umount('/.oldroot', MNT_DETACH)
        report.append('корень сменён pivot_root, прежний корень отмонтирован')
    except OSError as e:
        os.chroot('.')
        os.chdir('/')
        report.append('pivot_root недоступен (%s), использован chroot' % e)
    if prof['readonly_root']:
        remount_bind('/', ro=True)


def drop_privileges(prof):
    caps = prof['capabilities']
    if caps != 'ALL':
        keep = set(probe.CAPS.index(c) for c in caps)
        last = int((rfile('/proc/sys/kernel/cap_last_cap') or '40').strip())
        for c in range(last + 1):
            if c not in keep:
                sys_prctl(PR_CAPBSET_DROP, c)
        try:
            sys_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
        except OSError:
            pass
        sys_capset(sum(1 << c for c in keep))
    if prof['no_new_privs']:
        sys_prctl(PR_SET_NO_NEW_PRIVS, 1)


def drop_all_caps():
    """The intermediate process only waits for the container: it keeps no privileges."""
    try:
        last = int((rfile('/proc/sys/kernel/cap_last_cap') or '40').strip())
        for c in range(last + 1):
            sys_prctl(PR_CAPBSET_DROP, c)
        sys_capset(0)
    except OSError:
        pass


def container_init(prof, cmd, w_ready, out_fd, env):
    """Runs as the first process of the container (PID 1 if a PID namespace is used)."""
    report = []
    try:
        sys_prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        os.setsid()
        setup_mounts(prof, report)
        if 'uts' in prof['namespaces'] and prof['hostname']:
            sys_sethostname(prof['hostname'])
        if 'net' in prof['namespaces']:
            lo_up()
        drop_privileges(prof)
        if prof['user']:
            os.setgroups([])
            os.setresgid(prof['user'], prof['user'], prof['user'])
            os.setresuid(prof['user'], prof['user'], prof['user'])
    except Exception as e:
        os.write(out_fd, ('ОШИБКА ЗАПУСКА КОНТЕЙНЕРА: %s\n' % e).encode())
        os.write(w_ready, ('E %s\n' % str(e).replace('\n', ' ')).encode())
        os._exit(125)
    os.write(w_ready, ('R %s\n' % json.dumps(report, ensure_ascii=False)).encode())
    os.close(w_ready)
    pid = os.fork()
    if pid == 0:
        if out_fd is not None and out_fd > 2:
            os.dup2(out_fd, 1)
            os.dup2(out_fd, 2)
            os.close(out_fd)
        try:
            os.execvpe(cmd[0], cmd, env)
        except OSError as e:
            os.write(2, ('exec %s: %s\n' % (cmd[0], e)).encode())
            os._exit(127)

    def forward(sig, _frame):
        try:
            os.kill(pid, sig)
        except OSError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    code = 0
    while True:
        try:
            p, st = os.wait()
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        if p == pid:
            code = os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st)
    os._exit(code)


def readline(fd, timeout=30):
    buf = b''
    end = time.time() + timeout
    while not buf.endswith(b'\n'):
        r, _, _ = select.select([fd], [], [], max(0.1, end - time.time()))
        if not r:
            if time.time() > end:
                raise SystemExit('нет ответа от процесса контейнера')
            continue
        ch = os.read(fd, 1)
        if not ch:
            break
        buf += ch
    return buf.decode('utf-8', 'replace').strip()


def start_container(prof, label, cmd, capture=True, timeout=180, echo=True):
    """Fork the container, set it up and wait for it. Returns a run record."""
    os.makedirs(RUNDIR, exist_ok=True)
    cg = Cgroup(label, prof['limits'])
    cg.create()
    flags = 0
    for n in prof['namespaces']:
        flags |= NS_FLAGS[n]
    r_sync, w_sync = os.pipe()
    r_ready, w_ready = os.pipe()
    r_out, w_out = os.pipe() if capture else (None, None)
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/tmp',
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONIOENCODING': 'utf-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'container': 'pr14', 'TERM': os.environ.get('TERM', 'dumb')}
    if prof['hostname']:
        env['HOSTNAME'] = prof['hostname']
    t0 = time.time()
    pid = os.fork()
    if pid == 0:  # intermediate process: unshare, then fork the container init
        try:
            os.close(w_sync)
            os.close(r_ready)
            if r_out is not None:
                os.close(r_out)
            sys_prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
            os.read(r_sync, 1)
            sys_unshare(flags)
            os.write(w_ready, b'U\n')
            os.read(r_sync, 1)
            if 'user' in prof['namespaces']:
                os.setgroups([])
                os.setresgid(0, 0, 0)
                os.setresuid(0, 0, 0)
            child = os.fork()
            if child == 0:
                container_init(prof, cmd, w_ready, w_out if w_out is not None else 2, env)
            os.write(w_ready, ('P %d\n' % child).encode())
            os.close(w_ready)
            drop_all_caps()
            if w_out is not None:
                os.close(w_out)
            _, st = os.waitpid(child, 0)
            os._exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st))
        except Exception as e:
            try:
                os.write(w_ready, ('E %s\n' % e).encode())
            except OSError:
                pass
            os._exit(125)
    os.close(r_sync)
    os.close(w_ready)
    if w_out is not None:
        os.close(w_out)
    rec = dict(label=label, started=utc(t0), command=cmd, host_pid_intermediate=pid)
    try:
        cg.attach(pid)
        os.write(w_sync, b'1')
        msg = readline(r_ready)
        if msg.startswith('E'):
            raise SystemExit('unshare не выполнен: %s' % msg[2:])
        if 'user' in prof['namespaces']:
            u, g = prof['uid_map'], prof['gid_map']
            with open('/proc/%d/uid_map' % pid, 'w') as s:
                s.write('%d %d %d\n' % tuple(u))
            with open('/proc/%d/gid_map' % pid, 'w') as s:
                s.write('%d %d %d\n' % tuple(g))
        os.write(w_sync, b'2')
        os.close(w_sync)
        init_pid, report = None, []
        for _ in range(2):
            msg = readline(r_ready)
            if msg.startswith('P '):
                init_pid = int(msg[2:])
            elif msg.startswith('R '):
                report = json.loads(msg[2:])
            elif msg.startswith('E '):
                rec['setup_error'] = msg[2:]
                break
        os.close(r_ready)
        rec.update(host_pid_init=init_pid, setup=report)
        info = dict(label=label, init_pid=init_pid, intermediate_pid=pid, cgroup=cg.paths, profile=prof['path'],
                    started=rec['started'])
        with open('%s/%s.json' % (RUNDIR, label), 'w') as s:
            json.dump(info, s)
        out = []
        if r_out is not None:
            deadline = t0 + timeout
            killed = False
            while True:
                r, _, _ = select.select([r_out], [], [], 0.5)
                if r:
                    chunk = os.read(r_out, 65536)
                    if not chunk:
                        break
                    out.append(chunk)
                    if echo:
                        sys.stdout.write(chunk.decode('utf-8', 'replace'))
                        sys.stdout.flush()
                if time.time() > deadline and not killed:
                    if init_pid:
                        try:
                            os.killpg(init_pid, signal.SIGKILL)
                        except OSError:
                            pass
                    for p in (init_pid, pid):
                        if p:
                            try:
                                os.kill(p, signal.SIGKILL)
                            except OSError:
                                pass
                    killed = True
                    rec['timeout'] = True
            os.close(r_out)
        _, st = os.waitpid(pid, 0)
        rec['rc'] = os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st)
        rec['seconds'] = round(time.time() - t0, 2)
        rec['output'] = b''.join(out).decode('utf-8', 'replace')
        time.sleep(0.2)
        rec['cgroup'] = cg.stats()
    finally:
        cg.remove()
        try:
            os.unlink('%s/%s.json' % (RUNDIR, label))
        except OSError:
            pass
    rec['cgroup_removed'] = not any(os.path.isdir(p) for p in cg.paths.values())
    return rec


def parse_output(text):
    res, progress = None, None
    for line in text.splitlines():
        if line.startswith('PR14-RESULT '):
            try:
                res = json.loads(line[12:])
            except ValueError:
                pass
        elif line.startswith('PR14-PROGRESS '):
            progress = line[14:]
    return res, progress


# ------------------------------------------------------------------ commands
def install_probe():
    """The probe is part of the image: a copy owned by root, readable by the mapped container root."""
    src = os.path.join(KIT, 'pr14_probe.py')
    dst = ROOTFS + '/opt/pr14/pr14_probe.py'
    if not os.path.exists(dst) or sha256_file(dst) != sha256_file(src):
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)
    return sha256_file(dst)


def cmd_init(a):
    need_root()
    op = operator()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('вариант должен быть от 1 до 27')
    if os.path.exists(STATE) or os.path.exists(SRV):
        raise SystemExit('объекты ПР14 уже существуют; вернитесь к снимку или выполните cleanup --yes')
    env = environment()
    if os.uname().machine not in SYS_PIVOT_ROOT:
        print('ВНИМАНИЕ: архитектура %s — вместо pivot_root будет использован chroot' % os.uname().machine)
    miss = [n for n in REQUIRED_NS if not env['ns'][n]]
    if miss:
        raise SystemExit('ядро не поддерживает пространства имён: %s' % ' '.join(miss))
    if env['max_user_namespaces'] == 0:
        raise SystemExit('user.max_user_namespaces = 0: создание user namespace запрещено (см. диагностику)')
    if not all(env['cgroup']['controllers'].values()):
        print('ВНИМАНИЕ: недоступны контроллеры cgroup: %s (см. диагностику)' % ', '.join(
            c for c, ok in env['cgroup']['controllers'].items() if not ok))
    p = variant_params(v)
    work = os.path.abspath(a.work)
    for d in (work, os.path.join(work, 'evidence'), os.path.join(work, 'profiles')):
        if not os.path.isdir(d):
            os.makedirs(d)
        give(d, op)
    # image
    os.makedirs(STATE, mode=0o755)
    os.chmod(STATE, 0o755)
    os.makedirs(ROOTFS)
    os.chmod(ROOTFS, 0o755)
    for d in ('proc', 'dev', 'tmp', 'run', 'data', 'hostdata', 'opt', 'opt/pr14', 'mnt', 'root', 'etc', '.oldroot'):
        os.makedirs(os.path.join(ROOTFS, d), exist_ok=True)
        os.chmod(os.path.join(ROOTFS, d), 0o755)
    os.chmod(ROOTFS + '/tmp', 0o1777)
    os.chmod(ROOTFS + '/root', 0o700)
    layout = {}
    for d in SYSDIRS:
        host = '/' + d
        if os.path.islink(host):
            os.symlink(os.readlink(host), ROOTFS + host)
            layout[d] = 'symlink -> ' + os.readlink(host)
        elif os.path.isdir(host):
            os.mkdir(ROOTFS + host)
            layout[d] = 'bind ro'
    etc = {
        'passwd': 'root:x:0:0:root:/root:/bin/sh\nsvc:x:1:1:service:/data:/bin/sh\n'
                  'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n',
        'group': 'root:x:0:\nsvc:x:1:\nnogroup:x:65534:\n',
        'hostname': p['hostname'] + '\n',
        'hosts': '127.0.0.1 localhost\n',
        'resolv.conf': '# сеть контейнера не использует DNS\n',
        'nsswitch.conf': 'passwd: files\ngroup: files\nhosts: files\n',
        'os-release': 'NAME="PR14 training image"\nID=pr14\nVERSION_ID="v%s"\nPRETTY_NAME="PR14 training image v%s"\n' % (
            p['nn'], p['nn']),
        'pr14-image': 'image pr14-v%s; system directories are read-only binds of the host\n' % p['nn'],
    }
    image = {'opt/pr14/pr14_probe.py': install_probe()}
    for name, text in sorted(etc.items()):
        path = ROOTFS + '/etc/' + name
        wfile(path, text, 0o644)
        os.utime(path, (EPOCH, EPOCH))
        image['etc/' + name] = sha256_file(path)
    # data
    os.makedirs(SRV)
    os.chmod(SRV, 0o755)
    os.makedirs(DATA)
    os.chown(DATA, p['uid_base'], p['uid_base'])
    os.chmod(DATA, 0o770)
    os.makedirs(HOSTDIR)
    os.chmod(HOSTDIR, 0o755)
    wfile(HOSTDIR + '/reference.txt', 'справочные данные хоста для службы, вариант %s\n' % p['nn'], 0o644)
    token = 'PR14-SECRET-v%s-%s' % (p['nn'], os.urandom(12).hex())
    wfile(HOSTDIR + '/secret.txt', token + '\n', 0o600)
    os.makedirs(RUNDIR, exist_ok=True)
    # profiles
    shared = os.path.join(work, 'profiles', 'shared.ini')
    wfile(shared, profile_text_shared(p), 0o644)
    give(shared, op)
    st = dict(variant=v, operator=op, work=work, created=utc(), secret_sha256=hashlib.sha256(token.encode()).hexdigest(),
              shared_profile=shared, shared_sha256=sha256_file(shared), profile=None, profile_sha256=None, image=image,
              environment=env)
    save_state(st)
    ses = dict(p, work=work, kit=KIT, data=DATA, hostdir=HOSTDIR, rootfs=ROOTFS, shared_profile=shared,
               profile='profiles/restricted.ini', cgroup_version=env['cgroup']['version'], created=st['created'])
    with open(os.path.join(work, 'session.json'), 'w', encoding='utf-8') as s:
        json.dump(ses, s, indent=2, sort_keys=True, ensure_ascii=False)
    give(os.path.join(work, 'session.json'), op)
    evidence(work, 'init.json', dict(session=ses, environment=env, image_layout=layout, image_files=image,
                                     secret_sha256=st['secret_sha256']), op)
    print('Вариант %s: образ %s, данные %s созданы.' % (p['nn'], ROOTFS, SRV))
    print('Ядро %s, cgroup v%d, user.max_user_namespaces=%d, unprivileged_userns_clone=%s' % (
        env['kernel'], env['cgroup']['version'], env['max_user_namespaces'], env['unprivileged_userns_clone']))
    print('Требования к контейнеру: hostname %s, root -> uid %d (65536 шт.), capabilities: %s, память %dM, '
          'процессов %d, CPU %d%%' % (p['hostname'], p['uid_base'], p['caps_text'], p['memory_mb'], p['pids'], p['cpu']))
    print('Профиль слабой изоляции для сравнения: %s' % shared)


def cmd_info(a):
    ses = load_session(a.work)
    if a.field:
        if a.field not in ses:
            raise SystemExit('нет поля %s; есть: %s' % (a.field, ', '.join(sorted(ses))))
        val = ses[a.field]
        print(' '.join(map(str, val)) if isinstance(val, list) else val)
    else:
        print(json.dumps(ses, indent=2, sort_keys=True, ensure_ascii=False))


def cmd_profile_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    p = variant_params(st['variant'])
    path = os.path.abspath(a.profile)
    prof, checks = check_profile(path, p)
    for c in checks:
        print('%-4s %-24s %s' % ('OK' if c['ok'] else 'FAIL', c['id'], c['detail']))
    ok = all(c['ok'] for c in checks)
    name = 'profile-check.json' if not a.name else 'profile-check-%s.json' % a.name
    evidence(st['work'], name, dict(time=utc(), profile=path, sha256=prof['sha256'] if prof else None, ok=ok,
                                    checks=checks, parsed=prof), op)
    if ok:
        dst = os.path.join(st['work'], 'evidence', 'profile-restricted.ini')
        shutil.copyfile(path, dst)
        give(dst, op)
        st['profile'] = path
        st['profile_sha256'] = prof['sha256']
        save_state(st)
        print('Профиль принят и зарегистрирован: %s' % path)
    else:
        print('Профиль не принят: исправьте строки FAIL и повторите проверку.')
        sys.exit(2)


def resolve_profile(st, path, label):
    path = os.path.abspath(path)
    prof = load_profile(path)
    if label == 'shared':
        if path != st['shared_profile'] or prof['sha256'] != st['shared_sha256']:
            raise SystemExit('метка shared: используйте неизменённый profiles/shared.ini')
    elif label == 'restricted':
        if not st.get('profile'):
            raise SystemExit('метка restricted: сначала profile-check')
        if path != st['profile'] or prof['sha256'] != st['profile_sha256']:
            raise SystemExit('профиль изменён после profile-check: повторите проверку')
    return prof


def test_command(test, a, ses, prof):
    py = os.environ.get('PR14_PYTHON', 'python3')
    base = [py, '/opt/pr14/pr14_probe.py']
    lim = prof['limits']
    if test == 'probe':
        return base + ['probe', '--label', a.label, '--files', '--caps', '--bind-port', str(ses['bind_port'])]
    if test == 'net':
        return base + ['net', '--peer', a.peer or ses['peer'], '--label', a.label]
    if test == 'mem':
        target = min(2 * (lim.get('memory') or (ses['memory_mb'] << 20)) >> 20, 256)
        return base + ['mem', '--target-mb', str(target)]
    if test == 'pids':
        return base + ['pids', '--max', str(min(2 * (lim.get('pids') or ses['pids']), 128))]
    if test == 'cpu':
        return base + ['cpu', '--seconds', '3']
    return base + ['hold', '--seconds', str(a.seconds)]


def cmd_run(a):
    need_root()
    st = load_state()
    op = st['operator']
    ses = load_session(st['work'])
    if not re.match(r'^[a-z0-9][a-z0-9-]{0,30}$', a.label):
        raise SystemExit('метка: строчные латинские буквы, цифры, дефис')
    if os.path.exists('%s/%s.json' % (RUNDIR, a.label)):
        info = json.load(open('%s/%s.json' % (RUNDIR, a.label)))
        if info.get('init_pid') and os.path.exists('/proc/%d' % info['init_pid']):
            raise SystemExit('контейнер с меткой %s уже работает (pid %d)' % (a.label, info['init_pid']))
    try:
        prof = resolve_profile(st, a.profile, a.label)
    except ValueError as e:
        raise SystemExit('профиль: %s' % e)
    cmd = list(a.command)
    if cmd and cmd[0] == '--':
        cmd = cmd[1:]
    if a.test:
        cmd = test_command(a.test, a, ses, prof)
    if not cmd:
        raise SystemExit('укажите --test или команду после --')
    interactive = not a.test and sys.stdin.isatty()
    install_probe()
    print('Контейнер %s: ns=%s, uid_map=%s, caps=%s, nnp=%s, ro_root=%s, лимиты=%s' % (
        a.label, ' '.join(prof['namespaces']), ' '.join(map(str, prof['uid_map'] or [])) or 'нет (root = root хоста)',
        prof['capabilities'] if prof['capabilities'] == 'ALL' else (' '.join(prof['capabilities']) or 'нет'),
        'да' if prof['no_new_privs'] else 'нет', 'да' if prof['readonly_root'] else 'нет',
        ', '.join('%s=%s' % kv for kv in sorted(prof['limits'].items())) or 'нет'))
    sys.stdout.flush()
    rec = start_container(prof, a.label, cmd, capture=not interactive, timeout=a.timeout, echo=True)
    res, progress = parse_output(rec.get('output', ''))
    rec.update(result=res, last_progress=progress, profile=dict((k, prof[k]) for k in prof if k != 'path'),
               profile_path=prof['path'], test=a.test)
    for name in (['probe-%s.txt' % a.label] if a.test == 'probe' else []):
        for d, key in ((DATA, 'data_file_host'), (HOSTDIR, 'hostdata_file_host')):
            path = os.path.join(d, name)
            if os.path.exists(path):
                s = os.stat(path)
                rec[key] = dict(path=path, uid=s.st_uid, gid=s.st_gid, mode='%04o' % stat.S_IMODE(s.st_mode))
    if res and res.get('secret', {}).get('sha256'):
        rec['secret_matches'] = res['secret']['sha256'] == st['secret_sha256']
    cgs = rec.get('cgroup', {})
    print('\nКод завершения: %s%s; время %.1f с' % (rec.get('rc'), ' (SIGKILL)' if rec.get('rc') == 137 else '',
                                                  rec.get('seconds', 0)))
    print('cgroup v%s: память пик %s, событий лимита %s, oom_kill %s; pids событий %s; cpu периодов %s, '
          'с ограничением %s' % (cgs.get('version'), cgs.get('memory_peak'), cgs.get('memory_max_events'),
                                 cgs.get('oom_kill'), cgs.get('pids_max_events'), cgs.get('nr_periods'),
                                 cgs.get('nr_throttled')))
    for key in ('data_file_host', 'hostdata_file_host'):
        if key in rec:
            print('На хосте: %s владелец %d:%d' % (rec[key]['path'], rec[key]['uid'], rec[key]['gid']))
    if a.test:
        name = 'run-%s-%s.json' % (a.label, a.test)
    else:
        name = 'run-%s-cmd.json' % a.label
    evidence(st['work'], name, rec, op)
    print('Сохранено: evidence/%s' % name)
    if rec.get('setup_error'):
        sys.exit(125)


def proc_status(pid):
    res = {}
    for line in (rfile('/proc/%d/status' % pid) or '').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            res[k] = v.strip()
    return res


def cmd_observe(a):
    need_root()
    st = load_state()
    path = '%s/%s.json' % (RUNDIR, a.label)
    if not os.path.exists(path):
        raise SystemExit('контейнер %s не запущен: запустите его в фоне (--test hold)' % a.label)
    info = json.load(open(path))
    init = info['init_pid']
    if not init or not os.path.exists('/proc/%d' % init):
        raise SystemExit('процесс %s уже завершился' % init)
    host_ns = dict((n, os.readlink('/proc/self/ns/' + n)) for n in NS_FLAGS if os.path.exists('/proc/self/ns/' + n))
    my_pidns = os.readlink('/proc/%d/ns/pid' % init)
    pids = []
    for d in os.listdir('/proc'):
        if d.isdigit():
            try:
                if os.readlink('/proc/%s/ns/pid' % d) == my_pidns:
                    pids.append(int(d))
            except OSError:
                pass
    cgprocs = set()
    for p in set(info['cgroup'].values()):
        cgprocs |= set(int(x) for x in (rfile(p + '/cgroup.procs') or '').split())
    members = sorted(set(pids) | cgprocs) if my_pidns != host_ns.get('pid') else sorted(cgprocs)
    procs = []
    for pid in members:
        s = proc_status(pid)
        if not s:
            continue
        procs.append(dict(pid=pid, name=s.get('Name'), uid_host=s.get('Uid', '').split()[:1],
                          nspid='/'.join(s.get('NSpid', '').split()), cap_eff=probe.decode_caps(s.get('CapEff')),
                          no_new_privs=s.get('NoNewPrivs'),
                          cmd=(rfile('/proc/%d/cmdline' % pid) or '').replace('\0', ' ').strip()[:100]))
    ns = {}
    for n in NS_FLAGS:
        try:
            ns[n] = dict(container=os.readlink('/proc/%d/ns/%s' % (init, n)), host=host_ns.get(n))
            ns[n]['same_as_host'] = ns[n]['container'] == ns[n]['host']
        except OSError:
            pass
    cg = {}
    for c, p in sorted(info['cgroup'].items()):
        files = {'memory': ['memory.limit_in_bytes', 'memory.usage_in_bytes', 'memory.max', 'memory.current'],
                 'pids': ['pids.max', 'pids.current'], 'cpu': ['cpu.cfs_quota_us', 'cpu.cfs_period_us', 'cpu.max'],
                 'cpuacct': ['cpuacct.usage'],
                 'unified': ['memory.max', 'memory.current', 'pids.max', 'pids.current', 'cpu.max']}.get(c, [])
        cg[c] = dict(path=p, values=dict((f, (rfile(p + '/' + f) or '').strip()) for f in files
                                         if os.path.exists(p + '/' + f)))
    rec = dict(time=utc(), label=a.label, init_pid=init, uid_map=' '.join((rfile('/proc/%d/uid_map' % init) or '').split()),
               gid_map=' '.join((rfile('/proc/%d/gid_map' % init) or '').split()), namespaces=ns, processes=procs,
               cgroup=cg, root=os.readlink('/proc/%d/root' % init) if os.path.exists('/proc/%d/root' % init) else None)
    print('Контейнер %s, init: pid %d на хосте' % (a.label, init))
    print('uid_map: %s' % rec['uid_map'])
    for n in sorted(ns):
        print('  ns %-6s %-22s %s' % (n, ns[n]['container'], 'как у хоста' if ns[n]['same_as_host'] else 'своё'))
    print('Процессы (вид с хоста):')
    for p in procs:
        print('  pid %-7d uid(хост) %-8s NSpid %-14s caps %-3d %s' % (
            p['pid'], (p['uid_host'] or ['?'])[0], p['nspid'], len(p['cap_eff']), p['cmd']))
    for c in sorted(cg):
        print('  cgroup %-8s %s %s' % (c, cg[c]['path'], ' '.join('%s=%s' % kv for kv in sorted(cg[c]['values'].items()))))
    evidence(st['work'], 'observe-%s.json' % a.label, rec, st['operator'])
    print('Сохранено: evidence/observe-%s.json' % a.label)


def collect(work):
    host = load_evidence(work, 'probe-host.json')
    kali = load_evidence(work, 'probe-kali.json')
    sh = load_evidence(work, 'run-shared-probe.json')
    rs = load_evidence(work, 'run-restricted-probe.json')
    missing = [n for n, x in (('probe-host.json', host), ('probe-kali.json', kali), ('run-shared-probe.json', sh),
                              ('run-restricted-probe.json', rs)) if not x]
    return host, kali, (sh or {}).get('result'), (rs or {}).get('result'), sh, rs, missing


def truth(host, kali, shp, rsp, shrun, rsrun):
    """Verdicts derived from the measurements: isolated / shared, relative to the Astra host."""
    t = {}
    full = lambda pr: pr['caps']['eff_hex'] == host['caps']['bnd_hex']  # all that host root may have
    for prop in PROPS:
        t[prop] = {}
    t['kernel']['vm'] = 'isolated' if kali['kernel']['boot_id'] != host['kernel']['boot_id'] else 'shared'
    for ctx, pr in (('shared', shp), ('restricted', rsp)):
        t['kernel'][ctx] = 'shared' if pr['kernel']['boot_id'] == host['kernel']['boot_id'] else 'isolated'
        for n in ('pid', 'net', 'mnt', 'uts', 'ipc', 'user'):
            t[n][ctx] = 'shared' if pr['ns'][n] == host['ns'][n] else 'isolated'
        t['host-files'][ctx] = 'shared' if pr['secret']['result'] == 'read' else 'isolated'
        t['privileges'][ctx] = 'shared' if (full(pr) and pr['identity']['uid_map'].split()[:2] == ['0', '0']) \
            else 'isolated'
        t['meminfo'][ctx] = 'shared' if pr['memory']['memtotal_kb'] == host['memory']['memtotal_kb'] else 'isolated'
    vmdiff = kali['kernel']['boot_id'] != host['kernel']['boot_id']
    for n in ('pid', 'net', 'mnt', 'uts', 'ipc', 'user', 'host-files', 'privileges', 'meminfo'):
        t[n]['vm'] = 'isolated' if vmdiff else 'shared'
    if kali['secret']['result'] == 'read':
        t['host-files']['vm'] = 'shared'
    t['resources']['vm'] = 'isolated'
    for ctx, run in (('shared', shrun), ('restricted', rsrun)):
        lim = (run or {}).get('profile', {}).get('limits', {})
        t['resources'][ctx] = 'isolated' if all(lim.get(k) for k in ('memory', 'pids', 'cpu')) else 'shared'
    return t


def cmd_compare(a):
    work = os.path.abspath(a.work)
    host, kali, shp, rsp, shrun, rsrun, missing = collect(work)
    if missing or not shp or not rsp:
        raise SystemExit('не хватает доказательств: %s' % (', '.join(missing) or 'результат probe в run-*.json'))
    cols = [('Astra', host), ('Kali VM', kali), ('shared', shp), ('restricted', rsp)]

    def row(name, fn):
        vals = []
        for _, pr in cols:
            try:
                vals.append(str(fn(pr)))
            except (KeyError, TypeError, IndexError):
                vals.append('—')
        return [name] + vals

    rows = [row('ядро (release)', lambda p: p['kernel']['release']),
            row('boot_id', lambda p: p['kernel']['boot_id'][:13]),
            row('hostname', lambda p: p['hostname'])]
    for n in ('pid', 'net', 'mnt', 'uts', 'ipc', 'user', 'cgroup'):
        rows.append(row('ns ' + n, lambda p, n=n: p['ns'][n].split(':')[-1].strip('[]')))
    rows += [row('uid / uid_map', lambda p: '%d / %s' % (p['identity']['uid'], p['identity']['uid_map'])),
             row('CapEff (число)', lambda p: len(p['caps']['eff'])),
             row('NoNewPrivs', lambda p: p['no_new_privs']),
             row('видимых процессов', lambda p: p['proc']['visible']),
             row('PID 1', lambda p: p['proc']['pid1'][:24]),
             row('интерфейсы', lambda p: ','.join(p['net']['interfaces'])),
             row('маршрут default', lambda p: p['net']['default_route']),
             row('MemTotal, МБ', lambda p: p['memory']['memtotal_kb'] // 1024),
             row('CPU (os.cpu_count)', lambda p: p['cpu']['count']),
             row('флаг hypervisor', lambda p: p['virt']['cpu_hypervisor_flag']),
             row('detect-virt / -c', lambda p: '%s / %s' % (p['virt']['detect_virt'], p['virt']['detect_container'])),
             row('секрет хоста', lambda p: p['secret']['result'])]
    lim = lambda run: ', '.join('%s=%s' % kv for kv in sorted(((run or {}).get('profile') or {}).get('limits', {}).items())) or 'нет'
    rows.append(['лимиты cgroup', '—', '—', lim(shrun), lim(rsrun)])
    w = [max(len(r[i]) for r in rows + [['Свойство', 'Astra', 'Kali VM', 'shared', 'restricted']]) for i in range(5)]
    hdr = ['Свойство', 'Astra (хост)', 'Kali (VM)', 'shared', 'restricted']
    w = [max(w[i], len(hdr[i])) for i in range(5)]
    lines = ['  '.join(hdr[i].ljust(w[i]) for i in range(5))]
    for r in rows:
        lines.append('  '.join(r[i].ljust(w[i]) for i in range(5)))
    text = '\n'.join(lines)
    print(text)
    out = os.path.join(work, 'evidence', 'matrix.txt')
    with open(out, 'w', encoding='utf-8') as s:
        s.write(text + '\n')
    with open(os.path.join(work, 'evidence', 'matrix.json'), 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), header=hdr, rows=rows), s, indent=2, ensure_ascii=False)
    print('\nСохранено: evidence/matrix.txt, evidence/matrix.json')


def read_isolation(work):
    path = os.path.join(os.path.abspath(work), 'isolation.csv')
    if not os.path.exists(path):
        raise SystemExit('нет файла isolation.csv (шаг 7)')
    rows, errors = {}, []
    with open(path, encoding='utf-8') as s:
        rd = csv.DictReader(s)
        need = ['property', 'vm', 'shared', 'restricted', 'evidence']
        if rd.fieldnames is None or [x.strip() for x in rd.fieldnames] != need:
            raise SystemExit('заголовок isolation.csv должен быть: ' + ','.join(need))
        for i, r in enumerate(rd, 2):
            r = dict((k.strip(), (v or '').strip()) for k, v in r.items())
            if r['property'] not in PROPS:
                errors.append('строка %d: property — одно из %s' % (i, ', '.join(PROPS)))
                continue
            for c in CONTEXTS:
                if r[c] not in ('isolated', 'shared'):
                    errors.append('строка %d: %s — isolated или shared' % (i, c))
            if not r['evidence']:
                errors.append('строка %d: пустое обоснование' % i)
            rows[r['property']] = r
    miss = [p for p in PROPS if p not in rows]
    if miss:
        errors.append('нет строк: %s' % ', '.join(miss))
    return rows, errors


def cmd_assess(a):
    work = os.path.abspath(a.work)
    rows, errors = read_isolation(work)
    if errors:
        print('\n'.join(errors))
        sys.exit(2)
    host, kali, shp, rsp, shrun, rsrun, missing = collect(work)
    if missing or not shp or not rsp:
        raise SystemExit('не хватает доказательств: %s' % ', '.join(missing))
    t = truth(host, kali, shp, rsp, shrun, rsrun)
    res, ok = [], 0
    for prop in PROPS:
        for c in CONTEXTS:
            good = rows[prop][c] == t[prop][c]
            ok += good
            res.append(dict(property=prop, context=c, given=rows[prop][c], measured=t[prop][c], ok=good))
    print('%-12s %-22s %-22s %-22s' % ('Свойство', 'vm', 'shared', 'restricted'))
    for prop in PROPS:
        cells = []
        for c in CONTEXTS:
            r = [x for x in res if x['property'] == prop and x['context'] == c][0]
            cells.append(('%s' % r['given']) if r['ok'] else '%s ≠ %s' % (r['given'], r['measured']))
        print('%-12s %-22s %-22s %-22s' % (prop, cells[0], cells[1], cells[2]))
    score = '%d/%d' % (ok, len(res))
    print('Совпадение с измерениями: %s' % score)
    out = os.path.join(work, 'evidence', 'assess.json')
    with open(out, 'w', encoding='utf-8') as s:
        json.dump(dict(time=utc(), score=score, results=res, rows=rows), s, indent=2, ensure_ascii=False)
    print('Сохранено: evidence/assess.json')


def cmd_check(a):
    need_root()
    st = load_state()
    op = st['operator']
    work = st['work']
    p = variant_params(st['variant'])
    checks = []

    def add(cid, ok, detail):
        checks.append(dict(id=cid, ok=bool(ok), detail=detail))
        print('%-4s %-28s %s' % ('OK' if ok else 'FAIL', cid, detail))

    ok_prof = bool(st.get('profile')) and os.path.exists(st['profile']) and sha256_file(st['profile']) == st['profile_sha256']
    add('profile', ok_prof, 'профиль restricted принят и не изменялся')
    host, kali, shp, rsp, shrun, rsrun, missing = collect(work)
    add('evidence', not missing and shp and rsp, 'probe Astra, Kali, shared, restricted: %s' % (
        'есть' if not missing else 'нет ' + ', '.join(missing)))
    if missing or not shp or not rsp:
        evidence(work, 'final-check.json', dict(time=utc(), passed=False, checks=checks), op)
        print('passed: False')
        sys.exit(2)
    add('vm boundary', kali['kernel']['boot_id'] != host['kernel']['boot_id'] and kali['secret']['result'] == 'absent',
        'Kali: другое ядро (%s), boot_id отличается, файлов Astra нет' % kali['kernel']['release'])
    add('shared: root = root', shp['identity']['uid_map'].split()[:2] == ['0', '0'] and
        (shrun.get('data_file_host') or {}).get('uid') == 0,
        'uid_map «%s», файл на томе принадлежит uid %s на хосте' % (
            shp['identity']['uid_map'], (shrun.get('data_file_host') or {}).get('uid')))
    add('shared: host files', shp['secret']['result'] == 'read' and shrun.get('secret_matches'),
        'секрет хоста прочитан (хеш совпал): %s' % shrun.get('secret_matches'))
    add('restricted: hostname', rsp['hostname'] == p['hostname'], rsp['hostname'])
    want = '0 %d %d' % (p['uid_base'], p['uid_count'])
    add('restricted: uid_map', rsp['identity']['uid_map'] == want and
        (rsrun.get('data_file_host') or {}).get('uid') == p['uid_base'],
        'uid_map «%s», файл на томе: uid %s на хосте' % (rsp['identity']['uid_map'],
                                                       (rsrun.get('data_file_host') or {}).get('uid')))
    add('restricted: CapEff', sorted(rsp['caps']['eff']) == sorted(p['caps']), 'CapEff: %s' % (
        ' '.join(rsp['caps']['eff']) or 'пусто'))
    ct = rsp.get('cap_tests', {})
    exp = dict((c, 'allowed' if c in p['caps'] else 'denied') for c in probe.CAP_TESTS)
    bad = ['%s=%s' % (c, ct.get(c)) for c in probe.CAP_TESTS if ct.get(c) != exp[c]]
    add('restricted: cap tests', not bad, 'расхождения: %s' % (', '.join(bad) or 'нет'))
    add('restricted: no_new_privs', rsp['no_new_privs'] == '1', 'NoNewPrivs=%s' % rsp['no_new_privs'])
    f = rsp.get('files', {})
    add('restricted: files', rsp['secret']['result'] == 'denied' and f.get('hostdata_write') in ('readonly', 'denied')
        and f.get('root_write') == 'readonly' and f.get('data_write') == 'written',
        'секрет: %s, /hostdata: %s, корень: %s, /data: %s' % (rsp['secret']['result'], f.get('hostdata_write'),
                                                             f.get('root_write'), f.get('data_write')))
    add('restricted: namespaces', all(rsp['ns'][n] != host['ns'][n] for n in REQUIRED_NS),
        'все шесть пространств имён отличаются от хоста')
    nets = load_evidence(work, 'run-shared-net.json'), load_evidence(work, 'run-restricted-net.json')
    nres = [((x or {}).get('result') or {}).get('result') for x in nets]
    add('net', nres[0] in ('connected', 'refused') and nres[1] == 'unreachable',
        'shared: %s, restricted: %s' % (nres[0], nres[1]))
    kl = load_evidence(work, 'kali-listen.json')
    conns = (kl or {}).get('connections', [])
    add('kali listener', bool(conns) and any(c.get('peer_ip') == p['astra'] for c in conns),
        'подключений к Kali: %d; от %s: %s' % (len(conns), p['astra'], any(c.get('peer_ip') == p['astra'] for c in conns)))
    mem = load_evidence(work, 'run-restricted-mem.json') or {}
    mc = mem.get('cgroup', {})
    add('memory limit', mem.get('rc') == 137 and ((mc.get('oom_kill') or 0) > 0 or (mc.get('memory_max_events') or 0) > 0),
        'rc=%s, достигнуто %s МБ, событий лимита %s, oom_kill %s' % (
            mem.get('rc'), mem.get('last_progress'), mc.get('memory_max_events'), mc.get('oom_kill')))
    smem = load_evidence(work, 'run-shared-mem.json') or {}
    add('memory: shared', ((smem.get('result') or {}).get('completed')), 'без лимита тест выделил %s МБ' % (
        (smem.get('result') or {}).get('allocated_mb')))
    pr = load_evidence(work, 'run-restricted-pids.json') or {}
    prr = pr.get('result') or {}
    add('pids limit', prr.get('limit_hit') and prr.get('forked', 999) < p['pids'] and
        (pr.get('cgroup', {}).get('pids_max_events') or 0) > 0,
        'создано %s дочерних при лимите %d, событий %s' % (prr.get('forked'), p['pids'],
                                                         pr.get('cgroup', {}).get('pids_max_events')))
    cpu = load_evidence(work, 'run-restricted-cpu.json') or {}
    cr = (cpu.get('result') or {}).get('ratio')
    scpu = ((load_evidence(work, 'run-shared-cpu.json') or {}).get('result') or {}).get('ratio')
    add('cpu limit', cr is not None and cr <= p['cpu'] / 100.0 * 1.5 + 0.05 and
        (cpu.get('cgroup', {}).get('nr_throttled') or 0) > 0 and scpu is not None and scpu > cr,
        'restricted %.0f%% (лимит %d%%), shared %s' % ((cr or 0) * 100, p['cpu'],
                                                     '%.0f%%' % (scpu * 100) if scpu is not None else '—'))
    add('observe', bool(load_evidence(work, 'observe-restricted.json')) and bool(load_evidence(work, 'observe-shared.json')),
        'наблюдение с хоста за обоими контейнерами')
    asm = load_evidence(work, 'assess.json')
    add('assess', bool(asm), 'сопоставление isolation.csv: %s' % ((asm or {}).get('score') or 'не выполнено'))
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
    killed = []
    if os.path.isdir(RUNDIR):
        for n in os.listdir(RUNDIR):
            try:
                info = json.load(open(os.path.join(RUNDIR, n)))
            except (ValueError, OSError):
                continue
            for pid in (info.get('init_pid'), info.get('intermediate_pid')):
                if pid and os.path.exists('/proc/%d' % pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                        killed.append(pid)
                    except OSError:
                        pass
    time.sleep(0.3)
    groups = Cgroup.remove_all()
    for d in (STATE, SRV, RUNDIR):
        if os.path.exists(d):
            shutil.rmtree(d)
    left = []
    info = Cgroup.detect()
    bases = ['/sys/fs/cgroup'] if info['version'] == 2 else sorted(set(info['mounts'].values()))
    for b in bases:
        if os.path.exists(b + '/' + CGNAME):
            left.append(b + '/' + CGNAME)
    res = dict(time=utc(), killed=killed, cgroups_removed=groups, cgroups_left=left,
               removed=dict((d, not os.path.exists(d)) for d in (STATE, SRV, RUNDIR)))
    res['clean'] = all(res['removed'].values()) and not left
    if st:
        evidence(st['work'], 'cleanup.json', res, st['operator'])
    print(json.dumps(res, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description='PR14: изоляция виртуальной машины и контейнера (Astra)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('init')
    s.add_argument('--work', required=True)
    s.add_argument('--variant', type=int, required=True)
    s = sub.add_parser('info')
    s.add_argument('--work', required=True)
    s.add_argument('--field')
    s = sub.add_parser('profile-check')
    s.add_argument('--profile', required=True)
    s.add_argument('--name', help='имя протокола для отрицательной проверки')
    s = sub.add_parser('run')
    s.add_argument('--profile', required=True)
    s.add_argument('--label', required=True)
    s.add_argument('--test', choices=TESTS)
    s.add_argument('--peer', help='адрес:порт приёмника на Kali (по умолчанию из варианта)')
    s.add_argument('--seconds', type=int, default=90, help='длительность теста hold')
    s.add_argument('--timeout', type=int, default=180)
    s.add_argument('command', nargs=argparse.REMAINDER)
    s = sub.add_parser('observe')
    s.add_argument('--label', required=True)
    s = sub.add_parser('compare')
    s.add_argument('--work', required=True)
    s = sub.add_parser('assess')
    s.add_argument('--work', required=True)
    sub.add_parser('check')
    s = sub.add_parser('cleanup')
    s.add_argument('--yes', action='store_true')
    a = ap.parse_args()
    fn = {'init': cmd_init, 'info': cmd_info, 'profile-check': cmd_profile_check, 'run': cmd_run,
          'observe': cmd_observe, 'compare': cmd_compare, 'assess': cmd_assess, 'check': cmd_check,
          'cleanup': cmd_cleanup}.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(a)


if __name__ == '__main__':
    main()
