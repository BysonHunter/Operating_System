#!/usr/bin/env python3
"""PR14: isolation probe. Runs on the Astra host, on Kali and inside the training containers.

Commands:
  probe   facts about the current execution context (kernel, namespaces, identity, capabilities,
          network, memory, cgroups); inside a container also file and capability tests
  net     TCP connection to a peer (the Kali listener) and the kind of failure, if any
  listen  TCP listener for Kali: records who connected
  mem, pids, cpu, hold   load tests for the resource limits (run inside a container)

Standard library only, Python 3.5 syntax. Every test prints readable lines and a final line
"PR14-RESULT <json>", which pr14.py parses. Nothing here changes the system outside temporary files
in /tmp and the training directories of the container.
"""
import argparse
import ctypes
import datetime
import errno
import fcntl
import hashlib
import io
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time

CAPS = ['CHOWN', 'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP',
        'LINUX_IMMUTABLE', 'NET_BIND_SERVICE', 'NET_BROADCAST', 'NET_ADMIN', 'NET_RAW', 'IPC_LOCK', 'IPC_OWNER',
        'SYS_MODULE', 'SYS_RAWIO', 'SYS_CHROOT', 'SYS_PTRACE', 'SYS_PACCT', 'SYS_ADMIN', 'SYS_BOOT', 'SYS_NICE',
        'SYS_RESOURCE', 'SYS_TIME', 'SYS_TTY_CONFIG', 'MKNOD', 'LEASE', 'AUDIT_WRITE', 'AUDIT_CONTROL', 'SETFCAP',
        'MAC_OVERRIDE', 'MAC_ADMIN', 'SYSLOG', 'WAKE_ALARM', 'BLOCK_SUSPEND', 'AUDIT_READ', 'PERFMON', 'BPF',
        'CHECKPOINT_RESTORE']
CAP_TESTS = ['CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'NET_BIND_SERVICE', 'SYS_CHROOT', 'NET_RAW', 'SYS_ADMIN',
             'NET_ADMIN']
NS = ['mnt', 'uts', 'ipc', 'pid', 'net', 'user', 'cgroup']
HOST_SECRET = '/srv/pr14/host/secret.txt'


def _utf8_stdio():
    """Python 3.5 under a C/POSIX locale writes ASCII: switch the console streams to UTF-8."""
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def read(path, default=None):
    try:
        with open(path, encoding='utf-8', errors='replace') as s:
            return s.read()
    except (IOError, OSError):
        return default


def result(obj, out=None):
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    if out:
        with open(out, 'w', encoding='utf-8') as s:
            json.dump(obj, s, indent=2, sort_keys=True, ensure_ascii=False)
            s.write('\n')
        print('Результат сохранён: %s' % out)
    print('PR14-RESULT ' + text)
    sys.stdout.flush()


def err_name(e):
    return errno.errorcode.get(e.errno, str(e.errno)) if getattr(e, 'errno', None) else type(e).__name__


def decode_caps(hexmask):
    try:
        v = int(hexmask, 16)
    except (TypeError, ValueError):
        return []
    return [CAPS[i] if i < len(CAPS) else 'CAP_%d' % i for i in range(64) if v >> i & 1]


def status_fields():
    res = {}
    for line in (read('/proc/self/status') or '').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            if k in ('Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'NSpid'):
                res[k] = v.strip()
    return res


def namespaces():
    res = {}
    for n in NS:
        try:
            res[n] = os.readlink('/proc/self/ns/' + n)
        except OSError as e:
            res[n] = 'n/a:' + err_name(e)
    return res


def interfaces():
    res = []
    for line in (read('/proc/net/dev') or '').splitlines()[2:]:
        if ':' in line:
            res.append(line.split(':', 1)[0].strip())
    return sorted(res)


def routes():
    res = []
    for line in (read('/proc/net/route') or '').splitlines()[1:]:
        f = line.split()
        if len(f) >= 8:
            dst = socket.inet_ntoa(struct.pack('<L', int(f[1], 16)))
            mask = socket.inet_ntoa(struct.pack('<L', int(f[7], 16)))
            res.append('%s/%s dev %s' % (dst, mask, f[0]))
    return res


def ipv4_addrs():
    """Addresses of interfaces via SIOCGIFADDR (no external tools)."""
    res = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for name in interfaces():
            try:
                r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', name.encode()[:15]))
                res[name] = socket.inet_ntoa(r[20:24])
            except (IOError, OSError):
                pass
    finally:
        s.close()
    return res


def meminfo_total_kb():
    for line in (read('/proc/meminfo') or '').splitlines():
        if line.startswith('MemTotal:'):
            return int(line.split()[1])
    return None


def processes():
    pids = [int(x) for x in os.listdir('/proc') if x.isdigit()]
    pid1 = (read('/proc/1/cmdline') or '').replace('\0', ' ').strip()
    return len(pids), pid1


def virt_hint():
    flags = ''
    for line in (read('/proc/cpuinfo') or '').splitlines():
        if line.startswith('flags'):
            flags = line
            break
    res = dict(cpu_hypervisor_flag=' hypervisor' in flags,
               dmi_product=(read('/sys/class/dmi/id/product_name') or '').strip() or None,
               run_systemd_container=(read('/run/systemd/container') or '').strip() or None,
               env_container=os.environ.get('container'))
    for args, key in ((['systemd-detect-virt'], 'detect_virt'), (['systemd-detect-virt', '-c'], 'detect_container')):
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            res[key] = p.communicate()[0].decode().strip()
        except OSError:
            res[key] = None
    return res


def secret_state():
    for path in ('/hostdata/secret.txt', HOST_SECRET):
        if os.path.lexists(path):
            try:
                with open(path, 'rb') as s:
                    data = s.read()
                return dict(path=path, result='read', sha256=hashlib.sha256(data.strip()).hexdigest())
            except (IOError, OSError) as e:
                return dict(path=path, result='denied', error=err_name(e))
    return dict(path=HOST_SECRET, result='absent')


# ------------------------------------------------------------------ tests inside a container
def try_write(path):
    try:
        with open(path, 'w') as s:
            s.write('pr14 write test %s\n' % utc())
        return 'written'
    except (IOError, OSError) as e:
        if e.errno == errno.EROFS:
            return 'readonly'
        if e.errno in (errno.EACCES, errno.EPERM):
            return 'denied'
        return 'error:' + err_name(e)


def file_tests(label):
    res = {}
    res['data_write'] = try_write('/data/probe-%s.txt' % label)
    res['hostdata_write'] = try_write('/hostdata/probe-%s.txt' % label)
    res['root_write'] = try_write('/.pr14-root-%s' % label)
    if res['root_write'] == 'written':
        os.unlink('/.pr14-root-%s' % label)
        res['root_write'] = 'written (удалён)'
    try:
        with open('/hostdata/reference.txt') as s:
            s.read()
        res['reference_read'] = 'read'
    except (IOError, OSError) as e:
        res['reference_read'] = 'error:' + err_name(e)
    try:
        st = os.stat('/data/probe-%s.txt' % label)
        res['data_owner_inside'] = '%d:%d' % (st.st_uid, st.st_gid)
    except OSError:
        res['data_owner_inside'] = None
    try:
        st = os.stat('/hostdata/secret.txt')
        res['secret_owner_inside'] = '%d:%d' % (st.st_uid, st.st_gid)
    except OSError:
        res['secret_owner_inside'] = None
    return res


def in_child(fn):
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            fn()
            code = 0
        except OSError as e:
            code = 2 if e.errno in (errno.EPERM, errno.EACCES) else 3
        except Exception:
            code = 3
        os._exit(code)
    _, st = os.waitpid(pid, 0)
    return os.WEXITSTATUS(st) if os.WIFEXITED(st) else 4


def verdict_from_code(code):
    return {0: 'allowed', 2: 'denied'}.get(code, 'error')


def cap_tests(bind_port):
    res = {}
    tmp = tempfile.mkdtemp(prefix='pr14-caps-', dir='/tmp')
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        f = os.path.join(tmp, 'chown')
        open(f, 'w').close()
        try:
            os.chown(f, 1, 1)
            res['CHOWN'] = 'allowed'
        except OSError as e:
            res['CHOWN'] = 'denied' if e.errno == errno.EPERM else 'error:' + err_name(e)
        f = os.path.join(tmp, 'dac')
        open(f, 'w').close()
        os.chmod(f, 0)
        try:
            open(f, 'w').close()
            res['DAC_OVERRIDE'] = 'allowed'
        except (IOError, OSError) as e:
            res['DAC_OVERRIDE'] = 'denied' if e.errno in (errno.EACCES, errno.EPERM) else 'error:' + err_name(e)
        res['SETUID'] = verdict_from_code(in_child(lambda: os.setresuid(1, 1, 1)))
        res['SETGID'] = verdict_from_code(in_child(lambda: os.setresgid(1, 1, 1)))
        res['SYS_CHROOT'] = verdict_from_code(in_child(lambda: os.chroot('/')))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', bind_port))
            res['NET_BIND_SERVICE'] = 'allowed'
        except (IOError, OSError) as e:
            if e.errno == errno.EADDRINUSE:
                res['NET_BIND_SERVICE'] = 'allowed'
            elif e.errno in (errno.EACCES, errno.EPERM):
                res['NET_BIND_SERVICE'] = 'denied'
            else:
                res['NET_BIND_SERVICE'] = 'error:' + err_name(e)
        finally:
            s.close()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            res['NET_RAW'] = 'allowed'
        except (IOError, OSError) as e:
            res['NET_RAW'] = 'denied' if e.errno in (errno.EPERM, errno.EACCES) else 'error:' + err_name(e)
        mnt = '/mnt' if os.path.isdir('/mnt') else tmp
        r = libc.mount(b'tmpfs', mnt.encode(), b'tmpfs', ctypes.c_ulong(0), b'size=64k')
        if r == 0:
            libc.umount2(mnt.encode(), 2)
            res['SYS_ADMIN'] = 'allowed'
        else:
            e = ctypes.get_errno()
            res['SYS_ADMIN'] = 'denied' if e in (errno.EPERM, errno.EACCES) else 'error:' + errno.errorcode.get(e, str(e))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            r = fcntl.ioctl(s.fileno(), 0x8921, struct.pack('16si12s', b'lo', 0, b'\0' * 12))
            mtu = struct.unpack('16si', r[:20])[1]
            fcntl.ioctl(s.fileno(), 0x8922, struct.pack('16si12s', b'lo', mtu, b'\0' * 12))
            res['NET_ADMIN'] = 'allowed'
        except (IOError, OSError) as e:
            res['NET_ADMIN'] = 'denied' if e.errno in (errno.EPERM, errno.EACCES) else 'error:' + err_name(e)
        finally:
            s.close()
    finally:
        for root, dirs, files in os.walk(tmp, topdown=False):
            for n in files:
                try:
                    os.unlink(os.path.join(root, n))
                except OSError:
                    pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
    return res


# ------------------------------------------------------------------ commands
def cmd_probe(a):
    st = status_fields()
    nproc, pid1 = processes()
    try:
        affinity = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity = None
    u = os.uname()
    obj = dict(label=a.label, time=utc(), python=platform.python_version(),
               kernel=dict(release=u.release, version=u.version, machine=u.machine,
                           boot_id=(read('/proc/sys/kernel/random/boot_id') or '').strip() or None),
               hostname=socket.gethostname(),
               os_release=dict((l.split('=', 1)[0], l.split('=', 1)[1].strip('"')) for l in
                               (read('/etc/os-release') or '').splitlines() if '=' in l and l.split('=', 1)[0] in
                               ('NAME', 'VERSION_ID', 'PRETTY_NAME')),
               ns=namespaces(),
               identity=dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), groups=os.getgroups(),
                             uid_map=' '.join((read('/proc/self/uid_map') or '').split()),
                             gid_map=' '.join((read('/proc/self/gid_map') or '').split())),
               caps=dict(eff_hex=st.get('CapEff'), bnd_hex=st.get('CapBnd'), eff=decode_caps(st.get('CapEff')),
                         bnd_count=len(decode_caps(st.get('CapBnd'))),
                         cap_last_cap=int((read('/proc/sys/kernel/cap_last_cap') or '-1').strip() or -1)),
               no_new_privs=st.get('NoNewPrivs'), seccomp=st.get('Seccomp'), nspid=st.get('NSpid'),
               proc=dict(pid=os.getpid(), visible=nproc, pid1=pid1[:120]),
               net=dict(interfaces=interfaces(), ipv4=ipv4_addrs(), routes=routes(),
                        default_route=any(r.startswith('0.0.0.0/0.0.0.0') for r in routes())),
               memory=dict(memtotal_kb=meminfo_total_kb()),
               cpu=dict(count=os.cpu_count(), affinity=affinity),
               cgroup=[l for l in (read('/proc/self/cgroup') or '').splitlines() if l][:12],
               mounts=dict(count=len((read('/proc/self/mountinfo') or '').splitlines())),
               virt=virt_hint(), secret=secret_state())
    if a.files:
        obj['files'] = file_tests(a.label)
    if a.caps:
        obj['cap_tests'] = cap_tests(a.bind_port)
    print('Контекст %s: ядро %s, boot_id %s, hostname %s' % (a.label, u.release, (obj['kernel']['boot_id'] or '?')[:8],
                                                         obj['hostname']))
    print('uid=%d, uid_map: %s; CapEff: %d из %d; NoNewPrivs=%s' % (
        os.getuid(), obj['identity']['uid_map'] or '—', len(obj['caps']['eff']), obj['caps']['cap_last_cap'] + 1,
        obj['no_new_privs']))
    print('Видимых процессов: %d; интерфейсы: %s; MemTotal: %s kB; CPU: %s' % (
        nproc, ', '.join(obj['net']['interfaces']), obj['memory']['memtotal_kb'], obj['cpu']['count']))
    for n in NS:
        print('  ns %-6s %s' % (n, obj['ns'][n]))
    print('Секрет хоста: %s' % obj['secret']['result'])
    if a.files:
        for k in sorted(obj['files']):
            print('  файл %-20s %s' % (k, obj['files'][k]))
    if a.caps:
        for k in CAP_TESTS:
            print('  cap  %-20s %s' % (k, obj['cap_tests'].get(k)))
    result(obj, a.out)


def cmd_net(a):
    host, port = a.peer.rsplit(':', 1)
    port = int(port)
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(a.timeout)
    res = dict(label=a.label, peer=a.peer, time=utc())
    try:
        s.connect((host, port))
        res['local'] = '%s:%d' % s.getsockname()
        s.sendall(('pr14 %s\n' % a.label).encode())
        try:
            res['banner'] = s.recv(200).decode('utf-8', 'replace').strip()
        except socket.timeout:
            res['banner'] = None
        res['result'] = 'connected'
    except socket.timeout:
        res['result'] = 'timeout'
    except (IOError, OSError) as e:
        name = err_name(e)
        res['error'] = name
        res['result'] = {'ECONNREFUSED': 'refused', 'ENETUNREACH': 'unreachable', 'EHOSTUNREACH': 'unreachable',
                         'EACCES': 'blocked', 'EPERM': 'blocked'}.get(name, 'error')
    finally:
        s.close()
    res['seconds'] = round(time.time() - t0, 3)
    res['routes'] = routes()
    print('Подключение к %s: %s %s' % (a.peer, res['result'], res.get('error') or res.get('local') or ''))
    result(res, a.out)


def cmd_listen(a):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    srv.listen(8)
    srv.settimeout(1.0)
    log = dict(label=a.label, port=a.port, started=utc(), hostname=socket.gethostname(),
               boot_id=(read('/proc/sys/kernel/random/boot_id') or '').strip(), connections=[])

    def save():
        if a.out:
            with open(a.out, 'w', encoding='utf-8') as s:
                json.dump(log, s, indent=2, ensure_ascii=False)
                s.write('\n')

    save()
    print('Ожидание подключений на %s:%d (%d с; Ctrl+C — завершить)' % (a.bind, a.port, a.seconds))
    deadline = time.time() + a.seconds
    try:
        while time.time() < deadline:
            try:
                c, addr = srv.accept()
            except socket.timeout:
                continue
            c.settimeout(3)
            try:
                line = c.recv(200).decode('utf-8', 'replace').strip()
            except (socket.timeout, OSError):
                line = ''
            try:
                c.sendall(('pr14-%s %s\n' % (a.label, socket.gethostname())).encode())
            except OSError:
                pass
            c.close()
            rec = dict(time=utc(), peer_ip=addr[0], peer_port=addr[1], line=line)
            log['connections'].append(rec)
            save()
            print('%s подключение от %s:%d: %s' % (rec['time'], addr[0], addr[1], line))
    except KeyboardInterrupt:
        print('\nОстановлено.')
    finally:
        srv.close()
        log['stopped'] = utc()
        save()
    print('Подключений: %d' % len(log['connections']))


def cmd_mem(a):
    chunks = []
    step = 4
    total = 0
    print('Цель: %d МБ, шаг %d МБ' % (a.target_mb, step))
    sys.stdout.flush()
    while total < a.target_mb:
        try:
            chunks.append(b'\x5a' * (step << 20))
        except MemoryError:
            result(dict(test='mem', allocated_mb=total, completed=False, error='MemoryError'))
            return
        total += step
        print('PR14-PROGRESS mem %d' % total)
        sys.stdout.flush()
    result(dict(test='mem', allocated_mb=total, completed=True))


def cmd_pids(a):
    r, w = os.pipe()
    kids = []
    error = None
    for _ in range(a.max):
        try:
            pid = os.fork()
        except OSError as e:
            error = '%s: %s' % (err_name(e), e.strerror)
            break
        if pid == 0:
            os.close(w)
            try:
                os.read(r, 1)
            finally:
                os._exit(0)
        kids.append(pid)
    os.close(w)
    for pid in kids:
        os.waitpid(pid, 0)
    os.close(r)
    print('Создано дочерних процессов: %d; ошибка: %s' % (len(kids), error or 'нет'))
    result(dict(test='pids', forked=len(kids), limit_hit=error is not None, error=error, max=a.max))


def cmd_cpu(a):
    t0 = time.time()
    c0 = os.times()
    n = 0
    while time.time() - t0 < a.seconds:
        for _ in range(20000):
            n += 1
    c1 = os.times()
    wall = time.time() - t0
    cpu = (c1[0] - c0[0]) + (c1[1] - c0[1])
    ratio = cpu / wall if wall else 0
    print('Процессорное время %.2f с за %.2f с: %.0f%% одного ядра' % (cpu, wall, ratio * 100))
    result(dict(test='cpu', cpu_seconds=round(cpu, 3), wall_seconds=round(wall, 3), ratio=round(ratio, 3)))


def cmd_hold(a):
    pid = os.fork()
    if pid == 0:
        time.sleep(a.seconds)
        os._exit(0)
    print('Процесс теста: pid %d в контейнере, дочерний pid %d; ожидание %d с' % (os.getpid(), pid, a.seconds))
    print('NSpid: %s' % status_fields().get('NSpid'))
    sys.stdout.flush()
    os.waitpid(pid, 0)
    result(dict(test='hold', pid=os.getpid(), child=pid, seconds=a.seconds))


def main():
    ap = argparse.ArgumentParser(description='PR14: зонд изоляции (Astra, Kali, контейнер)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('probe')
    s.add_argument('--label', required=True)
    s.add_argument('--out')
    s.add_argument('--files', action='store_true', help='проверки файлов внутри контейнера')
    s.add_argument('--caps', action='store_true', help='проверки привилегий внутри контейнера')
    s.add_argument('--bind-port', type=int, default=601)
    s = sub.add_parser('net')
    s.add_argument('--peer', required=True)
    s.add_argument('--label', default='net')
    s.add_argument('--timeout', type=float, default=4.0)
    s.add_argument('--out')
    s = sub.add_parser('listen')
    s.add_argument('--port', type=int, required=True)
    s.add_argument('--bind', default='0.0.0.0')
    s.add_argument('--seconds', type=int, default=3600)
    s.add_argument('--label', default='kali')
    s.add_argument('--out')
    s = sub.add_parser('mem')
    s.add_argument('--target-mb', type=int, required=True)
    s = sub.add_parser('pids')
    s.add_argument('--max', type=int, required=True)
    s = sub.add_parser('cpu')
    s.add_argument('--seconds', type=float, default=3.0)
    s = sub.add_parser('hold')
    s.add_argument('--seconds', type=int, default=90)
    a = ap.parse_args()
    fn = {'probe': cmd_probe, 'net': cmd_net, 'listen': cmd_listen, 'mem': cmd_mem, 'pids': cmd_pids,
          'cpu': cmd_cpu, 'hold': cmd_hold}.get(a.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(a)


if __name__ == '__main__':
    main()
