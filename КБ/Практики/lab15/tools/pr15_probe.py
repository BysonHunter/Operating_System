#!/usr/bin/env python3
"""PR15 (Kali): генератор серии неуспешных входов для воспроизведения инцидента на реальном стенде.

Необязательный иллюстративный шаг. Делает ограниченную, заведомо неуспешную серию попыток входа по
SSH на учебную Astra, чтобы в её журнале (/var/log/auth.log или journald) появились настоящие записи
«Failed password»/«Invalid user» с адреса Kali. Это даёт студенту увидеть реальный формат журнала и
подтвердить, что источник — Kali. Пароли не подбираются: используется несуществующий ключ и/или
несуществующий пользователь, BatchMode, попытка сразу завершается отказом.

Безопасность: число попыток ограничено (по умолчанию 8, максимум 15), только учебная Astra,
интервал между попытками, остановка при первом успехе (его быть не должно). Разбор инцидента в работе
ведётся по журналам, подложенным командой init на Astra, и от этого шага не зависит.

Только стандартная библиотека Python 3.5.
"""
import argparse
import datetime
import io
import os
import subprocess
import sys
import time


def _utf8_stdio():
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()

MAX_ATTEMPTS = 15


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def one_attempt(host, user, port, nokey, connect_timeout):
    """Одна заведомо неуспешная попытка входа. Возвращает (rc, краткий итог)."""
    cmd = ['ssh', '-p', str(port), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
           '-o', 'PreferredAuthentications=publickey,password', '-o', 'PubkeyAuthentication=yes',
           '-o', 'IdentitiesOnly=yes', '-i', nokey, '-o', 'NumberOfPasswordPrompts=0',
           '-o', 'ConnectTimeout=%d' % connect_timeout, '-o', 'LogLevel=ERROR',
           '%s@%s' % (user, host), 'true']
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=connect_timeout + 5)
    except OSError as e:
        return 255, 'ssh не запущен: %s' % e
    except subprocess.TimeoutExpired:
        p.kill()
        return 255, 'тайм-аут соединения'
    msg = err.decode('utf-8', 'replace').strip().splitlines()
    tail = msg[-1] if msg else ''
    return p.returncode, tail or ('rc=%d' % p.returncode)


def cmd_knock(a):
    if a.attempts < 1 or a.attempts > MAX_ATTEMPTS:
        raise SystemExit('число попыток от 1 до %d' % MAX_ATTEMPTS)
    nokey = os.path.join('/tmp', 'pr15-nokey-%d' % os.getpid())
    # заведомо отсутствующий у сервера ключ, чтобы публичная аутентификация не прошла
    try:
        subprocess.check_call(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', nokey],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        nokey = '/dev/null'
    print('Серия из %d неуспешных попыток входа на %s:%d (пользователь %s). %s'
          % (a.attempts, a.host, a.port, a.user, utc()))
    results = []
    try:
        for i in range(a.attempts):
            rc, tail = one_attempt(a.host, a.user, a.port, nokey, a.timeout)
            results.append(rc)
            print('  попытка %2d/%d: rc=%-3d %s' % (i + 1, a.attempts, rc, tail[:80]))
            if rc == 0:
                print('ВНИМАНИЕ: вход удался — это не ожидалось. Остановка.')
                break
            time.sleep(a.interval)
    finally:
        if nokey != '/dev/null' and os.path.exists(nokey):
            for suf in ('', '.pub'):
                try:
                    os.unlink(nokey + suf)
                except OSError:
                    pass
    fails = sum(1 for r in results if r != 0)
    print('Готово: %d неуспешных попыток. На Astra выполните: sudo python3 pr15.py capture --work "$HOME/pr15".'
          % fails)
    print('Проверьте в журнале Astra строки «Failed password»/«Invalid user» с адреса этой Kali.')


def main():
    ap = argparse.ArgumentParser(description='PR15: генератор серии неуспешных входов (Kali)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('knock', help='ограниченная серия заведомо неуспешных входов на Astra')
    s.add_argument('--host', required=True, help='адрес учебной Astra (10.50.V.10)')
    s.add_argument('--user', default='admin', help='пользователь для попыток (по умолчанию несуществующий admin)')
    s.add_argument('--port', type=int, default=22)
    s.add_argument('--attempts', type=int, default=8, help='число попыток (1..%d)' % MAX_ATTEMPTS)
    s.add_argument('--interval', type=float, default=1.0, help='пауза между попытками, с')
    s.add_argument('--timeout', type=int, default=6, help='тайм-аут соединения, с')
    a = ap.parse_args()
    if a.cmd != 'knock':
        ap.print_help()
        sys.exit(1)
    cmd_knock(a)


if __name__ == '__main__':
    main()
