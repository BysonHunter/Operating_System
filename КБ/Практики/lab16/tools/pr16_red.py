#!/usr/bin/env python3
"""PR16 (Kali): разведка красной команды — ТОЛЬКО разрешённые проверки.

Подключается к endpoint учебной службы pr16-svc на Astra и выполняет проверки из опубликованного
каталога (правила полигона): каждая проверка — один безопасный запрос только на чтение. Скрипт не
подбирает пароли, не сканирует порты вслепую и не делает ничего вне каталога: он запрашивает у
службы факт и оценивает его как «слабо» или «норма». Результат сохраняется в findings json для
передачи на Astra.

Используется в двух раундах: baseline (до усиления) и recheck (после усиления синей командой).
Только стандартная библиотека Python 3.5.
"""
import argparse
import datetime
import io
import json
import socket
import sys


def _utf8_stdio():
    for name in ('stdout', 'stderr'):
        s = getattr(sys, name)
        if (getattr(s, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(s, 'buffer'):
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding='utf-8', errors='replace', line_buffering=True))


_utf8_stdio()

TITLE = {
    'c1_banner': 'Раскрытие версии в баннере',
    'c2_anon': 'Анонимный доступ',
    'c3_tls': 'Передача без шифрования',
    'c4_debug': 'Открыт отладочный порт',
    'c5_secret': 'Секрет доступен другим на чтение',
    'c6_lockout': 'Нет ограничения неуспешных входов',
    'c7_admin': 'Админ-порт открыт для всех',
    'c8_allow': 'Устаревшая запись в списке доступа',
    'c9_errors': 'Подробные ошибки раскрывают пути',
}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def verdict(check_id, fact):
    """Оценка факта как «слабо»/«норма». Правила — часть правил полигона красной команды."""
    val = fact.split('=', 1)[1].strip() if '=' in fact else fact.strip()
    if check_id == 'c1_banner':
        return 'weak' if '/' in val else 'ok', 'версия раскрыта' if '/' in val else 'версия скрыта'
    if check_id == 'c2_anon':
        return ('weak', 'анонимный доступ разрешён') if val == 'yes' else ('ok', 'анонимный доступ запрещён')
    if check_id == 'c3_tls':
        return ('weak', 'шифрование не требуется') if val == 'no' else ('ok', 'требуется TLS')
    if check_id in ('c4_debug', 'c7_admin'):
        return ('weak', 'порт открыт для всех') if val == 'open' else ('ok', 'порт недоступен извне')
    if check_id == 'c5_secret':
        try:
            bad = bool(int(val, 8) & 0o077)
        except ValueError:
            bad = True
        return ('weak', 'доступ группе/прочим (%s)' % val) if bad else ('ok', 'доступ только владельцу (%s)' % val)
    if check_id == 'c6_lockout':
        try:
            n = int(val)
        except ValueError:
            n = 0
        return ('weak', 'нет ограничения (%s)' % val) if n < 5 else ('ok', 'ограничение %s' % val)
    if check_id == 'c8_allow':
        return ('weak', 'есть устаревший узел') if val == 'present' else ('ok', 'устаревших узлов нет')
    if check_id == 'c9_errors':
        return ('weak', 'подробные ошибки включены') if val == 'yes' else ('ok', 'подробные ошибки выключены')
    return 'ok', 'неизвестная проверка'


def ask(host, port, line, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall((line + '\n').encode())
        buf = b''
        while b'\n' not in buf:
            chunk = s.recv(512)
            if not chunk:
                break
            buf += chunk
        return buf.decode('utf-8', 'replace').splitlines()[0].strip() if buf else ''
    finally:
        s.close()


def local_ip(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except (IOError, OSError):
        return '-'
    finally:
        s.close()


def cmd_scan(a):
    try:
        cat = ask(a.host, a.port, 'CATALOG', a.timeout)
    except (IOError, OSError) as e:
        raise SystemExit('служба недоступна на %s:%d — %s (синяя команда должна запустить serve)' % (a.host, a.port, e))
    if not cat.startswith('catalog='):
        raise SystemExit('неожиданный ответ службы: %s' % cat)
    ids = [x for x in cat[len('catalog='):].split(',') if x]
    results, weak = [], []
    print('Разрешённые проверки каталога против %s:%d (раунд %s), %s' % (a.host, a.port, a.round, utc()))
    for cid in ids:
        try:
            fact = ask(a.host, a.port, 'CHECK ' + cid, a.timeout)
        except (IOError, OSError) as e:
            fact = 'error=%s' % e
        v, ev = verdict(cid, fact)
        if v == 'weak':
            weak.append(cid)
        results.append(dict(check=cid, title=TITLE.get(cid, cid), fact=fact, verdict=v, evidence=ev))
        print('  %-5s %-10s %-34s %s' % (v.upper(), cid, TITLE.get(cid, cid), fact))
    out = dict(service='pr16-svc', host=a.host, port=a.port, round=a.round, time=utc(),
               source=local_ip(a.host, a.port), catalog=ids, results=results, weak=sorted(weak),
               summary='слабых: %d из %d' % (len(weak), len(ids)))
    with open(a.out, 'w', encoding='utf-8') as s:
        json.dump(out, s, indent=2, ensure_ascii=False)
        s.write('\n')
    print('Слабых проверок: %d из %d. Результат: %s' % (len(weak), len(ids), a.out))
    print('Передайте файл на Astra: scp %s student@%s:pr16/evidence/' % (a.out, a.host))


def main():
    ap = argparse.ArgumentParser(description='PR16: разведка красной команды, только разрешённые проверки (Kali)')
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('scan')
    s.add_argument('--host', required=True, help='адрес Astra (10.50.V.10)')
    s.add_argument('--port', type=int, default=7016, help='порт endpoint службы pr16-svc')
    s.add_argument('--round', choices=['baseline', 'recheck'], default='baseline')
    s.add_argument('--out', help='куда сохранить findings json')
    s.add_argument('--timeout', type=float, default=5.0)
    a = ap.parse_args()
    if a.cmd != 'scan':
        ap.print_help()
        sys.exit(1)
    if not a.out:
        a.out = 'findings-%s.json' % a.round
    cmd_scan(a)


if __name__ == '__main__':
    main()
