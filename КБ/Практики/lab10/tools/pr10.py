#!/usr/bin/env python3
"""PR10: bounded teaching service, inotify observer and own configuration."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs


def utc(epoch=None):
    return datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch, datetime.timezone.utc).isoformat()


def emit(session, event, **fields):
    row = dict(event=event, run=session['run'], variant=session['variant'],
               app_utc=utc(), actor_pid=os.getpid())
    row.update(fields)
    print(json.dumps(row, ensure_ascii=True, sort_keys=True), flush=True)
    return row


def load(work):
    work = Path(work).resolve()
    s = json.loads((work / 'session.json').read_text(encoding='utf-8'))
    v = s['variant']
    if not isinstance(v, int) or not 1 <= v <= 27 or not re.fullmatch(r'v\d\d-[a-f0-9]{12}', s['run']):
        raise ValueError('invalid session')
    s['work'] = str(work)
    s['data'] = str(work / 'labdata' / ('control_v%02d.txt' % v))
    s['config'] = str(work / 'labdata' / ('service_v%02d.json' % v))
    for key in ['data', 'config']:
        if Path(s[key]).is_symlink() or not Path(s[key]).is_file():
            raise ValueError('missing or symbolic teaching file: ' + key)
    return s


def initialize(work, variant):
    if not 1 <= variant <= 27:
        raise ValueError('variant must be 1..27')
    work = Path(work).resolve()
    if (work / 'session.json').exists() or (work / 'labdata').exists():
        raise ValueError('session/labdata already exists; preserve the previous work first')
    (work / 'labdata').mkdir(parents=True)
    (work / 'evidence').mkdir(exist_ok=True)
    start = time.time()
    s = dict(variant=variant, run='v%02d-%s' % (variant, uuid.uuid4().hex[:12]),
             port=21000 + variant, reads=1 + ((variant - 1) % 3),
             since=datetime.datetime.fromtimestamp(start - 1, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
             started_epoch=start, astra='10.50.%d.10' % variant, kali='10.50.%d.20' % variant)
    data = work / 'labdata' / ('control_v%02d.txt' % variant)
    config = work / 'labdata' / ('service_v%02d.json' % variant)
    data.write_text('PR10 artificial control text; variant=%d\n' % variant, encoding='utf-8')
    config.write_text(json.dumps(dict(mode='observe_%02d' % variant), sort_keys=True) + '\n', encoding='utf-8')
    (work / 'evidence/config-original.bin').write_bytes(config.read_bytes())
    (work / 'evidence/control-original.sha256').write_text(hashlib.sha256(data.read_bytes()).hexdigest() + '\n', encoding='ascii')
    (work / 'session.json').write_text(json.dumps(s, indent=2, sort_keys=True), encoding='utf-8')
    return load(work)


def configure(session, state):
    path = Path(session['config'])
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    content = ((Path(session['work']) / 'evidence/config-original.bin').read_bytes() if state == 'restore'
               else (json.dumps(dict(mode='check_%02d' % session['variant']), sort_keys=True) + '\n').encode())
    # Deliberately modify this one teaching file in place, without renaming.
    with path.open('wb') as stream:
        stream.write(content)
    return emit(session, 'CONFIG_RESTORED' if state == 'restore' else 'CONFIG_CHANGED',
                path=str(path), sha256_before=before,
                sha256_after=hashlib.sha256(content).hexdigest())


def server(session, bind, peer):
    bind = str(ipaddress.IPv4Address(bind)); peer = str(ipaddress.IPv4Address(peer))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            part = urlsplit(self.path)
            rid = parse_qs(part.query).get('rid', [''])[0]
            if self.client_address[0] != peer:
                self.send_error(403, 'only the configured teaching peer')
                return
            if not re.fullmatch(re.escape(session['run']) + r'-(?:before|after|restored)-(?:clock[1-3]|read[1-3]|status|denied)', rid):
                self.send_error(400, 'invalid teaching request id')
                return
            code = 200; event = 'HTTP_PING'; details = {}
            payload = dict(run=session['run'], request_id=rid, server_epoch=time.time())
            if part.path == '/ping':
                pass
            elif part.path == '/read':
                content = Path(session['data']).read_bytes()
                event = 'CONTROL_READ'
                details = dict(path=session['data'], bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
                payload.update(details)
            elif part.path == '/status':
                conf = json.loads(Path(session['config']).read_text(encoding='utf-8'))
                event = 'CONFIG_READ'; details = dict(path=session['config'], mode=conf['mode'])
                payload.update(details)
            elif part.path == '/denied':
                code = 403; event = 'APPLICATION_DENIED'; payload['reason'] = 'teaching application policy'
            else:
                self.send_error(404, 'unknown teaching path');return
            body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            emit(session, event, request_id=rid, peer=self.client_address[0],
                 http_status=code, server_epoch=payload['server_epoch'], **details)
    http = HTTPServer((bind, session['port']), Handler)
    emit(session, 'SERVER_READY', bind=bind, port=session['port'], allowed_peer=peer)
    try:
        http.serve_forever(poll_interval=0.3)
    finally:
        http.server_close()


def parse_notification(line, session):
    event, separator, filename = line.rstrip('\r\n').partition('|')
    if 'Q_OVERFLOW' in event:
        return dict(event='FS_LOSS', cause='inotify queue overflow')
    if not separator or filename not in [Path(session['data']).name, Path(session['config']).name]:
        return None
    return dict(event='FS_EVENT', fs_event=event,
                path=str(Path(session['work']) / 'labdata' / filename),
                attribution='observer PID is not the file actor PID')


def watch(session):
    args = ['inotifywait', '-m', '--format', '%e|%f']
    for event in ['open', 'access', 'modify', 'close_write', 'attrib', 'create', 'delete', 'moved_from', 'moved_to']:
        args += ['-e', event]
    args.append(str(Path(session['work']) / 'labdata'))
    env = os.environ.copy();env['LC_ALL'] = 'C'
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    streams = [process.stdout, process.stderr];buffers = {stream:b'' for stream in streams}
    ready = False;started = time.monotonic()
    try:
        while streams:
            if not ready and time.monotonic() - started > 15:
                raise RuntimeError('inotify readiness timeout')
            available, _, _ = select.select(streams, [], [], 0.5)
            for stream in available:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    streams.remove(stream);continue
                buffers[stream] += chunk
                while b'\n' in buffers[stream]:
                    raw, buffers[stream] = buffers[stream].split(b'\n',1)
                    line = raw.decode('utf-8', 'replace')
                    if stream is process.stderr:
                        if 'Watches established.' in line:
                            ready = True;emit(session, 'WATCH_READY', directory=str(Path(session['work']) / 'labdata'))
                        else:
                            emit(session, 'WATCH_DIAGNOSTIC', detail=line.strip())
                    else:
                        row = parse_notification(line, session)
                        if row:
                            event = row.pop('event');emit(session, event, **row)
                            if event == 'FS_LOSS':raise RuntimeError('inotify lost events; repeat the bounded experiment')
            if process.poll() is not None and not available:
                break
        if process.wait() != 0:
            raise RuntimeError('inotifywait exited unsuccessfully')
    finally:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:process.kill();process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'info', 'serve', 'watch', 'configure', 'verify'])
    parser.add_argument('--work', required=True)
    parser.add_argument('--variant', type=int)
    parser.add_argument('--field')
    parser.add_argument('--bind')
    parser.add_argument('--peer')
    parser.add_argument('--state', choices=['after', 'restore'])
    a = parser.parse_args()
    try:
        if a.action == 'init':
            if a.variant is None:raise ValueError('--variant is required')
            print(json.dumps(initialize(a.work, a.variant), sort_keys=True));return
        s = load(a.work)
        if a.action == 'info':
            if a.field not in s:raise ValueError('unknown field')
            print(s[a.field])
        elif a.action == 'serve':
            if not a.bind or not a.peer:raise ValueError('--bind and --peer are required')
            server(s, a.bind, a.peer)
        elif a.action == 'watch':watch(s)
        elif a.action == 'configure':
            if not a.state:raise ValueError('--state is required')
            configure(s, a.state)
        else:
            original = (Path(s['work']) / 'evidence/config-original.bin').read_bytes()
            expected = (Path(s['work']) / 'evidence/control-original.sha256').read_text().strip()
            ok = (Path(s['config']).read_bytes() == original and hashlib.sha256(Path(s['data']).read_bytes()).hexdigest() == expected)
            print(json.dumps(dict(restored=ok)))
            if not ok:parser.exit(1, 'teaching files were not restored\n')
    except (ValueError, OSError, RuntimeError) as e:
        parser.exit(1, 'PR10 error: %s\n' % e)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
