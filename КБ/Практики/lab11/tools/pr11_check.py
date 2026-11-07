#!/usr/bin/env python3
"""PR11 (Kali): bounded remote check of the own Astra teaching service.

One host, one TCP port of the variant, a fixed short list of GET requests, no proxies, no brute force,
no exploitation, no file uploads. The value of the teaching token is never stored: only key names.
Standard library only, Python 3.5 syntax.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def get(opener, url):
    t0 = time.time()
    try:
        r = opener.open(url, timeout=5)
        code, headers, body, err = r.status, r.headers, r.read(65536), ''
    except urllib.error.HTTPError as e:
        code, headers, body, err = e.code, e.headers, e.read(65536), ''
    except Exception as e:  # noqa: network errors are recorded, not hidden
        code, headers, body, err = None, {}, b'', '%s: %s' % (type(e).__name__, e)
    return code, headers, body, err, round(time.time() - t0, 4)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host', required=True)
    ap.add_argument('--variant', type=int, required=True)
    ap.add_argument('--run', required=True)
    ap.add_argument('--phase', required=True, choices=['before', 'updated', 'restarted'])
    ap.add_argument('--advisory', required=True, help='verified copy of OSLAB-2026-11.json')
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    v = a.variant
    if not 1 <= v <= 27:
        raise SystemExit('variant must be 1..27')
    if not re.match(r'^v%02d-[a-f0-9]{12}$' % v, a.run):
        raise SystemExit('RUN_ID does not match the variant; copy it exactly from Astra parameters.txt')
    host = ipaddress.IPv4Address(a.host)
    if not host.is_private or host.is_loopback:
        raise SystemExit('target must be the own Astra address in the isolated teaching segment')
    if str(host) != '10.50.%d.10' % v:
        print('WARNING: %s differs from the default passport 10.50.%d.10; record the approved passport' % (host, v),
              file=sys.stderr)
    if os.path.exists(a.output):
        raise SystemExit('refusing to overwrite ' + a.output)
    bulletin = json.load(open(a.advisory, encoding='utf-8'))
    port = 22000 + v
    probes = 1 + (v - 1) % 3
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    plan = [('root%d' % i, '/') for i in range(1, probes + 1)] + [('health', '/health'), ('debug', '/debug')]
    rows = []
    banner = ''
    debug_observed = False
    debug_keys = []
    valid = True
    for name, path in plan:
        rid = '%s-%s-%s' % (a.run, a.phase, name)
        url = 'http://%s:%d%s?rid=%s' % (host, port, path, rid)
        code, headers, body, err, rtt = get(opener, url)
        server = headers.get('Server', '') if headers else ''
        banner = banner or server
        row = dict(kind='request', run=a.run, variant=v, phase=a.phase, request_id=rid, path=path, http_status=code,
                   server_header=server, rtt_s=rtt, client_utc=utc(), body_sha256=hashlib.sha256(body).hexdigest(),
                   error=err)
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except ValueError:
            data = {}
        if path in ('/', '/health'):
            row['valid'] = code == 200 and data.get('run') == a.run
            valid = valid and row['valid']
        if path == '/debug' and code == 200 and isinstance(data.get('config'), dict):
            debug_observed = True
            debug_keys = sorted(data['config'])
            row['debug_config_keys'] = debug_keys
            row['note'] = 'values not stored'
        rows.append(row)
    m = re.match(r'^PR11Demo/([0-9][0-9.]*)', banner)
    upstream = m.group(1) if m else ''
    findings = []
    for adv in bulletin['advisories']:
        by_version = upstream in adv.get('affected_upstream', [])
        if adv['id'].endswith('1101') and debug_observed:
            st, why = 'OBSERVED', 'GET /debug -> 200 with config keys %s' % (','.join(debug_keys) or '(none)')
        elif by_version and adv.get('remote_check'):
            st, why = 'POSSIBLE_BY_VERSION', 'banner %s in affected_upstream; remote check negative' % banner
        elif by_version:
            st, why = 'POSSIBLE_BY_VERSION', 'banner %s in affected_upstream; no remote check exists' % banner
        else:
            st, why = 'NOT_FLAGGED', 'banner %s not in affected_upstream' % (banner or '(none)')
        findings.append(dict(id=adv['id'], remote_status=st, basis=why))
    summary = dict(kind='summary', run=a.run, variant=v, phase=a.phase, target='%s:%d' % (host, port),
                   banner=banner, upstream=upstream, requests=len(rows), valid=valid, findings=findings,
                   client_utc=utc(), limits='one host, one port, %d GET requests, no exploitation' % len(rows))
    with open(a.output, 'w', encoding='utf-8') as s:
        for r in rows + [summary]:
            s.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n')
    for r in rows:
        print('%-8s %-8s HTTP %-4s %s %s' % (r['request_id'].split('-')[-1], r['path'], r['http_status'],
                                           r['server_header'], r['error']))
    for f in findings:
        print('%s %-19s %s' % (f['id'], f['remote_status'], f['basis']))
    print('valid=%s saved %s' % (valid, a.output))
    return 0 if valid else 5


if __name__ == '__main__':
    sys.exit(main())
