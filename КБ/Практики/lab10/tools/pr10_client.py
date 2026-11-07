#!/usr/bin/env python3
"""Send a finite set of benign PR10 HTTP requests to one explicit IPv4."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.request import build_opener, ProxyHandler, Request, HTTPRedirectHandler
from urllib.error import HTTPError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(opener, host, port, run, phase, suffix, route):
    rid = '%s-%s-%s' % (run, phase, suffix)
    url = 'http://%s:%d%s?rid=%s' % (host, port, route, rid)
    start = time.time();status = None;payload = None;error = None
    try:
        try:response = opener.open(Request(url), timeout=3)
        except HTTPError as exc:response = exc
        with response:
            status = response.code
            payload = json.loads(response.read(4096).decode('utf-8'))
    except (OSError, ValueError) as exc:
        error = str(exc)
    end = time.time()
    return dict(source='kali_client', run=run, phase=phase, request_id=rid, route=route,
                client_send=start, client_recv=end, rtt_seconds=end-start,
                http_status=status, payload=payload, error=error)


def run_requests(host, variant, run, phase, output):
    host = str(ipaddress.IPv4Address(host))
    if not 1 <= variant <= 27 or not re.fullmatch(r'v%02d-[a-f0-9]{12}' % variant, run):
        raise ValueError('variant/run mismatch')
    target = Path(output)
    if target.exists():raise ValueError('output exists; preserve it before repeating')
    opener = build_opener(ProxyHandler({}), NoRedirect())
    items = [('clock%d' % n, '/ping') for n in range(1,4)]
    items += [('read%d' % n, '/read') for n in range(1,2 + ((variant-1) % 3))]
    items += [('status','/status'),('denied','/denied')]
    ok = True
    with target.open('w', encoding='utf-8') as stream:
        for suffix,route in items:
            row = request(opener, host, 21000+variant, run, phase, suffix, route)
            payload = row['payload'] or {}
            valid = (row['error'] is None and row['http_status'] == (403 if route == '/denied' else 200)
                     and payload.get('run') == run and payload.get('request_id') == row['request_id'])
            row['valid_response'] = valid;ok = ok and valid
            stream.write(json.dumps(row, sort_keys=True) + '\n');stream.flush()
            print('%s HTTP=%s valid=%s' % (row['request_id'],row['http_status'],valid))
            time.sleep(0.2)
    return ok


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True);p.add_argument('--variant',type=int,required=True)
    p.add_argument('--run',required=True);p.add_argument('--phase',choices=['before','after','restored'],required=True)
    p.add_argument('--output',required=True);a=p.parse_args()
    try:ok=run_requests(a.host,a.variant,a.run,a.phase,a.output)
    except (OSError,ValueError) as exc:p.exit(1,'PR10 client: %s\n'%exc)
    if not ok:p.exit(1,'At least one response was not confirmed; inspect the saved evidence.\n')


if __name__=='__main__':main()
