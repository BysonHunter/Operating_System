#!/usr/bin/env python3
"""Two HTTP services and one bounded UDP echo service for PR8."""
import argparse
import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind', required=True)
    p.add_argument('--variant', type=int, required=True)
    a = p.parse_args()
    ipaddress.IPv4Address(a.bind)
    if not 1 <= a.variant <= 27:
        p.error('variant must be 1..27')
    base = 18000 + 10 * a.variant
    servers = []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for label, port in [('A', base), ('B', base + 1)]:
            def handler(service):
                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        body = ('PR8 variant=%d service=%s\n' % (a.variant, service)).encode()
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/plain; charset=utf-8')
                        self.send_header('Content-Length', str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                return Handler
            servers.append(ThreadingHTTPServer((a.bind, port), handler(label)))
        udp.bind((a.bind, base + 2))
        udp.settimeout(0.5)
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print('PR8: HTTP A=%d B=%d UDP=%d on %s; Ctrl+C stops all services'
              % (base, base + 1, base + 2, a.bind), flush=True)
        while True:
            try:
                data, peer = udp.recvfrom(1024)
            except socket.timeout:
                continue
            # Answer only the exact benign probe used by this work.
            if data == b'PR8?':
                udp.sendto(('PR8 variant=%d udp=ok\n' % a.variant).encode(), peer)
                print('UDP probe from %s:%d' % peer, flush=True)
    except KeyboardInterrupt:
        print('\nStopping PR8 services', flush=True)
    finally:
        udp.close()
        for server in servers:
            server.server_close()


if __name__ == '__main__':
    main()
