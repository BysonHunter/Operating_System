#!/usr/bin/env python3
"""One UDP request; report an application response, timeout or network error."""
import argparse
import ipaddress
import socket
import sys
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('host')
p.add_argument('port', type=int)
a = p.parse_args()
ipaddress.IPv4Address(a.host)
if not 1 <= a.port <= 65535:
    p.error('port must be 1..65535')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    s.connect((a.host, a.port))
    try:
        s.send(b'PR8?')
        print(s.recv(1024).decode('utf-8', errors='replace'), end='')
    except socket.timeout:
        print('TIMEOUT: no application response; correlate with service and firewall counters')
        sys.exit(2)
    except OSError as e:
        print('NETWORK ERROR: %s' % e)
        sys.exit(3)
