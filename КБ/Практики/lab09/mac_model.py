#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Educational Bell-LaPadula model. Python >= 3.5; NOT PARSEC or OS security."""
from __future__ import print_function
import argparse
import csv
import datetime
import hashlib
import json
import os
import sys

VERSION = '1.0'


def digest(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                     separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def load_json(path):
    with open(path, 'r', encoding='utf-8') as stream:
        return json.load(stream)


def save_json(path, value):
    temporary = path + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')
    os.replace(temporary, path)


def parameters(variant):
    if type(variant) is not int or not 1 <= variant <= 27:
        raise ValueError('variant must be an integer from 1 to 27')
    n = variant - 1
    high = n // 9 + 1
    a = 1 << ((n // 3) % 3)
    b = 1 << (3 + n % 3)
    return {'V': variant, 'H': high, 'L': high - 1, 'A': a, 'B': b}


def label(level, categories):
    return {'level': level, 'categories': categories}


def valid_label(value):
    return (isinstance(value, dict) and
            set(value) == set(['level', 'categories']) and
            type(value['level']) is int and 0 <= value['level'] <= 3 and
            type(value['categories']) is int and 0 <= value['categories'] <= 63)


def dominates(left, right):
    """A level dominates B iff level >= and B categories are a subset of A."""
    return (left['level'] >= right['level'] and
            (left['categories'] & right['categories']) == right['categories'])


def make_policy(variant):
    p = parameters(variant)
    labels = {'low': label(p['L'], p['A']),
              'high': label(p['H'], p['A']),
              'foreign': label(p['H'], p['B']),
              'wide': label(p['H'], p['A'] | p['B'])}
    users = dict((name, {'active': value.copy(), 'clearance': value.copy()})
                 for name, value in labels.items())
    objects = {}
    for name, key in [('low_note', 'low'), ('high_note', 'high'),
                      ('foreign_note', 'foreign')]:
        objects[name] = {'label': labels[key].copy(),
                         'data': 'SYNTHETIC-V{0:02d}-{1}\n'.format(variant, name)}
    return {'model': 'BLP-fixed-labels', 'version': VERSION,
            'parameters': p, 'subjects': users}, objects


def load_workspace(workspace):
    policy = load_json(os.path.join(workspace, 'policy.json'))
    objects = load_json(os.path.join(workspace, 'objects.json'))
    if policy.get('model') != 'BLP-fixed-labels' or policy.get('version') != VERSION:
        raise ValueError('unknown model or format version')
    if not isinstance(policy.get('subjects'), dict) or not isinstance(objects, dict):
        raise ValueError('invalid subject/object table')
    for subject in policy['subjects'].values():
        if (not isinstance(subject, dict) or not valid_label(subject.get('active'))
                or not valid_label(subject.get('clearance'))
                or not dominates(subject['clearance'], subject['active'])):
            raise ValueError('invalid subject label or clearance')
    for obj in objects.values():
        if (not isinstance(obj, dict) or not valid_label(obj.get('label'))
                or not isinstance(obj.get('data'), str)):
            raise ValueError('invalid object label/data')
    return policy, objects


def read_decision(active, obj):
    if active['level'] < obj['level']:
        return False, 'READ_LEVEL'
    if (active['categories'] & obj['categories']) != obj['categories']:
        return False, 'READ_CATEGORY'
    return True, 'OK'


def write_decision(active, obj):
    if obj['level'] < active['level']:
        return False, 'WRITE_LEVEL'
    if (obj['categories'] & active['categories']) != active['categories']:
        return False, 'WRITE_CATEGORY'
    return True, 'OK'


def decision(policy, objects, request):
    subject = policy['subjects'].get(request['subject'])
    if subject is None:
        return False, 'UNKNOWN_SUBJECT', None
    active = subject['active'].copy()
    if request.get('level') is not None:
        active['level'] = request['level']
    if request.get('categories') is not None:
        active['categories'] = request['categories']
    if not valid_label(active) or not dominates(subject['clearance'], active):
        return False, 'CLEARANCE', active
    op = request['op']
    if op not in ('read', 'write', 'readwrite', 'copy'):
        return False, 'UNKNOWN_OPERATION', active
    obj = objects.get(request['object'])
    if obj is None:
        return False, 'UNKNOWN_OBJECT', active
    if op == 'copy':
        target = objects.get(request.get('target'))
        if target is None:
            return False, 'UNKNOWN_TARGET', active
        ok, reason = read_decision(active, obj['label'])
        if not ok:
            return False, 'SOURCE_' + reason, active
        ok, reason = write_decision(active, target['label'])
        return ok, ('OK' if ok else 'TARGET_' + reason), active
    if op in ('read', 'readwrite'):
        ok, reason = read_decision(active, obj['label'])
        if not ok:
            return False, reason, active
    if op in ('write', 'readwrite'):
        ok, reason = write_decision(active, obj['label'])
        if not ok:
            return False, reason, active
    return True, 'OK', active


def execute(workspace, request, case_id='manual'):
    policy, objects = load_workspace(workspace)
    before = digest(objects)
    allowed, reason, active = decision(policy, objects, request)
    output = None
    if allowed:
        obj = objects[request['object']]
        if request['op'] in ('read', 'readwrite'):
            output = obj['data']
        if request['op'] in ('write', 'readwrite'):
            obj['data'] += request.get('data', 'SYNTHETIC-APPEND\n')
        elif request['op'] == 'copy':
            objects[request['target']]['data'] = obj['data']
        if request['op'] != 'read':
            save_json(os.path.join(workspace, 'objects.json'), objects)
    after = digest(objects)
    record = {'utc': datetime.datetime.utcnow().isoformat() + 'Z',
              'model': 'EDUCATIONAL-NOT-PARSEC', 'case': case_id,
              'request': request, 'active': active,
              'allowed': allowed, 'reason': reason,
              'state_before': before, 'state_after': after,
              'policy_sha256': digest(policy)}
    with open(os.path.join(workspace, 'audit.jsonl'), 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n')
    return record, output


def cases(variant):
    p = parameters(variant)
    raw = [('low', 'read', 'low_note', None),
           ('low', 'read', 'high_note', None),
           ('high', 'read', 'low_note', None),
           ('high', 'write', 'high_note', None),
           ('high', 'write', 'low_note', None),
           ('low', 'write', 'high_note', None),
           ('foreign', 'read', 'high_note', None),
           ('wide', 'read', 'foreign_note', None),
           ('high', 'write', 'foreign_note', None),
           ('high', 'readwrite', 'low_note', None),
           ('high', 'readwrite', 'high_note', None),
           ('high', 'copy', 'high_note', 'low_note'),
           ('high', 'copy', 'low_note', 'high_note'),
           ('low', 'readwrite', 'low_note', None),
           ('low', 'read', 'high_note', None),
           ('high', 'read', 'missing_note', None)]
    result = []
    for index, item in enumerate(raw, 1):
        request = dict(zip(('subject', 'op', 'object', 'target'), item))
        if index == 15:
            request['level'] = p['H']
        result.append(('T{0:02d}'.format(index), request))
    return result


def initialize(workspace, variant):
    policy, objects = make_policy(variant)
    os.mkdir(workspace, 0o700)  # existing directories are never overwritten
    save_json(os.path.join(workspace, 'policy.json'), policy)
    save_json(os.path.join(workspace, 'objects.json'), objects)
    with open(os.path.join(workspace, 'audit.jsonl'), 'w', encoding='utf-8'):
        pass
    with open(os.path.join(workspace, 'predictions.csv'), 'w',
              encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['case', 'subject', 'op', 'object', 'target',
                         'requested_level', 'predicted', 'explanation'])
        for case_id, request in cases(variant):
            writer.writerow([case_id, request['subject'], request['op'],
                             request['object'], request.get('target') or '',
                             request.get('level', ''), '', ''])
    print('INITIALIZED {0}; EDUCATIONAL MODEL, NOT PARSEC'.format(workspace))


def run_suite(workspace):
    policy, unused_objects = load_workspace(workspace)
    variant = policy['parameters']['V']
    if os.path.getsize(os.path.join(workspace, 'audit.jsonl')) != 0:
        raise ValueError('suite needs a fresh workspace with empty audit.jsonl')
    output_path = os.path.join(workspace, 'results.csv')
    with open(output_path, 'x', encoding='utf-8', newline='') as stream:
        fields = ['case', 'subject', 'op', 'object', 'target', 'decision',
                  'reason', 'active', 'state_unchanged', 'policy_sha256']
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for case_id, request in cases(variant):
            record, unused_data = execute(workspace, request, case_id)
            writer.writerow({'case': case_id, 'subject': request['subject'],
                             'op': request['op'], 'object': request['object'],
                             'target': request.get('target') or '',
                             'decision': 'ALLOW' if record['allowed'] else 'DENY',
                             'reason': record['reason'],
                             'active': json.dumps(record['active'], sort_keys=True),
                             'state_unchanged': record['state_before'] == record['state_after'],
                             'policy_sha256': record['policy_sha256']})
            print('{0}: {1} {2}'.format(case_id,
                  'ALLOW' if record['allowed'] else 'DENY', record['reason']))
    print('16 cases saved to results.csv and audit.jsonl')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    init = sub.add_parser('init', help='create a new model workspace')
    init.add_argument('--variant', type=int, required=True)
    init.add_argument('--workspace', required=True)
    for name in ('show', 'suite'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--workspace', required=True)
    access = sub.add_parser('access', help='one logical access request')
    access.add_argument('--workspace', required=True)
    access.add_argument('--subject', required=True)
    access.add_argument('--op', choices=('read', 'write', 'readwrite', 'copy'), required=True)
    access.add_argument('--object', required=True)
    access.add_argument('--target')
    access.add_argument('--level', type=int)
    access.add_argument('--categories', type=lambda x: int(x, 0))
    access.add_argument('--data', default='SYNTHETIC-APPEND\n')
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        if args.command == 'init':
            initialize(args.workspace, args.variant)
        elif args.command == 'suite':
            run_suite(args.workspace)
        elif args.command == 'show':
            policy, objects = load_workspace(args.workspace)
            summary = {'policy': policy,
                       'objects': dict((key, {'label': value['label'],
                                               'data_sha256': digest(value['data'])})
                                       for key, value in objects.items())}
            print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            request = dict((key, getattr(args, key)) for key in
                           ('subject', 'op', 'object', 'target', 'level', 'categories', 'data'))
            record, data = execute(args.workspace, request)
            print(json.dumps(record, ensure_ascii=False, sort_keys=True))
            if data is not None:
                print(data, end='')
            return 0 if record['allowed'] else 3
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('ERROR: {0}'.format(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
