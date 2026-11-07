#!/usr/bin/env python3
"""Merge preserved journal/HTTP evidence. Does not modify clocks or logs."""
import argparse
import csv
import datetime
import json
from pathlib import Path


def read_jsonl(path):
    rows=[]
    for n,line in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(),1):
        if line.strip():
            try:rows.append(json.loads(line))
            except ValueError:raise ValueError('%s:%d is not JSON'%(path,n))
    return rows


def utc(epoch):
    return datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).isoformat()


def merge(journal, auth, clients, run):
    client_rows=[]
    for path in clients:client_rows.extend(row for row in read_jsonl(path) if row.get('run')==run)
    calibration={}
    for row in client_rows:
        if row.get('route')!='/ping' or not row.get('valid_response'):continue
        payload=row.get('payload') or {}
        if not isinstance(payload.get('server_epoch'),(int,float)):continue
        lo=payload['server_epoch']-row['client_recv'];hi=payload['server_epoch']-row['client_send']
        phase=row['phase'];candidate=dict(low=lo,high=hi,mid=(lo+hi)/2,half_width=(hi-lo)/2,request_id=row['request_id'])
        if phase not in calibration or candidate['half_width']<calibration[phase]['half_width']:
            calibration[phase]=candidate
    output=[];seen=set()
    for row in read_jsonl(journal):
        try:message=json.loads(row.get('MESSAGE',''))
        except (ValueError,TypeError):continue
        if message.get('run')!=run:continue
        stamp=int(row['__REALTIME_TIMESTAMP'])/1000000.0
        ident=(row.get('_BOOT_ID'),row.get('__CURSOR'))
        if ident[1] and ident in seen:continue
        seen.add(ident)
        event=message.get('event','UNKNOWN')
        detail=message.get('fs_event') or message.get('mode') or message.get('http_status') or ''
        output.append(dict(epoch=stamp,utc=utc(stamp),source='astra_journal',event=event,
                           request_id=message.get('request_id',''),object=message.get('path',''),
                           sender_pid=row.get('_PID',''),sender_uid=row.get('_UID',''),
                           unit=row.get('_SYSTEMD_UNIT',''),peer=message.get('peer',''),
                           uncertainty_seconds='',detail=str(detail)))
    for row in read_jsonl(auth):
        if '__REALTIME_TIMESTAMP' not in row:continue
        stamp=int(row['__REALTIME_TIMESTAMP'])/1000000.0
        output.append(dict(epoch=stamp,utc=utc(stamp),source='astra_auth_candidate',event='LOGIN_CONTEXT_REVIEW',
                           request_id='',object='',sender_pid=row.get('_PID',''),sender_uid=row.get('_UID',''),
                           unit=row.get('_SYSTEMD_UNIT',''),peer='',uncertainty_seconds='',
                           detail=str(row.get('MESSAGE',''))[:600]))
    for row in client_rows:
        cal=calibration.get(row['phase'])
        corrected=row['client_send']+cal['mid'] if cal else row['client_send']
        output.append(dict(epoch=corrected,utc=utc(corrected),source='kali_corrected' if cal else 'kali_uncalibrated',
                           event='HTTP_REQUEST',request_id=row['request_id'],object=row['route'],sender_pid='',sender_uid='',
                           unit='',peer='',uncertainty_seconds=cal['half_width'] if cal else 'unknown',
                           detail='HTTP=%s valid=%s'%(row.get('http_status'),row.get('valid_response'))))
    output.sort(key=lambda x:(x['epoch'],x['source'],x['request_id']))
    return output,calibration


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--journal',required=True);p.add_argument('--auth',required=True)
    p.add_argument('--client',action='append',required=True);p.add_argument('--run',required=True)
    p.add_argument('--output',required=True);a=p.parse_args()
    try:
        target=Path(a.output)
        if target.exists():raise ValueError('output exists; preserve the previous timeline')
        rows,cal=merge(a.journal,a.auth,a.client,a.run)
        if not rows:raise ValueError('no matching events')
        with target.open('w',encoding='utf-8-sig',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['utc','source','event','request_id','object','sender_pid','sender_uid','unit','peer','uncertainty_seconds','detail'],extrasaction='ignore')
            writer.writeheader();writer.writerows(rows)
        target.with_suffix('.clock.json').write_text(json.dumps(cal,sort_keys=True,indent=2),encoding='utf-8')
        print('timeline rows=%d; calibrated phases=%d'%(len(rows),len(cal)))
        if not cal:print('WARNING: clocks were not calibrated; cross-host ordering is unconfirmed')
    except (OSError,ValueError,KeyError) as exc:p.exit(1,'Timeline error: %s\n'%exc)


if __name__=='__main__':main()
