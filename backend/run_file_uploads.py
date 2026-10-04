"""Explicitly authorized A-group upload experiment. Reads bytes, never executes files."""
import argparse
import csv
import io
import json
import os
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from app.database import create_session_factory
from app.providers.upload import FileUploadClient
from app.services.quota import PersistentDailyQuota
from app.services.detection_reports import DetectionReports

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'results'/'experiment-3'

def make_state(manifest):
    seen=set()
    samples=[]
    for file in manifest['groupA']['files']:
        if file['sha256'] in seen: continue
        seen.add(file['sha256'])
        samples.append(dict(file,status='pending',analysisId=None,uploadAttempts=0,pollAttempts=0,report=None,error=None))
    return {'method':'file_upload','apiRequests':0,'lastRequestAt':None,'cooldownUntil':None,'samples':samples,'readErrors':manifest['groupA']['errors']}

def read_member(archive_path, row):
    parts=row['path'].split('!/')
    data=archive_path.read_bytes()
    for name in parts:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member=archive.getinfo(name)
            if member.file_size > 32*1024*1024: raise ValueError('Member exceeds upload limit')
            data=archive.read(member,pwd=b'virus')
    return data

def run_uploads(state,save,read_file,provider,quota,max_uploads=1,interval=16,poll_delay=120,sleeper=time.sleep):
    def now(): return datetime.now(UTC)
    if state.get('cooldownUntil') and datetime.fromisoformat(state['cooldownUntil']) > now(): return
    def reserve():
        if quota.remaining(now()) <= 0:
            state['pauseReason']='Local daily request budget exhausted'; save(); return False
        if state.get('lastRequestAt'):
            sleeper(max(0,interval-(now()-datetime.fromisoformat(state['lastRequestAt'])).total_seconds()))
        if not quota.reserve(now(),1).allowed: return False
        state['apiRequests']+=1
        state['lastRequestAt']=now().isoformat()
        return True
    def halted(result):
        if result.status in ('rate_limited','authentication_error','submission_unknown','failed'):
            state['pauseReason']=result.error or result.status
            if result.status=='rate_limited': state['cooldownUntil']=(now()+timedelta(seconds=max(interval,result.retry_after or 60))).isoformat()
            save(); return True
        return False
    state.pop('pauseReason',None)
    submitted=0
    for row in state['samples']:
        if row['status']!='pending' or submitted>=max_uploads: continue
        if quota.remaining(now()) <= 0: reserve(); return
        try: contents=read_file(row)
        except (OSError,ValueError,RuntimeError,zipfile.BadZipFile,NotImplementedError) as exc:
            row.update(status='read_failed',error=type(exc).__name__); save(); continue
        if not reserve(): return
        # Commit uncertainty before sending: an interrupted POST must not be submitted again.
        row.update(status='submission_unknown',uploadAttempts=1,uploadedAt=now().isoformat(),error='Submission outcome not yet known')
        save()
        result=provider.upload(contents,row['sha256'])
        del contents
        row.update(status=result.status,error=result.error)
        if result.status=='accepted':
            row['analysisId']=result.raw['data']['id']
            row['nextPollAt']=(now()+timedelta(seconds=poll_delay)).isoformat()
        save(); submitted+=1
        if halted(result): return
    for row in state['samples']:
        if not row['analysisId'] or row['status']=='success' or row['pollAttempts']>=3: continue
        deadline=datetime.fromisoformat(row['nextPollAt'])
        if deadline > now(): continue  # Resume later rather than blocking or aggressive polling.
        if not reserve(): return
        row['pollAttempts']+=1; row['queriedAt']=now().isoformat(); save()
        result=provider.analysis(row['analysisId'],row['sha256'])
        row.update(status=result.status,error=result.error,report=result.report)
        row['nextPollAt']=(now()+timedelta(seconds=300)).isoformat()
        if result.raw is not None:
            row['rawAnalysis']=result.raw
        save()
        if halted(result): return

def save_state(state,output,detection_reports=None):
    state['updatedAt']=datetime.now(UTC).isoformat()
    destination=output/'group-a-upload-results.json'
    temporary=destination.with_suffix('.tmp')
    temporary.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
    temporary.replace(destination)
    with (output/'group-a-upload-results.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.writer(stream)
        writer.writerow(['archivePath','sha256','uploadStatus','analysisId','risk','malicious','totalEngines','analysisTime','uploadAttempts','pollAttempts','error'])
        for row in state['samples']:
            report=row['report'] or {}
            writer.writerow([row['path'],row['sha256'],row['status'],row['analysisId'],report.get('risk','unknown'),report.get('stats',{}).get('malicious'),report.get('totalEngines'),report.get('analysisTime'),row['uploadAttempts'],row['pollAttempts'],row['error']])
    if detection_reports is not None:
        error_before=state.get('reportError')
        try:
            detection_reports.save_uploads(state)
            detection_reports.last_error=None
            state.pop('reportError',None)
        except OSError:
            detection_reports.last_error='report_write_failed'
            state['reportError']='report_write_failed'
        if state.get('reportError')!=error_before:
            temporary.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
            temporary.replace(destination)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--acknowledge-upload',action='store_true',help='Explicit consent to send malware bytes to VirusTotal standard scanning')
    parser.add_argument('--all',action='store_true')
    parser.add_argument('--poll-only',action='store_true')
    args=parser.parse_args()
    if not args.acknowledge_upload: raise SystemExit('Explicit upload acknowledgement required; no request sent')
    load_dotenv(ROOT/'.env.local',override=False)
    key=os.getenv('VIRUSTOTAL_API_KEY','')
    if not key: raise SystemExit('Missing API key; no request sent')
    manifest=json.loads((OUTPUT/'input-inventory.json').read_text(encoding='utf-8'))
    path=OUTPUT/'group-a-upload-results.json'
    state=json.loads(path.read_text(encoding='utf-8')) if path.exists() else make_state(manifest)
    reports=DetectionReports(ROOT/'results',OUTPUT)
    save=lambda:save_state(state,OUTPUT,reports)
    save()
    quota=PersistentDailyQuota(create_session_factory(f"sqlite:///{ROOT/'backend'/'data'/'analysis.db'}"),'virustotal',int(os.getenv('VIRUSTOTAL_DAILY_BUDGET','500')))
    run_uploads(state,save,lambda row:read_member(args.archive,row),FileUploadClient(key),quota,max_uploads=0 if args.poll_only else len(state['samples']) if args.all else 1)
    counts={status:sum(row['status']==status for row in state['samples']) for status in sorted({row['status'] for row in state['samples']})}
    print(json.dumps({'apiRequests':state['apiRequests'],'statuses':counts,'pauseReason':state.get('pauseReason')},ensure_ascii=False),flush=True)

if __name__=='__main__': main()
