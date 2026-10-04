"""Only hashes and GET reports; never opens, uploads or executes sample files."""
import argparse
import csv
import json
from pathlib import Path
from datetime import UTC, datetime
from dotenv import load_dotenv


def save_results(service, batch_ids: dict, output: Path) -> None:
    summary = {}
    for group, batch_id in batch_ids.items():
        result = service.export_batch(batch_id)
        summary[group] = result['summary']
        (output / f'group-{group.lower()}-results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),encoding='utf-8')
        with (output / f'group-{group.lower()}-results.csv').open('w',encoding='utf-8-sig',newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['sha256','queryStatus','risk','malicious','suspicious','undetected','totalEngines','analysisTime','queriedAt','attempts','fromCache','error'])
            for row in result['samples']:
                report = row['report'] or {}
                stats = report.get('stats',{})
                writer.writerow([row['sha256'],row['queryStatus'],row['risk'],stats.get('malicious'),stats.get('suspicious'),stats.get('undetected'),report.get('totalEngines'),report.get('analysisTime'),row['queriedAt'],row['attempts'],row['fromCache'],row['error']])
    (output/'execution-summary.json').write_text(json.dumps({'updatedAt':datetime.now(UTC).isoformat(),'groups':summary},ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'results'/'experiment-3')
    parser.add_argument('--max-jobs',type=int,default=3,help='Default small real verification; use --all only after verification')
    parser.add_argument('--all',action='store_true')
    parser.add_argument('--export-only',action='store_true')
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    load_dotenv(root/'.env.local',override=False)
    from app.main import create_app
    app = create_app(database_url=f"sqlite:///{root/'backend'/'data'/'analysis.db'}",cverc_enabled_reports=(),cn_platform_api_key='')
    service = app.state.batch_service
    output = arguments.output.resolve()
    output.mkdir(parents=True,exist_ok=True)
    state_path = output/'batch-ids.json'
    if state_path.exists():
        batch_ids = json.loads(state_path.read_text(encoding='utf-8'))
        if any(service.detail(value) is None for value in batch_ids.values()):
            raise SystemExit('Stored batch IDs are absent from database; do not overwrite existing results')
    else:
        batch_ids = {}
        for group, filename in [('A','group-a-candidate-sha256.txt'),('B','group-b-sha256.txt')]:
            from app.services.inputs import preview_hashes
            preview = preview_hashes((output/filename).read_text(encoding='utf-8-sig').splitlines())
            if preview.invalid or preview.duplicates or not preview.valid_sha256s:
                raise SystemExit('Invalid experiment manifest')
            batch_ids[group] = service.create(f'实验第三部分 · {group}组全部样本','txt',preview.valid_sha256s).id
        state_path.write_text(json.dumps(batch_ids,indent=2),encoding='utf-8')
    save_results(service,batch_ids,output)
    if arguments.export_only:
        return
    if app.state.dispatcher._virustotal is None:
        raise SystemExit('VIRUSTOTAL_API_KEY is missing; no API requests sent')
    remaining = None if arguments.all else max(1,min(3,arguments.max_jobs))
    try:
        for group, batch_id in batch_ids.items():
            if remaining == 0:
                break
            before = service.export_batch(batch_id)['summary']['pending']
            app.state.dispatcher.run_batch(batch_id,max_jobs=remaining)
            save_results(service,batch_ids,output)
            after = service.export_batch(batch_id)
            if any(row['queryStatus'] in {'authentication_error','rate_limited'} for row in after['samples']):
                print('Paused: authentication or quota limit; no further groups requested',flush=True)
                break
            if remaining is not None:
                remaining = max(0,remaining - (before-after['summary']['pending']))
    finally:
        save_results(service,batch_ids,output)


if __name__ == '__main__':
    main()
