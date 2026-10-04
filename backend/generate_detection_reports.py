"""Build Markdown/CSV/XLSX from local results only; no network client or sample reads."""
import argparse
import json
from pathlib import Path

from app.services.detection_reports import DetectionReports, render_markdown
from app.services.result_exports import bundle_bytes
from app.providers.virustotal import normalize_report


def generate_saved_reports(experiment: Path, results: Path, raw_reports: Path | None = None) -> DetectionReports:
    store=DetectionReports(results,experiment)
    inventory=json.loads((experiment/'input-inventory.json').read_text(encoding='utf-8'))
    for group in ('A','B'):
        saved=json.loads((experiment/f'group-{group.lower()}-results.json').read_text(encoding='utf-8'))
        for sample in saved['samples']:
            report=sample.get('report')
            raw_path=raw_reports/f'{sample["sha256"]}.json' if raw_reports is not None else None
            if report and raw_path is not None and raw_path.is_file():
                normalized=normalize_report(json.loads(raw_path.read_text(encoding='utf-8')),sample['sha256'])
                if normalized['stats']==report['stats'] and normalized['analysisTime']==report.get('analysisTime'):
                    report=dict(report,threatClassification=normalized.get('threatClassification'))
            aliases=[file for file in inventory['groupA']['files'] if file['sha256']==sample['sha256']] if group=='A' else [{}]
            for file in aliases:
                store.save(sample['sha256'],sample['queryStatus'],report,filename=file.get('path'),
                    size=file.get('size'),group=group,queried_at=sample.get('queriedAt'),error=sample.get('error'))
    upload=experiment/'group-a-upload-results.json'
    if upload.is_file():
        store.save_uploads(json.loads(upload.read_text(encoding='utf-8')))
    else:
        store.export_indexes()
    temporary=results/'detection-reports.zip.tmp'
    rows=store.rows()
    temporary.write_bytes(bundle_bytes(results,rows,{row['report']:render_markdown(row,row['normalized_report']) for row in rows}))
    temporary.replace(results/'detection-reports.zip')
    return store


def main():
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment',type=Path,default=root/'results/experiment-3')
    parser.add_argument('--results',type=Path,default=root/'results')
    parser.add_argument('--raw-reports',type=Path,default=root/'data/reports/virustotal')
    args=parser.parse_args()
    store=generate_saved_reports(args.experiment,args.results,args.raw_reports)
    print(json.dumps({'reports':len(store.rows()),'apiRequests':0,'source':'saved_results'},ensure_ascii=False))


if __name__=='__main__': main()
