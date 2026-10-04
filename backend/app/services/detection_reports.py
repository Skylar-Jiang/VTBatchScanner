"""Generate concise evidence-based reports from saved, normalized VT results."""
import html
import json
import re
from pathlib import Path
from threading import Lock

from app.services.inputs import SHA256_PATTERN
from app.services.result_exports import csv_bytes, xlsx_bytes


def basename(filename: str) -> str:
    return re.split(r'[/\\]', filename)[-1]


def safe_filename(filename: str) -> str:
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', '_', basename(filename)).strip(' .')
    if not name:
        name = 'unnamed'
    if re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', name, re.I):
        name = '_' + name
    suffix = Path(name).suffix[:24]
    stem = name[:-len(suffix)] if suffix else name
    # Leave room for .md and a full-SHA collision suffix on Linux as well as Windows.
    while len(stem + suffix) > 150 or len((stem + suffix).encode('utf-8')) > 180:
        stem = stem[:-1]
    return stem + suffix


def md_text(value) -> str:
    if value is None or value == '':
        return '未提供'
    text = re.sub(r'[\x00-\x1f]', ' ', str(value))
    return html.escape(text).replace('|', r'\|').replace('`', '&#96;').replace('[', r'\[').replace(']', r'\]')


def representative_engines(report: dict) -> list[tuple[str, str | None]]:
    priority = ('Microsoft', 'Kaspersky', 'BitDefender', 'ESET-NOD32', 'ALYac', 'Sophos', 'Avast', 'TrendMicro')
    engines = [(name, engine.get('result')) for name, engine in report.get('engines', {}).items() if engine.get('category') == 'malicious']
    return sorted(engines, key=lambda item: (priority.index(item[0]) if item[0] in priority else len(priority), item[0]))[:8]


def render_markdown(row: dict, report: dict) -> str:
    lines = ['# 检测报告', '', '## Sample Information', '']
    fields = [('Original Filename', row['filename'] or None), ('SHA-256', row['sha256']),
        ('File Size', row['file_size']), ('File Type', row['file_type']),
        ('Analysis Time', row['analysis_time']), ('Detection Source', row['source']), ('Query Status', row['query_status'])]
    lines += [f'- {label}: {md_text(value)}' for label, value in fields]
    lines += ['', '## VirusTotal Detection Summary', '', '| 指标 | 数量 |', '|---|---:|']
    lines += [f'| {key} | {row[key] if row[key] is not None else "未提供"} |' for key in ('malicious','suspicious','undetected','unsupported','total_engines')]
    classification = report.get('threatClassification') or {}
    lines += ['', '## Threat Classification', '', f'- suggested_threat_label: {md_text(classification.get("suggested_threat_label"))}']
    for field in ('popular_threat_category', 'popular_threat_name'):
        values = classification.get(field) or []
        text = ', '.join(f'{md_text(item.get("value"))} ({item.get("count", "未提供")})' for item in values if isinstance(item, dict))
        lines.append(f'- {field}: {text or "未提供"}')
    lines += ['', '## Representative Engine Results', '']
    engines = representative_engines(report)
    if engines:
        lines += ['| 引擎 | 检测标签 |', '|---|---|']
        lines += [f'| {md_text(name)} | {md_text(result)} |' for name, result in engines]
    else:
        lines.append('没有可展示的恶意引擎结果。')
    lines += ['', '## Analysis Summary', '']
    if row['query_status'] != 'success':
        summary = f'当前状态为 {row["query_status"]}，尚无可用的成功检测报告，不能据此认定文件安全。'
    elif row['risk'] == 'malicious':
        summary = f'本次报告有 {row["malicious"]} / {row["total_engines"]} 个引擎报告恶意，汇总标签为“恶意命中”。'
    elif row['risk'] == 'suspicious':
        summary = f'没有恶意命中，{row["suspicious"]} 个引擎报告可疑，汇总标签为“可疑”。'
    elif row['risk'] == 'undetected':
        summary = '当前报告没有恶意或可疑命中，汇总标签为“未检出”，不能据此认定文件安全。'
    else:
        summary = '可用引擎信息不足，汇总标签为“未知”，不能据此认定文件安全。'
    lines += [summary]
    if row['error']:
        lines += ['', '错误记录：' + md_text(row['error'])]
    lines += ['', '## Source', '', f'- VirusTotal: [{row["sha256"]}]({row["virustotal"]})',
        f'- 查询时间（UTC）: {md_text(row["queried_at"])}', f'- 分析时间（UTC）: {md_text(row["analysis_time"])}', '']
    history = row.get('history_query')
    if history:
        lines += ['## Historical SHA-256 Query', '',
            f'- 查询状态: {md_text(history["query_status"])}',
            f'- 恶意 / 引擎总数: {md_text(history["malicious"])} / {md_text(history["total_engines"])}',
            f'- suggested_threat_label: {md_text(history["threat_label"])}',
            f'- 查询时间（UTC）: {md_text(history["queried_at"])}',
            f'- 分析时间（UTC）: {md_text(history["analysis_time"])}', '']
    return '\n'.join(lines)


class DetectionReports:
    def __init__(self, root: Path, experiment_root: Path | None = None):
        self.root = root.resolve()
        self.index_path = self.root / '.report-index.json'
        self._lock = Lock()
        self.experiment_root = experiment_root
        self.last_error = None

    def rows(self) -> list[dict]:
        return json.loads(self.index_path.read_text(encoding='utf-8')) if self.index_path.is_file() else []

    def _path(self, kind: str, sha256: str, filename: str, rows: list[dict]) -> str:
        name = safe_filename(filename) if filename else sha256
        relative = f'reports/{kind}/{name}.md'
        occupied = {row['report'].casefold() for row in rows}
        existing = {path.name.casefold() for path in (self.root/'reports'/kind).glob('*')}
        if relative.casefold() in occupied or (name+'.md').casefold() in existing:
            name += '__' + sha256[:8]
            relative = f'reports/{kind}/{name}.md'
            number = 0
            while relative.casefold() in occupied or (name+'.md').casefold() in existing:
                number += 1
                name = (safe_filename(filename) if filename else sha256) + '__' + sha256 + f'_{number}'
                relative = f'reports/{kind}/{name}.md'
        return relative

    def save(self, sha256: str, status: str, report: dict | None = None, *, filename: str | None = None,
             source: str = 'SHA-256 Query', group: str = '', queried_at: str | None = None,
             size: int | None = None, error: str | None = None, persist: bool = True,
             existing_rows: list[dict] | None = None) -> dict:
        sha256 = sha256.strip().lower()
        if not SHA256_PATTERN.fullmatch(sha256):
            raise ValueError('Invalid SHA256')
        if report and report.get('sha256') != sha256:
            raise ValueError('Report SHA256 mismatch')
        report = report if status == 'success' and report else {}
        filename = basename(filename) if filename else ''
        kind = 'files' if filename else 'hashes'
        with self._lock:
            rows = self.rows() if existing_rows is None else existing_rows
            previous = next((row for row in rows if row['sha256'] == sha256 and row['filename'].casefold() == filename.casefold()), None)
            relative = previous['report'] if previous else self._path(kind, sha256, filename, rows)
            stats = report.get('stats', {})
            classification = report.get('threatClassification') or {}
            row = {'group': group, 'filename': filename, 'sha256': sha256, 'query_status': status,
                'risk': report.get('risk', 'unknown'), 'malicious': stats.get('malicious', 0) if report else None,
                'suspicious': stats.get('suspicious', 0) if report else None, 'undetected': stats.get('undetected', 0) if report else None,
                'unsupported': stats.get('type-unsupported', 0) if report else None, 'total_engines': report.get('totalEngines'),
                'threat_label': classification.get('suggested_threat_label') or '', 'analysis_time': report.get('analysisTime'),
                'report': relative, 'virustotal': f'https://www.virustotal.com/gui/file/{sha256}', 'source': source,
                'queried_at': queried_at, 'file_size': size if size is not None else report.get('size'),
                'file_type': report.get('fileType'), 'error': error}
            row['normalized_report'] = report
            if not persist:
                return row
            exported_row = row
            if filename and previous:
                if source == 'Uploaded File':
                    row['history_query'] = previous.get('history_query') or (previous if previous['source']=='SHA-256 Query' else None)
                elif previous['source'] == 'Uploaded File':
                    row = dict(previous, history_query=exported_row)
                    report = previous.get('normalized_report', {})
            path = (self.root / relative).resolve()
            if self.root not in path.parents or path.suffix != '.md':
                raise ValueError('Unsafe report path')
            path.parent.mkdir(parents=True, exist_ok=True)
            contents = render_markdown(row, report)
            if not path.is_file() or path.read_text(encoding='utf-8') != contents:
                temporary = path.with_suffix('.md.tmp')
                temporary.write_text(contents, encoding='utf-8')
                temporary.replace(path)
            rows = [item for item in rows if item is not previous] + [row]
            rows.sort(key=lambda item: (item['group'], item['filename'].casefold(), item['sha256']))
            temporary = self.index_path.with_suffix('.tmp')
            temporary.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
            temporary.replace(self.index_path)
            return exported_row

    def export_indexes(self) -> None:
        with self._lock:
            rows = self.rows()
            self.root.mkdir(parents=True, exist_ok=True)
            for name, contents in [('summary.csv', csv_bytes(rows)), ('summary.xlsx', xlsx_bytes(rows))]:
                temporary = self.root / (name + '.tmp')
                temporary.write_bytes(contents)
                temporary.replace(self.root / name)

    def find(self, kind: str, sha256: str, filename: str | None = None) -> dict | None:
        if kind not in {'files', 'hashes'} or not SHA256_PATTERN.fullmatch(sha256):
            return None
        return next((row for row in self.rows() if row['sha256'] == sha256 and row['report'].startswith(f'reports/{kind}/')
            and (filename is None or row['filename'].casefold() == basename(filename).casefold())), None)

    def save_query(self, sha256: str, status: str, report: dict | None, batch_id: str,
                   queried_at: str | None = None, error: str | None = None, *, persist: bool = True,
                   existing_rows: list[dict] | None = None) -> list[dict]:
        group = batch_id
        files = []
        if self.experiment_root is not None:
            ids_path = self.experiment_root / 'batch-ids.json'
            ids = json.loads(ids_path.read_text(encoding='utf-8')) if ids_path.is_file() else {}
            group = next((key for key, value in ids.items() if value == batch_id), batch_id)
            inventory = self.experiment_root / 'input-inventory.json'
            if group == 'A' and inventory.is_file():
                files = [file for file in json.loads(inventory.read_text(encoding='utf-8'))['groupA']['files'] if file['sha256'] == sha256]
        saved=[]
        planning=self.rows() if not persist and existing_rows is None else existing_rows
        for file in files or [{}]:
            row=self.save(sha256,status,report,filename=file.get('path'),size=file.get('size'),group=group,
                queried_at=queried_at,error=error,persist=persist,existing_rows=planning)
            saved.append(row)
            if not persist: planning.append(row)
        return saved

    def batch_rows(self, batch: dict) -> list[dict]:
        """Plan export paths and values without modifying shared runtime files."""
        rows=[]
        planning=self.rows()
        for sample in batch['samples']:
            rows.extend(self.save_query(sample['sha256'],sample['queryStatus'],sample.get('report'),batch['batchId'],
                sample.get('queriedAt'),sample.get('error'),persist=False,existing_rows=planning))
        return rows

    def save_batch(self, batch: dict) -> list[dict]:
        rows = []
        for sample in batch['samples']:
            rows.extend(self.save_query(sample['sha256'], sample['queryStatus'], sample.get('report'), batch['batchId'],
                sample.get('queriedAt'), sample.get('error')))
        self.export_indexes()
        return rows

    def save_uploads(self, state: dict) -> None:
        files = []
        inventory = self.experiment_root / 'input-inventory.json' if self.experiment_root else None
        if inventory is not None and inventory.is_file():
            files = json.loads(inventory.read_text(encoding='utf-8'))['groupA']['files']
        for sample in state['samples']:
            aliases = [file for file in files if file['sha256'] == sample['sha256']] or [sample]
            for file in aliases:
                self.save(sample['sha256'], sample['status'], sample.get('report'), filename=file['path'],
                    source='Uploaded File', group='A', queried_at=sample.get('queriedAt'), size=file.get('size'), error=sample.get('error'))
        self.export_indexes()
