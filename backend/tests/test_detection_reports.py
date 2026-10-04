import csv
import importlib
import io
import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest


SHA = 'a' * 64
NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


def generator(root):
    assert importlib.util.find_spec('app.services.detection_reports') is not None, 'Automatic report generation is not implemented'
    return importlib.import_module('app.services.detection_reports').DetectionReports(root)


def report(malicious=6):
    return {
        'sha256': SHA, 'risk': 'malicious' if malicious else 'undetected',
        'stats': {'malicious': malicious, 'suspicious': 0, 'undetected': 70, 'type-unsupported': 4},
        'totalEngines': malicious + 74, 'analysisTime': '2026-09-27T03:58:51Z',
        'fileName': 'VT-different-name.exe', 'size': 298648, 'fileType': 'Win32 EXE',
        'threatClassification': {'suggested_threat_label': 'trojan.cerber',
            'popular_threat_category': [{'value': 'trojan', 'count': 5}],
            'popular_threat_name': [{'value': 'cerber', 'count': 4}]},
        'engines': {f'Engine {i}': {'category': 'malicious', 'result': f'Trojan.Cerber.{i}'} for i in range(malicious)},
    }


def test_file_report_preserves_extension_and_only_uses_basename(tmp_path):
    store = generator(tmp_path)
    row = store.save(SHA, 'success', report(), filename=r'C:\private\samples\sample.exe', source='Uploaded File', group='A')
    assert row['filename'] == 'sample.exe'
    assert row['report'] == 'reports/files/sample.exe.md'
    text = (tmp_path / row['report']).read_text(encoding='utf-8')
    assert 'C:\\private' not in text
    assert 'Original Filename: sample.exe' in text
    assert 'Uploaded File' in text


def test_hash_reports_never_invent_original_filenames(tmp_path):
    row = generator(tmp_path).save(SHA, 'success', report(), group='B')
    assert row['filename'] == ''
    assert row['report'] == f'reports/hashes/{SHA}.md'
    assert 'VT-different-name.exe' not in (tmp_path / row['report']).read_text(encoding='utf-8')


def test_collisions_do_not_overwrite_and_identical_identity_reuses_report(tmp_path):
    store = generator(tmp_path)
    first = store.save(SHA, 'success', report(), filename='sample.exe')
    second = store.save('b' * 64, 'success', dict(report(), sha256='b'*64), filename='sample.exe')
    assert second['report'] == 'reports/files/sample.exe__bbbbbbbb.md'
    repeated = generator(tmp_path).save(SHA, 'success', report(), filename='sample.exe')
    assert repeated['report'] == first['report']
    assert len(store.rows()) == 2
    assert len(list((tmp_path / 'reports/files').glob('*.md'))) == 2


def test_short_hash_collision_and_case_insensitive_names_are_resolved(tmp_path):
    store = generator(tmp_path)
    store.save(SHA, 'success', report(), filename='sample.exe')
    one = 'b'*8 + 'c'*56
    two = 'b'*8 + 'd'*56
    row1 = store.save(one, 'not_found', filename='SAMPLE.EXE')
    row2 = store.save(two, 'not_found', filename='sample.exe')
    assert row1['report'].lower() != row2['report'].lower()
    assert len(list((tmp_path/'reports/files').glob('*.md'))) == 3


@pytest.mark.parametrize('filename', ['../CON.exe', 'a/b/<bad>:?.dll', r'..\..\NUL', 'a'*280 + '.exe'])
def test_unsafe_filenames_stay_inside_report_directory(tmp_path, filename):
    row = generator(tmp_path).save(SHA, 'not_found', filename=filename)
    destination = (tmp_path / row['report']).resolve()
    assert destination.parent == (tmp_path/'reports/files').resolve()
    assert len(destination.name) <= 220
    assert not any(char in destination.name for char in '<>:"\\|?*')
    assert destination.stem.split('.')[0].upper() not in {'CON', 'NUL'}


def test_existing_unowned_file_is_preserved(tmp_path):
    destination = tmp_path/'reports/files/sample.exe.md'
    destination.parent.mkdir(parents=True)
    destination.write_text('Keep this user file', encoding='utf-8')
    row = generator(tmp_path).save(SHA, 'not_found', filename='sample.exe')
    assert row['report'] != 'reports/files/sample.exe.md'
    assert destination.read_text(encoding='utf-8') == 'Keep this user file'


def test_markdown_includes_actual_classification_and_representative_engines(tmp_path):
    row = generator(tmp_path).save(SHA, 'success', report(), queried_at='2026-10-04T05:00:00Z')
    text = (tmp_path / row['report']).read_text(encoding='utf-8')
    for heading in ['Sample Information', 'VirusTotal Detection Summary', 'Threat Classification',
        'Representative Engine Results', 'Analysis Summary', 'Source']:
        assert '## ' + heading in text
    assert 'trojan.cerber' in text
    assert 'Trojan.Cerber.5' in text
    assert '6 / 80' in text
    assert '2026-10-04T05:00:00Z' in text
    assert f'https://www.virustotal.com/gui/file/{SHA}' in text


def test_missing_labels_and_zero_detections_are_not_fabricated(tmp_path):
    data = report(0)
    data.pop('threatClassification')
    row = generator(tmp_path).save(SHA, 'success', data)
    text = (tmp_path / row['report']).read_text(encoding='utf-8')
    assert '未检出' in text
    assert '未提供' in text
    assert 'trojan.cerber' not in text
    assert '判定为安全' not in text
    assert '不能据此认定文件安全' in text


@pytest.mark.parametrize('status', ['not_found', 'failed', 'timeout', 'authentication_error', 'rate_limited', 'pending'])
def test_non_success_reports_keep_unknown_statistics(tmp_path, status):
    row = generator(tmp_path).save(SHA, status, report())
    assert row['malicious'] is None
    assert row['query_status'] == status
    assert row['risk'] == 'unknown'
    assert status in (tmp_path / row['report']).read_text(encoding='utf-8')


def test_markdown_escapes_external_text(tmp_path):
    data = report()
    data['threatClassification']['suggested_threat_label'] = '<script>alert(1)</script>'
    data['engines']['Engine 0']['result'] = 'name|label\n<script>bad</script>'
    row = generator(tmp_path).save(SHA, 'success', data)
    text = (tmp_path / row['report']).read_text(encoding='utf-8')
    assert '<script>' not in text
    assert '&lt;script&gt;' in text
    assert 'name\\|label' in text


def test_invalid_hash_cannot_become_a_report_path(tmp_path):
    store = generator(tmp_path)
    with pytest.raises(ValueError, match='SHA256'):
        store.save('../private', 'success', report())
    assert not list(tmp_path.rglob('*.md'))


def test_csv_and_xlsx_use_real_portable_links_and_typed_numbers(tmp_path):
    store = generator(tmp_path)
    row = store.save(SHA, 'success', report(), filename='sample.exe', group='A')
    store.export_indexes()
    with (tmp_path/'summary.csv').open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]['report'] == row['report']
    assert (tmp_path / rows[0]['report']).is_file()
    with zipfile.ZipFile(tmp_path/'summary.xlsx') as archive:
        assert archive.testzip() is None
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
        rels = ET.fromstring(archive.read('xl/worksheets/_rels/sheet1.xml.rels'))
        targets = [link.attrib['Target'] for link in rels]
        assert row['report'] in targets
        assert row['virustotal'] in targets
        texts = [node.text for node in sheet.findall('.//s:t', NS)]
        assert '查看检测报告' in texts
        assert '查看 VirusTotal 原始报告' in texts
        malicious = sheet.find('.//s:c[@r="E2"]', NS)
        assert malicious.attrib.get('t', 'n') == 'n'
        assert malicious.find('s:v', NS).text == '6'
        assert not sheet.findall('.//s:f', NS)


def test_csv_neutralizes_formula_injection(tmp_path):
    store = generator(tmp_path)
    store.save(SHA, 'not_found', filename='=1+1.exe')
    store.export_indexes()
    with (tmp_path/'summary.csv').open(encoding='utf-8-sig', newline='') as stream:
        assert next(csv.DictReader(stream))['filename'] == "'=1+1.exe"
def test_unicode_name_fits_linux_filename_byte_limit(tmp_path):
    store = generator(tmp_path)
    row = store.save('a'*64, 'not_found', filename='病'*140+'.exe')
    assert len(Path(row['report']).name.encode('utf-8')) <= 255
    assert row['report'].endswith('.exe.md')


def test_history_export_does_not_overwrite_this_upload_analysis(tmp_path):
    store=generator(tmp_path)
    store.save(SHA,'success',report(6),filename='sample.exe',source='Uploaded File',group='A')
    history=report(2)
    row=store.save(SHA,'success',history,filename='sample.exe',group='A')
    assert row['malicious']==2
    assert store.rows()[0]['malicious']==6
    text=(tmp_path/row['report']).read_text(encoding='utf-8')
    assert '6 / 80' in text
    assert 'Historical SHA-256 Query' in text
    assert '2 / 76' in text
