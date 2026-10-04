"""Portable CSV/XLSX indexes and bundles; no API requests or Excel formulas."""
import csv
import io
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET


COLUMNS = ('group', 'filename', 'sha256', 'query_status', 'malicious', 'suspicious',
    'undetected', 'unsupported', 'total_engines', 'threat_label', 'analysis_time', 'report', 'virustotal', 'source', 'queried_at')
S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
P = 'http://schemas.openxmlformats.org/package/2006/relationships'


def csv_safe(value):
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def csv_bytes(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([csv_safe(row.get(column)) for column in COLUMNS])
    return ('\ufeff' + stream.getvalue()).encode('utf-8')


def xlsx_bytes(rows: list[dict]) -> bytes:
    """Write the small SpreadsheetML subset needed for this flat result index."""
    sheet = ET.Element(f'{{{S}}}worksheet')
    views = ET.SubElement(sheet, f'{{{S}}}sheetViews')
    view = ET.SubElement(views, f'{{{S}}}sheetView', workbookViewId='0', showGridLines='0')
    ET.SubElement(view, f'{{{S}}}pane', xSplit='2', ySplit='1', topLeftCell='C2', activePane='bottomRight', state='frozen')
    cols = ET.SubElement(sheet, f'{{{S}}}cols')
    widths = (14, 54, 68, 24, 15, 15, 15, 15, 18, 32, 26, 24, 34, 24, 26)
    for number, width in enumerate(widths, 1):
        ET.SubElement(cols, f'{{{S}}}col', min=str(number), max=str(number), width=str(width), customWidth='1')
    data = ET.SubElement(sheet, f'{{{S}}}sheetData')
    links = ET.Element(f'{{{S}}}hyperlinks')
    relationships = ET.Element(f'{{{P}}}Relationships')
    for number, row in enumerate([dict(zip(COLUMNS, COLUMNS)), *rows], 1):
        element = ET.SubElement(data, f'{{{S}}}row', r=str(number), ht='32' if number == 1 else '36', customHeight='1')
        for column, field in enumerate(COLUMNS):
            address = f'{chr(65 + column)}{number}'
            value = row.get(field)
            cell = ET.SubElement(element, f'{{{S}}}c', r=address, s='1' if number == 1 else '0')
            if value is None:
                continue
            if number > 1 and field in {'report', 'virustotal'} and value:
                identifier = f'rId{len(relationships) + 1}'
                ET.SubElement(links, f'{{{S}}}hyperlink', ref=address, attrib={f'{{{R}}}id': identifier})
                target = quote(value, safe='/._-') if field == 'report' else value
                ET.SubElement(relationships, f'{{{P}}}Relationship', Id=identifier, Type=R+'/hyperlink', Target=target, TargetMode='External')
                value = '查看检测报告' if field == 'report' else '查看 VirusTotal 原始报告'
                cell.set('s', '2')
            elif number > 1 and field in {'analysis_time','queried_at'} and value:
                timestamp = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(UTC)
                value = (timestamp - datetime(1899, 12, 30, tzinfo=UTC)).total_seconds() / 86400
                cell.set('s', '3')
            if isinstance(value, (int, float)):
                cell.set('t', 'n')
                ET.SubElement(cell, f'{{{S}}}v').text = str(value)
            else:
                cell.set('t', 'inlineStr')
                string = ET.SubElement(cell, f'{{{S}}}is')
                ET.SubElement(string, f'{{{S}}}t', attrib={'{http://www.w3.org/XML/1998/namespace}space': 'preserve'}).text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))
    ET.SubElement(sheet, f'{{{S}}}autoFilter', ref=f'A1:O{len(rows) + 1}')
    if len(links):
        sheet.append(links)
    styles = f'''<styleSheet xmlns="{S}"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>
<fonts count="3"><font><sz val="11"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Arial"/></font><font><u/><color rgb="FF0563C1"/><sz val="11"/><name val="Arial"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF20354B"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'''
    content_types = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' + ''.join(f'<Override PartName="/{part}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.{kind}+xml"/>' for part, kind in [('xl/workbook.xml','sheet.main'), ('xl/worksheets/sheet1.xml','worksheet'), ('xl/styles.xml','styles')]) + '</Types>'
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', content_types)
        archive.writestr('_rels/.rels', f'<Relationships xmlns="{P}"><Relationship Id="rId1" Type="{R}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr('xl/workbook.xml', f'<workbook xmlns="{S}" xmlns:r="{R}"><sheets><sheet name="检测结果" sheetId="1" r:id="rId1"/></sheets></workbook>')
        archive.writestr('xl/_rels/workbook.xml.rels', f'<Relationships xmlns="{P}"><Relationship Id="rId1" Type="{R}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="{R}/styles" Target="styles.xml"/></Relationships>')
        archive.writestr('xl/styles.xml', styles)
        archive.writestr('xl/worksheets/sheet1.xml', ET.tostring(sheet, encoding='utf-8', xml_declaration=True))
        archive.writestr('xl/worksheets/_rels/sheet1.xml.rels', ET.tostring(relationships, encoding='utf-8', xml_declaration=True))
    return output.getvalue()


def bundle_bytes(root: Path, rows: list[dict], report_texts: dict[str,str] | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('summary.csv', csv_bytes(rows))
        archive.writestr('summary.xlsx', xlsx_bytes(rows))
        for relative in sorted({row['report'] for row in rows}):
            path = (root / relative).resolve()
            if root.resolve() not in path.parents or path.suffix != '.md':
                raise ValueError('Invalid detection report path')
            if report_texts is not None:
                archive.writestr(relative,report_texts[relative])
            else:
                archive.write(path, relative)
    return output.getvalue()
