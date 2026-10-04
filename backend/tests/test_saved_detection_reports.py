import json
import zipfile
from pathlib import Path
from generate_detection_reports import generate_saved_reports


def test_saved_generation_keeps_groups_and_upload_history_separate(tmp_path):
    experiment=tmp_path/'experiment'; experiment.mkdir()
    sha='a'*64
    (experiment/'input-inventory.json').write_text(json.dumps({'groupA':{'files':[{'path':'folder/sample.exe','sha256':sha,'size':10}],'errors':[]}}))
    historical={'sha256':sha,'risk':'malicious','stats':{'malicious':2},'totalEngines':2,'analysisTime':'2026-09-01T00:00:00Z','engines':{}}
    for group,samples in [('a',[{'sha256':sha,'queryStatus':'success','report':historical}]),('b',[{'sha256':'b'*64,'queryStatus':'not_found','report':None}])]:
        (experiment/f'group-{group}-results.json').write_text(json.dumps({'samples':samples}))
    (experiment/'group-a-upload-results.json').write_text(json.dumps({'samples':[{'path':'sample.exe','sha256':sha,'size':10,'status':'success','report':dict(historical,stats={'malicious':3},totalEngines=3)}]}))
    raw=tmp_path/'raw'; raw.mkdir()
    (raw/f'{sha}.json').write_text(json.dumps({'data':{'id':sha,'attributes':{'last_analysis_stats':{'malicious':2},'last_analysis_date':1788220800,'popular_threat_classification':{'suggested_threat_label':'trojan.fixture'}}}}))
    store=generate_saved_reports(experiment,tmp_path/'results',raw)
    assert len(store.rows())==2
    uploaded=next(row for row in store.rows() if row['group']=='A')
    assert uploaded['source']=='Uploaded File' and uploaded['malicious']==3
    assert uploaded['threat_label']==''
    assert uploaded['history_query']['threat_label']=='trojan.fixture'
    assert next(row for row in store.rows() if row['group']=='B')['filename']==''
    with zipfile.ZipFile(store.root/'detection-reports.zip') as archive:
        assert set(archive.namelist())=={'summary.csv','summary.xlsx','reports/files/sample.exe.md','reports/hashes/'+'b'*64+'.md'}
