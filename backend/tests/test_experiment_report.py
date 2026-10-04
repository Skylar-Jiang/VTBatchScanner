from generate_report import render_report

def test_pending_experiment_report_never_claims_complete():
    groups = {key:{'summary':{'total':1,'successful':0,'notFound':0,'failed':0,'pending':1,'apiAttempts':0,'cacheHits':0},'samples':[]} for key in ('A','B')}
    text = render_report(groups, {'groupA':{'leafFiles':116,'uniqueHashes':115,'duplicateFiles':1,'errors':[{'path':'locked','error':'RuntimeError'}]},'groupB':{'total':100,'duplicates':0}}, 'now')
    assert '尚未完成' in text
    assert '实际 API 请求：0' in text
    assert '全部查询完成' not in text

def test_upload_progress_is_distinct_from_completed_historical_hash_queries():
    groups={key:{'summary':{'total':1,'successful':1,'notFound':0,'failed':0,'pending':0,'apiAttempts':1,'cacheHits':0},'samples':[]} for key in ('A','B')}
    inventory={'groupA':{'leafFiles':116,'uniqueHashes':115,'duplicateFiles':1,'errors':[{'path':'locked','error':'password'}]},'groupB':{'total':100,'duplicates':0}}
    upload={'apiRequests':1,'samples':[{'status':'accepted','report':None}]}
    text=render_report(groups,inventory,'now',upload)
    assert '上传分析尚未完成' in text
    assert '历史哈希查询' in text
    assert '新增上传流程请求：1' in text
