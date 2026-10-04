import httpx
import pytest

from app.providers.virustotal import VirusTotalProvider


def provider(handler):
    return VirusTotalProvider('mock-secret', httpx.Client(transport=httpx.MockTransport(handler)))


def test_invalid_hash_never_sends_request():
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(404)
    result = provider(handler).fetch('invalid')
    assert result.status == 'invalid_hash'
    assert seen == []


def test_report_normalizes_stats_engines_and_utc_date():
    raw = {'data': {'id': 'a' * 64, 'type': 'file', 'attributes': {
        'last_analysis_stats': {'malicious': 3, 'undetected': 7},
        'last_analysis_date': 1700000000,
        'last_analysis_results': {'Test': {'category': 'malicious', 'result': 'Trojan'}},
    }}}
    result = provider(lambda request: httpx.Response(200, json=raw)).fetch('A' * 64)
    assert result.status == 'success'
    assert result.report['risk'] == 'malicious'
    assert result.report['stats']['malicious'] == 3
    assert result.report['totalEngines'] == 10
    assert result.report['analysisTime'] == '2023-11-14T22:13:20Z'
    assert result.report['engines']['Test']['result'] == 'Trojan'


@pytest.mark.parametrize('stats,risk', [({'suspicious': 1}, 'suspicious'),
    ({'undetected': 2}, 'undetected'), ({'failure': 2}, 'unknown'), ({}, 'unknown')])
def test_no_detection_is_not_safe(stats, risk):
    raw = {'data': {'id': 'b' * 64, 'attributes': {'last_analysis_stats': stats}}}
    result = provider(lambda request: httpx.Response(200, json=raw)).fetch('b' * 64)
    assert result.report['risk'] == risk


@pytest.mark.parametrize('code,status', [(404,'not_found'), (401,'authentication_error'),
    (403,'authentication_error'), (429,'rate_limited'), (500,'failed')])
def test_http_errors(code, status):
    result = provider(lambda request: httpx.Response(code, headers={'Retry-After':'42'})).fetch('a'*64)
    assert result.status == status
    assert 'mock-secret' not in str(result)
    if code == 429:
        assert result.retry_after == 42


@pytest.mark.parametrize('exception,status', [(httpx.ReadTimeout,'timeout'), (httpx.ConnectError,'failed')])
def test_network_errors(exception, status):
    def handler(request):
        raise exception('private response must not leak', request=request)
    assert provider(handler).fetch('a'*64).status == status


def test_malformed_report_is_not_success():
    assert provider(lambda request: httpx.Response(200, json={})).fetch('a'*64).status == 'failed'


def test_optional_threat_classification_is_preserved_without_inference():
    classification = {'suggested_threat_label': 'trojan.cerber',
        'popular_threat_category': [{'value':'trojan','count':3}],
        'popular_threat_name': [{'value':'cerber','count':2}]}
    raw = {'data': {'id': 'a'*64, 'attributes': {'last_analysis_stats': {'malicious': 3},
        'popular_threat_classification': classification}}}
    result = provider(lambda _: httpx.Response(200, json=raw)).fetch('a'*64)
    assert result.report.get('threatClassification') == classification
    raw['data']['attributes'].pop('popular_threat_classification')
    assert provider(lambda _: httpx.Response(200, json=raw)).fetch('a'*64).report.get('threatClassification') is None


@pytest.mark.parametrize('data', [None, [], {'id':'a'*64,'attributes':None},
    {'id':'a'*64,'attributes':{'last_analysis_results':{'engine':None}}}])
def test_malformed_nested_fields_are_failure_not_crash(data):
    assert provider(lambda request:httpx.Response(200,json={'data':data})).fetch('a'*64).status == 'failed'
