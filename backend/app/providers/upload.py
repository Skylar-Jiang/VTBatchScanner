"""Explicit file submissions; never executes the bytes supplied to the client."""
import hashlib
from urllib.parse import quote
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
import httpx
from app.providers.result import ProviderFetch
from app.providers.virustotal import normalize_report


class FileUploadClient:
    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.key = api_key
        self.client = client or httpx.Client(timeout=120.0)

    def _request(self, method: str, path: str, **kwargs) -> ProviderFetch:
        try:
            response = self.client.request(method,'https://www.virustotal.com/api/v3'+path,headers={'x-apikey':self.key},**kwargs)
        except httpx.HTTPError:
            return ProviderFetch('submission_unknown' if method == 'POST' else 'failed',None,'Network error; do not automatically repeat a file submission')
        if response.status_code in (401,403):
            return ProviderFetch('authentication_error',None,'Account cannot use this endpoint')
        if response.status_code == 429:
            retry = 60.0
            value=response.headers.get('Retry-After','60')
            try: retry=max(0.0,float(value))
            except ValueError:
                try: retry=max(0.0,(parsedate_to_datetime(value)-datetime.now(UTC)).total_seconds())
                except (ValueError,TypeError,OverflowError): pass
            return ProviderFetch('rate_limited',None,'Quota limit; submission paused',retry_after=retry)
        if response.status_code >= 400:
            return ProviderFetch('failed',None,f'Provider HTTP {response.status_code}')
        try:
            raw=response.json()
            if not isinstance(raw['data']['id'],str) or raw['data']['type'] != 'analysis': raise ValueError()
        except (ValueError,KeyError,TypeError):
            return ProviderFetch('submission_unknown' if method == 'POST' else 'failed',None,'Invalid analysis response')
        return ProviderFetch('accepted',raw)

    def upload(self, contents: bytes, sha256: str) -> ProviderFetch:
        if hashlib.sha256(contents).hexdigest() != sha256:
            return ProviderFetch('invalid_file',None,'File bytes do not match manifest hash')
        if len(contents) > 32 * 1024 * 1024:
            return ProviderFetch('invalid_file',None,'This experiment client supports files up to 32 MiB')
        return self._request('POST','/files',files={'file':(sha256+'.bin',contents,'application/octet-stream')})

    def analysis(self, analysis_id: str, sha256: str) -> ProviderFetch:
        result=self._request('GET','/analyses/'+quote(analysis_id,safe=''))
        if result.status != 'accepted': return result
        try:
            # Upload receipts may be opaque tokens; GET can return a canonical resource ID.
            attributes=result.raw['data']['attributes']
            status=attributes['status']
            if status in ('queued','in-progress'): return ProviderFetch(status,result.raw)
            if status != 'completed': raise ValueError()
            returned_hash=result.raw.get('meta',{}).get('file_info',{}).get('sha256',sha256)
            if returned_hash != sha256: raise ValueError()
            report=normalize_report({'data':{'id':sha256,'attributes':{
                'last_analysis_stats':attributes['stats'],'last_analysis_results':attributes['results'],
                'last_analysis_date':attributes['date']}}},sha256)
        except (ValueError,KeyError,TypeError,AttributeError,OverflowError,OSError):
            return ProviderFetch('failed',result.raw,'Invalid or mismatched analysis report')
        return ProviderFetch('success',result.raw,report=report)
