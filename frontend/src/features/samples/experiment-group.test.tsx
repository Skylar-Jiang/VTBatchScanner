import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { it, expect, vi, afterEach } from 'vitest';
import { SamplesPage } from './samples-page';

afterEach(cleanup);

it('separates file upload statuses from assigned hash reports', async () => {
  const data={A:{method:'file_upload',files:[{path:'folder/sample.exe',sha256:'a'.repeat(64),size:1,status:'accepted',analysisId:'id',error:null,report:null}],readErrors:[],apiRequests:1},B:{method:'hash_query',batchId:'B',samples:[{sha256:'b'.repeat(64),risk:'malicious',status:'completed',lastAnalysisAt:null,riskSources:['virustotal'],providerStatuses:{virustotal:'success',cn_platform:'not_supported'}}]}};
  vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({data}),{status:200})));
  render(<SamplesPage onSelect={()=>{}}/>);
  expect(await screen.findByText('folder/sample.exe')).toBeInTheDocument();
  expect(screen.getByText('待查询')).toBeInTheDocument();
  expect(screen.queryByText('bbbbbbbbbbbb…bbbbbbbb')).not.toBeInTheDocument();
  fireEvent.mouseDown(screen.getByRole('tab',{name:'哈希查询'}),{button:0,ctrlKey:false});
  expect(await screen.findByText('bbbbbbbbbbbb…bbbbbbbb')).toBeInTheDocument();
  expect(screen.queryByText('folder/sample.exe')).not.toBeInTheDocument();
});

it('opens this upload analysis above the long file table', async () => {
  const report={risk:'malicious',stats:{malicious:1},totalEngines:1,analysisTime:'2026-09-27T00:00:00Z',fileName:null,fileType:null,engines:{Engine:{category:'malicious',result:'fixture'}}};
  const data={A:{method:'file_upload',files:[{path:'fixture.exe',sha256:'a'.repeat(64),size:1,status:'success',analysisId:'receipt',error:null,report}],readErrors:[],apiRequests:2},B:{method:'hash_query',batchId:null,samples:[]}};
  vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({data}),{status:200})));
  render(<SamplesPage onSelect={()=>{}}/>);
  fireEvent.mouseDown(screen.getByRole('tab',{name:'上传记录'}),{button:0,ctrlKey:false});
  fireEvent.click(await screen.findByRole('button',{name:'详情'}));
  const heading=screen.getByRole('heading',{name:/上传分析/});
  expect(heading.compareDocumentPosition(screen.getByText('fixture.exe')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});

it('defaults to existing file reports without experiment prose', async () => {
  const report={risk:'malicious',stats:{malicious:1},totalEngines:1,analysisTime:null,engines:{}};
  const data={A:{files:[{path:'existing.exe',sha256:'a'.repeat(64),size:1,status:'accepted',analysisId:'receipt',report:null,queryStatus:'success',queryReport:report}],readErrors:[],apiRequests:1},B:{samples:[]}};
  vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({data}),{status:200})));
  render(<SamplesPage onSelect={()=>{}}/>);
  expect(await screen.findByText('已有报告')).toBeInTheDocument();
  expect(screen.getByText('1 / 1')).toBeInTheDocument();
  expect(screen.queryByText(/实际样本 A|新增请求|不用旧报告|分配的 SHA256|独立流程/)).not.toBeInTheDocument();
});
