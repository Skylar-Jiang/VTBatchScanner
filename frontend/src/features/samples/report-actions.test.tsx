import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SampleDetailPage } from './sample-detail-page';
import { BatchesPage } from '../batches/batches-page';
import type { SampleRow } from '@/lib/workspace';
import { apiBaseUrl } from '@/api/client';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const sha='a'.repeat(64);
const sample:SampleRow={sha256:sha,fileName:null,risk:'unknown',status:'completed',lastAnalysisAt:null,riskSource:[],virustotal:'not_found',cnPlatform:'not_supported'};
function data(extra={}) { return {...sample,riskSources:[],providerStatuses:{virustotal:'not_found',cn_platform:'not_supported'},providerResults:[],...extra}; }
function fetchData(value:unknown) { const fetch=vi.fn(async()=>new Response(JSON.stringify({data:value}),{status:200})); vi.stubGlobal('fetch',fetch); return fetch; }

it('opens saved Markdown report without creating a remote query', async()=>{
  const fetch=fetchData(data({detectionReports:[{filename:'',source:'SHA-256 Query',url:'/api/v1/reports/hashes/'+sha}]}));
  render(<SampleDetailPage sample={sample} onBack={()=>{}}/>);
  const link=await screen.findByRole('link',{name:'查看检测报告'});
  expect(link).toHaveAttribute('href',apiBaseUrl+'/reports/hashes/'+sha);
  expect(link).toHaveAttribute('rel','noreferrer');
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('shows missing report as disabled and requires confirmation to refresh', async()=>{
  const fetch=fetchData(data({detectionReports:[]}));
  render(<SampleDetailPage sample={sample} onBack={()=>{}}/>);
  expect(await screen.findByRole('button',{name:'暂无检测报告'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'刷新报告'}));
  expect(screen.getByRole('button',{name:'确认刷新'})).toBeDisabled();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('retains visible report generation error', async()=>{
  fetchData(data({reportError:'report_write_failed'}));
  render(<SampleDetailPage sample={sample} onBack={()=>{}}/>);
  expect(await screen.findByText('检测报告未能写入')).toBeInTheDocument();
});

it('exports XLSX and portable report bundle without another VT request', async()=>{
  const fetch=fetchData([{id:'bat_mock',name:'Offline batch',sampleCount:1,createdAt:'2026-10-04T00:00:00Z',status:'completed',progress:{percent:100,succeeded:1,notFound:0,failed:0,terminalProviderJobs:1,totalProviderJobs:1}}]);
  render(<BatchesPage/>);
  expect(await screen.findByRole('link',{name:'XLSX'})).toHaveAttribute('href',apiBaseUrl+'/batches/bat_mock/export?format=xlsx');
  expect(screen.getByRole('link',{name:'报告包'})).toHaveAttribute('href',apiBaseUrl+'/batches/bat_mock/export?format=zip');
  expect(fetch).toHaveBeenCalledTimes(1);
});
