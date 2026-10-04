import { useState } from 'react';
import { toast } from 'sonner';
import { refreshSample } from '@/api/samples';
import { apiBaseUrl } from '@/api/client';
import { sampleRow, type StoredSample } from '@/api/workspace';
import { useLocalData } from '@/hooks/use-local-data';
import { LocalDataState } from '@/components/local-data-state';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ProviderBadge, RiskBadge } from '@/components/status-badge';
import type { SampleRow } from '@/lib/workspace';

const isActive = (sample: StoredSample) => sample.status==='running';
export function SampleDetailPage({sample, onBack}: {sample: SampleRow; onBack:()=>void}) {
  const {data,error,reload} = useLocalData<StoredSample>('/samples/'+sample.sha256,isActive);
  const current = data ? sampleRow(data) : sample;
  const result = data?.providerResults?.filter(row=>row.provider==='virustotal').at(-1);
  const report = result?.report;
  const [refreshOpen,setRefreshOpen] = useState(false);
  const [reanalysisOpen,setReanalysisOpen] = useState(false);
  const [acknowledged,setAcknowledged] = useState(false);
  const [busy,setBusy] = useState(false);
  async function confirmRefresh() {
    setBusy(true);
    try { await refreshSample(sample.sha256); toast.success('已有报告刷新已排队'); setRefreshOpen(false); reload(); }
    catch { toast.error('刷新未能排队；未触发重新分析。'); }
    finally {setBusy(false);}
  }
  function exportSummary() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
    const link = document.createElement('a'); link.href=url; link.download=sample.sha256+'.json'; link.click(); URL.revokeObjectURL(url);
  }
  return <section className="flex flex-col gap-6"><Button className="self-start" variant="ghost" onClick={onBack}>返回样本库</Button><div className="flex flex-wrap justify-between gap-4"><div className="min-w-0"><p className="eyebrow">SAMPLE DETAIL</p><h1 className="mt-2 break-all font-mono text-lg font-semibold">{sample.sha256}</h1><div className="mt-3 flex gap-2"><RiskBadge risk={current.risk}/><ProviderBadge status={current.virustotal}/></div></div><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={()=>{setRefreshOpen(true);setAcknowledged(false);}}>刷新报告</Button><Button variant="outline" onClick={()=>setReanalysisOpen(true)}>重新分析</Button><Button variant="outline" disabled={!data} onClick={exportSummary}>导出汇总</Button></div></div><LocalDataState error={error} loading={!data && !error} reload={reload}/><Alert><AlertTitle>刷新不等于重新分析</AlertTitle><AlertDescription>刷新绕过缓存重新获取已有报告，额外消耗 VirusTotal 请求配额。未检出、未收录和请求失败均不能视为安全。</AlertDescription></Alert>
    <div className="flex flex-wrap gap-2">{data?.detectionReports?.length ? data.detectionReports.map(row=><Button key={row.url} variant="outline" asChild><a className="max-w-full" href={apiBaseUrl+row.url.replace(/^\/api\/v1/, '')} target="_blank" rel="noreferrer"><span className="truncate">查看检测报告{row.filename ? ' · '+row.filename : ''}</span></a></Button>) : <Button variant="outline" disabled>暂无检测报告</Button>}</div>
    {data?.reportError && <Alert variant="destructive"><AlertTitle>检测报告未能写入</AlertTitle><AlertDescription>查询结果已保存。请关闭占用的文件、检查写入权限，再从批次导出报告包。</AlertDescription></Alert>}
    <Tabs defaultValue="overview"><TabsList variant="line"><TabsTrigger value="overview">Overview</TabsTrigger><TabsTrigger value="vt">VirusTotal</TabsTrigger><TabsTrigger value="raw">Raw Reports</TabsTrigger></TabsList>
      <TabsContent value="overview" className="mt-6"><article className="panel p-6"><h2 className="text-sm font-medium">报告信息</h2><dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">{[['文件名',report?.fileName],['文件类型',report?.fileType],['最后分析',report?.analysisTime],['查询时间',result?.queriedAt],['缓存复用',result ? result.fromCache ? '是' : '否' : null],['查询错误',result?.error]].map(([label,value])=><div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-all">{value ?? '—'}</dd></div>)}</dl></article></TabsContent>
      <TabsContent value="vt" className="mt-6"><article className="panel overflow-hidden"><div className="p-6"><h2 className="text-sm font-medium">VirusTotal 引擎结果</h2><p className="mt-2 text-sm text-muted-foreground">恶意 {report?.stats.malicious ?? '—'} / 可疑 {report?.stats.suspicious ?? '—'} / 引擎总数 {report?.totalEngines ?? '—'}</p></div><div className="overflow-x-auto"><table className="min-w-[500px] w-full text-left text-sm"><thead><tr>{['引擎','类别','结果'].map(label=><th key={label} className="px-6 py-3">{label}</th>)}</tr></thead><tbody>{Object.entries(report?.engines ?? {}).map(([name,engine])=><tr key={name} className="border-t border-border"><td className="px-6 py-3">{engine.engine_name ?? name}</td><td className="px-6 py-3">{engine.category}</td><td className="px-6 py-3 break-all">{engine.result ?? '—'}</td></tr>)}</tbody></table></div>{!report && <p className="px-6 pb-6 text-sm text-muted-foreground">暂无成功报告。请查看查询状态或错误记录。</p>}</article></TabsContent>
      <TabsContent value="raw" className="mt-6"><article className="panel p-6"><h2 className="text-sm font-medium">原始 JSON 报告</h2><p className="mt-2 text-sm text-muted-foreground">只下载已保存的报告，不下载样本。</p><Button className="mt-5" variant="outline" disabled={current.virustotal!=='success'} asChild={current.virustotal==='success'}>{current.virustotal==='success' ? <a href={apiBaseUrl+'/samples/'+sample.sha256+'/providers/virustotal/raw/report'} target="_blank" rel="noreferrer">下载 JSON</a> : '暂无原始报告'}</Button></article></TabsContent>
    </Tabs>
    <Dialog open={refreshOpen} onOpenChange={setRefreshOpen}><DialogContent><DialogHeader><DialogTitle>确认刷新报告</DialogTitle><DialogDescription>预计至少额外调用 1 次，失败重试另计；只查询现有报告，不提交文件或发起重新分析。</DialogDescription></DialogHeader><label className="flex gap-2 text-sm"><input type="checkbox" checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)}/>我已知晓额外配额消耗。</label><DialogFooter><Button variant="outline" onClick={()=>setRefreshOpen(false)}>取消</Button><Button disabled={!acknowledged || busy} onClick={()=>void confirmRefresh()}>{busy ? '排队中…' : '确认刷新'}</Button></DialogFooter></DialogContent></Dialog>
    <Dialog open={reanalysisOpen} onOpenChange={setReanalysisOpen}><DialogContent><DialogHeader><DialogTitle>重新分析当前不可用</DialogTitle><DialogDescription>未确认账号重新分析权限，系统不会调用。该操作与刷新报告独立；刷新报告仅获取已有结果，不触发重新分析。</DialogDescription></DialogHeader><DialogFooter><Button onClick={()=>setReanalysisOpen(false)}>我知道了</Button></DialogFooter></DialogContent></Dialog>
  </section>;
}
