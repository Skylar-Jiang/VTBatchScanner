import { useState } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Progress } from '@/components/ui/progress';
import { LocalDataState } from '@/components/local-data-state';
import { useLocalData } from '@/hooks/use-local-data';
import { batchOperation, type Batch } from '@/api/workspace';
import { apiBaseUrl } from '@/api/client';

const isActive = (batches: Batch[]) => batches.some(batch=>batch.progress.percent < 100);
export function BatchesPage() {
  const {data, error, updatedAt, reload} = useLocalData<Batch[]>('/batches',isActive);
  const [selected, setSelected] = useState<Batch | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  async function operate(batch: Batch, operation: 'resume' | 'refresh') {
    setBusy(true);
    try { await batchOperation(batch.id,operation); toast.success(operation==='refresh' ? '刷新已排队' : '续跑已排队'); setSelected(null); reload(); }
    catch { toast.error('任务未能排队，请检查本地后端。'); }
    finally { setBusy(false); }
  }
  return <section className="flex flex-col gap-6"><div><p className="eyebrow">BATCH OPERATIONS</p><h1 className="mt-2 text-2xl font-semibold">批次任务</h1><p className="mt-2 text-sm text-muted-foreground">续跑仅处理等待或中断任务，已完成项不重复请求。最后本地更新：{updatedAt ?? '—'}</p></div><LocalDataState error={error} loading={!data && !error} reload={reload}/><article className="panel overflow-hidden"><div className="overflow-x-auto"><table className="min-w-[920px] w-full text-left text-sm"><thead className="bg-muted/30 text-xs text-muted-foreground"><tr>{['批次','创建时间','样本数','成功／未收录／失败','进度','操作'].map(label=><th className="px-5 py-3 font-medium" key={label}>{label}</th>)}</tr></thead><tbody>{data?.map(batch=><tr className="border-t border-border hover:bg-muted/30" key={batch.id}><td className="px-5 py-4"><p className="font-medium">{batch.name}</p><p className="mt-1 text-xs text-muted-foreground">{batch.progress.percent===100 ? '查询结束' : '待处理／查询中'}</p></td><td className="px-5 py-4 text-xs text-muted-foreground">{new Date(batch.createdAt).toLocaleString()}</td><td className="px-5 py-4">{batch.sampleCount}</td><td className="px-5 py-4">{batch.progress.succeeded} / {batch.progress.notFound} / {batch.progress.failed}</td><td className="px-5 py-4"><p className="mb-2 text-xs">{batch.progress.percent}%</p><Progress value={batch.progress.percent}/></td><td className="px-5 py-4"><div className="flex flex-wrap gap-1"><Button size="sm" variant="ghost" disabled={busy || batch.progress.percent===100} onClick={()=>void operate(batch,'resume')}>续跑</Button><Button size="sm" variant="ghost" disabled={busy} onClick={()=>{setSelected(batch);setAcknowledged(false);}}>刷新</Button>{(['csv','json','xlsx','zip'] as const).map(format=><Button key={format} size="sm" variant="outline" asChild><a href={apiBaseUrl+'/batches/'+batch.id+'/export?format='+format} target="_blank" rel="noreferrer">{format==='zip' ? '报告包' : format.toUpperCase()}</a></Button>)}</div></td></tr>)}</tbody></table></div>{data?.length===0 && <p className="p-8 text-sm text-muted-foreground">暂无批次。请先从“新建分析”导入 SHA256。</p>}</article>
    <Dialog open={Boolean(selected)} onOpenChange={open=>{if(!open)setSelected(null);}}><DialogContent><DialogHeader><DialogTitle>确认刷新批次报告</DialogTitle><DialogDescription>“{selected?.name}”将绕过缓存，预计至少额外请求 {selected?.sampleCount} 次；失败重试另计。只获取已有报告，不触发重新分析。</DialogDescription></DialogHeader><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={acknowledged} onChange={event=>setAcknowledged(event.target.checked)}/>我已知晓额外配额消耗。</label><DialogFooter><Button variant="outline" onClick={()=>setSelected(null)}>取消</Button><Button disabled={!acknowledged || busy} onClick={()=>selected && void operate(selected,'refresh')}>{busy ? '排队中…' : '确认刷新'}</Button></DialogFooter></DialogContent></Dialog>
  </section>;
}
