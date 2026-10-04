import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { LocalDataState } from '@/components/local-data-state';
import { ProviderBadge, RiskBadge } from '@/components/status-badge';
import { useLocalData } from '@/hooks/use-local-data';
import { sampleRow, type StoredSample } from '@/api/workspace';
import { shortHash, type SampleRow } from '@/lib/workspace';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { ExperimentGroup } from './experiment-group';

const isActive = (samples: StoredSample[]) => samples.some(sample=>sample.status==='running');
export function SamplesPage({onSelect}: {onSelect: (sample: SampleRow)=>void}) {
  return <section className="flex flex-col gap-6"><h1 className="text-2xl font-semibold">样本库</h1><Tabs defaultValue="A"><TabsList className="max-w-full"><TabsTrigger value="A">文件样本</TabsTrigger><TabsTrigger value="B">哈希查询</TabsTrigger><TabsTrigger value="uploads">上传记录</TabsTrigger><TabsTrigger value="history">全部记录</TabsTrigger></TabsList><TabsContent value="A"><ExperimentGroup group="A" onSelect={onSelect}/></TabsContent><TabsContent value="B"><ExperimentGroup group="B" onSelect={onSelect}/></TabsContent><TabsContent value="uploads"><ExperimentGroup group="A" source="uploads" onSelect={onSelect}/></TabsContent><TabsContent value="history"><HistorySamplesPage onSelect={onSelect}/></TabsContent></Tabs></section>;
}
function HistorySamplesPage({onSelect}: {onSelect: (sample: SampleRow)=>void}) {
  const [query,setQuery] = useState('');
  const {data,error,reload} = useLocalData<StoredSample[]>('/samples',isActive);
  const rows = (data ?? []).map(sampleRow).filter(sample=>sample.sha256.includes(query.trim().toLowerCase()));
  return <section className="flex flex-col gap-6"><div><p className="eyebrow">SAMPLE INVENTORY</p><h1 className="mt-2 text-2xl font-semibold">样本库</h1><p className="mt-2 text-sm text-muted-foreground">报告记录：{rows.length} / {data?.length ?? 0} 条。未检出、未收录与失败不是安全结论。</p></div><LocalDataState error={error} loading={!data && !error} reload={reload}/><article className="panel overflow-hidden"><div className="p-4"><Input aria-label="搜索 SHA256" placeholder="搜索 SHA256" value={query} onChange={event=>setQuery(event.target.value)} className="sm:max-w-sm"/></div><div className="overflow-x-auto"><table className="min-w-[800px] w-full text-left text-sm"><thead className="bg-muted/30 text-xs text-muted-foreground"><tr>{['SHA256','风险','VirusTotal','总体状态','最后分析','操作'].map(label=><th className="px-5 py-3 font-medium" key={label}>{label}</th>)}</tr></thead><tbody>{rows.map(sample=><tr className="border-t border-border hover:bg-muted/30" key={sample.sha256}><td className="px-5 py-4 font-mono text-xs" title={sample.sha256}>{shortHash(sample.sha256)}</td><td className="px-5 py-4"><RiskBadge risk={sample.risk}/></td><td className="px-5 py-4"><ProviderBadge status={sample.virustotal}/></td><td className="px-5 py-4">{sample.status==='running' ? '待处理／查询中' : sample.status==='failed' ? '失败' : sample.status==='partial_failed' ? '部分失败' : '查询结束'}</td><td className="px-5 py-4 text-xs text-muted-foreground">{sample.lastAnalysisAt ? new Date(sample.lastAnalysisAt).toLocaleString() : '—'}</td><td className="px-5 py-4"><Button variant="ghost" size="sm" onClick={()=>onSelect(sample)}>详情</Button></td></tr>)}</tbody></table></div>{data && rows.length===0 && <p className="p-8 text-sm text-muted-foreground">暂无匹配的本地样本；可从“新建分析”导入。</p>}</article></section>;
}
