import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, XAxis, YAxis } from 'recharts';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { LocalDataState } from '@/components/local-data-state';
import { useLocalData } from '@/hooks/use-local-data';
import type { Dashboard } from '@/api/workspace';
import type { View } from '@/lib/workspace';

const isActive = (data: Dashboard) => Boolean(data.samples?.analyzing);
export function DashboardPage({onViewChange}: {onViewChange: (view: View) => void}) {
  const {data, error, updatedAt, reload} = useLocalData<Dashboard>('/dashboard', isActive);
  const risks = data?.riskDistribution;
  const riskData = [{name:'恶意',count:risks?.malicious ?? 0,color:'var(--color-destructive)'}, {name:'可疑',count:risks?.suspicious ?? 0,color:'var(--color-primary)'}, {name:'未检出',count:risks?.undetected ?? 0,color:'var(--color-primary)'}, {name:'未知',count:risks?.unknown ?? 0,color:'var(--color-muted-foreground)'}];
  const budget = data?.requestBudget;
  const metrics = [{label:'累计样本',value:data?.samples?.total}, {label:'查询终态',value:data?.samples?.completed}, {label:'等待／查询中',value:data?.samples?.analyzing}, {label:'查询失败',value:data?.samples?.failed}];
  return <section className="flex flex-col gap-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="eyebrow">WORKSPACE STATUS</p><h1 className="mt-2 text-2xl font-semibold tracking-tight">分析总览</h1><p className="mt-2 text-sm text-muted-foreground">查询记录与风险统计</p></div><p className="text-xs text-muted-foreground">最后更新 · {updatedAt ?? '—'}</p></div>
    <LocalDataState error={error} loading={!data && !error} reload={reload}/>
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{metrics.map(metric=><article className="panel p-5" key={metric.label}><p className="text-sm text-muted-foreground">{metric.label}</p><p className="mt-5 text-3xl font-semibold">{metric.value ?? '—'}</p></article>)}</div>
    <div className="grid gap-6 xl:grid-cols-[1.3fr_0.7fr]">
      <article className="panel p-5 sm:p-6"><h2 className="text-sm font-medium">查询风险分布</h2><p className="mt-1 text-xs text-muted-foreground">未收录、请求失败和等待中的样本均保持未知；未检出不代表安全。</p><div className="mt-5 h-64" role="img" aria-label={riskData.map(row=>row.name+' '+row.count+' 个').join('，')}><ResponsiveContainer width="100%" height="100%"><BarChart data={riskData} layout="vertical" margin={{right:35}}><XAxis type="number" allowDecimals={false} tick={{fill:"var(--color-muted-foreground)",fontSize:12}}/><YAxis type="category" dataKey="name" width={55} tick={{fill:"var(--color-muted-foreground)",fontSize:12}}/><Bar dataKey="count" isAnimationActive={false}>{riskData.map(row=><Cell key={row.name} fill={row.color}/>)}<LabelList dataKey="count" position="right" fill="var(--color-foreground)"/></Bar></BarChart></ResponsiveContainer></div><div className="flex flex-wrap gap-4 text-xs text-muted-foreground">{riskData.map(row=><span key={row.name}>{row.name} {row.count}</span>)}</div></article>
      <article className="panel p-5 sm:p-6"><h2 className="text-sm font-medium">VirusTotal 请求预算</h2><p className="mt-1 text-xs text-muted-foreground">本地保护预算，不等于账户剩余配额；失败和重试计入。</p><div className="mt-8 flex justify-between gap-3"><p><span className="text-4xl font-semibold">{budget?.used ?? '—'}</span><span className="ml-2 text-sm text-muted-foreground">已请求</span></p><p className="text-sm">预算余量 {budget?.remaining ?? '—'}</p></div><Progress className="mt-4" value={budget ? budget.used / budget.dailyLimit * 100 : 0}/><p className="mt-5 text-xs text-muted-foreground">刷新报告将绕过缓存并额外消耗 API 配额。</p><div className="mt-6 flex flex-wrap gap-2"><Button variant="outline" onClick={()=>onViewChange('samples')}>查看样本</Button><Button variant="outline" onClick={()=>onViewChange('batches')}>查看批次</Button></div></article>
    </div>
  </section>;
}
