import { useState } from 'react';
import { apiBaseUrl } from '@/api/client';
import { type Report, type StoredSample, sampleRow } from '@/api/workspace';
import { LocalDataState } from '@/components/local-data-state';
import { RiskBadge, ProviderBadge } from '@/components/status-badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { useLocalData } from '@/hooks/use-local-data';
import { type SampleRow, shortHash } from '@/lib/workspace';

type UploadedFile={path:string;sha256:string;size:number;status:string;analysisId:string|null;error:string|null;report:Report|null;queryStatus?:string;queryReport?:Report|null};
type Groups={A:{method:string;files:UploadedFile[];readErrors:{path:string;error:string}[];apiRequests:number;pauseReason?:string|null;updatedAt?:string;reportError?:string|null};B:{method:string;batchId:string|null;samples:StoredSample[]}};
const active=(data:Groups)=>!data.A.pauseReason && data.A.files.some(file=>['pending','accepted','queued','in-progress'].includes(file.status));
const statuses:Record<string,string>={pending:'待上传',accepted:'已上传／待分析',queued:'等待平台分析','in-progress':'平台分析中',success:'分析完成',failed:'请求失败',authentication_error:'权限错误',rate_limited:'配额受限',submission_unknown:'提交结果待确认',read_failed:'读取失败',invalid_file:'文件校验失败'};

export function ExperimentGroup({group,source='reports',onSelect}:{group:'A'|'B';source?:'reports'|'uploads';onSelect:(sample:SampleRow)=>void}) {
  const {data,error,reload}=useLocalData<Groups>('/experiment/groups',active);
  const [expanded,setExpanded]=useState<string|null>(null);
  const files=(data?.A.files ?? []).map(file=>source==='uploads' ? file : {...file,status:file.queryStatus ?? 'pending',report:file.queryReport ?? null,analysisId:null,error:null});
  const labels=source==='uploads' ? statuses : {pending:'待查询',success:'已有报告',not_found:'未收录',failed:'请求失败',timeout:'请求超时',authentication_error:'权限错误',rate_limited:'配额受限'};
  const unique=new Map(files.map(file=>[file.sha256,file]));
  const succeeded=[...unique.values()].filter(file=>file.status==='success').length;
  return <div className="flex flex-col gap-4"><LocalDataState error={error} loading={!data && !error} reload={reload}/>
    {group==='A' ? <>
      <p className="text-sm text-muted-foreground">{files.length} 个文件 · {unique.size} 个唯一样本 · {source==='uploads' ? '分析完成' : '已有报告'} {succeeded}</p>
      {source==='uploads' && data?.A.pauseReason && <Alert variant="destructive"><AlertTitle>上传任务暂停</AlertTitle><AlertDescription>{data.A.pauseReason}</AlertDescription></Alert>}
      {source==='uploads' && data?.A.reportError && <Alert variant="destructive"><AlertTitle>检测报告未能写入</AlertTitle><AlertDescription>上传结果已保存，请检查文件占用与写入权限，再运行本地报告生成脚本。</AlertDescription></Alert>}
      <div className="flex flex-wrap gap-3 text-sm">{source==='uploads' && <><a href={`${apiBaseUrl}/experiment/a-upload/export?format=csv`}>导出 CSV</a><a href={`${apiBaseUrl}/experiment/a-upload/export?format=json`}>导出 JSON</a></>}<Button size="sm" variant="outline" asChild><a href={`${apiBaseUrl}/reports/index?format=xlsx`}>导出 XLSX</a></Button><Button size="sm" variant="outline" asChild><a href={`${apiBaseUrl}/reports/index?format=zip`}>报告包</a></Button><Button size="sm" variant="outline" onClick={reload}>更新列表</Button></div>
      {expanded && unique.get(expanded)?.report && <article className="panel p-4"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-medium break-all">{source==='uploads' ? '上传分析' : '报告详情'} · {shortHash(expanded)}</h2><div className="flex flex-wrap gap-2"><Button size="sm" variant="outline" asChild><a href={`${apiBaseUrl}/reports/files/${expanded}?filename=${encodeURIComponent(unique.get(expanded)!.path.split(/[/\\\\]/).at(-1)!)}`} target="_blank" rel="noreferrer">查看检测报告</a></Button><Button size="sm" variant="outline" onClick={()=>setExpanded(null)}>关闭详情</Button></div></div><p className="mt-3 break-all text-sm text-muted-foreground">{source==='uploads' && <>分析 ID：{unique.get(expanded)?.analysisId}；</>}分析时间：{unique.get(expanded)?.report?.analysisTime ?? '未知'}</p><div className="mt-3 max-h-80 overflow-auto"><table className="min-w-[560px] w-full text-left text-sm"><thead><tr><th>引擎</th><th>类别</th><th>结果</th></tr></thead><tbody>{Object.entries(unique.get(expanded)!.report!.engines).map(([name,engine])=><tr className="border-t border-border" key={name}><td className="py-2">{name}</td><td>{engine.category}</td><td className="break-all">{engine.result ?? '—'}</td></tr>)}</tbody></table></div></article>}
      <article className="panel overflow-x-auto"><table className="min-w-[900px] w-full text-left text-sm"><thead className="bg-muted/30 text-muted-foreground"><tr>{['文件路径','SHA256',source==='uploads' ? '分析状态' : '报告状态','风险','恶意 / 引擎','操作'].map(label=><th className="px-4 py-3" key={label}>{label}</th>)}</tr></thead><tbody>{files.map(file=><tr key={file.path} className="border-t border-border hover:bg-muted/30"><td className="px-4 py-3 max-w-80 break-all">{file.path}</td><td className="px-4 py-3 font-mono text-xs" title={file.sha256}>{shortHash(file.sha256)}</td><td className="px-4 py-3">{labels[file.status as keyof typeof labels] ?? file.status}{file.error && <p className="text-xs text-destructive">{file.error}</p>}</td><td className="px-4 py-3">{file.report ? <RiskBadge risk={file.report.risk}/> : '未知'}</td><td className="px-4 py-3">{file.report ? `${file.report.stats.malicious ?? 0} / ${file.report.totalEngines}` : '—'}</td><td className="px-4 py-3"><Button size="sm" variant="ghost" disabled={!file.report} onClick={()=>setExpanded(file.sha256)}>详情</Button></td></tr>)}</tbody></table></article>
      {!!data?.A.readErrors.length && <Alert><AlertTitle>未能读取的加密条目</AlertTitle><AlertDescription>{data.A.readErrors.map(item=><p key={item.path} className="break-all">{item.path}：文件读取失败，请检查压缩包密码。</p>)}</AlertDescription></Alert>}
    </> : <>
      <p className="text-sm text-muted-foreground">{data?.B.samples.length ?? 0} 条哈希记录</p>
      <article className="panel overflow-x-auto"><table className="min-w-[650px] w-full text-left text-sm"><thead className="bg-muted/30 text-muted-foreground"><tr>{['SHA256','风险','查询状态','操作'].map(label=><th className="px-4 py-3" key={label}>{label}</th>)}</tr></thead><tbody>{data?.B.samples.map(sample=><tr key={sample.sha256} className="border-t border-border hover:bg-muted/30"><td className="px-4 py-3 font-mono text-xs" title={sample.sha256}>{shortHash(sample.sha256)}</td><td className="px-4 py-3"><RiskBadge risk={sample.risk}/></td><td className="px-4 py-3"><ProviderBadge status={sample.providerStatuses.virustotal}/></td><td className="px-4 py-3"><Button size="sm" variant="ghost" onClick={()=>onSelect(sampleRow(sample))}>详情</Button></td></tr>)}</tbody></table></article>
    </>}
    <p className="text-xs text-muted-foreground">未检出不代表安全；未收录和请求失败不计入未检出。</p>
  </div>;
}
