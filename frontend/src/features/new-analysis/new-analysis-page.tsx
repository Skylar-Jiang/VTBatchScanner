import { CheckCircle2, CircleAlert, ClipboardPaste, FileUp, Info, Plus, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { createBatch, previewBatch } from "@/api/batches";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { importHashes } from '@/lib/import-hashes';
import { sha256Bytes } from '@/lib/hash-file';
import type { View } from "@/lib/workspace";

const sha256Pattern = /^[a-fA-F0-9]{64}$/;

type Preview = { valid: string[]; duplicates: Array<{ value: string; line: number }>; invalid: Array<{ value: string; line: number }> };

function previewHashes(input: string): Preview {
  const seen = new Set<string>();
  return input.split(/\r?\n/).reduce<Preview>((preview, raw, index) => {
    const value = raw.trim().toLowerCase();
    if (!value) return preview;
    if (!sha256Pattern.test(value)) preview.invalid.push({ value: raw, line: index + 1 });
    else if (seen.has(value)) preview.duplicates.push({ value, line: index + 1 });
    else { seen.add(value); preview.valid.push(value); }
    return preview;
  }, { valid: [], duplicates: [], invalid: [] });
}

export function NewAnalysisPage({ onViewChange }: { onViewChange: (view: View) => void }) {
  async function hashFile(file: File) {
    try {
      if (file.size > 64 * 1024 * 1024) throw new Error('本地哈希计算支持至多 64 MiB 的文件');
      const hash = await sha256Bytes(await file.arrayBuffer());
      setInput(current => current.trim() ? `${current.trim()}\n${hash}` : hash);
      toast.success('SHA256 已加入输入；文件未上传、未运行');
    } catch (error) { toast.error(error instanceof Error ? error.message : '无法计算文件哈希'); }
  }
  async function importFile(file: File) {
    try {
      if (file.size > 65536) throw new Error('哈希清单不能超过 64 KiB');
      setInput(importHashes(await file.text(), file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'txt').join('\n'));
      toast.success('本地清单已导入，请检查预览后创建');
    } catch (error) { toast.error(error instanceof Error ? error.message : '无法读取清单'); }
  }
  const [name, setName] = useState("批量查询");
  const [input, setInput] = useState("");
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const preview = useMemo(() => previewHashes(input), [input]);
  const canCreate = Boolean(name.trim()) && preview.valid.length > 0 && preview.valid.length <= 1000;

  async function requestPreview() {
    setIsPreviewing(true);
    try {
      const response = await previewBatch(input.split(/\r?\n/));
      toast.success("服务端预览已完成", { description: `有效 ${response.data.validSha256s.length} 个 SHA256。` });
    } catch {
      toast.error("无法连接本地 API", { description: "请先启动后端后重试；当前输入未提交。" });
    } finally { setIsPreviewing(false); }
  }

  async function submitBatch() {
    if (!canCreate) return;
    setIsCreating(true);
    try {
      const response = await previewBatch(input.split(/\r?\n/));
      const validSha256s = response.data.validSha256s;
      await createBatch(name.trim(), validSha256s);
      toast.success("已创建本地批次", { description: `已验证 ${validSha256s.length} 个 SHA256；不会触发重新分析。` });
      onViewChange("batches");
    } catch {
      toast.error("未能创建批次", { description: "请检查本地后端是否已启动，以及输入是否符合 SHA256 规则。" });
    } finally { setIsCreating(false); }
  }

  return <section className="mx-auto max-w-5xl space-y-6">
    <div><p className="eyebrow">CREATE BATCH</p><h1 className="mt-2 text-2xl font-semibold">新建分析</h1><p className="mt-2 text-sm text-slate-400">仅提交 SHA256。创建批次默认优先复用有效本地报告，绝不上传或执行样本。</p></div>
    <div className="grid gap-6 lg:grid-cols-[1fr_0.85fr]">
      <article className="panel p-5 sm:p-6">
        <label className="text-sm font-medium" htmlFor="batch-name">批次名称</label>
        <Input className="mt-2 bg-white/[0.025]" id="batch-name" onChange={(event) => setName(event.target.value)} value={name} />
        <div className="mt-6 flex items-center justify-between"><div><p className="text-sm font-medium">SHA256 输入</p><p className="mt-1 text-xs text-slate-500">一行一个；上限 1000 个有效且去重后的 SHA256。</p></div><ClipboardPaste className="size-5 text-sky-300" /></div>
        <Textarea aria-label="SHA256 输入" className="mt-3 min-h-70 bg-white/[0.025] font-mono text-xs leading-6" onChange={(event) => setInput(event.target.value)} placeholder="粘贴 SHA256，每行一个" value={input} />
        <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500"><span className="rounded border border-white/8 px-2 py-1">TXT：逐行读取</span><span className="rounded border border-white/8 px-2 py-1">CSV：必须含 sha256 列</span><span className="rounded border border-white/8 px-2 py-1">文件最大 64 KiB</span></div>
        <label className="mt-4 block text-sm">本地计算文件 SHA256<input className="mt-2 block max-w-full text-xs" type="file" aria-label="计算文件 SHA256" onChange={event => { const file = event.target.files?.[0]; if (file) void hashFile(file); }} /><span className="mt-2 block text-xs text-slate-500">只读取字节，不上传、不运行；最大 64 MiB。恶意文件仅在隔离环境中处理。</span></label>
        <div className="mt-5 flex flex-col gap-3 border-t border-white/8 pt-5 sm:flex-row sm:items-center sm:justify-between"><label className="text-sm"><FileUp className="inline size-4" /> 导入 TXT / CSV<input className="mt-2 block max-w-full text-xs" type="file" accept=".txt,.csv" aria-label="导入 TXT 或 CSV 哈希清单" onChange={event=>{const file=event.target.files?.[0]; if(file) void importFile(file);}}/></label><div className="flex gap-2"><Button disabled={!input.trim() || isPreviewing} onClick={requestPreview} variant="outline">{isPreviewing ? "预览中…" : "服务端预览"}</Button><Button className="bg-sky-400 text-slate-950 hover:bg-sky-300" disabled={!canCreate || isCreating} onClick={submitBatch}><Plus className="size-4" /> {isCreating ? "创建中…" : "创建批次"}</Button></div></div>
      </article>
      <aside className="space-y-4">
        <article className="panel p-5 sm:p-6"><p className="text-sm font-medium">提交预览</p><div className="mt-5 grid grid-cols-3 gap-2"><Counter color="text-emerald-300" label="有效" value={preview.valid.length} /><Counter color="text-amber-200" label="重复" value={preview.duplicates.length} /><Counter color="text-red-300" label="无效" value={preview.invalid.length} /></div>
          {preview.valid.length > 1000 && <Alert className="mt-5 border-red-400/25 bg-red-500/8 text-red-1000" variant="destructive"><CircleAlert /><AlertTitle>超出单批上限</AlertTitle><AlertDescription>请保留至多 1000 个有效 SHA256 后再创建。</AlertDescription></Alert>}
          <div className="mt-6 space-y-3 text-sm"><PreviewList icon={<CheckCircle2 className="size-4 text-emerald-300" />} items={preview.valid.slice(0, 3).map((value, index) => `第 ${index + 1} 行 · ${value.slice(0, 16)}…`)} title="有效输入" empty="尚未输入 SHA256" /><PreviewList icon={<CircleAlert className="size-4 text-amber-200" />} items={preview.duplicates.slice(0, 3).map((item) => `第 ${item.line} 行 · ${item.value.slice(0, 16)}…`)} title="重复项" empty="无" /><PreviewList icon={<XCircle className="size-4 text-red-300" />} items={preview.invalid.slice(0, 3).map((item) => `第 ${item.line} 行 · ${item.value || "空白"}`)} title="无效项" empty="无" /></div>
        </article>
        <Alert className="border-sky-400/20 bg-sky-400/7"><Info className="text-sky-300" /><AlertTitle className="text-sky-1000">查询策略</AlertTitle><AlertDescription>先检查有效缓存；需要查询时只读取第三方现有报告。批量查询不会触发重新分析。</AlertDescription></Alert>
      </aside>
    </div>
  </section>;
}

function Counter({ color, label, value }: { color: string; label: string; value: number }) { return <div className="rounded-md bg-white/[0.035] p-3"><p className={`text-xl font-semibold ${color}`}>{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></div>; }
function PreviewList({ icon, title, items, empty }: { icon: React.ReactNode; title: string; items: string[]; empty: string }) { return <div><div className="flex items-center gap-2 text-slate-300">{icon}<span>{title}</span></div><div className="mt-1 space-y-1 pl-6 font-mono text-xs text-slate-500">{items.length ? items.map((item) => <p key={item}>{item}</p>) : <p>{empty}</p>}</div></div>; }
