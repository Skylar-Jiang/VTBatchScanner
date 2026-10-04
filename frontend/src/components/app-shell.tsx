import {
  Activity,
  Boxes,
  FileSearch,
  Gauge,
  Plus,
  ShieldCheck,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import type { View } from "@/lib/workspace";

const navigation: Array<{ view: Exclude<View, "detail">; label: string; icon: typeof Gauge }> = [
  { view: "dashboard", label: "分析总览", icon: Gauge },
  { view: "samples", label: "样本库", icon: FileSearch },
  { view: "new", label: "新建分析", icon: Plus },
  { view: "batches", label: "批次任务", icon: Boxes },
];

export function AppShell({
  activeView,
  onViewChange,
  children,
}: {
  activeView: View;
  onViewChange: (view: Exclude<View, "detail">) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#09111c] text-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-white/8 bg-[#0c1624] lg:flex lg:flex-col">
        <div className="flex h-20 items-center gap-3 border-b border-white/8 px-6">
          <div className="grid size-9 place-items-center rounded-lg bg-sky-500 text-slate-950">
            <ShieldCheck className="size-5" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-tight">HASHGUARD</p>
            <p className="text-[11px] tracking-[0.14em] text-slate-500">ANALYSIS CONSOLE</p>
          </div>
        </div>
        <nav className="space-y-1 p-3" aria-label="主导航">
          {navigation.map(({ view, label, icon: Icon }) => (
            <button
              className={`flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition ${
                activeView === view || (activeView === "detail" && view === "samples")
                  ? "bg-sky-500/12 text-sky-200"
                  : "text-slate-400 hover:bg-white/5 hover:text-slate-100"
              }`}
              key={view}
              onClick={() => onViewChange(view)}
              type="button"
            >
              <Icon className="size-4" />
              {label}
            </button>
          ))}
        </nav>
        <div className="mt-auto m-3 rounded-lg border border-white/8 bg-white/[0.025] p-4">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-300">
            <Activity className="size-3.5 text-emerald-300" />
            本地运行模式
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-500">报告与任务持久化保存。样本仅作静态处理，不在本机执行。</p>
        </div>
      </aside>
      <main className="min-h-screen lg:pl-64">
        <header className="flex h-20 items-center justify-between border-b border-white/8 bg-[#0b1421]/95 px-5 backdrop-blur lg:px-8">
          <div className="lg:hidden text-sm font-semibold">HASHGUARD</div>
          <p className="hidden text-sm text-slate-500 sm:block">SHA256 报告管理</p>
          <Button className="bg-sky-400 text-slate-950 hover:bg-sky-300" onClick={() => onViewChange("new")} size="sm">
            <Plus className="size-4" /> 新建分析
          </Button>
        </header>
        <nav aria-label="移动端导航" className="flex flex-wrap gap-1 border-b border-border p-3 lg:hidden">{navigation.map(({view, label}) => <Button key={view} variant={activeView === view ? 'secondary' : 'ghost'} size="sm" onClick={() => onViewChange(view)}>{label}</Button>)}</nav>
        <div className="mx-auto max-w-[1600px] p-5 lg:p-8">{children}</div>
      </main>
    </div>
  );
}
