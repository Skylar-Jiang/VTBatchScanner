import { Badge } from "@/components/ui/badge";
import { providerStatusLabel, riskLabel, type ProviderStatus, type Risk } from "@/lib/workspace";

const riskClass: Record<Risk, string> = {
  malicious: "border-red-500/30 bg-red-500/10 text-red-300",
  suspicious: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  clean: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  undetected: "border-slate-500/30 bg-slate-500/10 text-slate-300",
  unknown: "border-slate-500/30 bg-slate-500/10 text-slate-300",
};

const statusClass: Record<ProviderStatus, string> = {
  pending: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  running: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  success: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  not_found: "border-slate-500/30 bg-slate-500/10 text-slate-300",
  failed: "border-red-500/30 bg-red-500/10 text-red-300",
  rate_limited: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  timeout: "border-destructive/30 bg-destructive/10 text-destructive",
  authentication_error: "border-destructive/30 bg-destructive/10 text-destructive",
  invalid_hash: "border-destructive/30 bg-destructive/10 text-destructive",
  not_supported: "border-slate-500/30 bg-slate-500/10 text-slate-300",
};

export function RiskBadge({ risk }: { risk: Risk }) {
  return <Badge className={riskClass[risk]}>{riskLabel[risk]}</Badge>;
}

export function ProviderBadge({ status }: { status: ProviderStatus }) {
  return <Badge className={statusClass[status]}>{providerStatusLabel[status]}</Badge>;
}
