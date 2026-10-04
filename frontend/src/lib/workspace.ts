export type Risk = "malicious" | "suspicious" | "clean" | "undetected" | "unknown";
export type ProviderStatus =
  | "pending"
  | "running"
  | "success"
  | "not_found"
  | "failed"
  | "rate_limited"
  | "timeout"
  | "authentication_error"
  | "invalid_hash"
  | "not_supported";

export type View = "dashboard" | "samples" | "new" | "batches" | "detail";

export type SampleRow = {
  sha256: string;
  fileName: string | null;
  risk: Risk;
  virustotal: ProviderStatus;
  cnPlatform: ProviderStatus;
  status: "completed" | "running" | "partial_failed" | "failed";
  lastAnalysisAt: string | null;
  riskSource: string[];
};

export const demoSamples: SampleRow[] = [
  {
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    fileName: "signed-installer.exe",
    risk: "malicious",
    virustotal: "success",
    cnPlatform: "success",
    status: "completed",
    lastAnalysisAt: "2026-09-14T06:40:00Z",
    riskSource: ["VirusTotal", "CN Platform"],
  },
  {
    sha256: "3f786850e387550fdab836ed7e6dc881de23001b0c0d0e4fdb796a27cf9e65a6",
    fileName: "invoice_2026.scr",
    risk: "suspicious",
    virustotal: "success",
    cnPlatform: "pending",
    status: "running",
    lastAnalysisAt: "2026-09-14T06:35:00Z",
    riskSource: ["VirusTotal"],
  },
  {
    sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    fileName: null,
    risk: "unknown",
    virustotal: "not_found",
    cnPlatform: "not_supported",
    status: "completed",
    lastAnalysisAt: null,
    riskSource: [],
  },
  {
    sha256: "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    fileName: "loader.dll",
    risk: "clean",
    virustotal: "success",
    cnPlatform: "rate_limited",
    status: "partial_failed",
    lastAnalysisAt: "2026-09-14T06:27:00Z",
    riskSource: ["VirusTotal"],
  },
];

export const riskLabel: Record<Risk, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  clean: "低风险",
  undetected: "未检出",
  unknown: "未知",
};

export const providerStatusLabel: Record<ProviderStatus, string> = {
  pending: "等待中",
  running: "查询中",
  success: "已完成",
  not_found: "未收录",
  failed: "失败",
  rate_limited: "受限",
  timeout: "超时",
  authentication_error: "认证／权限失败",
  invalid_hash: "无效哈希",
  not_supported: "未开通",
};

export function shortHash(sha256: string) {
  return `${sha256.slice(0, 12)}…${sha256.slice(-8)}`;
}
