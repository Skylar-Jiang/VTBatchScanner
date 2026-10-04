import { apiRequest } from "@/api/client";

export function refreshSample(sha256: string) {
  return apiRequest(`/samples/${sha256}/refresh`, {
    method: "POST",
    body: JSON.stringify({ providers: ["virustotal"], acknowledgeQuotaCost: true }),
  });
}
