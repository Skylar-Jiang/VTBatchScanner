import { apiRequest } from "@/api/client";

export type PreviewResponse = { data: { validSha256s: string[]; duplicates: Array<{ line: number; value: string }>; invalid: Array<{ line: number; value: string }> } };

export function previewBatch(values: string[]) {
  return apiRequest<PreviewResponse>("/batch-previews/hashes", {
    method: "POST",
    body: JSON.stringify({ inputSource: "paste", values }),
  });
}

export function createBatch(name: string, sha256s: string[]) {
  return apiRequest("/batches", {
    method: "POST",
    body: JSON.stringify({ name, inputSource: "paste", sha256s }),
  });
}
