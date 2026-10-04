import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import App from "./App";

describe("App", () => {
  it("shows real local workspace data and no demo quota", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({data: []}), {status:200})));
    render(<App />);

    expect(screen.getByRole("heading", { name: "分析总览" })).toBeInTheDocument();
    expect(await screen.findByText("VirusTotal 请求预算")).toBeInTheDocument();
    expect(screen.queryByText("CVERC 今日配额")).not.toBeInTheDocument();
    expect(screen.getByText(/^报告与任务持久化保存/)).toHaveTextContent('不在本机执行');
  });
});
