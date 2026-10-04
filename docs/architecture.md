# 系统架构

系统由 React 前端、FastAPI 后端和 SQLite 数据库组成，使用单进程在本机运行。前端通过 HTTP API 创建任务、读取进度和导出结果。SQLite 保存任务、缓存、配额及查询记录，文件系统保存原始 JSON、单样本 Markdown 和汇总表。

## 模块关系

```mermaid
flowchart TD
    UI[React 页面] --> HTTP[apiRequest / 本地 HTTP API]
    HTTP --> API[FastAPI 路由]
    API --> BS[BatchService / 任务与进度]
    BS <--> DB[(SQLite)]
    API --> Q[QueryDispatcher / 串行查询]
    Q --> CACHE{7 天成功缓存有效?}
    CACHE -->|是| DB
    CACHE -->|否| LIMIT[持久预算 / 请求间隔 / 冷却]
    LIMIT --> VT[VirusTotalProvider / GET files]
    VT --> N[normalize_report]
    N --> DB
    Q --> RAW[ReportStore / 原始 JSON]
    Q --> MD[DetectionReports / Markdown 与索引]
    MD --> OUT[results / CSV 与 XLSX]
    API --> EXP[只读导出 / 内存报告包]
    EXP --> UI
    ZIP[隔离环境 / ZIP 字节] --> INV[inventory_zip / SHA-256 提取与去重]
    INV --> BS
    INV -->|独立显式授权| UP[run_file_uploads / FileUploadClient]
    UP --> POST[VirusTotal POST files / GET analyses]
    POST --> STATE[上传结果 JSON / 分析 ID / 续跑时间]
    STATE --> MD
    SAVED[已保存的 A/B 结果] --> OFF[generate_detection_reports / 离线补建]
    OFF --> MD
```

哈希查询读取 VirusTotal 已有报告；文件上传提交样本字节，并通过分析 ID 获取结果。网页选择文件时只计算哈希，上传由带有 `--acknowledge-upload` 参数的命令行执行。刷新绕过缓存重新查询已有报告。重新分析是独立操作，当前入口返回 `409 reanalysis_not_supported`。

## 创建批次的请求时序

```mermaid
sequenceDiagram
    participant UI as NewAnalysisPage
    participant API as FastAPI batches
    participant BS as BatchService
    participant DB as SQLite
    participant Q as QueryDispatcher
    participant VT as VirusTotal
    participant MD as DetectionReports
    UI->>API: POST batch-previews/hashes
    API-->>UI: 有效 / 重复 / 无效输入
    UI->>API: POST batches
    API->>BS: create(name, source, hashes)
    BS->>DB: 保存 Batch / Sample / ProviderJob
    API-->>UI: 201 + batchId
    Note over API,Q: 响应发送后由 BackgroundTasks 执行查询
    API->>Q: run_batch(batchId)
    loop 待处理任务，已完成项跳过
        Q->>DB: 查询成功缓存与持久冷却
        alt 有效缓存
            Q->>DB: 保存 fromCache 与成功状态
        else 需要外部查询
            Q->>DB: 预留预算，记录尝试次数与查询时间
            Q->>VT: GET files/{sha256}
            VT-->>Q: 检测报告或错误状态
            Q->>DB: 保存规范化结果 / 失败 / 缓存
        end
        Q->>MD: save_query / 固定模板 Markdown
    end
    Q->>MD: export_indexes / CSV + XLSX
    UI->>API: GET batches，活跃任务按 5 秒本地轮询
    API->>BS: progress / 已保存结果
    API-->>UI: 本地进度与状态
    UI->>API: GET reports 或批次 export
    API-->>UI: 已保存文本或内存导出，不请求 VirusTotal
```

## 数据与配置

- `QueryRecord` 保存每个查询任务的尝试数、缓存标记、查询时间、错误和规范化报告；`VirusTotalCache` 以 SHA-256 为键。
- `ProviderDailyQuota` 按提供方和 UTC 日期累计请求数，`ProviderCooldown` 保存 429 冷却时间。查询、上传和报告生成使用单个写入进程。
- 单样本报告以文件名 + SHA-256 标识或纯 SHA-256 标识复用。文件主报告保留上传分析，历史查询写在附节；批次报告包用该批次的数据在内存中生成。
- 全局报告包根据同一份索引数据生成汇总表和 Markdown；网页导出在内存中完成。
- 查询或上传结果先保存，再生成报告。报告写入错误独立显示，已保存的结果可用于离线补建。
- Key 由后端环境变量提供，不传给前端。服务默认绑定回环地址，没有登录功能，不直接面向公网部署。

安装、配置与操作步骤见 [README](../README.md)。
