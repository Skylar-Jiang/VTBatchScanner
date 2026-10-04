# 实验报告代码索引

对应最终源码的函数、范围与节选。节选为原文，行号以本次代码版本为准；全部 API 行为已通过 Mock 验证，本次新增工作未调用真实 VirusTotal。

## 12 项功能定位

| 项目 | 源文件 / 函数 | 函数范围 | 节选范围 |
|---|---|---|---|
| 1. 输入规范化与静态哈希 | [backend/app/services/inputs.py](../backend/app/services/inputs.py#L31-L57) · `preview_hashes` | 31–57 | 31–51 |
| 2. VirusTotal API 请求封装 | [backend/app/providers/virustotal.py](../backend/app/providers/virustotal.py#L14-L56) · `fetch` | 14–56 | 14–38 |
| 3. 批量任务与断点续跑 | [backend/app/services/dispatcher.py](../backend/app/services/dispatcher.py#L65-L102) · `_run_batch` | 65–102 | 65–88 |
| 4. 请求间隔与配额 | [backend/app/services/quota.py](../backend/app/services/quota.py#L40-L64) · `reserve` | 40–64 | 40–64 |
| 5. 429 退避与严格重试上限 | [backend/app/services/dispatcher.py](../backend/app/services/dispatcher.py#L104-L203) · `_run_job` | 104–203 | 146–169 |
| 6. 成功缓存与刷新区别 | [backend/app/services/dispatcher.py](../backend/app/services/dispatcher.py#L104-L203) · `_run_job` | 104–203 | 104–127 |
| 7. 上传分析与独立重新分析 | [backend/app/providers/upload.py](../backend/app/providers/upload.py#L47-L63) · `analysis` | 47–63 | 40–63 |
| 8. 报告 JSON 规范化与风险分类 | [backend/app/providers/virustotal.py](../backend/app/providers/virustotal.py#L59-L95) · `normalize_report` | 59–95 | 59–83 |
| 9. Markdown 模板与安全报告命名 | [backend/app/services/detection_reports.py](../backend/app/services/detection_reports.py#L43-L88) · `render_markdown` | 43–88 | 43–64 |
| 10. CSV / XLSX 链接与报告包 | [backend/app/services/result_exports.py](../backend/app/services/result_exports.py#L34-L91) · `xlsx_bytes` | 34–91 | 50–73 |
| 11. 数据库持久化与最新状态 | [backend/app/models.py](../backend/app/models.py#L77-L84) · `QueryRecord` | 77–84 | 69–90 |
| 12. 前后端创建链与配置边界 | [backend/app/main.py](../backend/app/main.py#L27-L81) · `create_app` | 27–81 | 52–74 |

## 1. 输入规范化与静态哈希

职责：统一小写 SHA-256，逐行校验并记录重复位置。文件哈希由 archive_inventory.inventory_zip 或浏览器 sha256Bytes 静态计算。

调用链：NewAnalysisPage → previewBatch → previews 路由 → preview_hashes；inventory_inputs → inventory_zip。

适合写入报告的原因：输入去重是减少重复请求的第一步，能用少量代码说明两类输入的统一标识。

节选：`backend/app/services/inputs.py:31–51`。

```python
def preview_hashes(values: list[str]) -> InputPreview:
    valid_sha256s: list[str] = []
    duplicates: list[DuplicateItem] = []
    invalid: list[InvalidItem] = []
    first_lines: dict[str, int] = {}

    for line, raw_value in enumerate(values, start=1):
        value = raw_value.strip()
        if not SHA256_PATTERN.fullmatch(value):
            invalid.append(InvalidItem(line=line, value=raw_value, reason="invalid_format"))
            continue

        sha256 = value.lower()
        if sha256 in first_lines:
            duplicates.append(
                DuplicateItem(line=line, value=sha256, first_line=first_lines[sha256])
            )
            continue

        first_lines[sha256] = line
        valid_sha256s.append(sha256)
```

## 2. VirusTotal API 请求封装

职责：只调用官方文件查询 GET，Key 放在 x-apikey 请求头，区分认证、404、限流、超时和网络异常。

调用链：QueryDispatcher._run_job → VirusTotalProvider.fetch → normalize_report → ProviderFetch。

适合写入报告的原因：展示官方接口如何变成统一结果，以及未收录为何不能等同于安全。

节选：`backend/app/providers/virustotal.py:14–38`。

```python
    def fetch(self, sha256: str) -> ProviderFetch:
        sha256 = sha256.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            return ProviderFetch(status="invalid_hash", raw=None, error="Invalid SHA256")
        try:
            response = self._client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self._api_key},
            )
        except httpx.TimeoutException:
            return ProviderFetch(status="timeout", raw=None, error="Provider request timed out")
        except httpx.HTTPError:
            return ProviderFetch(status="failed", raw=None, error="Provider request failed")
        if response.status_code in {401, 403}:
            return ProviderFetch(status="authentication_error", raw=None, error="Provider authentication failed")
        if response.status_code == 404:
            return ProviderFetch(status="not_found", raw=None)
        if response.status_code == 429:
            retry_after = None
            value = response.headers.get("Retry-After", "")
            try:
                retry_after = max(0.0, float(value))
            except ValueError:
                try:
                    retry_after = max(0.0, (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
```

## 3. 批量任务与断点续跑

职责：将中断的 running 项恢复为 pending，只逐个处理等待任务；已终态任务跳过，单进程锁串行调度。

调用链：create_batch / resume_batch → run_batch → _run_batch → _run_job → save_query → export_indexes。

适合写入报告的原因：批量处理并非一次性循环请求；持久任务状态决定续跑范围。

节选：`backend/app/services/dispatcher.py:65–88`。

```python
    def _run_batch(self, batch_id: str, max_jobs: int | None = None) -> None:
        self._halted = False
        report_failed = False
        with self._session_factory() as session:
            for job in session.scalars(select(ProviderJob).where(ProviderJob.batch_id == batch_id, ProviderJob.status == "running")):
                job.status = "pending"
            session.commit()
            job_ids = list(
                session.scalars(
                    select(ProviderJob.id).where(
                        ProviderJob.batch_id == batch_id,
                        ProviderJob.status == "pending",
                    )
                )
            )
        for job_id in job_ids[:max_jobs] if max_jobs is not None else job_ids:
            if self._halted:
                break
            self._run_job(job_id)
            if self._detection_reports is not None:
                try:
                    with self._session_factory() as session:
                        job = session.get(ProviderJob, job_id)
                        record = session.get(QueryRecord, job_id)
```

## 4. 请求间隔与配额

职责：请求发送前持久预留当日预算；调度器使用上次查询时间保证至少 16 秒间隔。失败和重试同样消耗预算。

调用链：QueryDispatcher._run_job → PersistentDailyQuota.reserve → ProviderDailyQuota；main.create_app 限定最小间隔。

适合写入报告的原因：预算是本地保护上限而非官方余量，预扣与失败计数值得说明。

节选：`backend/app/services/quota.py:40–64`。

```python
    def reserve(self, requested_at: datetime, request_count: int) -> QuotaReservation:
        day_key = requested_at.date().isoformat()
        with self._session_factory() as session:
            usage = session.scalar(
                select(ProviderDailyQuota).where(
                    ProviderDailyQuota.provider == self._provider,
                    ProviderDailyQuota.day == day_key,
                )
            )
            used = usage.used if usage is not None else 0
            if request_count <= 0 or used + request_count > self._limit:
                return QuotaReservation(allowed=False, remaining=self._limit - used)
            if usage is None:
                usage = ProviderDailyQuota(
                    provider=self._provider,
                    day=day_key,
                    used=request_count,
                    updated_at=requested_at,
                )
                session.add(usage)
            else:
                usage.used += request_count
                usage.updated_at = requested_at
            session.commit()
            return QuotaReservation(allowed=True, remaining=self._limit - usage.used)
```

## 5. 429 退避与严格重试上限

职责：遵循 Retry-After 或指数退避，查询最多尝试 2 次。长冷却和认证错误暂停后续任务，不无限重试。

调用链：VirusTotalProvider.fetch 解析 Retry-After → _run_job → ProviderCooldown → 手动 resume。

适合写入报告的原因：这一段同时体现限流、终态判断与保存进度，适合作为异常处理示例。

节选：`backend/app/services/dispatcher.py:146–169`。

```python
                    result = self._virustotal.fetch(job.sha256)
                    record.error = result.error
                    record.report = result.report
                    job.status = result.status
                    if result.status == "rate_limited":
                        delay = max(self._request_interval, result.retry_after or 2 ** record.attempts)
                        if cooldown is None:
                            cooldown = ProviderCooldown(provider="virustotal", available_after=datetime.now(UTC) + timedelta(seconds=delay))
                            session.add(cooldown)
                        else:
                            cooldown.available_after = datetime.now(UTC) + timedelta(seconds=delay)
                    session.commit()
                    if result.status == "rate_limited" and delay > 60:
                        self._halted = True
                        break
                    if result.status not in {"timeout", "failed", "rate_limited"} or record.attempts >= 2:
                        break
                    self._sleeper(max(self._request_interval, result.retry_after or 2 ** record.attempts))
                else:
                    job.status = "failed"
                    record.error = "Attempt limit reached; explicit refresh required"
                    session.commit()
                    return
                if result.status in {"authentication_error", "rate_limited"}:
```

## 6. 成功缓存与刷新区别

职责：按 SHA-256 复用 7 天内成功缓存；失败不写成功缓存。refresh_batch 删除所选缓存并重置任务，仍只执行 GET。

调用链：样本 / 批次 refresh → refresh_batch → _run_batch；普通查询 → VirusTotalCache → fromCache。

适合写入报告的原因：说明缓存命中不请求第三方，以及刷新不等于重新分析。

节选：`backend/app/services/dispatcher.py:104–127`。

```python
    def _run_job(self, job_id: int) -> None:
        with self._session_factory() as session:
            job = session.get(ProviderJob, job_id)
            if job is None or job.status != "pending":
                return
            if job.provider == "virustotal":
                if self._virustotal is None:
                    return
                record = session.get(QueryRecord, job.id)
                if record is None:
                    record = QueryRecord(job_id=job.id, attempts=0, from_cache=0)
                    session.add(record)
                cache = session.get(VirusTotalCache, job.sha256)
                if cache is not None and (datetime.now(UTC) - cache.queried_at.replace(tzinfo=UTC)).total_seconds() < 7 * 86400:
                    record.report = cache.report
                    record.queried_at = cache.queried_at
                    record.from_cache = 1
                    job.status = "success"
                    session.commit()
                    return
                session.commit()
                cooldown = session.get(ProviderCooldown, "virustotal")
                if cooldown is not None and cooldown.available_after.replace(tzinfo=UTC) > datetime.now(UTC):
                    record.error = "Provider cooldown active; resume after Retry-After expires"
```

## 7. 上传分析与独立重新分析

职责：upload 校验字节哈希和 32 MiB 上限，返回分析 ID；analysis 查询该次分析并验证 SHA-256。重新分析未启用，prepare_reanalysis 返回 409。

调用链：run_file_uploads.main 明确授权 → run_uploads → upload / analysis → save_state → save_uploads。

适合写入报告的原因：文件可以送检，纯哈希只能匹配；本次分析结果不能由旧文件报告替代。

节选：`backend/app/providers/upload.py:40–63`。

```python
    def upload(self, contents: bytes, sha256: str) -> ProviderFetch:
        if hashlib.sha256(contents).hexdigest() != sha256:
            return ProviderFetch('invalid_file',None,'File bytes do not match manifest hash')
        if len(contents) > 32 * 1024 * 1024:
            return ProviderFetch('invalid_file',None,'This experiment client supports files up to 32 MiB')
        return self._request('POST','/files',files={'file':(sha256+'.bin',contents,'application/octet-stream')})

    def analysis(self, analysis_id: str, sha256: str) -> ProviderFetch:
        result=self._request('GET','/analyses/'+quote(analysis_id,safe=''))
        if result.status != 'accepted': return result
        try:
            # Upload receipts may be opaque tokens; GET can return a canonical resource ID.
            attributes=result.raw['data']['attributes']
            status=attributes['status']
            if status in ('queued','in-progress'): return ProviderFetch(status,result.raw)
            if status != 'completed': raise ValueError()
            returned_hash=result.raw.get('meta',{}).get('file_info',{}).get('sha256',sha256)
            if returned_hash != sha256: raise ValueError()
            report=normalize_report({'data':{'id':sha256,'attributes':{
                'last_analysis_stats':attributes['stats'],'last_analysis_results':attributes['results'],
                'last_analysis_date':attributes['date']}}},sha256)
        except (ValueError,KeyError,TypeError,AttributeError,OverflowError,OSError):
            return ProviderFetch('failed',result.raw,'Invalid or mismatched analysis report')
        return ProviderFetch('success',result.raw,report=report)
```

## 8. 报告 JSON 规范化与风险分类

职责：解析 stats、engines、UTC 时间和可选威胁分类。malicious > 0 为恶意命中，其次 suspicious，未检出与未知分开。

调用链：fetch / 上传分析 → normalize_report → QueryRecord / 缓存 → 页面与 Markdown。

适合写入报告的原因：风险汇总采用明确规则，不用简单多数票；引擎命中比例不是概率。

节选：`backend/app/providers/virustotal.py:59–83`。

```python
def normalize_report(raw: dict, sha256: str) -> dict:
    data = raw["data"]
    if data.get("id", "").lower() != sha256:
        raise ValueError("Mismatched file hash")
    attributes = data["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict) or any(type(value) is not int or value < 0 for value in stats.values()):
        raise ValueError("Invalid statistics")
    risk = "unknown"
    if stats.get("malicious", 0):
        risk = "malicious"
    elif stats.get("suspicious", 0):
        risk = "suspicious"
    elif stats.get("undetected", 0) + stats.get("harmless", 0):
        risk = "undetected"
    timestamp = attributes.get("last_analysis_date")
    analysis_time = datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z") if timestamp is not None else None
    engines = attributes.get("last_analysis_results", {})
    if not isinstance(engines, dict) or any(not isinstance(engine, dict) for engine in engines.values()):
        raise ValueError("Invalid engine results")
    classification = attributes.get('popular_threat_classification')
    if classification is not None:
        if not isinstance(classification, dict):
            raise ValueError('Invalid threat classification')
        classification = {key: value for key, value in classification.items()
```

## 9. Markdown 模板与安全报告命名

职责：固定六节模板，保留真实来源、时间和提供的字段。safe_filename 清理路径与系统保留名，_path 处理短哈希冲突，save 复用同名同哈希。

调用链：save_query / save_uploads → save → render_markdown → reports/files 或 reports/hashes。

适合写入报告的原因：这段展示无需大语言模型也能生成可核验的单样本报告。

节选：`backend/app/services/detection_reports.py:43–64`。

```python
def render_markdown(row: dict, report: dict) -> str:
    lines = ['# 检测报告', '', '## Sample Information', '']
    fields = [('Original Filename', row['filename'] or None), ('SHA-256', row['sha256']),
        ('File Size', row['file_size']), ('File Type', row['file_type']),
        ('Analysis Time', row['analysis_time']), ('Detection Source', row['source']), ('Query Status', row['query_status'])]
    lines += [f'- {label}: {md_text(value)}' for label, value in fields]
    lines += ['', '## VirusTotal Detection Summary', '', '| 指标 | 数量 |', '|---|---:|']
    lines += [f'| {key} | {row[key] if row[key] is not None else "未提供"} |' for key in ('malicious','suspicious','undetected','unsupported','total_engines')]
    classification = report.get('threatClassification') or {}
    lines += ['', '## Threat Classification', '', f'- suggested_threat_label: {md_text(classification.get("suggested_threat_label"))}']
    for field in ('popular_threat_category', 'popular_threat_name'):
        values = classification.get(field) or []
        text = ', '.join(f'{md_text(item.get("value"))} ({item.get("count", "未提供")})' for item in values if isinstance(item, dict))
        lines.append(f'- {field}: {text or "未提供"}')
    lines += ['', '## Representative Engine Results', '']
    engines = representative_engines(report)
    if engines:
        lines += ['| 引擎 | 检测标签 |', '|---|---|']
        lines += [f'| {md_text(name)} | {md_text(result)} |' for name, result in engines]
    else:
        lines.append('没有可展示的恶意引擎结果。')
    lines += ['', '## Analysis Summary', '']
```

## 10. CSV / XLSX 链接与报告包

职责：CSV 记录相对报告路径，XLSX 使用原生超链接和数值日期类型。报告包携带相对路径对应的 Markdown，并按来源和组别保留行。

调用链：batches.export_batch → batch_rows → xlsx_bytes / bundle_bytes；reports.export_index → 索引快照。

适合写入报告的原因：原生链接与便携目录结构直接支撑实验交付；内存导出避免与写入进程竞争。

节选：`backend/app/services/result_exports.py:50–73`。

```python
            address = f'{chr(65 + column)}{number}'
            value = row.get(field)
            cell = ET.SubElement(element, f'{{{S}}}c', r=address, s='1' if number == 1 else '0')
            if value is None:
                continue
            if number > 1 and field in {'report', 'virustotal'} and value:
                identifier = f'rId{len(relationships) + 1}'
                ET.SubElement(links, f'{{{S}}}hyperlink', ref=address, attrib={f'{{{R}}}id': identifier})
                target = quote(value, safe='/._-') if field == 'report' else value
                ET.SubElement(relationships, f'{{{P}}}Relationship', Id=identifier, Type=R+'/hyperlink', Target=target, TargetMode='External')
                value = '查看检测报告' if field == 'report' else '查看 VirusTotal 原始报告'
                cell.set('s', '2')
            elif number > 1 and field in {'analysis_time','queried_at'} and value:
                timestamp = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(UTC)
                value = (timestamp - datetime(1899, 12, 30, tzinfo=UTC)).total_seconds() / 86400
                cell.set('s', '3')
            if isinstance(value, (int, float)):
                cell.set('t', 'n')
                ET.SubElement(cell, f'{{{S}}}v').text = str(value)
            else:
                cell.set('t', 'inlineStr')
                string = ET.SubElement(cell, f'{{{S}}}is')
                ET.SubElement(string, f'{{{S}}}t', attrib={'{http://www.w3.org/XML/1998/namespace}space': 'preserve'}).text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))
    ET.SubElement(sheet, f'{{{S}}}autoFilter', ref=f'A1:O{len(rows) + 1}')
```

## 11. 数据库持久化与最新状态

职责：任务、缓存、配额、原始报告路径与查询记录使用 SQLAlchemy 持久化。BatchService._sample_payload 取每个提供方报告类型的最新任务，历史失败不影响新成功状态。

调用链：create_session_factory → BatchService.create → ProviderJob / QueryRecord → progress / sample_detail。

适合写入报告的原因：展示断点续跑、缓存与结果追踪的存储基础，不将旧失败误用于当前结论。

节选：`backend/app/models.py:69–90`。

```python

class VirusTotalCache(Base):
    __tablename__ = "virustotal_cache"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report: Mapped[dict] = mapped_column(JSON)


class QueryRecord(Base):
    __tablename__ = "query_records"
    job_id: Mapped[int] = mapped_column(ForeignKey("provider_jobs.id"), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    from_cache: Mapped[int] = mapped_column(Integer, default=0)
    queried_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ProviderCooldown(Base):
    __tablename__ = "provider_cooldowns"
    provider: Mapped[str] = mapped_column(String(30), primary_key=True)
    available_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
```

## 12. 前后端创建链与配置边界

职责：后端读取环境变量注入提供方，前端只配置本地 API 地址。创建链经输入预览、HTTP 路由、服务和后台调度，201 响应不是全部检测已完成。

调用链：NewAnalysisPage.submitBatch → previewBatch / createBatch → apiRequest → API create_batch → BatchService.create → BackgroundTasks → QueryDispatcher。

适合写入报告的原因：连接用户操作和后端实际执行；同时指出 Key 的信任边界和 Git 排除规则。

节选：`backend/app/main.py:52–74`。

```python
    )
    app.state.cverc_quota = PersistentDailyQuota(session_factory, "cn_platform", daily_quota)
    app.state.cverc_daily_quota = daily_quota
    app.state.cverc_enabled_reports = enabled_reports
    app.state.virustotal_daily_budget = int(os.getenv("VIRUSTOTAL_DAILY_BUDGET", "500"))
    app.state.virustotal_quota = PersistentDailyQuota(session_factory, "virustotal", app.state.virustotal_daily_budget)
    virustotal_key = virustotal_api_key if virustotal_api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
    cn_platform_key = cn_platform_api_key if cn_platform_api_key is not None else os.getenv("CN_PLATFORM_API_KEY", "")
    resolved_report_root = (report_root or Path(__file__).resolve().parents[2] / "data" / "reports").resolve()
    app.state.report_root = resolved_report_root
    app.state.experiment_root = (experiment_root or Path(__file__).resolve().parents[2] / 'results' / 'experiment-3').resolve()
    app.state.detection_reports = DetectionReports(detection_root or DEFAULT_RESULTS_ROOT, app.state.experiment_root)
    app.state.dispatcher = QueryDispatcher(
        session_factory,
        VirusTotalProvider(virustotal_key) if virustotal_key else None,
        CnPlatformProvider(cn_platform_key, enabled_reports) if cn_platform_key and enabled_reports else None,
        app.state.cverc_quota,
        ReportStore(resolved_report_root),
        virustotal_quota=app.state.virustotal_quota,
        request_interval=max(16.0, float(os.getenv("VIRUSTOTAL_REQUEST_INTERVAL", "16"))),
        detection_reports=app.state.detection_reports,
    )
    app.include_router(previews_router, prefix="/api/v1")
```

## 前端入口及配置补充

- `frontend/src/features/new-analysis/new-analysis-page.tsx`：`submitBatch`，63–76 行，先预览再创建；浏览器文件选择只计算哈希。
- `frontend/src/api/batches.ts`：`previewBatch`，5–10 行；`createBatch`，12–17 行。
- `frontend/src/api/client.ts`：`apiRequest`，3–10 行，只请求本地后端，不包含 Key。
- `backend/app/api/batches.py`：`create_batch`，62–65 行，保存任务后登记后台处理；导出函数只读取任务和索引。
- `frontend/src/hooks/use-local-data.ts`：`useLocalData`，5–28 行，活跃任务按 5 秒读取本地数据，不重发 VT 查询。
- `backend/start_backend.py`：5–7 行，加载根目录 `.env.local`，单工作进程且绑定回环地址。
- `.env.example` 是空 Key 模板；`.gitignore` 排除真实环境文件、数据库、样本、原始 JSON 和构建缓存，仅保留审核过的报告与汇总。

## 推荐用于正文的 7 处节选

1. 项目 1：输入校验与去重，解释两组数据如何使用统一 SHA-256 标识。
2. 项目 2：官方 API 封装，解释状态区分与错误返回。
3. 项目 4：请求预算预留，解释配额保护和失败计数。
4. 项目 5：429 与重试上限，解释暂停、退避与续跑。
5. 项目 8：规范化与风险规则，解释多引擎结果的汇总口径。
6. 项目 9：固定模板报告，解释字段来源及代表性引擎。
7. 项目 10：原生链接与便携导出，解释报告管理与最终交付。

项目 3、6、7、11、12 可作为附录或结构说明，避免正文堆叠相似代码。
