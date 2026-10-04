# 报告入口设计与验收

本次保留现有深色布局、表格和 shadcn/Radix 组件，仅补充报告操作。

信息顺序：样本标识与状态 → 刷新等操作 → 检测报告入口 → 报告字段与引擎结果。

组件关系：`SampleDetailPage → Button(asChild) → a`；`ExperimentGroup → 表格操作 / 详情工具栏`；`BatchesPage → CSV / JSON / XLSX / 报告包`。链接读取本地已保存结果，不派发 VirusTotal 请求。

重点验收：长文件名换行；手机端工具栏不撑开页面；暂无报告时不能点击；报告写入失败可见；刷新仍须确认且重新分析保持独立。具体测试结果和截图见 README。
