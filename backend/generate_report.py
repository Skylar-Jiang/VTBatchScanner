"""Generate a concise, evidence-linked report from saved real query results."""
import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


def render_report(groups: dict, inventory: dict, generated_at: str, upload: dict | None = None) -> str:
    complete = all(group['summary']['pending'] == 0 for group in groups.values())
    if upload is not None:
        complete = complete and all(row['status'] == 'success' for row in upload['samples'])
    attempts = sum(group['summary']['apiAttempts'] for group in groups.values())
    lines = ['# 恶意代码实验第三部分：VirusTotal 批量检测', '', f'生成时间：{generated_at}。状态：' + ('全部查询及上传分析完成。' if complete and upload is not None else '全部查询完成。' if complete else '上传分析尚未完成，以下为真实进度快照。' if upload is not None else '尚未完成，以下为真实进度快照。'), '',
             '## 实验环境与方法', '',
             'Windows、Python 3.12、FastAPI/SQLAlchemy/SQLite、React/TypeScript/Vite。样本仅在内存中读取 ZIP 字节，不解压程序到磁盘、不在本机运行。历史流程只计算 SHA256 查询已有报告；用户另行授权后，A 组新增 POST /files 文件上传及 GET /analyses/{id} 获取本次分析，B 组仍只查询已有报告。标准上传属于远端分析，样本进入平台数据集。', '',
             f"所提供压缩包实际有 {inventory['groupA']['leafFiles']} 个可读取文件，本次纳入全部文件（去重后 {inventory['groupA']['uniqueHashes']} 条 SHA256）；另 {len(inventory['groupA']['errors'])} 项读取失败。", '',
             'B 组为老师分配的 100 条有效、唯一 SHA256；两组哈希交集为 0。使用官方 GET /api/v3/files/{sha256} 查询已有报告，解析 last_analysis_stats、last_analysis_results 与 UTC 分析时间。成功报告持久化缓存 7 天；刷新绕过缓存且提示配额消耗，重新分析未启用。', '',
             '## 测试过程', '',
             '先完成 Mock 测试，覆盖正常响应、无效哈希、404、401/403、429、超时、网络异常、缓存、配额、限速、续跑及 CSV/JSON 导出；测试不访问真实平台。通过后验证 2 条真实哈希：2 次请求均成功，再执行完整批次。具体测试验收记录见 docs/verification.md。', '',
             '## 历史哈希查询结果（保留原始实验记录）', '',
             '| 组别 | 唯一哈希 | 成功查询 | 未收录 | 失败 | 等待 | 输入去重 | 请求次数 |',
             '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name, group in groups.items():
        summary = group['summary']
        duplicates = inventory['groupA']['duplicateFiles'] if name == 'A' else inventory['groupB']['duplicates']
        lines.append(f"| {name} | {summary['total']} | {summary['successful']} | {summary['notFound']} | {summary['failed']} | {summary['pending']} | {duplicates} | {summary['apiAttempts']} |")
    lines += ['', f'历史哈希查询实际 API 请求：{attempts} 次（包含失败和重试）；国家平台请求：0 次。', '',
              '| 组别 | 恶意 | 可疑 | 未检出 | 成功报告但风险未知 | 恶意引擎命中累计 / 引擎统计累计 |',
              '|---|---:|---:|---:|---:|---|']
    for name, group in groups.items():
        reports = [row['report'] for row in group['samples'] if row['queryStatus'] == 'success' and row.get('report')]
        counts = Counter(report['risk'] for report in reports)
        malicious = sum(report['stats'].get('malicious',0) for report in reports)
        total = sum(report['totalEngines'] for report in reports)
        lines.append(f"| {name} | {counts['malicious']} | {counts['suspicious']} | {counts['undetected']} | {counts['unknown']} | {malicious} / {total} |")
    lines += ['', '上述风险分布仅统计成功报告；引擎累计数用于描述报告，不视为样本个数或独立重复实验。未检出不是安全证明，未收录、失败、等待不计入未检出。']
    if upload is not None:
        states=Counter(row['status'] for row in upload['samples'])
        risks=Counter(row['report']['risk'] for row in upload['samples'] if row['status']=='success' and row.get('report'))
        lines += ['', '## A 组文件上传分析（独立于历史哈希查询）', '',
                  f"唯一文件哈希 {len(upload['samples'])} 条；本次上传分析完成 {states['success']} 条，待上传 {states['pending']} 条，已提交/分析中 {sum(states[key] for key in ('accepted','queued','in-progress'))} 条；其他未完成状态 {sum(value for key,value in states.items() if key not in ('success','pending','accepted','queued','in-progress'))} 条。", '',
                  f"本次分析风险：恶意 {risks['malicious']}、可疑 {risks['suspicious']}、未检出 {risks['undetected']}、未知 {risks['unknown']}。只统计本次 completed 分析，不用已有哈希报告补齐。", '',
                  f"新增上传流程请求：{upload['apiRequests']} 次；含历史查询累计请求：{attempts+upload['apiRequests']} 次。原始本次分析、上传回执 ID、每条上传/查询次数和状态保存在 group-a-upload-results.json，表格导出为 group-a-upload-results.csv。", '',
                  '上传流程先用 Mock 验证，再用 1 个文件完成 POST 上传和 GET 分析共 2 次真实验证，随后执行其余唯一文件。每个文件只提交 1 次，分析轮询最多 3 次；提交结果不明确时停止，不自动重复上传。']
    lines += ['',
              '## 异常与结论', '',
              '1 个嵌套加密条目使用给定密码 virus 读取失败，已记录路径及错误，不猜测密码、不计为查询成功。401/403 或持续 429 会停止后续请求；本地预算不足时保留等待任务。每个查询任务最多尝试 2 次，至少 16 秒间隔，429 遵循 Retry-After 或退避。', '',
              ('已完成所列流程，结果以保存的原始 JSON 为依据；本机没有运行样本。历史查询与新增上传分析分别统计。' if complete else '当前仍有未完成任务，不作最终检测结论；待完成或确认配额阻塞后重新生成报告。'), '',
              '## 结果文件与截图', '',
              'group-a-results.csv/json、group-b-results.csv/json：逐哈希结果；group-a-files.csv：逐文件映射；input-inventory.json：静态清点和读取错误；execution-summary.json：完成情况；batch-ids.json：续跑批次。原始响应位于 data/reports/virustotal。', '',
              '历史查询截图：../../output/playwright/dashboard.png、batches.png、sample-detail.png。新增分组页面及上传分析截图：../../output/playwright/group-a-upload-final.png、group-b-hash-results.png、group-a-analysis-detail.png、group-a-mobile-detail.png。上传未完成时以 group-a-upload-progress.png 为进度快照；截图不能替代结果文件。', '',
              '## 官方依据', '',
              '- [文件哈希报告接口](https://docs.virustotal.com/reference/file-info)',
              '- [File 对象字段](https://docs.virustotal.com/reference/files)',
              '- [公共 API 配额](https://docs.virustotal.com/reference/public-vs-premium-api)',
              '- [上传文件](https://docs.virustotal.com/reference/files-scan)',
              '- [读取本次分析](https://docs.virustotal.com/reference/analysis)', '',
              '## Material Passport', '',
              'Origin Skill: academic-research-suite / experiment-agent；Mode: run-record；Verification Status: 原始报告已保存，未重复查询以避免额外配额；Version: experiment-3-v1。统计为描述性，不作因果推断。']
    return '\n'.join(lines) + '\n'


def main():
    import csv
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'results'/'experiment-3')
    args = parser.parse_args()
    output = args.output.resolve()
    inventory = json.loads((output/'input-inventory.json').read_text(encoding='utf-8'))
    groups = {name:json.loads((output/f'group-{name.lower()}-results.json').read_text(encoding='utf-8')) for name in ('A','B')}
    by_hash = {row['sha256']:row for row in groups['A']['samples']}
    with (output/'group-a-files.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['archivePath','size','sha256','queryStatus','risk','malicious','totalEngines'])
        for file in inventory['groupA']['files']:
            row = by_hash[file['sha256']]
            report = row.get('report') or {}
            writer.writerow([file['path'],file['size'],file['sha256'],row['queryStatus'],row['risk'],report.get('stats',{}).get('malicious'),report.get('totalEngines')])
    upload_path=output/'group-a-upload-results.json'
    upload=json.loads(upload_path.read_text(encoding='utf-8')) if upload_path.exists() else None
    (output/'实验报告.md').write_text(render_report(groups,inventory,datetime.now(UTC).isoformat(),upload),encoding='utf-8')
    print('Generated report and file-level mapping; no API requests sent')


if __name__ == '__main__':
    main()
