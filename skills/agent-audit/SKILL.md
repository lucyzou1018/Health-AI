---
name: agent-audit
description: Run the Agent Audit health-check for OpenClaw workspaces—scan agent/skill 权限、memory、日志与 token 消耗并输出风险评分 + 修复建议。触发：用户要求体检/审计/刷新 dashboard 数据，或排查越权、隐私、成本异常时。
---

# Agent Audit Skill

## 概览
- 作用：一键调用 `scripts/audit_scan.py`，分析 OpenClaw 配置、skills、memory、日志、token，并生成 JSON + Markdown 报告以及自动化建议。
- 何时使用：发布前的安全体检、定期巡检、用户提到“权限/日志/记忆/token 消耗”异常、需要刷新 `agent_audit_dashboard.html`。
- 交付：文字总结（5 项分值 + 证据 + 建议），必要时附上 `audit_report.json`/`audit_report.md` 或 dashboard 截图。

## 快速开始
1. `cd ~/.openclaw/workspace`
2. 运行：`python3 audit_scan.py --markdown audit_report.md`
   - 该入口会委托到本 Skill 的 `scripts/audit_scan.py`，生成 `audit_report.json` 与 Markdown。
3. 如需前端展示：`python3 -m http.server 8080` → `http://127.0.0.1:8080/agent_audit_dashboard.html` → 点击「一键体检」。
4. 汇报时概括五大风险分、关键证据、修复建议，并告知是否有附件/截图。

## 工作流
### 1. 执行扫描脚本
- **命令**：
  ```bash
  cd ~/.openclaw/workspace
  python3 audit_scan.py --markdown audit_report.md
  # 或直接运行 Skill 脚本
  python3 skills/agent-audit/scripts/audit_scan.py --output audit_report.json --markdown audit_report.md
  ```
- **脚本行为**：
  - 读取 `~/.openclaw/openclaw.json` 内的 agent/skill 权限
  - 扫描 `workspace/memory/*.md`（敏感信息 + 文件大小）
  - 遍历 `~/.openclaw/logs/*.log`（错误率 + tokenUsage）
  - 生成建议列表
- **输出**：
  - `audit_report.json`（供前端 & 程序读取）
  - `audit_report.md`（直接贴在回复里的 Markdown）

### 2. 提炼 & 汇报
- 必报要素：
  1. 五个风险分（隐私、越权、记忆、token、失败率）及对应等级
  2. 关键证据（命中文件、拥有高危工具的 agent 等）
  3. 自动生成的 `suggestions`
- 根据风险等级排序（高风险 → 需关注 → 正常）。
- 若用户需要解释分数含义或阈值，加载 `references/risk-model.md`。

### 3. （可选）刷新 Dashboard
- `python3 -m http.server 8080`
- 浏览器访问 `http://127.0.0.1:8080/agent_audit_dashboard.html` 并点击按钮重新 fetch JSON。
- 结束后 `Ctrl+C` 停止静态服，避免端口被占。

## 风险指标速查
- **隐私泄露**：memory/日志中命中的 API Key、私钥、助记词次数；≥60 说明有高危泄漏，先清理再复检。
- **越权风险**：agent 是否有 `exec`、`browser`、`cron`、`message`、`nodes`、`canvas`、`gateway` 等高危工具；≥60 要求拆分或加双重确认。
- **记忆膨胀**：`memory/` 总体积；超过 5MB 即进入黄色/红色区。
- **Token 成本**：最近日志解析到的 tokenUsage 汇总；若日志未记录则为 0。
- **失败率**：日志中包含 error/traceback/failed 的行占比，提示是否需要重试/修复脚本。
- 完整模型、阈值、建议映射见 [references/risk-model.md](references/risk-model.md)。

## 故障排查
- `openclaw.json` 不存在或读不到：先确认 OpenClaw 已初始化、文件可读。
- tokenUsage 始终为 0：多半是日志里没有模型 + token 字段，属于正常情况，可在报告中说明。
- Dashboard 不刷新：确保已重新运行扫描脚本，再刷新浏览器（或清 cache）。
- 风险分长期偏高：说明真实存在越权/泄漏/大日志，协助用户修复或给出行动项。

## 资源
- `scripts/audit_scan.py`：主扫描脚本，可直接运行或通过 `audit_scan.py` 包装器调用。
- `references/risk-model.md`：风险分区、阈值、建议映射，解释分值时加载。
