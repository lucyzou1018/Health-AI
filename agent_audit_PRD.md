# Agent Audit Skill PRD

## 1. 背景
OpenClaw 环境中的 Agent / Skill 持续增多，但缺乏统一的安全与成本体检手段。需要一套可以一键扫描配置、权限、记忆、日志和 token 消耗的工具，并将结果可视化/文本化，方便安全审核、每日巡检和对外同步。

## 2. 目标
1. 30 秒内完成一次体检，输出 JSON + Markdown 报告。
2. 量化 5 大风险（隐私泄露、越权、记忆膨胀、token 成本、失败率），附带证据和修复建议。
3. 支持多种运行形态：OpenClaw Skill、独立脚本、pip 包、Docker 镜像、REST API。
4. 报告与 `agent_audit_dashboard.html` 联动，提供图形化卡片展示。
5. 无敏感信息泄露，可在纯本地环境运行，无需依赖 OpenClaw Runtime。

## 3. 范围
| 模块 | 功能 | 状态 |
| --- | --- | --- |
| 权限扫描 | 解析 `openclaw.json`，列出 agent/skill 工具与高危项 | ✅ |
| 记忆/日志 | 扫描 `memory/*.md`、`logs/*.log`，检测敏感串、统计大小与错误率 | ✅ |
| Token 消耗 | 解析日志中的 `totalTokens` 字样，统计近 7 天调用 | ✅ |
| 风险评分 | 隐私/越权/记忆/token/失败率 0-100 分并解释 | ✅ |
| 修复建议 | 根据分值给出行动项（脱敏/降权/归档/预算守卫/重试） | ✅ |
| 报告输出 | JSON（供前端）+ Markdown（文字汇报） | ✅ |
| 可视化 | Dashboard 读取 JSON，展示卡片与表格 | ✅ |
| 运行形态 | Skill / 脚本 / pip / Docker / REST API | ✅ |
| REST 接口 | `POST /run` 返回 report + markdown | ✅ |

## 4. 风险指标与评分
| 指标 | 数据来源 | 评分逻辑 | 行动建议 |
| --- | --- | --- | --- |
| 隐私泄露 | memory + 日志中的 API Key/私钥/助记词 | 0 命中=5；每命中 +15，封顶 100 | 立即脱敏/迁移 |
| 越权风险 | agent 拥有的高危工具数量 | 每个高危工具增加 20 | 降权、拆分、双重确认 |
| 记忆膨胀 | `memory/` 总体积 | ≤2MB=10，2-5MB=40，>5MB 每 MB +10 | 归档旧文件、替换摘要 |
| Token 成本 | 日志 `totalTokens` 汇总 | 0=10；≤50 万=35；之后每 5 万 +1 | 设预算守卫，换低成本模型 |
| 失败率 | 日志 error/traceback 行占比 | error_rate × 400，封顶 100 | 排查脚本/网络，增加重试 |

等级划分：0-29 安全；30-59 需关注；≥60 高风险。

## 5. 运行形态
| 形态 | 目录 | 启动方式 | 适用场景 |
| --- | --- | --- | --- |
| OpenClaw Skill (`agent-audit`) | `skills/agent-audit/` | 聊天指令触发 | 主 OpenClaw 环境 |
| 独立脚本 | `standalone-agent-audit/agent_audit.py` | `python3 agent_audit.py --config ...` | 本地/离线巡检 |
| pip 包 | `standalone-agent-audit/pip_package/` | `pip install .` → `agent-audit --config ...` | 多台机器快速使用 |
| Docker 镜像 | `standalone-agent-audit/docker/` | `docker build && docker run ...` | 无 Python 环境、CI 执行 |
| REST API | `standalone-agent-audit/rest_api/` | `uvicorn app:app` → `POST /run` | 外部按钮、Webhook 集成 |

## 6. 工作流
1. 运行体检命令（Skill/脚本/CLI/API）。
2. 读取配置、memory、日志，计算指标与建议。
3. 输出 `audit_report.json` + 可选 `audit_report.md`。
4. 如需可视化，`python3 -m http.server 8080` + `agent_audit_dashboard.html` 即可展示。

## 7. 依赖 & 配置
- 读取路径（可通过参数传入）：`openclaw.json`、`memory/`、`logs/`。
- 无第三方 API 调用；纯本地文件分析。
- Docker 需通过 volume 映射所需文件；REST API 需在请求体提供真实路径。

## 8. 非功能需求
| 项目 | 说明 |
| --- | --- |
| 性能 | 默认数据量下 ≤30s 完成一次体检 |
| 安全 | 不上传数据，所有操作在本机完成 |
| 可扩展 | 评分/建议可通过核心函数扩展，REST、CLI、Skill 共享同一逻辑 |

## 9. 当前成果
- Skill：`agent-audit`（JSON + Markdown + dashboard）
- 独立脚本：`standalone-agent-audit/agent_audit.py`
- pip 包：`standalone-agent-audit/pip_package (agent-audit-cli)`
- Docker：`standalone-agent-audit/docker`（入口即脚本）
- REST API：`standalone-agent-audit/rest_api`（FastAPI `/run`）
- 平台化服务：`platform/oneclick_server.py`（FastAPI `/audit`，可对外暴露公网入口）

## 10. 后续可选工作
- 自动化截图或 SVG 生成用于报告中直接嵌图。
- 增加任务队列/cron 集成，周期性运行并推送到 Telegram/邮件。
- 丰富 Token 统计（按模型拆分）与日志来源（兼容 structured logging）。
