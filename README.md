# Health AI

Health AI = Agent Audit + Multichain Contract Scanner + Skill Stress Lab 的 Web 门面。它基于 `yingjingyang/AIagentEraDemo` 的三类技能，现已提供：

- 🔐 Agent/Skill 权限体检（调用 `skills/agent-audit/scripts/audit_scan.py`）
- 🛡️ 多链合约漏洞扫描（调用 `skills/multichain-contract-vuln/scripts/run_cli.py`）
- 🚀 Skill 压力测试（调用 `skills/skill-stress-lab/scripts/stress_runner.py`，可传入命令模板）

## 目录结构
```
Health-AI/
├─ backend/
│  ├─ app/
│  │  ├─ main.py            # FastAPI：/api/uploads、/api/tasks、/api/tasks/{id}
│  │  └─ task_manager.py    # 任务调度 + 三大技能的子进程执行
│  ├─ requirements.txt
│  └─ storage/              # 上传文件 + 任务产物（report/summary/log）
├─ frontend/
│  ├─ index.html            # 三个 Tab + 表单
│  ├─ main.js               # 调用 API，支持上传/路径/参数
│  └─ styles.css
├─ skills/                  # agent-audit / multichain-contract-vuln / skill-stress-lab
└─ ...
```

## 快速开始
1. **启动后端**
   ```bash
   cd backend
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload --port 8000
   ```
2. **启动前端（静态）**
   ```bash
   cd ../frontend
   python3 -m http.server 4173
   ```
   浏览器访问 `http://127.0.0.1:4173`，三个 Tab 均可上传或填写路径并触发任务。

## API 摘要
- `POST /api/uploads`：上传 skill 压缩包/文件，返回 `uploadId`。
- `POST /api/tasks`：提交任务（body 含 `skillType`、`codePath` 或 `uploadId`、可选 params）。
- `GET /api/tasks/{taskId}`：查询状态 + 报告、日志路径。
- `GET /api/tasks/{taskId}/report`：下载主报告（Markdown）。

### params 约定
| skillType | 支持的 params | 说明 |
| --- | --- | --- |
| `agent-audit` | `skillPath`（自动来自上传/路径） | 会调用 `audit_scan.py --skill-path <dir>`，输出 JSON + Markdown |
| `multichain-contract-vuln` | `evmAddress`, `network`, `chain`, `scope`, `runAnchor`, `etherscanApiKey` | 若未填 `evmAddress` 则默认扫描上传/路径下代码 |
| `skill-stress-lab` | `command`（必填），`workdir`, `runs`, `concurrency`, `collectMetrics`, `openaiUsageFile`, `apiCountFile`, `skillDir` | 调用 `stress_runner.py`，并写入 summary/metrics/logs |

## 前端交互
- 顶部导航切换：Agent Audit / Contract Scanner / Skill Stress Lab。
- 输入方式：
  - 直接填写 skill 代码路径（位于服务器可访问位置）。
  - 上传 zip/tar/file（后端自动解压至临时目录）。
- Stress Lab Tab 需填写命令模板（例如 `python3 skills/skill-stress-lab/tests/helpers/run_http_load.py --url https://...`），系统会带上 runs、concurrency、log-dir 等参数。

## 部署建议
- 可将 `backend` 打包成 Docker 镜像（uvicorn 服务），挂载 `/backend/storage` 以持久化报告。
- `frontend` 为纯静态资源，可托管至任意静态服务器，或并入同一 Nginx。
- 如需长耗时异步处理，可在 `task_manager.create_task` 中改用后台队列（Celery/Redis），前端通过 `GET /api/tasks/{id}` 轮询进度。

欢迎在 `issues/PR` 中提出更多需求或扩展点。EOF