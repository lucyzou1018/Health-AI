# Health AI

Health AI = Agent Audit + Multichain Contract Scanner + Skill Stress Lab 的 Web 门面。它基于 `yingjingyang/AIagentEraDemo` 的三类技能，提供：

- 🔐 Agent/Skill 权限体检（agent-audit）
- 🛡️ 多链合约漏洞扫描（multichain-contract-vuln）
- 🚀 Skill 压力测试（skill-stress-lab）

当前版本包含一个 FastAPI 后端（任务/上传 API）和一个极简 Web 前端（导航 + 上传 + 任务触发），方便后续持续集成真实脚本与报告展示。

## 目录结构
```
Health-AI/
├─ backend/                 # FastAPI + 任务管理
│  ├─ app/
│  │  ├─ main.py            # API 入口 (/api/uploads, /api/tasks,...)
│  │  └─ task_manager.py    # 任务创建/代码入库/报告占位
│  ├─ requirements.txt
│  └─ storage/              # 上传文件 & 任务产物
├─ frontend/                # 原型级静态页面
│  ├─ index.html
│  ├─ main.js
│  └─ styles.css
├─ skills/                  # 继承自 AIagentEraDemo 的三个技能
└─ ...                      # 其他文档/报告
```

## 快速开始
1. **安装依赖**
   ```bash
   cd backend
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **启动 API**
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
3. **打开前端（静态）**
   ```bash
   cd ../frontend
   python3 -m http.server 4173
   ```
   浏览器访问 `http://127.0.0.1:4173`，即可看到包含三个导航 Tab 的 Health AI 控制台。
4. **配置 API 地址（可选）**
   - 默认前端会调用 `http://127.0.0.1:8000`。
   - 若部署到其他域名，可在 `index.html` 之前通过 `window.HEALTH_AI_API = 'https://your-api';` 注入。

## API 摘要
- `POST /api/uploads`：上传 skill/合约压缩包，返回 `uploadId`。
- `POST /api/tasks`：提交任务（需提供 `skillType` + `codePath` 或 `uploadId`）。
- `GET /api/tasks/{taskId}`：查询任务状态/报告路径。
- `GET /api/tasks/{taskId}/report`：下载 Markdown 报告（当前为占位内容，可替换为真实结果）。

`backend/app/task_manager.py` 中的 `_mock_*` 函数用于生成占位报告。替换为真实命令即可接入：
- `agent-audit`: 调 `skills/agent-audit/scripts/audit_scan.py` 输出 JSON/Markdown。
- `multichain-contract-vuln`: 调 `skills/multichain-contract-vuln/scripts/run_cli.py`。
- `skill-stress-lab`: 调 `skills/skill-stress-lab/scripts/stress_runner.py`。

## 后续路线
- ✅ 提供统一上传 + 任务 API & Web 导航原型。
- ⏳ 接入真实脚本输出（report/summary/log）。
- ⏳ Web 端支持任务进度轮询、Markdown 渲染、结果下载。
- ⏳ Docker 化部署（frontend + backend + worker）。

欢迎在 `issues/PR` 中继续扩展。EOF