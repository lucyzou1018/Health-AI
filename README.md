# Health AI

Health AI = Agent Audit + Multichain Contract Scanner + Skill Stress Lab 的 Web 门面。它基于 `yingjingyang/AIagentEraDemo` 的三类技能，现已具备：

- 🔐 调用 `skills/agent-audit/scripts/audit_scan.py` 的权限体检
- 🛡️ 调用 `skills/multichain-contract-vuln/scripts/run_cli.py` 的合约漏洞扫描
- 🚀 调用 `skills/skill-stress-lab/scripts/stress_runner.py` 的压力测试（支持命令模板 + metrics）
- 🧵 后台线程池异步执行任务 + 状态轮询 API + 日志/报告下载
- 🐳 Docker 镜像 + `docker-compose` 快速部署（同时暴露 `/ui` 静态页面和 `/api/*`）

## 目录结构
```
Health-AI/
├─ backend/
│  ├─ app/
│  │  ├─ main.py            # FastAPI：API + /ui 静态挂载
│  │  └─ task_manager.py    # 任务调度（ThreadPoolExecutor）+ 子进程脚本
│  ├─ requirements.txt
│  └─ storage/              # 上传/任务产物（volume）
├─ frontend/                # 纯静态 SPA（导航 + 轮询 + 下载按钮）
├─ Dockerfile               # 构建 uvicorn + FastAPI 容器
├─ docker-compose.yml       # 一条命令本地运行
└─ skills/                  # agent-audit / multichain-contract-vuln / skill-stress-lab
```

## 本地开发
1. **后端**
   ```bash
   cd backend
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
2. **前端**（开发时可用本地静态服务器，不想单独起可直接访问 `/ui`）
   ```bash
   cd ../frontend
   python3 -m http.server 4173
   ```
   浏览器访问 `http://127.0.0.1:4173`（或 `http://127.0.0.1:8000/ui`）。

## API & UI 提示
- `POST /api/uploads`：上传文件，返回 `uploadId`。
- `POST /api/tasks`：提交任务（body 含 `skillType`、`codePath`/`uploadId`、`params`）。
- `GET /api/tasks/{id}`：查询状态（前端自动轮询，直到 completed/failed）。
- `GET /api/tasks/{id}/report`：下载主报告。
- `GET /api/tasks/{id}/artifact?kind=summary|log`：下载摘要或日志。
- 前端 UI：
  - Contract Tab 提供 EVM 地址/链别/Anchor 选项。
  - Stress Tab 需要命令模板（可用 `{skill}` 占位符）并可设置 runs/concurrency/collectMetrics。
  - 任务发起后自动轮询并显示“下载报告/摘要/日志”按钮。

## Docker / 部署
```bash
# 构建镜像
docker build -t health-ai .

# 或使用 docker-compose（映射 8000 端口 + storage 卷）
docker-compose up --build
```
访问 `http://<host>:8000/ui` 使用 Web UI，或 `http://<host>:8000/api/health` 查看服务状态。
> 默认将 `backend/storage` 作为 volume，可保留上传文件与报告。如需自定义持久化路径，可修改 compose 文件或挂载其他目录。

## 后续可扩展
- 接入更多 skill，只需在 `TaskManager` 中新增分支 + Web 表单字段。
- 将线程池替换为 Celery/Redis 队列，实现水平扩展/重试。
- 在 `Dockerfile` 中预装 slither/anchor 等分析依赖，或在 compose 内添加独立 worker。

欢迎 issue/PR，或继续指示我实现更多功能。EOF