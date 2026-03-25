# Health AI

Health AI 是一个 AI Agent 安全审计平台，提供三类扫描能力：

- **Skill Security Audit** — 对 OpenClaw Skill/Agent ZIP 包进行权限、隐私、Token、稳定性全维度扫描，输出量化健康评分 + PDF 报告
- **Contract Audit** — 对 EVM 智能合约（本地文件或链上地址）进行漏洞分析，可选接入 Slither 静态分析
- **Stress Test** — 对任意命令（含 Skill）进行并发压力测试，输出成功率、P95 耗时等指标

---

## 目录结构

```
Health-AI/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI：API 路由 + /ui 静态页面挂载
│   │   ├── task_manager.py    # 任务调度（ThreadPoolExecutor）+ 子进程执行
│   │   └── pdf_generator.py   # Markdown → PDF 报告生成
│   ├── requirements.txt
│   └── storage/               # 运行时产物（上传文件、任务报告）
├── frontend/                  # 纯静态 SPA（无需构建，无外部 CDN 依赖）
│   ├── index.html             # 首页
│   ├── workspace.html         # 工作台（三个扫描功能入口）
│   ├── main.js
│   └── styles.css
├── skills/
│   ├── skill-security-audit/scripts/audit_skill.py
│   ├── multichain-contract-vuln/scripts/run_cli.py
│   └── skill-stress-lab/scripts/stress_runner.py
├── Dockerfile
├── docker-compose.yml
└── start.sh                   # 本地启动脚本
```

---

## 各功能依赖说明

| 功能 | OpenClaw | Python 额外依赖 | 系统工具 |
|------|----------|----------------|----------|
| Skill Security Audit | **必须安装** — 读取 `~/.openclaw/openclaw.json` 配置和 `~/.openclaw/logs/` 日志 | 无（仅标准库 + PyYAML 可选） | 无 |
| Contract Audit | 不需要 | 无（仅标准库） | `slither`（可选，用于深度 EVM 分析）；Anchor（可选，用于 Solana 合约） |
| Stress Test | **间接依赖** — runner 本身无依赖，但压测命令若调用 OpenClaw Skill（如 `openclaw run {skill}`），则需要安装 OpenClaw | 无（仅标准库） | 取决于被压测的命令 |

> **关于 Skill Security Audit 与 OpenClaw 的关系**
>
> `audit_skill.py` 直接读取 `~/.openclaw/openclaw.json`（OpenClaw 全局配置）和
> `~/.openclaw/logs/`（网关运行日志），以评估 Skill 的权限声明、隐私风险和稳定性。
> 若服务器上未安装 OpenClaw，这两个路径不存在，扫描结果中权限和日志分析部分将为空，
> 但 Skill ZIP 包本身（代码结构、文件内容）仍可正常扫描。

---

## 环境要求

- **Python 3.11+**
- **pip**
- （可选）OpenClaw — Skill Security Audit 深度分析所需
- （可选）Slither — Contract Audit EVM 深度分析所需：`pip install slither-analyzer`
- （可选）Foundry — Contract Audit Solana/Anchor 支持所需

---

## 本地部署（推荐）

### 1. 克隆仓库

```bash
git clone <repo-url> Health-AI
cd Health-AI
```

### 2. 安装 Python 依赖

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. 启动服务

```bash
cd ..
./start.sh
```

服务启动后访问：`http://localhost:8000/ui`

> `start.sh` 默认以**稳定模式**启动（不带 `--reload`），适合生产和日常使用。
> 开发调试时使用 `./start.sh --dev`，但注意 `--dev` 模式下文件变动会重启服务，
> **正在运行的扫描任务会被中断**。

### 4. （可选）安装 Slither

若需要 Contract Audit 的 EVM 深度分析能力：

```bash
pip install slither-analyzer
```

---

## Docker 部署

### 直接构建

```bash
docker build -t health-ai .
docker run -p 8000:8000 -v $(pwd)/backend/storage:/app/backend/storage health-ai
```

### 使用 docker-compose

```bash
docker-compose up --build
```

访问 `http://<host>:8000/ui`。

> `backend/storage` 以 volume 形式挂载，重建容器不会丢失历史任务报告。

### Nginx 反向代理（可选）

如需通过域名访问，推荐在 Nginx 中配置代理：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_read_timeout 300;    # 扫描任务可能耗时较长，建议加大超时
    }
}
```

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 服务健康检查 |
| `POST` | `/api/uploads` | 上传 ZIP 文件，返回 `uploadId` |
| `POST` | `/api/tasks` | 创建扫描任务（body 含 `skillType`、`uploadId`、`walletAddress` 等） |
| `GET` | `/api/tasks/{id}` | 查询任务状态（`queued` / `running` / `completed` / `failed`） |
| `GET` | `/api/tasks/{id}/report` | 下载 Markdown 原始报告 |
| `GET` | `/api/tasks/{id}/report/pdf` | 下载 PDF 格式报告 |
| `GET` | `/api/wallet/history` | 查询钱包的历史任务列表 |

前端通过轮询 `/api/tasks/{id}` 自动感知任务完成，无需手动刷新。

---

## 支持的 skillType

| skillType | 说明 |
|-----------|------|
| `skill-security-audit` | Skill / Agent 安全审计 |
| `multichain-contract-vuln` | 智能合约漏洞扫描 |
| `skill-stress-lab` | Skill 压力测试 |

---

## 注意事项

- `backend/storage/` 目录会持续增长（存储每次扫描的上传文件和报告），生产环境建议定期清理或挂载独立存储卷。
- Skill Security Audit 扫描日志时对大文件（> 512 KB）只采样最后 1000 行，以保证扫描性能。
- 同一钱包地址对同一类型任务同时只能运行一个，重复提交会被拒绝（HTTP 409）。
- **不要在生产环境使用 `--reload` 模式**，否则代码变动会重启服务并中断正在运行的扫描任务。
