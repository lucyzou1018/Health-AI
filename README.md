# Health AI

Health AI 是一个 AI Agent 安全审计平台，提供三类扫描能力：

- **Skill Security Audit** — 对 OpenClaw Skill/Agent ZIP 包进行 38 项逐条安全检查，覆盖权限、隐私、混淆、高危工具、日志卫生、配置与 Manifest 等维度，输出量化健康评分（6 维 0–100 分）+ 专业 PDF 报告
- **Contract Audit** — 对 EVM 智能合约（本地文件或链上地址）进行漏洞分析，可选接入 Slither 静态分析
- **Stress Test** — 对任意命令（含 Skill）进行并发压力测试，输出成功率、P95 耗时等指标

---

## 目录结构

```
Health-AI/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI：API 路由 + 钱包认证 + /ui 静态页面挂载
│   │   ├── task_manager.py    # 任务调度（ThreadPoolExecutor）+ 子进程执行
│   │   └── pdf_generator.py   # Markdown → PDF 报告生成
│   ├── requirements.txt
│   └── storage/               # 运行时产物（上传文件、任务报告）
├── frontend/
│   ├── index.html             # 首页
│   ├── workspace.html         # 工作台（三个扫描功能入口）
│   ├── report.html            # 报告查看器（含 6 维评分卡片）
│   ├── main.js                # 前端核心逻辑
│   └── styles.css             # 样式
├── skills/
│   ├── skill-security-audit/  # Skill 安全审计（38 项检查清单）
│   ├── multichain-contract-vuln/  # 智能合约漏洞扫描
│   ├── skill-stress-lab/      # 压力测试
│   └── agent-audit/           # Agent 审计（基础版）
├── Dockerfile
├── docker-compose.yml
└── start.sh                   # 本地启动脚本
```

---

## 各功能依赖说明

| 功能 | Python 额外依赖 | 系统工具 |
|------|----------------|----------|
| Skill Security Audit | PyYAML（可选） | 无 |
| Contract Audit | 无（仅标准库） | `slither`（可选，EVM 深度分析）；Anchor（可选，Solana 合约） |
| Stress Test | 无（仅标准库） | 取决于被压测的命令 |

---

## 环境要求

- **Python 3.11+**
- **pip**
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
> 开发调试时使用 `./start.sh --dev`，但 `--dev` 模式下文件变动会重启服务，
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

### 通用

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 服务健康检查，返回 `{"status": "ok"}` |

### 文件上传

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/uploads` | 上传 ZIP 文件（最大 50 MB），返回 `{"uploadId": "...", "filename": "..."}` |

### 任务管理

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/tasks` | 创建扫描任务（body 含 `skillType`、`uploadId`、`walletAddress` 等） |
| `GET` | `/api/tasks/{id}` | 查询任务状态：`pending` / `queued` / `running` / `completed` / `failed` |
| `GET` | `/api/tasks/{id}/report` | 下载 Markdown 原始报告 |
| `GET` | `/api/tasks/{id}/report/pdf` | 按需生成并下载 PDF 格式报告 |

### 钱包认证

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/wallet/nonce` | 获取签名用 nonce（参数：`wallet_address`） |
| `POST` | `/api/wallet/verify` | 验证 EIP-191 签名，返回 session token（有效期 7 天） |
| `GET` | `/api/wallet/me` | 获取当前登录钱包信息（需 `X-Wallet-Token` 头） |
| `GET` | `/api/wallet/history` | 查询钱包的历史任务列表（需 `X-Wallet-Token` 头） |

**钱包认证流程：**

```
1. GET /api/wallet/nonce?wallet_address=0x...   → 获取待签名消息
2. 用户钱包对消息签名（MetaMask 等）
3. POST /api/wallet/verify { walletAddress, signature, message }  → 返回 token
4. 后续请求携带 Header: X-Wallet-Token: <token>
```

前端通过轮询 `/api/tasks/{id}` 自动感知任务完成，无需手动刷新。

---

## 支持的 skillType

| skillType | 说明 |
|-----------|------|
| `skill-security-audit` | Skill / Agent 安全审计（38 项检查清单） |
| `multichain-contract-vuln` | 智能合约漏洞扫描（EVM / Solana） |
| `skill-stress-lab` | Skill 并发压力测试 |

---

## Skill Security Audit 评分维度

报告页面展示 6 个维度的 0–100 分（越高越安全）：

| 维度 | 说明 |
|------|------|
| 🏆 Overall Security | 综合安全评分（加权汇总） |
| 🔏 Privacy | 隐私风险（PII 处理、数据外传等） |
| 🔐 Privilege | 权限风险（声明权限过广、OS 命令执行等） |
| 💾 Memory Footprint | 内存安全（大文件加载、无界缓存等） |
| 🪙 Token Cost | Token 消耗（Prompt 膨胀、无限循环等） |
| ✅ Stability | 稳定性（异常处理、超时保护、重试机制等） |

评级标准：`80–100 = 🟢 Excellent` · `60–79 = 🟡 Good` · `40–59 = 🟠 Fair` · `<40 = 🔴 Needs Improvement`

检查清单包含 7 大分类共 38 项：

- **Critical**（9 项）：硬编码 Secret、明文凭证、代码注入、任意命令执行等
- **Obfuscation**（3 项）：Base64 编码指令、动态 exec/eval、混淆变量名
- **High-Risk Tools**（7 项）：文件系统写入、网络请求、子进程、OS 命令等
- **Sensitive Data Source**（7 项）：PII 关键词、私钥操作、数据库访问等
- **Log Hygiene**（4 项）：日志中的 Token、密码、SSN、信用卡号
- **Config / Env**（3 项）：环境变量文件、.env 读取、配置文件访问
- **Manifest**（5 项）：SKILL.md 存在性、描述完整性、权限声明一致性

---

## 安全与并发设计

本项目后端针对多用户并发场景做了以下加固：

| 问题 | 解决方案 |
|------|----------|
| 钱包 session 并发读写 | `threading.Lock`（`_sessions_lock`）保护 `wallet_sessions` dict |
| session 过期时的 KeyError | `dict.pop(token, None)` 替代 `del`，无锁竞争 |
| 同一 PDF 并发重复生成 | 每个 task 独立 Lock（`_get_pdf_lock`）+ mtime 新鲜度检查 |
| 上传文件阻塞事件循环 | `upload_file` 改为 `def`（FastAPI 自动调度至线程池），使用 `file.file.read()` |
| 上传文件无大小限制 | 50 MB 硬限制（`MAX_UPLOAD_BYTES`），超限返回 HTTP 413 |
| `_save_index` 持锁写磁盘 | 锁内序列化（`_build_index_payload`）+ 锁外写文件（`_flush_index`） |
| `get_tasks_by_wallet` 持锁排序 | 锁内仅快照数据，锁外执行 sort/filter |
| session 字典无界增长 | 超过 1000 条时驱逐最旧 session（`MAX_WALLET_SESSIONS`） |

---

## 注意事项

- `backend/storage/` 目录会持续增长（存储每次扫描的上传文件和报告），生产环境建议定期清理或挂载独立存储卷。
- Skill Security Audit 扫描日志时对大文件（> 512 KB）只采样最后 1000 行，以保证扫描性能。
- 同一钱包地址对同一类型任务同时只能运行一个，重复提交会被拒绝（HTTP 409）。
- 每个扫描任务最长执行 600 秒（10 分钟），超时后自动标记为 `failed`。
- 服务重启时，处于 `running` / `queued` 状态超过 30 秒的孤儿任务会被自动标记为 `failed`。
- **不要在生产环境使用 `--reload` 模式**，否则代码变动会重启服务并中断正在运行的扫描任务。
