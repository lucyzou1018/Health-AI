# Health AI

Health AI 是一个 AI Agent 安全审计平台，提供三类扫描能力：

- **Skill Security Audit** — 对 OpenClaw Skill/Agent ZIP 包进行多维安全检查，覆盖权限、隐私、混淆、高危工具、副作用、数据访问、调用深度、日志卫生、配置与 Manifest 等维度，**强制执行 AI 代码审查**，输出量化健康评分（5 维 0–100 分）+ 专业 PDF 报告
- **Contract Audit** — 对 EVM 智能合约（本地文件或链上地址）进行漏洞分析，基于 AI 大模型进行多维度安全评分
- **Stress Test** — 对任意命令（含 Skill）进行并发压力测试，输出成功率、P95 耗时等指标

---

## 目录结构

```
Health-AI/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI：API 路由 + 钱包认证 + 静态页面挂载
│   │   ├── task_manager.py    # 任务调度（ThreadPoolExecutor）+ 子进程执行
│   │   └── pdf_generator.py   # Markdown → PDF 报告生成
│   ├── requirements.txt
│   └── storage/               # 运行时产物（上传文件、任务报告）
├── frontend/
│   ├── index.html             # 首页
│   ├── workspace.html         # 工作台（三个扫描功能入口）
│   ├── report.html            # 报告查看器（含 5 维评分卡片）
│   ├── main.js                # 前端核心逻辑
│   └── styles.css             # 样式
├── skills/
│   ├── skill-security-audit/  # Skill 安全审计
│   ├── multichain-contract-vuln/  # 智能合约漏洞扫描
│   ├── skill-stress-lab/      # 压力测试
│   └── agent-audit/           # Agent 审计（基础版）
├── Dockerfile
├── docker-compose.yml
└── start.sh                   # 本地启动脚本
```

---

## 环境要求

- **Python 3.11+**
- **pip**

---

## 各功能依赖说明

| 功能 | Python 额外依赖 | 系统工具 |
|------|----------------|----------|
| Skill Security Audit（静态分析） | `PyYAML`（可选） | 无 |
| Skill Security Audit（AI 代码审查） | `openai>=1.0`（已含于 `requirements.txt`） | 需配置 API Key，见下方说明 |
| Contract Audit | 无（仅标准库） | 无 |
| Stress Test | 无（仅标准库） | 取决于被压测的命令 |

所有依赖（含 AI 代码审查所需的 `openai`）均已写入 `backend/requirements.txt`，执行 `pip install -r requirements.txt` 即可一次性安装完毕，无需额外操作。

---

## 环境变量配置

Skill Security Audit 包含**强制 AI 代码审查**，启动前需配置以下环境变量。

### AI 代码审查（必须配置其中一项）

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `OPENAI_API_KEY` | OpenAI API Key | `sk-...` |
| `XAI_API_KEY` | xAI（Grok）API Key | `xai-...` |
| `SKILL_AUDIT_AI_MODEL` | 使用的模型名称（默认 `gpt-4o-mini`） | `gpt-4o-mini` / `grok-3-mini` |
| `SKILL_AUDIT_AI_DETAIL` | AI 详细报告开关（默认关闭） | `true` / `false` |

### 每日任务配额（可选）

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `DAILY_TASK_LIMIT_ENABLED` | 每日任务配额开关（默认开启） | `true` / `false` |

> **说明：**
> - 开启后，同一设备每 UTC 自然日（00:00–23:59 UTC）最多提交 **3 个任务**（三种任务类型合计）。
> - 次日 UTC 00:00 自动重置为 3 次。
> - 设备识别基于**硬件指纹**（物理屏幕分辨率、CPU 核心数、内存大小、Canvas GPU 渲染特征、WebGL GPU 型号），仅使用用户无法通过软件修改的属性，修改时区/浏览器语言/UserAgent 不会影响识别结果。
> - 配额校验**仅在后端 `POST /api/tasks` 内执行**，不暴露任何配额查询接口，无法通过直接调用接口绕过。超限时后端返回 `HTTP 429`，前端展示友好提示。

> **说明：**
> - 优先使用 `OPENAI_API_KEY`，若未设置则自动切换到 `XAI_API_KEY`（xAI Grok，base_url 为 `https://api.x.ai/v1`）。
> - 若两者均未配置，AI 审查模块会跳过并在报告中标注"不可用"，静态分析结果仍然有效。
> - `SKILL_AUDIT_AI_MODEL` 未设置时默认使用 `gpt-4o-mini`（OpenAI）或 `grok-3-mini`（xAI）。
> - `SKILL_AUDIT_AI_DETAIL=true` 时，报告中会额外展示各维度风险分和 LLM 输出的具体风险项（findings）；默认关闭，仅显示"⚠️ Risk Detected"。

### 配置方式

**方式一：导出环境变量（推荐）**

```bash
# 使用 OpenAI
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxx"
export SKILL_AUDIT_AI_MODEL="gpt-4o-mini"

# 或使用 xAI (Grok)
export XAI_API_KEY="xai-xxxxxxxxxxxxxxxx"
export SKILL_AUDIT_AI_MODEL="grok-3-mini"
```

**方式二：写入 `.env` 文件（在 `backend/` 目录下）**

```bash
# backend/.env
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
SKILL_AUDIT_AI_MODEL=gpt-4o-mini
```

然后在启动前加载：

```bash
set -a && source backend/.env && set +a
./start.sh
```

**方式三：systemd 服务（EC2 / Linux 服务器）**

```ini
# /etc/systemd/system/health-ai.service
[Unit]
Description=Health AI Backend

[Service]
WorkingDirectory=/home/ec2-user/Health-AI/backend
ExecStart=/home/ec2-user/Health-AI/backend/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Environment=OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
Environment=SKILL_AUDIT_AI_MODEL=gpt-4o-mini
Restart=always

[Install]
WantedBy=multi-user.target
```

> **关键说明：**
> - `WorkingDirectory` 必须指向 `backend/` 目录，`app.main` 才能被正确解析。
> - `ExecStart` 必须使用 venv 内的 uvicorn（`backend/.venv/bin/uvicorn`），而非系统全局路径。
> - 如果部署路径不是 `/home/ec2-user/Health-AI`，请将两处路径统一替换为实际路径。

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
pip install -r requirements.txt    # 含 AI 代码审查所需的 openai 包
cd ..                              # 回到项目根目录
```

### 3. 配置环境变量

```bash
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxx"     # 或 XAI_API_KEY
export SKILL_AUDIT_AI_MODEL="gpt-4o-mini"
```

> 注意：`export` 仅对当前 shell 会话有效，**服务器重启后需重新设置**。
> 若需持久化，请使用下方方式二（`.env` 文件）或方式三（systemd 服务）。

### 4. 启动服务

```bash
./start.sh
```

服务启动后访问：`http://localhost:8000`

> `start.sh` 默认以**稳定模式**启动（不带 `--reload`），适合生产和日常使用。
> 开发调试时使用 `./start.sh --dev`，但 `--dev` 模式下文件变动会重启服务，
> **正在运行的扫描任务会被中断**。


---

## Docker 部署

### 直接构建

```bash
docker build -t health-ai .
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx \
  -e SKILL_AUDIT_AI_MODEL=gpt-4o-mini \
  -v $(pwd)/backend/storage:/app/backend/storage \
  health-ai
```

### 使用 docker-compose

在 `docker-compose.yml` 中添加环境变量：

```yaml
services:
  health-ai:
    build: .
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
      - SKILL_AUDIT_AI_MODEL=gpt-4o-mini
    volumes:
      - ./backend/storage:/app/backend/storage
```

然后启动：

```bash
docker-compose up --build
```

访问 `http://<host>:8000`。

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
| `skill-security-audit` | Skill / Agent 安全审计 |
| `multichain-contract-vuln` | 智能合约漏洞扫描（EVM / Solana） |
| `skill-stress-lab` | Skill 并发压力测试 |

---

## Skill Security Audit 评分维度

报告页面展示 5 个维度的 0–100 分（越高越安全），Overall 为 5 维平均值：

| 维度 | 说明 | 主要扣分来源 |
|------|------|-------------|
| 🏆 Overall | 综合安全评分（5 维平均） | — |
| 🔏 Privacy | 隐私风险 | 凭证外泄、日志敏感数据、敏感路径/文件读取、敏感 env 读取 |
| 🔐 Privilege | 权限风险 | 写 SOUL.md / openclaw.json、文件写入、env 修改、网络 POST/PUT、DB 写操作 |
| 🛡️ Integrity | 代码可信度 | 混淆代码、硬编码密钥、动态 eval/exec、深调用链 |
| 🔗 Dependency Risk | 依赖风险 | 动态 pip/npm 安装、高危工具权限、CLI 二进制依赖 |
| ✅ Stability | 稳定性 | SKILL.md 缺失、name/version/description 字段缺失 |

评级标准：`80–100 = 🟢 Excellent` · `60–79 = 🟡 Good` · `40–59 = 🟠 Caution` · `<40 = 🔴 Risk`

---

## Skill Security Audit 检查清单

共 10 大分类，逐项输出 ✅ Pass / ❌ Fail / ⚠️ Warning：

| 分类 | 检查项数 | 说明 |
|------|---------|------|
| 🚨 Critical Security Checks | 9 项 | eval 混淆、动态包安装、IP 外泄、凭证 POST、写系统文件等，任意命中 → REJECT |
| 🔍 Code Obfuscation | 3 项 | Base64 执行、密集 hex 字节、chr() 拼接 |
| ⚠️ High-Risk Tool Detection | 7 项 | exec / browser / message / nodes / cron / canvas / gateway |
| 🔑 Sensitive Data in Source | 7 项 | API Key、私钥、Mnemonic、JWT、AWS Key、DB URL 等硬编码 |
| 💥 Side-Effects Detection | 6 项 | 文件写入、Path.write_text、env 修改、网络 POST/PUT、DB 写、文件系统变更 |
| 🗄️ Data Access Analysis | 5 项 | /etc/ · ~/.ssh/ · ~/.aws/ 路径访问、敏感 env 读取、凭证文件读取、SSH/AWS 密钥 |
| 🔁 Tool Call Depth | 动态 | 方法链或嵌套调用深度 ≥ 4 |
| 📋 Log & Data Hygiene | 4 项 | 日志中的 API Key、私钥、个人信息、密码 |
| ⚙️ Configuration & Environment | 3 项 | 敏感配置 Key、env 变量声明、CLI 二进制依赖 |
| 📄 Skill Manifest Integrity | 5 项 | SKILL.md 存在性、YAML 完整性、name/description/version 字段 |

### 🤖 AI 代码审查（强制执行）

每次扫描都会调用 LLM 对 Skill 源码进行语义级安全分析，返回各维度风险分（0–100）：

- **有风险**：在报告中标注"⚠️ 存在风险"，风险分计入 5 个维度评分（各维度最多扣 25 分）
- **无风险**：在报告中标注"✅ Pass"
- **不可用**（未配置 API Key 或模型）：报告中标注跳过原因，静态分析分数不受影响

> AI 审查依赖 `OPENAI_API_KEY` 或 `XAI_API_KEY` + `SKILL_AUDIT_AI_MODEL`，**部署前务必配置**，否则此项始终显示为跳过。

---

## 最终判定逻辑

```
存在任意 Critical 检查命中  →  REJECT（拒绝安装）
Overall ≥ 70               →  SAFE（可安全安装）
Overall ≥ 45               →  CAUTION（谨慎安装，需人工审查）
Otherwise                  →  REJECT
```

---

## 安全与并发设计

| 问题 | 解决方案 |
|------|----------|
| 钱包 session 并发读写 | `threading.Lock`（`_sessions_lock`）保护 `wallet_sessions` dict |
| session 过期时的 KeyError | `dict.pop(token, None)` 替代 `del`，无锁竞争 |
| 同一 PDF 并发重复生成 | 每个 task 独立 Lock（`_get_pdf_lock`）+ mtime 新鲜度检查 |
| 上传文件阻塞事件循环 | `upload_file` 改为 `def`（FastAPI 自动调度至线程池） |
| 上传文件无大小限制 | 50 MB 硬限制（`MAX_UPLOAD_BYTES`），超限返回 HTTP 413 |
| `_save_index` 持锁写磁盘 | 锁内序列化 + 锁外写文件 |
| session 字典无界增长 | 超过 1000 条时驱逐最旧 session（`MAX_WALLET_SESSIONS`） |

---

## 注意事项

- `backend/storage/` 目录会持续增长（存储每次扫描的上传文件和报告），生产环境建议定期清理或挂载独立存储卷。
- Skill Security Audit 扫描日志时对大文件（> 512 KB）只采样最后 1000 行，以保证扫描性能。
- 同一钱包地址对同一类型任务同时只能运行一个，重复提交会被拒绝（HTTP 409）。
- 每个扫描任务最长执行 600 秒（10 分钟），超时后自动标记为 `failed`。
- 服务重启时，处于 `running` / `queued` 状态超过 30 秒的孤儿任务会被自动标记为 `failed`。
- **不要在生产环境使用 `--reload` 模式**，否则代码变动会重启服务并中断正在运行的扫描任务。
- AI 代码审查会将 Skill 包内所有源码文件（最多 200 个文件，**不设字符上限**）完整发送至 LLM API 进行语义分析，请确保被审查代码不含不希望上传至外部 API 的机密信息，或在内网环境中使用私有部署的模型。
