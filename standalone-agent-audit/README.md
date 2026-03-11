# Standalone Agent Audit

该目录包含多个形态的体检工具：

```
standalone-agent-audit/
├─ agent_audit.py          # 直接运行的独立脚本
├─ README.md               # 总览
├─ pip_package/            # pip 安装包工程（agent-audit-cli）
├─ docker/                 # Dockerfile + 用法
└─ rest_api/               # FastAPI 版 REST 服务
```

## 1. 直接运行脚本
```bash
python3 agent_audit.py \
  --config /path/to/openclaw.json \
  --memory /path/to/memory \
  --logs /path/to/logs \
  --output audit_report.json \
  --markdown audit_report.md
```
输出 JSON / Markdown，可直接喂给 `agent_audit_dashboard.html`。

## 2. pip 包（agent-audit-cli）
```
cd pip_package
pip install .
agent-audit --config ... --memory ... --logs ...
```
提供 `agent-audit` 命令（脚本逻辑与上面相同）。

## 3. Docker 镜像
```
cd docker
docker build -t agent-audit:latest .
docker run --rm -v ... agent-audit:latest --config ...
```
适用于没有直接安装 Python 的环境，通过 volume 传入配置/数据目录即可。

## 4. REST API
```
cd rest_api
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```
调用：`POST /run`，请求体中提供 `config/memory/logs` 路径，返回体包含 `report` 和可选的 `markdown`。

以上形态互不影响，均复用相同的体检逻辑，可按照需要选择。