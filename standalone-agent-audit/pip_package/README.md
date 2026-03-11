# agent-audit-cli

可通过 `pip install .` 安装的体检工具，安装后提供 `agent-audit` 命令。

## 安装
```bash
cd standalone-agent-audit/pip_package
pip install .
```

## 使用
```bash
agent-audit \
  --config /path/to/openclaw.json \
  --memory /path/to/memory \
  --logs /path/to/logs \
  --output audit_report.json \
  --markdown audit_report.md
```

生成的 JSON/Markdown 与独立脚本保持一致，可直接喂给 dashboard。