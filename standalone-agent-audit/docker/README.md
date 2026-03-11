# Docker usage

构建镜像：
```bash
cd standalone-agent-audit/docker
docker build -t agent-audit:latest .
```

运行体检（通过 volume 传入配置/数据目录）：
```bash
docker run --rm \
  -v /host/path/openclaw.json:/data/openclaw.json:ro \
  -v /host/path/memory:/data/memory:ro \
  -v /host/path/logs:/data/logs:ro \
  -v $(pwd):/output \
  agent-audit:latest \
  --config /data/openclaw.json \
  --memory /data/memory \
  --logs /data/logs \
  --output /output/audit_report.json \
  --markdown /output/audit_report.md
```
容器入口就是 `agent_audit.py`，参数与本地脚本一致。