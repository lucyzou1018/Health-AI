# Agent Audit REST API

## 安装依赖
```bash
cd standalone-agent-audit/rest_api
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 启动服务
```bash
uvicorn app:app --reload --port 8000
```

## 调用示例
```bash
curl -X POST http://127.0.0.1:8000/run \
  -H "Content-Type: application/json" \
  -d '{
        "config": "/path/to/openclaw.json",
        "memory": "/path/to/memory",
        "logs": "/path/to/logs",
        "return_markdown": true
      }'
```
返回 JSON 中包含 `report`（各项指标 + 建议），当 `return_markdown=true` 时还会附带 `markdown` 文本，可直接发送给用户或写入文件。