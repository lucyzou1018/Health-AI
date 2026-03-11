# Agent Audit 平台化部署

新增 `platform/oneclick_server.py`，可将体检能力通过 FastAPI 暴露给可外网访问的平台。

## 启动方式
```bash
cd ~/.openclaw/workspace/AIagentEraDemo
uvicorn platform.oneclick_server:app --host 0.0.0.0 --port 9000
```
> 将 `--host` 设为 `0.0.0.0` 后，若服务器具备公网 IP 或接入了反向代理（Nginx、Cloudflare Tunnel、ngrok 等），外部用户即可访问。

## 接口
### `GET /healthz`
- 用于探活；返回 `{ "status": "ok" }`。

### `POST /audit`
- 触发一次体检，返回 JSON 报告和 Markdown 文本。
- 可选 body：
```json
{
  "save_json": true,
  "save_markdown": true,
  "json_path": "/tmp/audit.json",
  "markdown_path": "/tmp/audit.md"
}
```
- `save_json`/`save_markdown` 为 `true` 时，会把报告保存到服务器本地指定路径（默认沿用 `audit_scan.py` 的输出路径）。

### `POST /audit/plain`
- 返回 Markdown 字符串，适合在 Webhook / 消息渠道中直接发送。

## 对接外部平台建议
1. **部署**：将该 FastAPI 服务部署到具备公网访问的环境（云服务器、容器平台、Render/Fly.io 等）。
2. **认证**：若平台对外开放，建议在反向代理层添加 API Key 或 Token 鉴权。
3. **反向代理**：可使用 Nginx/Traefik/Cloudflare Tunnel 为 `/audit` 提供 HTTPS 与访问控制。
4. **Webhook / Bot**：第三方平台可直接调用 `/audit` 并将 `markdown` 字段渲染到前端或消息机器人，实现“一键体检”体验。

## 安全性
- 设置环境变量 `AUDIT_PLATFORM_TOKEN` 后，调用方需在 Header 中携带 `Authorization: Bearer <token>`。
- 默认启用 30 秒缓存，可在请求体设置 `force_refresh` / `cache_ttl_seconds` 控制行为。
