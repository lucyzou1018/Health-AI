# AIagentEraDemo

本仓库存放 “Agent Audit” 体检 Skill 及相关资源，帮助你一键审计 OpenClaw agent/skill 权限、memory、日志与 token 消耗。

## 内容结构
```
AIagentEraDemo/
├─ skills/agent-audit/     # Skill 源码（SKILL.md + scripts + references）
└─ dist/agent-audit.skill  # 打包好的可安装 Skill
```

## 使用方式
1. 克隆仓库：
   ```bash
   git clone https://github.com/yingjingyang/AIagentEraDemo.git
   cd AIagentEraDemo
   ```
2. 安装 Skill：
   ```bash
   openclaw skills install dist/agent-audit.skill
   ```
   或者将 `skills/agent-audit/` 放入你的 workspace 后运行 `python3 audit_scan.py`（workspace 根目录的包装器会调用此 Skill 的脚本）。
3. 运行体检：
   ```bash
   cd ~/.openclaw/workspace
   python3 audit_scan.py --markdown audit_report.md
   ```
   - `audit_report.json`：供 `agent_audit_dashboard.html` 等前端加载
   - `audit_report.md`：可直接粘贴给用户的汇报文本
4. （可选）刷新 Dashboard：
   ```bash
   python3 -m http.server 8080
   # 浏览器访问 http://127.0.0.1:8080/agent_audit_dashboard.html 并点击「一键体检」
   ```

## 风险指标说明
详见 `skills/agent-audit/references/risk-model.md`：
- 隐私泄露
- 越权风险
- 记忆膨胀
- Token 成本
- 失败率

## 贡献
欢迎根据实际需要修改 `skills/agent-audit/` 后重新运行：
```bash
python3 ~/.nvm/versions/node/v22.22.0/lib/node_modules/openclaw/skills/skill-creator/scripts/package_skill.py \
  skills/agent-audit dist
```
即可生成新的 `.skill` 文件。欢迎 PR。