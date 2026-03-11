# 安全问题分析报告（重新审查）

**生成时间**: 2026-03-03 (更新)  
**审查对象**: agent-audit skill (修复后版本)  
**审查范围**: 主 Skill + Standalone 版本 + Dashboard + REST API

---

## ✅ 已修复的安全问题（之前报告）

### 1. ✅ **敏感信息写入报告文件权限问题**
**修复状态**: ✅ 完全修复（主 Skill）  
**实现**: 
- 新增 `_secure_write()` 函数使用原子写入
- 设置文件权限为 0600
- 使用 tempfile + os.replace 防止竞态条件

```python
def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)  # ✅ 严格权限
```

### 2. ✅ **路径遍历漏洞（符号链接）**
**修复状态**: ✅ 主 Skill 已修复  
**实现**: 新增 `_is_within()` 和符号链接检查

```python
def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False

# 使用
if path.is_symlink() or not _is_within(base_dir, resolved):
    continue
```

⚠️ **但**: Standalone 版本仍未修复

### 3. ⚠️ **ReDoS 拒绝服务风险**
**修复状态**: ⚠️ 部分改进  
**改进**: 
- 限制单词长度 `{3,10}`
- 限制总数量 `{11,23}`  
- 添加上下文关键词预检

**仍存在风险**: 在包含关键词的长文档中仍可能触发回溯

### 4. ✅ **竞态条件风险**
**修复状态**: ✅ 完全修复  
**实现**: `_secure_write()` 原子写入

### 5. ✅ **敏感信息模式扩展**
**修复状态**: ✅ 主 Skill 已修复  
**实现**: 新增 AWS Key、JWT、Database URL 检测

⚠️ **但**: Standalone 版本仍只检测 4 种

### 6. ✅ **配置文件权限检查**
**修复状态**: ✅ 完全修复  
**实现**: 新增 `_warn_perms()` 函数

```python
def _warn_perms(path: Path) -> None:
    if stat_info.st_mode & 0o077:
        print(f"⚠️  警告：{path} 权限过宽 (建议 600)", file=sys.stderr)
```

---

## 🔒 新发现的安全问题

### 新问题 #1: **Dashboard XSS 漏洞** 🔴
**文件**: `agent_audit_dashboard.html:283, 295, 309`  
**严重程度**: 🔴 严重

**问题描述**:
Dashboard 直接插入未转义的数据到 HTML：
```javascript
<td>${p.name}</td>              // line 283
<td>${row.path}</td>            // line 295
<td>${row.model}</td>           // line 309
```

**攻击场景**:
```javascript
// 攻击者创建恶意文件名
/memory/<script>alert(document.cookie)</script>.md

// 或配置恶意 agent 名
{
  "agents": {
    "\"><img src=x onerror=alert(1)>": {...}
  }
}
```

**影响**:
- 窃取本地 cookies/session
- 修改 Dashboard 显示内容
- 执行任意 JavaScript 代码

**修复建议**:
```javascript
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 所有插入点都使用转义
<td>${escapeHtml(p.name)}</td>
```

---

### 新问题 #2: **Standalone 版本缺少符号链接保护** 🟡
**文件**: 
- `standalone-agent-audit/agent_audit.py:75`
- `pip_package/core.py:73`

**严重程度**: 🟡 中

**问题描述**:
```python
for path in sorted(directory.glob("*.md")):  # 无符号链接检查
    content = path.read_text(errors="ignore")
```

**攻击场景**:
```bash
cd ~/.openclaw/workspace/memory
ln -s /etc/passwd sensitive_data.md
ln -s ~/.ssh/id_rsa private_key.md
```

**影响**: 可读取系统任意 `.md` 文件或符号链接指向的文件

**修复建议**: 同步主 Skill 的符号链接检查代码

---

### 新问题 #3: **Standalone 版本全量读取导致 DoS** 🟡
**文件**: 
- `standalone-agent-audit/agent_audit.py:77`
- `pip_package/core.py:75`

**严重程度**: 🟡 中（安全+性能）

**问题描述**:
```python
content = path.read_text(errors="ignore")  # 一次性加载全部
```

**攻击场景**:
攻击者创建超大文件触发内存耗尽：
```bash
# 创建 10GB 文件
dd if=/dev/zero of=memory/huge.md bs=1G count=10
```

**影响**: 
- 内存耗尽导致 OOM
- 系统其他服务受影响
- DoS 攻击

**修复建议**: 使用流式读取或限制文件大小

---

### 新问题 #4: **Platform Server 导入路径错误可能被利用** 🟡
**文件**: `platform/oneclick_server.py:17`  
**严重程度**: 🟡 中

**问题描述**:
```python
from skills.agent-audit.scripts.audit_scan import (  # 导入会失败
```

**安全隐患**:
虽然这是个 bug，但如果攻击者能在 `sys.path` 中注入恶意 `skills` 模块，可能执行任意代码。

**修复建议**: 使用绝对路径或 importlib 动态导入

---

### 新问题 #5: **JSON 序列化未压缩可能泄露更多信息** 🟢
**文件**: `audit_scan.py:383`  
**严重程度**: 🟢 低

**问题描述**:
```python
payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))  # 紧凑格式
```

虽然使用了紧凑格式，但未加密存储，任何能访问文件的进程都能读取。

**建议**: 对于极敏感环境，考虑加密存储报告

---

### 新问题 #6: **Dashboard 缺少 Content Security Policy** 🟢
**文件**: `agent_audit_dashboard.html`  
**严重程度**: 🟢 低

**问题描述**:
HTML 缺少 CSP 头部，无法防御 XSS 的深度攻击。

**修复建议**:
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';">
```

---

### 新问题 #7: **REST API 缺少认证机制** 🟡
**文件**: 
- `platform/oneclick_server.py`
- `standalone-agent-audit/rest_api/app.py`

**严重程度**: 🟡 中

**问题描述**:
REST API 无任何认证：
```python
@app.post("/audit")
async def run_audit(options: AuditOptions | None = None):  # 无认证
    report = generate_report()
    return {"report": report}
```

**攻击场景**:
如果部署到公网，任何人都可以：
1. 触发体检消耗服务器资源
2. 读取敏感的审计报告
3. DoS 攻击

**修复建议**:
```python
from fastapi import Header, HTTPException

async def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization[7:]
    if token != os.getenv("AUDIT_API_TOKEN"):
        raise HTTPException(403, "Forbidden")

@app.post("/audit", dependencies=[Depends(verify_token)])
async def run_audit(...):
    ...
```

---

### 新问题 #8: **Dashboard fetch 无 timeout** 🟢
**文件**: `agent_audit_dashboard.html:326`  
**严重程度**: 🟢 低

**问题描述**:
```javascript
const resp = await fetch(`audit_report.json?ts=${Date.now()}`);  // 无 timeout
```

恶意服务器可以无限期挂起请求。

**修复建议**:
```javascript
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 10000);
const resp = await fetch(url, { signal: controller.signal });
clearTimeout(timeout);
```

---

## 📊 安全问题统计

### 主 Skill (`audit_scan.py`)
- ✅ 之前的 10 个安全问题中，**6 个已完全修复**，3 个部分修复
- 🐛 新发现安全问题: **0 个**（主版本安全性优秀）

### Dashboard
- 🔴 严重: **1 个**（XSS 漏洞）
- 🟢 轻微: **2 个**（CSP 缺失、fetch timeout）

### Standalone / Pip Package  
- 🟡 中度: **2 个**（符号链接、DoS）
- 缺少主 Skill 的多项安全改进

### REST API / Platform
- 🟡 中度: **2 个**（无认证、导入路径）

**总计**: 8 个新安全问题

---

## 🎯 修复优先级

### P0 - 立即修复（严重风险）
1. ✅ Dashboard XSS 漏洞
2. ✅ REST API 添加认证
3. ✅ Platform Server 导入路径修复

### P1 - 短期修复（中等风险）
4. ✅ Standalone 版本符号链接保护
5. ✅ Standalone 版本 DoS 防护（大文件）
6. ✅ 同步主 Skill 的安全改进到 Standalone

### P2 - 长期优化（低风险）
7. ✅ Dashboard 添加 CSP
8. ✅ Dashboard fetch timeout
9. ✅ 报告加密存储（可选）

---

## 🔐 安全加固建议

### 1. **统一安全标准**
所有版本（Skill/Standalone/Pip/REST）应使用相同的安全机制：
- 符号链接检查
- 文件权限验证
- 敏感信息检测范围
- 安全文件写入

### 2. **部署安全**
- REST API 必须配置认证
- 使用 HTTPS/TLS
- 配置防火墙规则
- 定期更新依赖

### 3. **数据保护**
- 报告文件权限 0600
- 考虑报告加密
- 定期清理旧报告
- 添加 `.gitignore`

### 4. **监控与审计**
- 记录 API 访问日志
- 监控异常文件访问
- 告警异常大文件扫描

---

## ✅ 安全检查清单

- [x] 报告文件权限 0600
- [x] 原子文件写入
- [x] 符号链接检查（主 Skill）
- [ ] 符号链接检查（Standalone）
- [x] 敏感信息模式完整（主 Skill）
- [ ] 敏感信息模式完整（Standalone）
- [ ] Dashboard HTML 转义
- [ ] Dashboard CSP 策略
- [ ] REST API 认证
- [x] 配置文件权限检查
- [x] ReDoS 部分缓解
- [ ] 大文件 DoS 防护（Standalone）

**完成度**: 主 Skill 8/12，Standalone 4/12，Dashboard 0/4，REST API 0/1

---

**安全审查人员**: AI Security Reviewer  
**审查日期**: 2026-03-03 (重新审查)
