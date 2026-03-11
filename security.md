# 安全问题分析报告（重新审查）

**生成时间**: 2026-03-03 (更新)
**审查对象**: agent-audit skill (修复后版本)
**审查范围**: 主 Skill + Standalone 版本 + Dashboard + REST API

---

## ✅ 已修复的安全问题

### 1. ✅ **已修复：敏感信息写入报告文件权限问题**
**修复状态**: ✅ 完全修复
**实现**: 
1. 新增 `_secure_write()` 函数（lines 373-379）
2. 使用原子文件写入（tempfile + os.replace）
3. 设置文件权限为 0600（line 379）
```python
def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)  # ✅ 严格权限
```

### 2. ✅ **已修复：路径遍历漏洞（符号链接）**
**修复状态**: ✅ 主 Skill 已修复
**实现**: 新增 `_is_within()` 和符号链接检查（lines 173-195）
```python
def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False

# 在扫描中使用
if path.is_symlink() or not _is_within(base_dir, resolved):
    continue
```

⚠️ **但**: Standalone 版本仍未修复此问题

### 3. ⚠️ **部分修复：ReDoS 拒绝服务风险**
**修复状态**: ⚠️ 部分改进
**实现**: 
1. 限制单词长度 `{3,10}`
2. 限制总数量 `{11,23}`
3. 添加上下文关键词预检

**仍存在风险**: 在包含关键词的长文档中仍可能触发

### 4. ✅ **已修复：竞态条件风险**
**修复状态**: ✅ 完全修复
**实现**: `_secure_write()` 使用原子写入

### 5. ✅ **已修复：敏感信息模式扩展**
**修复状态**: ✅ 主 Skill 已修复
**实现**: 新增 AWS Key、JWT、Database URL 检测

⚠️ **但**: Standalone 版本仍只检测 4 种

### 6. ✅ **已修复：配置文件权限检查**
**修复状态**: ✅ 完全修复
**实现**: 新增 `_warn_perms()` 函数（lines 63-69）
```python
def _warn_perms(path: Path) -> None:
    try:
        stat_info = path.stat()
    except OSError:
        return
    if stat_info.st_mode & 0o077:
        print(f"⚠️  警告：{path} 权限过宽 (建议 600)", file=sys.stderr)
```

---

## 🔒 新发现的安全问题

### 新问题 #1: **Dashboard XSS 漏洞** 🔴
**文件**: `agent_audit_dashboard.html`
**严重程度**: 🔴 严重

**问题描述**:
Dashboard 使用模板字符串直接插入数据，未进行 HTML 转义：
```javascript
// line 283
<td>${p.name}</td>
// line 295  
<td>${row.path}</td>
// line 309
<td>${row.model}</td>
```

**攻击场景**:
如果 agent 名称、文件路径或模型名包含恶意代码：
```javascript
// 攻击者在 memory 文件中创建：
// /tmp/memory/<script>alert('XSS')</script>.md
// 或配置 agent 名为："><script>alert(1)</script>
```

**影响**: 
- 窃取 cookies/session
- 修改页面内容
- 重定向到钓鱼网站

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

// 使用
<td>${escapeHtml(p.name)}</td>
```
3. **持久化风险**: 报告文件长期保存在磁盘上，增加泄露风险
4. **git 泄露风险**: 如果 workspace 目录在 git 仓库中，报告可能被意外提交

**影响范围**: 
- API Keys 部分信息可能被推测
- 助记词的单词位置信息可能泄露
- 私钥格式信息暴露

**修复建议**:
```python
# 1. 设置严格的文件权限
import os
output_fd = os.open(str(args.output), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(output_fd, 'w') as f:
    f.write(json.dumps(report, ensure_ascii=False, indent=2))

# 2. 添加 .gitignore
# 3. 提供 --no-persist 选项仅输出到 stdout
# 4. 增强掩码算法，只显示类型不显示内容
```

---

### 2. **路径遍历漏洞风险**
**文件**: `scripts/audit_scan.py:136-153`
**严重程度**: 🟡 中

**问题描述**:
```python
for path in directory.glob("*.md"):
    content = path.read_text(errors="ignore")
```

虽然使用了 `glob("*.md")`，但如果攻击者能够创建符号链接，可能读取系统中的任意 `.md` 文件。

**攻击场景**:
```bash
cd ~/.openclaw/workspace/memory
ln -s /etc/passwd sensitive.md
ln -s ~/.ssh/id_rsa secret.md
```

**修复建议**:
```python
for path in directory.glob("*.md"):
    # 检查是否为符号链接
    if path.is_symlink():
        continue
    # 确保路径在预期目录内
    if not path.resolve().is_relative_to(directory.resolve()):
        continue
    content = path.read_text(errors="ignore")
```

---

### 3. **正则表达式拒绝服务 (ReDoS) 风险**
**文件**: `scripts/audit_scan.py:39`
**严重程度**: 🟡 中

**问题描述**:
```python
"Mnemonic": re.compile(r"(\b[a-z]+\b\s+){11,}\b[a-z]+\b"),
```

这个正则表达式存在灾难性回溯问题，当输入特定构造的字符串时可能导致 CPU 占用 100%。

**攻击场景**:
恶意用户在 memory 文件中写入：
```
aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa aaa!
```

重复的 "aaa " 会导致正则引擎进行大量回溯。

**修复建议**:
```python
# 使用原子组或限制匹配长度
"Mnemonic": re.compile(r"\b(?:[a-z]+\s+){11}[a-z]+\b"),

# 或添加超时保护
import signal
def timeout_handler(signum, frame):
    raise TimeoutError()

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(5)  # 5秒超时
try:
    matches = pattern.findall(content)
finally:
    signal.alarm(0)
```

---

### 4. **日志注入漏洞**
**文件**: `scripts/audit_scan.py:375-377`
**严重程度**: 🟢 低

**问题描述**:
```python
print(f"✅ 体检完成：JSON -> {args.output}")
if args.markdown:
    print(f"✅ Markdown -> {args.markdown}")
```

如果攻击者能控制文件路径（通过命令行参数），可能注入恶意内容到终端输出。

**攻击场景**:
```bash
python audit_scan.py --output "report.json\n[MALICIOUS] System compromised\n"
```

**修复建议**:
```python
# 转义路径或只显示文件名
print(f"✅ 体检完成：JSON -> {args.output.name}")
```

---

### 5. **竞态条件风险**
**文件**: `scripts/audit_scan.py:289-290`
**严重程度**: 🟡 中

**问题描述**:
```python
output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
```

在多进程/多用户环境下，如果两个进程同时运行审计，可能发生竞态条件：
1. 进程 A 开始写入 audit_report.json
2. 进程 B 同时写入同一文件
3. 导致文件内容损坏

**修复建议**:
```python
import tempfile
# 原子写入：先写临时文件，再重命名
with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as tmp:
    tmp.write(json.dumps(report, ensure_ascii=False, indent=2))
    tmp_name = tmp.name
os.replace(tmp_name, output)
```

---

### 6. **敏感信息模式不完整**
**文件**: `scripts/audit_scan.py:36-41`
**严重程度**: 🟡 中

**问题描述**:
当前仅检测 4 种敏感信息模式，但实际应用中可能存在更多类型的敏感数据。

**缺失的敏感信息类型**:
- AWS Access Key (`AKIA[A-Z0-9]{16}`)
- JWT Token (`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.`)
- OAuth Token
- 数据库连接串 (`postgres://`, `mongodb://`)
- 信用卡号
- 身份证号
- 电话号码
- 邮箱地址（在某些场景下）
- IP 地址（内网 IP）

**修复建议**:
扩展 `SENSITIVE_PATTERNS` 字典，添加更多模式，并支持自定义模式配置。

---

### 7. **错误处理信息泄露**
**文件**: `scripts/audit_scan.py:139`, `scripts/audit_scan.py:179`
**严重程度**: 🟢 低

**问题描述**:
```python
except Exception:
    continue
```

所有异常被静默吞噬，攻击者可能通过特殊构造的文件触发异常来隐藏恶意内容。

**修复建议**:
```python
except Exception as e:
    # 记录错误但不显示详细路径
    print(f"⚠️  扫描文件时遇到错误: {type(e).__name__}", file=sys.stderr)
    continue
```

---

### 8. **配置文件权限检查缺失**
**文件**: `scripts/audit_scan.py:58-62`
**严重程度**: 🟡 中

**问题描述**:
脚本直接读取 `~/.openclaw/openclaw.json`，但不检查文件权限。如果该文件权限设置不当（如 777），可能被其他用户读取。

**修复建议**:
```python
def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    
    # 检查文件权限
    stat_info = CONFIG_PATH.stat()
    if stat_info.st_mode & 0o077:  # 检查 group/other 权限
        print(f"⚠️  警告: {CONFIG_PATH} 权限过于宽松 (建议 0600)", file=sys.stderr)
    
    with CONFIG_PATH.open() as f:
        return json.load(f)
```

---

### 9. **依赖注入风险**
**文件**: `scripts/audit_scan.py:1-18`
**严重程度**: 🟢 低

**问题描述**:
脚本依赖标准库，但没有验证导入的模块是否被篡改。在某些攻击场景下，攻击者可能通过修改 `PYTHONPATH` 注入恶意模块。

**修复建议**:
添加完整性检查或使用虚拟环境隔离。

---

### 10. **Dashboard XSS 风险（推测）**
**文件**: `SKILL.md:17`, `SKILL.md:47-48`
**严重程度**: 🟡 中

**问题描述**:
文档中提到 `agent_audit_dashboard.html` 前端会 fetch JSON 数据并展示。如果前端没有正确转义，扫描结果中的恶意内容可能导致 XSS。

**攻击场景**:
攻击者在 memory 文件中写入：
```markdown
# My Notes
<script>alert('XSS')</script>
```

如果 dashboard 直接渲染文件路径或内容，可能触发 XSS。

**修复建议**:
1. 前端必须对所有动态内容进行 HTML 转义
2. 使用 Content Security Policy
3. 审计 `agent_audit_dashboard.html`（该文件在当前项目中缺失）

---

## 🎯 安全加固建议

### 立即修复（P0）:
1. ✅ 设置报告文件的严格权限（0600）
2. ✅ 防止符号链接遍历
3. ✅ 修复 ReDoS 漏洞

### 短期修复（P1）:
4. ✅ 实现原子文件写入
5. ✅ 添加配置文件权限检查
6. ✅ 扩展敏感信息检测模式
7. ✅ 审计并修复 dashboard XSS 风险

### 长期优化（P2）:
8. ✅ 改进错误处理和日志
9. ✅ 添加审计日志（记录谁在何时运行了审计）
10. ✅ 实现报告文件加密存储

---

## 📋 安全检查清单

- [ ] 敏感数据掩码是否充分？
- [ ] 报告文件权限是否正确？
- [ ] 是否防范路径遍历攻击？
- [ ] 正则表达式是否存在 ReDoS？
- [ ] 文件操作是否原子化？
- [ ] 配置文件权限是否安全？
- [ ] 前端是否防范 XSS？
- [ ] 是否记录审计操作日志？
- [ ] 错误信息是否泄露敏感路径？
- [ ] 依赖是否安全且最新？

---

## 📊 安全问题统计

- 🔴 严重: 1
- 🟡 中度: 6
- 🟢 轻微: 3
- **总计**: 10 个安全问题

**建议**: 在生产环境部署前，必须修复所有严重和中度安全问题。

---

**安全审查人员**: AI Security Reviewer  
**审查日期**: 2026-03-03
