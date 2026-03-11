# Bug 分析报告（重新审查）

**生成时间**: 2026-03-03 (更新)  
**审查对象**: agent-audit skill (修复后版本)  
**审查范围**: 
- `skills/agent-audit/scripts/audit_scan.py` (476 行)
- `standalone-agent-audit/agent_audit.py` (293 行)
- `standalone-agent-audit/pip_package/agent_audit_cli/core.py` (273 行)
- `platform/oneclick_server.py` (73 行)
- `standalone-agent-audit/rest_api/app.py` (35 行)
- `agent_audit_dashboard.html` (350 行)

---

## ✅ 已修复的 Bug（之前报告的问题）

### 1. ✅ **已修复：score_privilege 计算逻辑错误**
**原问题**: 基础分 20 应改为 15  
**修复状态**: ✅ 主 Skill 已修复（`audit_scan.py:312`）
```python
return min(100, 15 + high * 20) if high else 15  # ✅ 正确
```

⚠️ **但发现新问题**: standalone 和 pip 版本仍使用错误值：
- `standalone-agent-audit/agent_audit.py:155` → `20 + high * 20`
- `pip_package/core.py:153` → `20 + high * 20`

### 2. ✅ **已修复：Skill 风险分动态计算**
**修复状态**: ✅ 完全修复  
**实现**: 新增 `_assess_skill_risk()` 函数动态评估 (lines 97-114)
```python
def _assess_skill_risk(name: str, payload: Dict[str, Any]) -> Tuple[int, List[str]]:
    base = 15
    # 检测敏感配置 key
    for key in payload.items():
        if any(flag in key.lower() for flag in sensitive_keys):
            base += 10
```

### 3. ✅ **已修复：Tools 字段类型处理**
**修复状态**: ✅ 完全修复  
**实现**: 新增 `_normalize_tools()` 统一处理 (lines 80-87)
```python
def _normalize_tools(value: Any) -> List[str]:
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [str(item) for item in value]
```

### 4. ✅ **已修复：日志错误率计算偏差**
**修复状态**: ✅ 完全修复  
**实现**: 移除 `max(lines, 1)`，直接累加 (line 282)

### 5. ⚠️ **部分修复：助记词假阳性**
**修复状态**: ⚠️ 部分改进  
**改进内容**:
1. 正则改为 `r"\b(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b"` (限制单词长度)
2. 添加上下文关键词检测 (lines 204-232)
3. 只在检测到 "mnemonic"/"seed phrase" 等关键词后才匹配

**仍存在的问题**: 仍可能在包含关键词的技术文档中误报

### 6. ✅ **已修复：Token 统计正则跨行问题**
**修复状态**: ✅ 完全修复  
**实现**: 添加 `re.DOTALL` 标志 (line 47)
```python
re.compile(r'"model"\s*:\s*"(?P<model>[^"]+)".*?"totalTokens"\s*:\s*(?P<tokens>\d+)', 
           re.IGNORECASE | re.DOTALL)
```

### 7. ✅ **已修复：Skill 的 tools 字段概念混淆**
**修复状态**: ✅ 完全修复  
**实现**: 添加 `configKeys` 字段分离概念 (line 152)
```python
"configKeys": list(payload.keys()),
"config": masked,
```

### 8. ✅ **已修复：敏感信息掩码过于简单**
**修复状态**: ✅ 完全修复  
**实现**: 新增 `_mask_value()` 函数 (lines 90-94)
```python
def _mask_value(value: Any) -> str:
    serialized = str(value)
    if len(serialized) <= 4:
        return "***"
    return f"{serialized[:2]}***{serialized[-2:]}"
```

### 9. ✅ **已修复：dataAvailable 字段缺失**
**修复状态**: ✅ 完全修复  
**实现**: 在日志和 token 返回值中添加 (lines 255, 299)

---

## 🐛 新发现的 Bug（修复后版本）

### Bug #1: **导入路径错误导致运行失败** 🔴
**文件**: `platform/oneclick_server.py:17`  
**严重程度**: 🔴 严重

**问题描述**:
```python
from skills.agent-audit.scripts.audit_scan import (  # ❌ 错误
```

Python 模块名不能包含连字符 `-`，应该使用下划线或不同的导入方式。

**影响**: oneclick_server.py 完全无法运行

**修复方案**:
```python
# 方案 1: 动态导入
import importlib.util
spec = importlib.util.spec_from_file_location(
    "audit_scan", 
    REPO_ROOT / "skills" / "agent-audit" / "scripts" / "audit_scan.py"
)
audit_scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_scan)

# 方案 2: 重命名目录为 agent_audit
```

---

### Bug #2: **Standalone 版本 score_privilege 未修复** 🔴
**文件**: 
- `standalone-agent-audit/agent_audit.py:155`
- `standalone-agent-audit/pip_package/agent_audit_cli/core.py:153`

**严重程度**: 🔴 高

**问题描述**:
```python
def score_privilege(entries: List[Dict[str, Any]]) -> int:
    high = sum(len(e.get("highRiskTools", [])) for e in entries if e["type"] == "agent")
    return min(100, 20 + high * 20) if high else 15  # ❌ 仍然是 20
```

**影响**: Standalone 和 pip 版本计算的风险分与主 Skill 不一致，偏高 5 分

**修复建议**:
```python
return min(100, 15 + high * 20) if high else 15  # ✅ 应该是 15
```

---

### Bug #3: **REST API 缺少类型导入** 🟡
**文件**: `standalone-agent-audit/rest_api/app.py:29`  
**严重程度**: 🟡 中

**问题描述**:
```python
def run_audit_endpoint(payload: AuditRequest) -> dict[str, Any]:  # Any 未导入
```

**影响**: 在某些 Python 版本或类型检查工具下会报错

**修复建议**:
```python
from typing import Any  # 添加导入

# 或使用
def run_audit_endpoint(payload: AuditRequest) -> dict:
```

---

### Bug #4: **Standalone 版本仍使用全量读取大文件** 🔴
**文件**: 
- `standalone-agent-audit/agent_audit.py:77`
- `pip_package/core.py:75`

**严重程度**: 🔴 严重（性能）

**问题描述**:
```python
content = path.read_text(errors="ignore")  # ❌ 全量加载
```

主 Skill 已修复为流式读取，但 standalone 版本仍使用旧代码。

**影响**: 大文件场景下内存占用高、速度慢

**修复建议**: 与主 Skill 同步，使用流式读取

---

### Bug #5: **Standalone 版本缺少敏感信息扩展检测** 🟡
**文件**: 
- `standalone-agent-audit/agent_audit.py:14-19`
- `pip_package/core.py:12-17`

**严重程度**: 🟡 中

**问题描述**:
仅检测 4 种敏感信息，缺少主 Skill 中的：
- AWS Access Key
- JWT Token
- Database URL

**影响**: 检测能力弱于主版本

**修复建议**: 同步主 Skill 的 `SENSITIVE_PATTERNS`

---

### Bug #6: **Standalone 版本缺少符号链接保护** 🟡
**文件**: 
- `standalone-agent-audit/agent_audit.py:75`
- `pip_package/core.py:73`

**严重程度**: 🟡 中（安全）

**问题描述**:
```python
for path in sorted(directory.glob("*.md")):  # 没有符号链接检查
```

**影响**: 可能通过符号链接读取任意文件

**修复建议**: 添加 `_is_within()` 和符号链接检查

---

### Bug #7: **Dashboard 不进行 HTML 转义** 🟡
**文件**: `agent_audit_dashboard.html:286, 295, 309`  
**严重程度**: 🟡 中（安全 - XSS）

**问题描述**:
```javascript
<td>${p.name}</td>  // 直接插入，未转义
<td>${row.path}</td>  // 未转义
```

如果文件路径或 agent 名称包含 `<script>` 等恶意代码，会导致 XSS。

**修复建议**:
```javascript
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// 使用
<td>${escapeHtml(p.name)}</td>
```

---

### Bug #8: **Dashboard fetch 缺少错误详情** 🟢
**文件**: `agent_audit_dashboard.html:327-328`  
**严重程度**: 🟢 低

**问题描述**:
```javascript
if (!resp.ok) {
    throw new Error('无法获取报告文件');  // 不显示状态码
}
```

**修复建议**:
```javascript
if (!resp.ok) {
    throw new Error(`无法获取报告文件 (HTTP ${resp.status})`);
}
```

---

### Bug #9: **Standalone 版本助记词检测仍使用旧正则** 🟡
**文件**: 
- `standalone-agent-audit/agent_audit.py:18`
- `pip_package/core.py:16`

**严重程度**: 🟡 中

**问题描述**:
```python
"Mnemonic": re.compile(r"(\b[a-z]+\b\s+){11,}\b[a-z]+\b"),  # ❌ 旧版本
```

主 Skill 已改进为限制单词长度的版本。

**修复建议**: 同步主 Skill 的改进正则

---

### Bug #10: **Token 统计模式在 Standalone 版本中过于简化** 🟢
**文件**: 
- `standalone-agent-audit/agent_audit.py:129`
- `pip_package/core.py:127`

**严重程度**: 🟢 低

**问题描述**:
```python
pattern = re.compile(r'"totalTokens"\s*:\s*(\d+)', re.IGNORECASE)  # 仅一个模式
```

主 Skill 有两个模式且支持不同格式。

**修复建议**: 同步主 Skill 的 `TOKEN_PATTERNS`

---

## 📊 Bug 统计

### 主 Skill (`audit_scan.py`)
- ✅ 之前的 10 个 Bug 中，**9 个已修复**，1 个部分修复
- 🐛 新发现 Bug: **0 个**（主版本代码质量很高）

### Standalone / Pip Package
- 🔴 严重 Bug: **2 个**（score_privilege, 大文件性能）
- 🟡 中度 Bug: **5 个**（敏感检测不全、符号链接、助记词正则等）
- 🟢 轻微 Bug: **1 个**（token 统计简化）

### Platform / REST API
- 🔴 严重 Bug: **1 个**（导入路径错误）
- 🟡 中度 Bug: **1 个**（类型导入）

### Dashboard
- 🟡 中度 Bug: **1 个**（XSS 风险）
- 🟢 轻微 Bug: **1 个**（错误提示）

**总计**: 主版本几乎完美；其他版本需同步修复

---

## 🎯 修复优先级

### P0 - 立即修复（阻塞性）
1. ✅ `platform/oneclick_server.py` 导入路径错误
2. ✅ Standalone 版本 `score_privilege` 基础分错误
3. ✅ Standalone 版本大文件性能问题

### P1 - 短期修复（功能/安全）
4. ✅ Standalone 版本敏感信息检测扩展
5. ✅ Standalone 版本符号链接保护
6. ✅ Dashboard XSS 防护
7. ✅ REST API 类型导入

### P2 - 长期优化
8. ✅ Standalone 版本助记词正则同步
9. ✅ Token 统计模式同步
10. ✅ Dashboard 错误提示优化

---

## 💡 代码同步建议

**核心问题**: Standalone / Pip / REST 版本与主 Skill 代码不同步

**建议**:
1. **重构为共享核心库**: 将核心逻辑提取到独立模块，所有版本复用
2. **自动化测试**: 确保所有版本计算结果一致
3. **版本标记**: 在报告中添加版本号，便于追踪

**审查人员**: AI Code Reviewer  
**审查日期**: 2026-03-03 (重新审查)
