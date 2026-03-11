"""Core logic for Agent Audit scanner (shared by CLI/REST/Platform)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

HIGH_RISK_TOOLS = {"exec", "browser", "message", "nodes", "cron", "canvas", "gateway"}
SENSITIVE_PATTERNS = {
    "API Key": re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    "Ethereum Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Private Block": re.compile(r"-----BEGIN[\s\w]+PRIVATE KEY-----"),
    "Mnemonic": re.compile(r"\b(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b", re.IGNORECASE),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Database URL": re.compile(r"(postgres|mysql|mongodb|redis|mssql)://[^\s]+", re.IGNORECASE),
}
TOKEN_PATTERNS = [
    re.compile(r'"model"\s*:\s*"(?P<model>[^"]+)".*?"totalTokens"\s*:\s*(?P<tokens>\d+)', re.IGNORECASE | re.DOTALL),
    re.compile(r'model=(?P<model>\S+).*?(?:tokens|totalTokens)=(?P<tokens>\d+)', re.IGNORECASE),
]
MNEMONIC_KEYWORDS = ("mnemonic", "seed phrase", "seed", "助记词")


def _normalize_tools(value: Any) -> List[str]:
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def _mask_value(value: Any) -> str:
    serialized = str(value)
    if not serialized:
        return "***"
    if len(serialized) <= 4:
        return "***"
    return f"{serialized[:2]}***{serialized[-2:]}"


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def _assess_skill_risk(name: str, payload: Dict[str, Any]) -> Tuple[int, List[str]]:
    base = 15
    notes: List[str] = []
    sensitive_keys = ("key", "secret", "token", "password", "dsn", "api", "private")
    for key, value in payload.items():
        lower_key = key.lower()
        if any(flag in lower_key for flag in sensitive_keys):
            base += 10
            notes.append(f"包含敏感配置: {key}")
        if isinstance(value, str):
            for label, pattern in SENSITIVE_PATTERNS.items():
                if label == "Mnemonic":
                    continue
                if pattern.search(value):
                    base += 5
                    notes.append(f"{key} 匹配 {label}")
                    break
    return min(100, base), notes


def collect_permissions(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    agents = config.get("agents", {})
    for name, payload in agents.items():
        payload = payload or {}
        tools = _normalize_tools(payload.get("tools", {}))
        high_risk = [tool for tool in tools if tool in HIGH_RISK_TOOLS]
        score = min(100, 15 + 20 * len(high_risk)) if high_risk else 15
        entries.append(
            {
                "type": "agent",
                "name": name,
                "tools": tools,
                "highRiskTools": high_risk,
                "notes": (["包含高危工具：" + ", ".join(high_risk)] if high_risk else []),
                "riskScore": score,
            }
        )

    skill_cfg = (config.get("skills") or {}).get("entries", {})
    for name, payload in skill_cfg.items():
        payload = payload or {}
        masked = {key: _mask_value(value) for key, value in payload.items()}
        risk_score, extra_notes = _assess_skill_risk(name, payload)
        entries.append(
            {
                "type": "skill",
                "name": name,
                "tools": _normalize_tools(payload.get("tools", [])),
                "highRiskTools": [],
                "notes": (["已配置凭据"] if payload else []) + extra_notes,
                "riskScore": risk_score,
                "configKeys": list(payload.keys()),
                "config": masked,
            }
        )
    return entries


def scan_memory(directory: Path) -> Dict[str, Any]:
    total = 0
    findings: List[Dict[str, Any]] = []
    hits = 0
    if not directory.exists():
        return {"totalSize": 0, "files": [], "sensitiveHits": 0}

    base_dir = directory.resolve()
    for path in sorted(directory.glob("*.md")):
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if path.is_symlink() or not _is_within(base_dir, resolved):
            continue
        try:
            stat_info = path.stat()
        except OSError:
            continue
        size = stat_info.st_size
        total += size
        counts = {label: 0 for label in SENSITIVE_PATTERNS}
        mnemonic_snippets: List[str] = []
        capture_ttl = 0
        try:
            with path.open("r", errors="ignore") as fh:
                for line in fh:
                    lowered = line.lower()
                    if any(keyword in lowered for keyword in MNEMONIC_KEYWORDS):
                        capture_ttl = 4
                        mnemonic_snippets.append(line)
                    elif capture_ttl > 0:
                        mnemonic_snippets.append(line)
                        capture_ttl -= 1
                    for label, pattern in SENSITIVE_PATTERNS.items():
                        if label == "Mnemonic":
                            continue
                        matches = pattern.findall(line)
                        if matches:
                            counts[label] += len(matches)
                            hits += len(matches)
        except Exception:
            continue

        if mnemonic_snippets:
            snippet_text = " ".join(mnemonic_snippets)
            matches = SENSITIVE_PATTERNS["Mnemonic"].findall(snippet_text)
            if matches:
                counts["Mnemonic"] += len(matches)
                hits += len(matches)

        issues = [f"{label} ×{count}" for label, count in counts.items() if count]
        if size > 1_000_000:
            issues.append("文件超过 1MB，建议归档")
        if issues:
            findings.append({"path": str(path), "size": human_size(size), "issues": issues})
    return {"totalSize": total, "files": findings, "sensitiveHits": hits}


def scan_logs_and_tokens(directory: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    total_lines = 0
    total_errors = 0
    token_totals: Dict[str, int] = {}
    if not directory.exists():
        return ({"files": [], "errorRate": 0.0}, {"totalTokens": 0, "byModel": []})

    keywords = ("error", "failed", "traceback", "exception")
    for path in sorted(directory.glob("*.log")):
        errors = 0
        lines = 0
        try:
            stat_info = path.stat()
            with path.open("r", errors="ignore") as fh:
                for line in fh:
                    lines += 1
                    lower = line.lower()
                    if any(k in lower for k in keywords):
                        errors += 1
                    for pattern in TOKEN_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            model = match.group("model")
                            tokens = int(match.group("tokens"))
                            token_totals[model] = token_totals.get(model, 0) + tokens
                            break
        except Exception:
            continue
        total_lines += lines
        total_errors += errors
        entries.append(
            {
                "path": str(path),
                "size": human_size(stat_info.st_size),
                "errors": errors,
                "lines": lines,
                "updatedAt": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            }
        )

    error_rate = total_errors / total_lines if total_lines else 0.0
    total_tokens = sum(token_totals.values())
    per_model = [
        {"model": model, "tokens": count}
        for model, count in sorted(token_totals.items(), key=lambda item: item[1], reverse=True)
    ]
    return ({"files": entries, "errorRate": error_rate}, {"totalTokens": total_tokens, "byModel": per_model})


def human_size(num_bytes: int) -> str:
    step = 1024
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < step:
            return f"{num_bytes:.2f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= step
    return f"{num_bytes:.2f} PB"


def score_privacy(hits: int) -> int:
    if hits == 0:
        return 5
    return min(100, 30 + hits * 15)


def score_privilege(entries: List[Dict[str, Any]]) -> int:
    high = sum(len(e.get("highRiskTools", [])) for e in entries if e.get("type") == "agent")
    return min(100, 15 + high * 20) if high else 15


def score_memory(total_size: int) -> int:
    mb = total_size / 1_000_000
    if mb <= 2:
        return 10
    if mb <= 5:
        return 40
    return min(100, 40 + int((mb - 5) * 10))


def score_tokens(total_tokens: int) -> int:
    if total_tokens == 0:
        return 10
    if total_tokens <= 500_000:
        return 35
    return min(100, 35 + int((total_tokens - 500_000) / 50_000))


def score_failures(error_rate: float) -> int:
    return min(100, int(error_rate * 400))


def build_suggestions(report: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    if report["privacyRisk"] > 30:
        suggestions.append("在 memory/ 中查找敏感信息并进行脱敏或迁移到安全存储。")
    if report["privilegeRisk"] > 30:
        suggestions.append("为含 exec/browser 的 Agent 添加操作确认或拆分角色。")
    if report["memoryRisk"] > 40:
        suggestions.append("归档 memory 文件（>1MB）并替换为摘要。")
    if report["tokenRisk"] > 35:
        suggestions.append("为高消耗模型设置预算守卫或改用低成本模型。")
    if report["failureRisk"] > 25:
        suggestions.append("检查日志中高频错误，增加重试/超时保护。")
    return suggestions or ["暂无建议"]


def run_audit(config_path: Path, memory_dir: Path, log_dir: Path) -> Dict[str, Any]:
    config = load_config(config_path.expanduser())
    permissions = collect_permissions(config)
    memory = scan_memory(memory_dir.expanduser())
    logs, tokens = scan_logs_and_tokens(log_dir.expanduser())

    report = {
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "permissions": permissions,
        "memory": memory,
        "logs": logs,
        "tokens": tokens,
    }
    report["privacyRisk"] = score_privacy(memory.get("sensitiveHits", 0))
    report["privilegeRisk"] = score_privilege(permissions)
    report["memoryRisk"] = score_memory(memory.get("totalSize", 0))
    report["tokenRisk"] = score_tokens(tokens.get("totalTokens", 0))
    report["failureRisk"] = score_failures(logs.get("errorRate", 0.0))
    report["suggestions"] = build_suggestions(report)
    return report


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        return json.load(fh)


def to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Agent Audit 报告",
        f"生成时间：{report['generatedAt']}",
        "",
        "## 风险评分",
        f"- 隐私泄露：{report['privacyRisk']}",
        f"- 越权风险：{report['privilegeRisk']}",
        f"- 记忆膨胀：{report['memoryRisk']}",
        f"- Token 成本：{report['tokenRisk']}",
        f"- 失败率：{report['failureRisk']}",
        "",
        "## 修复建议",
    ]
    for item in report["suggestions"]:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## 权限概览",
        "| 类型 | 名称 | 工具 | 高危 | 备注 |",
        "| --- | --- | --- | --- | --- |",
    ])
    for entry in report["permissions"]:
        lines.append(
            f"| {entry['type']} | {entry['name']} | {', '.join(entry.get('tools', [])) or '-'} | {', '.join(entry.get('highRiskTools', [])) or '-'} | {'; '.join(entry.get('notes', [])) or '-'} |"
        )

    lines.extend([
        "",
        "## 记忆问题",
        "| 文件 | 大小 | 问题 |",
        "| --- | --- | --- |",
    ])
    if report["memory"]["files"]:
        for item in report["memory"]["files"]:
            lines.append(f"| {item['path']} | {item['size']} | {', '.join(item['issues'])} |")
    else:
        lines.append("| - | - | - |")

    lines.extend([
        "",
        "## 日志摘要",
        "| 文件 | 大小 | 错误 | 行数 | 更新时间 |",
        "| --- | --- | --- | --- | --- |",
    ])
    if report["logs"]["files"]:
        for item in report["logs"]["files"]:
            lines.append(
                f"| {item['path']} | {item['size']} | {item['errors']} | {item['lines']} | {item['updatedAt']} |"
            )
    else:
        lines.append("| - | - | - | - | - |")

    return "\n".join(lines)
