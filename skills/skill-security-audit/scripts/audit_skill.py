#!/usr/bin/env python3
"""AI Agent/Skill audit scanner.

Scans OpenClaw config, workspace memory, and log files to surface risk info
around permissions, privacy, token usage, and stability.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import ssl
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore


HOME = Path.home()
CONFIG_PATH = HOME / ".openclaw" / "openclaw.json"
WORKSPACE = HOME / ".openclaw" / "workspace"
MEMORY_DIR = WORKSPACE / "memory"
LOG_DIR = HOME / ".openclaw" / "logs"
DEFAULT_OUTPUT: Path | None = None

HIGH_RISK_TOOLS = {
    "exec",
    "browser",
    "message",
    "nodes",
    "cron",
    "canvas",
    "gateway",
}

HIGH_RISK_KEYWORDS = {
    "exec": ("subprocess", "os.system", "Popen(", "run_cmd(", "shlex"),
    "browser": ("playwright", "selenium", "browser."),
    "message": ("message.", "send_message", "message.send"),
    "nodes": ("nodes.", "node_client", "node.run"),
    "cron": ("schedule.", "cron", "apscheduler"),
    "canvas": ("canvas.", "canvas_"),
    "gateway": ("urlopen", "requests", "httpx", "aiohttp", "websocket", "socket.create_connection"),
}

TOOL_REMEDIATION_HINTS = {
    "exec": "Require manual approval or sandboxing before running subprocess/CLI commands (e.g., slither, forge).",
    "gateway": "Restrict outbound HTTP calls to allowlisted endpoints (e.g., Etherscan/Sourcify) and redact secrets.",
    "browser": "Limit headless browser access to trusted origins and rotate credentials.",
    "message": "Scope messaging actions to approved channels and add rate limits.",
    "nodes": "Validate node instructions and pin allowed commands for remote devices.",
    "cron": "Document scheduled actions and enforce owner acknowledgement before enabling cron jobs.",
    "canvas": "Restrict canvas interactions to non-sensitive dashboards and require read-only mode when possible.",
}

TOOL_REMEDIATION_HINTS_ZH = {
    "exec": "在运行 subprocess/CLI（如 slither、forge）前增加人工审批或沙箱隔离。",
    "gateway": "将外部 HTTP 请求限制在允许的端点（如 Etherscan/Sourcify）并做好脱敏。",
    "browser": "将浏览器自动化限制在可信域名，并定期轮换凭据。",
    "message": "仅允许向批准的频道发送消息，并加上频率限制。",
    "nodes": "校验节点指令，只允许预设的远端命令。",
    "cron": "记录所有定时任务并在启用前获得负责人确认。",
    "canvas": "仅对非敏感 Dashboard 使用 canvas，必要时改为只读模式。",
}
TEXT_PATTERN_DEFS = {
    "API Key": re.compile(r"(api[_-]?key|apikey)[\s:=]+['\"][A-Za-z0-9]{20,}['\"]", re.IGNORECASE),
    "Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Mnemonic": re.compile(r"(mnemonic|seed phrase)[^\n]*\b(\w+\s+){11,23}\w+\b", re.IGNORECASE),
    "Personal Info": re.compile(r"(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
    "Password": re.compile(r"(password|passwd|pwd)[\s:=]+['\"][^'\"]{8,}['\"]", re.IGNORECASE),
}
SENSITIVE_PATTERNS = {
    "API Key": re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    "Ethereum Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Mnemonic": re.compile(r"\b(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b", re.IGNORECASE),
    "Private Block": re.compile(r"-----BEGIN[\s\w]+PRIVATE KEY-----"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Database URL": re.compile(r"(postgres|mysql|mongodb|redis|mssql)://[^\s]+", re.IGNORECASE),
}
TOKEN_PATTERNS = [
    re.compile(r'"model"\s*:\s*"(?P<model>[^"]+)".*?"totalTokens"\s*:\s*(?P<tokens>\d+)', re.IGNORECASE | re.DOTALL),
    re.compile(r'model=(?P<model>\S+).*?(?:tokens|totalTokens)=(?P<tokens>\d+)', re.IGNORECASE),
]
MNEMONIC_KEYWORDS = ("mnemonic", "seed phrase", "seed", "助记词")

# ── 即时拒绝：发现任意一项则 verdict=REJECT ──────────────────────────────────
INSTANT_REJECT_PATTERNS: Dict[str, Any] = {
    "eval_obfuscation":     re.compile(r'eval\s*\(\s*base64\.b64decode\s*\(', re.IGNORECASE),
    "exec_compile":         re.compile(r'exec\s*\(\s*compile\s*\(', re.IGNORECASE),
    "dynamic_pip_install":  re.compile(r'(subprocess|os\.system|os\.popen|Popen)\s*[\.(].*?pip\s+install', re.IGNORECASE | re.DOTALL),
    "dynamic_npm_install":  re.compile(r'(subprocess|os\.system|os\.popen|Popen)\s*[\.(].*?npm\s+(install|i\b)', re.IGNORECASE | re.DOTALL),
    "ip_exfil":             re.compile(r'(requests|httpx|urlopen|aiohttp)\s*\.\s*(get|post|put)\s*\(\s*[\'"]https?://(\d{1,3}\.){3}\d{1,3}', re.IGNORECASE),
    "credential_exfil":     re.compile(r'(requests|httpx|urlopen|aiohttp)\s*\.\s*(post|put)\s*\(.*?(password|api_key|secret|private_key)', re.IGNORECASE | re.DOTALL),
    "soul_write":           re.compile(r'(open|write_text|Path)\s*\(.*?SOUL\.md.*?[,\s]+[\'"]w', re.IGNORECASE),
    "openclaw_config_write":re.compile(r'(open|write_text|Path)\s*\(.*?openclaw\.json.*?[,\s]+[\'"]w', re.IGNORECASE),
    "credential_request":   re.compile(r'input\s*\(\s*[\'"][^\'"]*?(api.?key|password|secret|token|private)', re.IGNORECASE),
}

INSTANT_REJECT_LABELS_ZH = {
    "eval_obfuscation":      "eval(base64.decode) 混淆执行",
    "exec_compile":          "exec(compile()) 动态编译执行",
    "dynamic_pip_install":   "动态安装 Python 包（pip install）",
    "dynamic_npm_install":   "动态安装 Node 包（npm install）",
    "ip_exfil":              "向 IP 地址直连发送 HTTP 请求（可疑数据外泄）",
    "credential_exfil":      "向外部接口 POST 凭证/密钥",
    "soul_write":            "修改 SOUL.md（AI 代理身份文件）",
    "openclaw_config_write": "修改 openclaw.json（配置文件）",
    "credential_request":    "通过 input() 请求用户输入凭证",
}

# ── 混淆代码检测 ──────────────────────────────────────────────────────────────
OBFUSCATION_PATTERNS: Dict[str, Any] = {
    "base64_exec":  re.compile(r'base64\.b64decode\s*\(', re.IGNORECASE),
    "hex_dense":    re.compile(r'(\\x[0-9a-fA-F]{2}){10,}'),
    "chr_concat":   re.compile(r'(chr\s*\(\s*\d+\s*\)\s*\+\s*){5,}'),
}

OBFUSCATION_LABELS_ZH = {
    "base64_exec": "Base64 解码执行代码",
    "hex_dense":   "大量十六进制字节（可能混淆）",
    "chr_concat":  "chr() 字符拼接（可能混淆）",
}


def _fallback_yaml(raw: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def _parse_front_matter(text: str) -> Tuple[Dict[str, Any], str]:
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}, text
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        return {}, text
    front_raw = parts[1]
    body = parts[2]
    manifest: Dict[str, Any] = {}
    if yaml:
        try:
            loaded = yaml.safe_load(front_raw)  # type: ignore[arg-type]
            if isinstance(loaded, dict):
                manifest = loaded
        except Exception:
            manifest = _fallback_yaml(front_raw)
    else:
        manifest = _fallback_yaml(front_raw)
    if not isinstance(manifest, dict):
        manifest = {}
    return manifest, body


def _extract_requirements(meta: Any) -> Tuple[List[str], List[str]]:
    bins: List[str] = []
    env_vars: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                except Exception:
                    return
                _walk(parsed)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in {"bins", "tools"}:
                    if isinstance(value, list):
                        bins.extend(str(item) for item in value)
                    else:
                        bins.append(str(value))
                elif lowered in {"env", "envs", "environment", "variables"}:
                    if isinstance(value, list):
                        env_vars.extend(str(item) for item in value)
                    elif isinstance(value, dict):
                        env_vars.extend(str(k) for k in value.keys())
                    else:
                        env_vars.append(str(value))
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    if isinstance(meta, dict):
        _walk(meta)
    return bins, env_vars


def detect_high_risk_tools_from_path(base_path: Optional[Path]) -> Tuple[List[str], Dict[str, List[Tuple[str, str]]]]:
    if base_path is None or not base_path.exists():
        return [], {}
    base_dir = base_path if base_path.is_dir() else base_path.parent
    findings: Dict[str, Set[Tuple[str, str]]] = {}
    for pattern in ("*.py", "*.ts", "*.js", "*.sh"):
        for candidate in base_dir.rglob(pattern):
            if candidate.is_dir() or candidate.stat().st_size > 500_000:
                continue
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lowered = text.lower()
            rel_path = str(candidate.relative_to(base_dir))
            for tool, keywords in HIGH_RISK_KEYWORDS.items():
                for keyword in keywords:
                    if keyword.lower() in lowered:
                        findings.setdefault(tool, set()).add((rel_path, keyword))
                        break
    detected = sorted(findings.keys())
    detail_map = {tool: sorted(list(values)) for tool, values in findings.items()}
    return detected, detail_map


def _score_external_metrics(payload: Dict[str, Any], body: str) -> Dict[str, int]:
    chunks: List[str] = []
    if payload:
        try:
            chunks.append(json.dumps(payload, ensure_ascii=False))
        except Exception:
            chunks.append(str(payload))
    if body:
        chunks.append(body)
    haystack = "\n".join(chunks).lower()

    def _hits(keywords: List[str]) -> int:
        return sum(1 for keyword in keywords if keyword in haystack)

    def _score(base: int, step: int, keywords: List[str], cap: int = 90) -> int:
        return min(cap, base + _hits(keywords) * step)

    privacy_keywords = [
        "private key",
        "mnemonic",
        "seed",
        "api_key",
        "bot_token",
        "secret",
        "wallet_private_key",
        "telegram_bot_token",
    ]
    privilege_keywords = [
        "exec",
        "subprocess",
        "docker",
        "curl",
        "requests",
        "websocket",
        "browser",
        "message",
        "nodes",
        "gateway",
    ]
    memory_keywords = ["log", "history", "persist", "state", "memory"]
    # Use precise multi-word or rare tokens to avoid false positives on generic words
    token_keywords = ["openai", "gpt-", "llm", "token_limit", "max_tokens", "prompt_tokens"]
    failure_keywords = ["kill switch", "retry", "timeout", "watchdog", "circuit breaker"]

    def _matched(keywords: List[str]) -> List[str]:
        return [kw for kw in keywords if kw in haystack]

    privacy_hits = _matched(privacy_keywords)
    privilege_hits = _matched(privilege_keywords)
    memory_hits = _matched(memory_keywords)
    token_hits = _matched(token_keywords)
    failure_hits = _matched(failure_keywords)

    return {
        # Base is 0: only deduct when a specific keyword is actually found.
        # This ensures a clean skill can achieve 100 in every dimension.
        "privacy":   min(90, len(privacy_hits)   * 15),
        "privilege": min(90, len(privilege_hits)  * 10),
        "memory":    min(90, len(memory_hits)     * 10),
        "token":     min(90, len(token_hits)      * 15),
        "failure":   min(90, len(failure_hits)    * 15),
        # Also store matched keywords so the report can explain deductions
        "_privacy_hits":   privacy_hits,
        "_privilege_hits": privilege_hits,
        "_memory_hits":    memory_hits,
        "_token_hits":     token_hits,
        "_failure_hits":   failure_hits,
    }

    bins: List[str] = []
    env_vars: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                except Exception:
                    return
                _walk(parsed)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in {"bins", "tools"}:
                    if isinstance(value, list):
                        bins.extend(str(item) for item in value)
                    else:
                        bins.append(str(value))
                elif lowered in {"env", "envs", "environment", "variables"}:
                    if isinstance(value, list):
                        env_vars.extend(str(item) for item in value)
                    elif isinstance(value, dict):
                        env_vars.extend(str(k) for k in value.keys())
                    else:
                        env_vars.append(str(value))
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    if isinstance(meta, dict):
        _walk(meta)
    return bins, env_vars


def _load_skill_text_from_path(raw_path: str) -> Tuple[str, str]:
    path = Path(raw_path).expanduser()
    candidate = path
    if path.is_dir():
        candidate = path / "SKILL.md"
    if not candidate.exists():
        raise FileNotFoundError(f"SKILL.md not found: {candidate}")
    text = candidate.read_text(encoding="utf-8", errors="ignore")
    return candidate.stem, text


def _fetch_text_from_url(url: str) -> str:
    try:
        context = ssl.create_default_context()
        with urlopen(url, context=context) as resp:  # nosec - user-supplied URL
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="ignore")
    except Exception:
        proc = subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True)
        if proc.returncode != 0:
            raise URLError(proc.stderr.strip() or "Unable to fetch content via curl")
        return proc.stdout


def _load_skill_text_from_url(url: str) -> Tuple[str, str]:
    text = _fetch_text_from_url(url)
    name = Path(urlparse(url).path).stem or url
    return name, text


def _analyze_external_skill(name_hint: str, text: str, origin: str) -> Dict[str, Any]:
    manifest, body = _parse_front_matter(text)
    payload = manifest if isinstance(manifest, dict) else {}
    name = payload.get("name") or name_hint or origin
    bins, env_vars = _extract_requirements(payload)
    risk_score, meta_notes = _assess_skill_risk(name, payload)
    notes: List[str] = []
    try:
        origin_path = Path(origin).expanduser()
        origin_path_str = str(origin_path) if origin_path.exists() else None
    except Exception:
        origin_path = None
        origin_path_str = None
    detected_high_risk, high_risk_details = detect_high_risk_tools_from_path(origin_path)
    # Do NOT expose server-side absolute paths in the report.
    # Show only the skill name (already available as `name`).
    if not origin_path_str:
        notes.append(f"External skill source: {origin}")
    if detected_high_risk:
        risk_score = max(risk_score, 40 + 15 * (len(detected_high_risk) - 1))
    if env_vars:
        unique_env = sorted(set(env_vars))
        notes.append("Environment variables: " + ", ".join(unique_env))
        risk_score = min(100, risk_score + 5)
    if bins:
        notes.append("CLI dependencies: " + ", ".join(sorted(set(bins))))
    for label, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(body):
            notes.append(f"Body matches {label}")
            risk_score = min(100, risk_score + 5)
    masked: Dict[str, str] = {}
    config_keys: List[str] = []
    if payload:
        for key, value in payload.items():
            config_keys.append(str(key))
            serialized = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
            masked[key] = _mask_value(serialized)
    external_scores = _score_external_metrics(payload, body)
    return {
        "type": "skill",
        "name": name,
        "tools": sorted(set(bins)),
        "highRiskTools": detected_high_risk,
        "skills": None,
        "riskScore": min(100, risk_score),
        "notes": notes + meta_notes,
        "configKeys": config_keys,
        "config": masked,
        "externalScores": external_scores,
        "highRiskDetails": high_risk_details,
        "originPath": origin_path_str,
    }


def load_external_skills(path_inputs: Optional[List[str]], url_inputs: Optional[List[str]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for raw in path_inputs or []:
        if not raw:
            continue
        try:
            name_hint, text = _load_skill_text_from_path(raw)
            origin = str(Path(raw).expanduser())
            entries.append(_analyze_external_skill(name_hint, text, origin))
        except Exception as exc:
            print(f"⚠️ Unable to read local skill {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            name_hint, text = _load_skill_text_from_url(url)
            entries.append(_analyze_external_skill(name_hint, text, url))
        except (URLError, OSError) as exc:
            print(f"⚠️ Unable to fetch remote skill {url}: {exc}", file=sys.stderr)
    return entries


def _load_agent_json_from_path(raw_path: str) -> Tuple[str, Any]:
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Agent JSON not found: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    data = json.loads(text)
    return path.stem, data


def _load_agent_json_from_url(url: str) -> Tuple[str, Any]:
    text = _fetch_text_from_url(url)
    data = json.loads(text)
    name = Path(urlparse(url).path).stem or url
    return name, data


def _normalize_agent_entries(blob: Any) -> List[Tuple[str, Dict[str, Any]]]:
    entries: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(blob, dict):
        agents_section = blob.get("agents")
        if isinstance(agents_section, dict):
            for name, payload in agents_section.items():
                entries.append((str(name), payload or {}))
        else:
            name = str(blob.get("name") or blob.get("agent") or "external-agent")
            entries.append((name, blob))
    return entries


def _analyze_external_agent(name: str, payload: Dict[str, Any], origin: str) -> Dict[str, Any]:
    payload = payload or {}
    tools = _normalize_tools(payload.get("tools", {}))
    skills = payload.get("skills") or []
    high_risk = [tool for tool in tools if tool in HIGH_RISK_TOOLS]
    score = min(100, 15 + 20 * len(high_risk)) if high_risk else 15
    notes = [f"External agent source: {origin}"]
    if skills:
        notes.append("Accessible skills: " + ", ".join(skills))
    description = payload.get("description")
    if description:
        notes.append(str(description))
    if high_risk:
        notes.append("Includes high-risk tools: " + ", ".join(high_risk))
    return {
        "type": "agent",
        "name": name,
        "tools": tools,
        "highRiskTools": high_risk,
        "skills": skills,
        "riskScore": score,
        "notes": notes,
    }


def load_external_agents(path_inputs: Optional[List[str]], url_inputs: Optional[List[str]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def _extend(blob: Any, origin: str) -> None:
        for name, payload in _normalize_agent_entries(blob):
            entries.append(_analyze_external_agent(name, payload, origin))

    for raw in path_inputs or []:
        if not raw:
            continue
        try:
            _, data = _load_agent_json_from_path(raw)
            origin = str(Path(raw).expanduser())
            _extend(data, origin)
        except Exception as exc:
            print(f"⚠️ Unable to read local agent {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            _, data = _load_agent_json_from_url(url)
            _extend(data, url)
        except (URLError, OSError, json.JSONDecodeError) as exc:
            print(f"⚠️ Unable to fetch remote agent {url}: {exc}", file=sys.stderr)
    return entries


def human_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    for unit in ["KB", "MB", "GB"]:
        num_bytes /= 1024.0
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
    return f"{num_bytes:.2f} TB"


def _warn_perms(path: Path) -> None:
    try:
        stat_info = path.stat()
    except OSError:
        return
    if stat_info.st_mode & 0o077:
        print(f"⚠️ Warning: {path} permissions are too broad (recommended 600)", file=sys.stderr)


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    _warn_perms(CONFIG_PATH)
    with CONFIG_PATH.open() as f:
        return json.load(f)


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
    if len(serialized) <= 4:
        return "***"
    return f"{serialized[:2]}***{serialized[-2:]}"


def _assess_skill_risk(name: str, payload: Dict[str, Any]) -> Tuple[int, List[str]]:
    base = 15
    notes: List[str] = []
    sensitive_keys = ("key", "secret", "token", "password", "dsn", "api", "private")
    for key, value in payload.items():
        lower_key = key.lower()
        if any(flag in lower_key for flag in sensitive_keys):
            base += 10
            notes.append(f"Sensitive config key detected: {key}")
        if isinstance(value, str):
            for label, pattern in SENSITIVE_PATTERNS.items():
                if label == "Mnemonic":
                    continue
                if pattern.search(value):
                    base += 5
                    notes.append(f"{key} matches {label}")
                    break
    return min(100, base), notes


def collect_permissions(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    agents = config.get("agents", {})
    for name, payload in agents.items():
        if isinstance(payload, list):
            continue
        payload = payload or {}
        tools = _normalize_tools(payload.get("tools", {}))
        skills = payload.get("skills") or []
        high_risk = [tool for tool in tools if tool in HIGH_RISK_TOOLS]
        score = min(100, 15 + 20 * len(high_risk)) if high_risk else 15
        entries.append(
            {
                "type": "agent",
                "name": name,
                "tools": tools,
                "highRiskTools": high_risk,
                "skills": skills,
                "riskScore": score,
                "notes": (["Includes high-risk tools: " + ", ".join(high_risk)] if high_risk else []),
            }
        )

    skill_cfg = (config.get("skills") or {}).get("entries", {})
    for name, payload in skill_cfg.items():
        payload = payload or {}
        masked = {key: _mask_value(value) for key, value in payload.items()}
        risk_score, risk_notes = _assess_skill_risk(name, payload)
        tool_list = _normalize_tools(payload.get("tools", []))
        high_risk = [tool for tool in tool_list if tool in HIGH_RISK_TOOLS]
        entries.append(
            {
                "type": "skill",
                "name": name,
                "tools": tool_list,
                "highRiskTools": high_risk,
                "skills": None,
                "riskScore": risk_score,
                "notes": (["Configured credentials detected"] if payload else []) + risk_notes,
                "configKeys": list(payload.keys()),
                "config": masked,
            }
        )
    return entries


@dataclass
class MemoryIssue:
    path: str
    size_bytes: int
    issues: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": human_size(self.size_bytes),
            "issues": self.issues,
        }


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def scan_memory(directory: Path) -> Dict[str, Any]:
    results: List[MemoryIssue] = []
    total_size = 0
    sensitive_hits = 0
    pattern_hits: List[Dict[str, str]] = []
    if not directory.exists():
        return {"totalSize": 0, "files": [], "sensitiveHits": 0, "dataAvailable": False, "patternHits": []}

    base_dir = directory.resolve()
    for path in directory.glob("*.md"):
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
        total_size += size
        file_issues: List[str] = []
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
                            count = len(matches)
                            counts[label] += count
                            sensitive_hits += count
                    matched_labels = _scan_patterns_in_line(line, path, pattern_hits)
                    if matched_labels:
                        sensitive_hits += len(matched_labels)
        except Exception:
            continue

        if mnemonic_snippets:
            snippet_text = " ".join(mnemonic_snippets)
            matches = SENSITIVE_PATTERNS["Mnemonic"].findall(snippet_text)
            if matches:
                counts["Mnemonic"] += len(matches)
                sensitive_hits += len(matches)

        for label, count in counts.items():
            if count:
                file_issues.append(f"{label} ×{count}")
        if size > 1_000_000:
            file_issues.append("文件超过 1MB，建议归档")
        if file_issues:
            results.append(MemoryIssue(str(path), size, file_issues))
    return {
        "totalSize": total_size,
        "files": [item.to_dict() for item in results],
        "sensitiveHits": sensitive_hits,
        "patternHits": pattern_hits,
        "dataAvailable": True,
    }


def scan_logs_and_tokens(directory: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    log_entries: List[Dict[str, Any]] = []
    total_errors = 0
    total_lines = 0
    token_totals: Dict[str, int] = {}
    pattern_hits: List[Dict[str, str]] = []
    if not directory.exists():
        return (
            {"files": [], "errorRate": 0.0, "dataAvailable": False, "patternHits": [], "sensitiveHits": 0},
            {"totalTokens": 0, "byModel": [], "dataAvailable": False},
        )

    # 超过此阈值的文件只采样末尾，避免扫描巨型日志卡住整个审计
    MAX_SCAN_BYTES = 512_000   # 512 KB
    TAIL_LINES     = 1_000     # 超限时只扫最后 1000 行

    keywords = ("error", "exception", "traceback", "failed")
    for path in directory.glob("*.log"):
        errors = 0
        lines = 0
        try:
            stat_info = path.stat()
            file_size = stat_info.st_size

            if file_size > MAX_SCAN_BYTES:
                # 大文件：只读末尾 TAIL_LINES 行，元数据正常记录
                from collections import deque
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    tail = list(deque(fh, maxlen=TAIL_LINES))
                scan_lines = tail
                # 行数/错误数基于采样，标注为估算
                lines = TAIL_LINES  # 用采样行数代表（已标注）
                skipped = True
            else:
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    scan_lines = fh.readlines()
                lines = len(scan_lines)
                skipped = False

            for line in scan_lines:
                lower = line.lower()
                if any(k in lower for k in keywords):
                    errors += 1
                if "model" in lower:
                    for pattern in TOKEN_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            model = match.group("model")
                            tokens = int(match.group("tokens"))
                            token_totals[model] = token_totals.get(model, 0) + tokens
                            break
                _scan_patterns_in_line(line, path, pattern_hits)
        except Exception:
            continue

        total_errors += errors
        total_lines += lines
        entry: Dict[str, Any] = {
            "path": str(path),
            "size": human_size(stat_info.st_size),
            "sizeBytes": stat_info.st_size,
            "errors": errors,
            "lines": lines,
            "updatedAt": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        }
        if skipped:
            entry["note"] = f"Large file — scanned last {TAIL_LINES} lines only"
        log_entries.append(entry)

    rate = total_errors / total_lines if total_lines else 0.0
    total_tokens = sum(token_totals.values())
    per_model = [
        {"model": model, "tokens": count}
        for model, count in sorted(token_totals.items(), key=lambda item: item[1], reverse=True)
    ]
    log_info = {
        "files": log_entries,
        "errorRate": rate,
        "dataAvailable": True,
        "patternHits": pattern_hits,
        "sensitiveHits": len(pattern_hits),
    }
    token_info = {"totalTokens": total_tokens, "byModel": per_model, "dataAvailable": True}
    return log_info, token_info


def score_privacy(sensitive_hits: int) -> int:
    if sensitive_hits == 0:
        return 0
    return min(100, 40 + (sensitive_hits - 1) * 15)


def score_privilege(permissions: List[Dict[str, Any]]) -> int:
    high = sum(len(entry.get("highRiskTools", [])) for entry in permissions)
    if high == 0:
        return 0
    return min(100, 40 + (high - 1) * 15)


def score_memory(total_size: int) -> int:
    mb = total_size / 1_000_000
    if mb <= 2:
        return 0
    if mb <= 5:
        return 40
    return min(100, 40 + int((mb - 5) * 10))


def score_tokens(total_tokens: int) -> int:
    if total_tokens == 0:
        return 0
    if total_tokens <= 500_000:
        return 35
    return min(100, 35 + int((total_tokens - 500_000) / 50_000))


def score_failures(error_rate: float) -> int:
    if error_rate == 0:
        return 0
    return min(100, 40 + int(error_rate * 400))


def build_suggestions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    memory_block = report.get("memory", {})
    memory_files = memory_block.get("files", [])
    if memory_files:
        focus = [
            {"path": item["path"], "issues": item.get("issues", [])}
            for item in memory_files[:3]
        ]
        suggestions.append({"type": "memory_sensitive", "files": focus})
    elif report["privacyScore"] < 60 and not memory_block.get("dataAvailable", True):
        suggestions.append({"type": "memory_missing"})

    permissions = report.get("permissions", [])
    for entry in permissions:
        risky = entry.get("highRiskTools") or []
        for tool in risky:
            suggestions.append({"type": "tool", "skill": entry["name"], "tool": tool})

    total_size = memory_block.get("totalSize", 0)
    if report.get("integrityScore", 100) < 60 and total_size:
        suggestions.append({"type": "memory_size", "size": total_size})

    token_block = report.get("tokens", {})
    models = token_block.get("byModel", [])
    if report.get("supplyChainScore", 100) < 60 and models:
        top = models[0]
        suggestions.append({"type": "token", "model": top["model"], "tokens": top["tokens"]})

    log_block = report.get("logs", {})
    logs = log_block.get("files", [])
    if report["failureScore"] < 60 and logs:
        worst = max(logs, key=lambda item: item.get("errors", 0))
        if worst.get("errors"):
            suggestions.append(
                {
                    "type": "log_errors",
                    "path": worst["path"],
                    "errors": worst["errors"],
                    "lines": worst["lines"],
                }
            )

    if not suggestions:
        suggestions.append({"type": "none"})
    return suggestions


def _translate_warning(message: str, lang: str) -> str:
    if lang != "zh":
        return message
    mapping = {
        "memory/ directory not found; skipped memory scan": "未检测到 memory/ 目录，已跳过记忆扫描",
        "memory/ directory not found; unable to audit persistence.": "未检测到 memory/ 目录，无法审计持久化内容",
        "logs/ directory not found; failure rate assumed 0": "未检测到 logs/ 目录，失败率按 0 处理",
        "logs/ directory is empty; failure rate assumed 0": "logs/ 目录为空，失败率按 0 处理",
        "logs/ directory not found; failure rate unavailable.": "未检测到 logs/ 目录，无法计算失败率",
        "Log files missing tokenUsage metadata; token cost set to 0": "日志缺少 tokenUsage 信息，Token 成本按 0 处理",
        "Token usage data missing from logs.": "日志缺少 tokenUsage 数据，无法统计。",
    }
    return mapping.get(message, message)


def _translate_note(note: str, lang: str) -> str:
    if lang != "zh":
        return note
    replacements = {
        "Local skill path:": "本地 Skill 路径：",
        "External skill source:": "外部 Skill 来源：",
        "Detected high-risk tools:": "检测到高危权限：",
        "Environment variables:": "声明的环境变量：",
        "CLI dependencies:": "依赖工具：",
        "Body matches": "正文匹配",
        "Sensitive config key detected:": "检测到敏感配置键：",
        "Configured credentials detected": "检测到已配置的凭据",
    }
    for eng, zh in replacements.items():
        if note.startswith(eng):
            return note.replace(eng, zh, 1)
    return note


def _render_suggestions(suggestions: List[Dict[str, Any]], lang: str) -> List[str]:
    rendered: List[str] = []
    for item in suggestions:
        stype = item.get("type")
        if stype == "memory_sensitive":
            files = item.get("files", [])
            summary = "; ".join(
                f"{Path(entry['path']).name} ({', '.join(entry.get('issues', []))})" for entry in files
            )
            if lang == "zh":
                rendered.append(f"清理以下 memory 文件中的敏感内容：{summary}")
            else:
                rendered.append(f"Scrub or relocate sensitive content in: {summary}")
        elif stype == "memory_missing":
            rendered.append(
                "请创建 memory/ 目录以启用隐私扫描。" if lang == "zh" else "Provide a memory/ directory so privacy scans can run."
            )
        elif stype == "tool":
            tool = item.get("tool", "-")
            skill = item.get("skill", "skill")
            hint = (
                TOOL_REMEDIATION_HINTS_ZH.get(tool, f"为 {tool} 增加防护。")
                if lang == "zh"
                else TOOL_REMEDIATION_HINTS.get(tool, f"Add guardrails before invoking {tool}.")
            )
            rendered.append(f"{skill} – {hint}")
        elif stype == "memory_size":
            size_text = human_size(item.get("size", 0))
            rendered.append(
                f"memory/ 总大小约 {size_text}，建议归档或压缩超 1MB 的文件。"
                if lang == "zh"
                else f"Memory footprint is {size_text}; archive or summarize files over 1MB."
            )
        elif stype == "token":
            model = item.get("model")
            tokens = item.get("tokens")
            rendered.append(
                f"模型 {model} 最近消耗 {tokens} tokens，建议设置预算或改用低成本模型。"
                if lang == "zh"
                else f"Model {model} consumed {tokens} tokens recently; enforce budgets or switch to cheaper models."
            )
        elif stype == "log_errors":
            path = item.get("path")
            errors = item.get("errors")
            lines = item.get("lines")
            rendered.append(
                f"{path} 记录 {errors} 个错误 / {lines} 行日志，建议排查并加上重试/超时。"
                if lang == "zh"
                else f"{path} logged {errors} errors across {lines} lines; investigate and add retries/timeouts."
            )
        elif stype == "none":
            rendered.append("暂无需要整改的项目。" if lang == "zh" else "No remediation required based on current telemetry.")
    return rendered


def _render_pattern_table(hits: List[Dict[str, str]], lang: str, title_en: str, title_zh: str) -> List[str]:
    if not hits:
        return []
    lines = ["", title_zh if lang == "zh" else title_en]
    if lang == "zh":
        lines.append("| 类型 | 文件 | 内容 |")
        lines.append("| --- | --- | --- |")
    else:
        lines.append("| Pattern | File | Snippet |")
        lines.append("| --- | --- | --- |")
    for hit in hits:
        lines.append(f"| {hit['label']} | {hit['path']} | {hit['line']} |")
    return lines


def _scan_patterns_in_line(line: str, path: Path, hits: List[Dict[str, str]]) -> List[str]:
    labels: List[str] = []
    for label, regex in TEXT_PATTERN_DEFS.items():
        if regex.search(line):
            snippet = line.strip()
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            hits.append({"label": label, "path": str(path), "line": snippet})
            labels.append(label)
    return labels


def scan_skill_logs(skill_path: Path, limit: int = 20) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    count = 0
    for log_file in sorted(skill_path.rglob("*.log")):
        if count >= limit:
            break
        try:
            if log_file.stat().st_size > 1_000_000:
                continue
            with log_file.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    _scan_patterns_in_line(line, log_file, hits)
        except Exception:
            continue
        count += 1
    return hits


def _build_skill_bundle(paths: List[Path], max_files: int = 20, max_chars: int = 12000) -> str:
    collected: List[str] = []
    remaining = max_chars
    files: List[Path] = []
    for base in paths:
        if not base.exists():
            continue
        candidates = []
        skill_md = base / "SKILL.md"
        if skill_md.exists():
            candidates.append(skill_md)
        for pattern in ("scripts/**/*", "references/**/*", "*.py", "*.md"):
            candidates.extend(sorted(base.glob(pattern)))
        for candidate in candidates:
            if candidate.is_dir() or candidate in files or candidate.suffix in {".log", ""}:
                continue
            files.append(candidate)
            if len(files) >= max_files:
                break
        if len(files) >= max_files:
            break
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        snippet = text.strip()
        if len(snippet) > remaining:
            snippet = snippet[: remaining - 3] + "..."
        collected.append(f"### {file_path}\n{snippet}")
        remaining -= len(snippet)
        if remaining <= 0:
            break
    return "\n\n".join(collected)


def run_ai_review(skill_entries: List[Dict[str, Any]], model: str, lang: str) -> Dict[str, Any]:
    paths = []
    for entry in skill_entries or []:
        origin = entry.get("originPath")
        if origin:
            p = Path(origin)
            if p.exists():
                paths.append(p)
    if not paths:
        return {"status": "skipped", "reason": "no local skill paths"}
    try:
        from openai import OpenAI
    except Exception as exc:
        return {"status": "error", "reason": f"openai package missing: {exc}"}
    if not os.getenv("OPENAI_API_KEY"):
        return {"status": "error", "reason": "OPENAI_API_KEY not set"}
    bundle = _build_skill_bundle(paths)
    if not bundle:
        return {"status": "skipped", "reason": "skill files empty"}
    client = OpenAI()
    system_prompt = (
        "You are a security auditor. Review provided skill files and list potential risks, sensitive data, or bad practices."
        if lang != "zh"
        else "你是一名安全审计员，请审查提供的 Skill 文件，指出潜在风险、敏感信息或不当做法。"
    )
    user_prompt = (
        "Summarize risks and actionable fixes for the following skill contents:\n\n"
        if lang != "zh"
        else "请审查以下 Skill 内容并用中文给出风险与修复建议：\n\n"
    ) + bundle
    try:
        response = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
        )
        summary = getattr(response, "output_text", "")
        if not summary:
            try:
                summary = response.output[0]["content"][0]["text"]  # type: ignore[index]
            except Exception:
                summary = ""
        return {"status": "ok", "model": model, "summary": summary or "(empty response)"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def _risk_label(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def detect_code_risks(base_path: Optional[Path]) -> Dict[str, Any]:
    """检测即时拒绝标志、混淆代码、供应链攻击风险，以及源码中的硬编码敏感数据。"""
    result: Dict[str, Any] = {"instantRejects": [], "obfuscation": [], "sensitiveData": []}
    if base_path is None or not base_path.exists():
        return result
    base_dir = base_path if base_path.is_dir() else base_path.parent
    for glob_pat in ("*.py", "*.ts", "*.js", "*.sh"):
        for candidate in base_dir.rglob(glob_pat):
            if candidate.is_dir() or candidate.stat().st_size > 500_000:
                continue
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(candidate.relative_to(base_dir))
            for label, pat in INSTANT_REJECT_PATTERNS.items():
                if pat.search(text):
                    result["instantRejects"].append({"label": label, "path": rel})
            for label, pat in OBFUSCATION_PATTERNS.items():
                if pat.search(text):
                    result["obfuscation"].append({"label": label, "path": rel})
            # 4D: 源码中的硬编码敏感数据（API Key / 私钥 / JWT 等）
            for label, pat in SENSITIVE_PATTERNS.items():
                if pat.search(text):
                    result["sensitiveData"].append({"label": label, "path": rel})
    # 去重（同一 label 只记录一次）
    result["sensitiveData"] = list({item["label"]: item for item in result["sensitiveData"]}.values())
    return result


def compute_verdict(report: Dict[str, Any]) -> str:
    """返回最终安全结论：SAFE / CAUTION / REJECT"""
    code_risks = report.get("codeRisks", {})
    if code_risks.get("instantRejects"):
        return "REJECT"
    overall = report.get("overallScore", 0)
    if overall >= 70:
        return "SAFE"
    if overall >= 45:
        return "CAUTION"
    return "REJECT"


def _select_logs(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not entries:
        return []
    focus = [entry for entry in entries if entry.get("errors", 0) > 0 or entry.get("sizeBytes", 0) >= 500_000]
    if not focus:
        focus = sorted(entries, key=lambda item: item.get("sizeBytes", 0), reverse=True)[:3]
    return focus


def generate_report(
    extra_skills: Optional[List[Dict[str, Any]]] = None,
    extra_agents: Optional[List[Dict[str, Any]]] = None,
    scan_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    scan_paths: 原始输入目录列表（始终执行代码扫描，无论 SKILL.md 是否存在）。
    当上传的 ZIP 不含 SKILL.md 时，load_external_skills() 返回空列表，代码扫描
    会被跳过。通过 scan_paths 把原始目录直接传入，确保扫描不被绕过。
    """
    skills = extra_skills or []
    agents = extra_agents or []
    # Only analyse the uploaded skill/agent package.
    # Never read server-side OpenClaw config, workspace memory or gateway logs.
    combined = list(skills) + list(agents)
    permissions = combined

    memory_info: Dict[str, Any] = {
        "totalSize": 0, "files": [], "sensitiveHits": 0,
        "dataAvailable": False, "patternHits": [],
    }
    log_info: Dict[str, Any] = {
        "files": [], "errorRate": 0.0, "dataAvailable": False,
        "patternHits": [], "sensitiveHits": 0,
    }
    token_info: Dict[str, Any] = {"totalTokens": 0, "byModel": [], "dataAvailable": False}

    skill_log_hits: List[Dict[str, str]] = []
    aggregate_code_risks: Dict[str, Any] = {"instantRejects": [], "obfuscation": [], "sensitiveData": []}

    # 已扫描路径集合，避免重复扫描同一目录
    _scanned: set = set()

    for entry in skills:
        origin = entry.get("originPath")
        if origin:
            origin_path = Path(origin).resolve()
            if origin_path.exists():
                _scanned.add(str(origin_path))
                skill_log_hits.extend(scan_skill_logs(origin_path))
                risks = detect_code_risks(origin_path)
                aggregate_code_risks["instantRejects"].extend(risks["instantRejects"])
                aggregate_code_risks["obfuscation"].extend(risks["obfuscation"])
                aggregate_code_risks["sensitiveData"].extend(risks.get("sensitiveData", []))

    # 对所有 scan_paths 执行代码扫描（即使 SKILL.md 缺失也不跳过）
    for raw in scan_paths or []:
        try:
            p = Path(raw).expanduser().resolve()
        except Exception:
            continue
        if not p.exists() or str(p) in _scanned:
            continue
        _scanned.add(str(p))
        skill_log_hits.extend(scan_skill_logs(p))
        risks = detect_code_risks(p)
        aggregate_code_risks["instantRejects"].extend(risks["instantRejects"])
        aggregate_code_risks["obfuscation"].extend(risks["obfuscation"])
        aggregate_code_risks["sensitiveData"].extend(risks.get("sensitiveData", []))

    # sensitiveData 全局去重（同 label 只保留一条）
    aggregate_code_risks["sensitiveData"] = list(
        {item["label"]: item for item in aggregate_code_risks["sensitiveData"]}.values()
    )

    log_sensitive_hits = log_info.get("sensitiveHits", 0) + len(skill_log_hits)
    privacy_hits = memory_info.get("sensitiveHits", 0) + log_sensitive_hits

    # Check if we have runtime data
    has_memory_data = memory_info.get("dataAvailable", True) and memory_info.get("totalSize", 0) > 0
    has_log_data = log_info.get("dataAvailable", True) and log_info.get("files")
    has_token_data = token_info.get("dataAvailable", True) and token_info.get("totalTokens", 0) > 0

    # Keyword-based static scores (memory / token only; all others now checklist-driven)
    static_scores = _aggregate_static_scores(skills)

    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "permissions": permissions,
        "memory": memory_info,
        "logs": log_info,
        "tokens": token_info,
        "externalOnly": bool(combined),
        "skillLogHits": skill_log_hits,
        "codeRisks": aggregate_code_risks,
        "staticScores": static_scores,
    }

    # Derive all five dimension scores directly from checklist findings so every
    # deduction is traceable to a visible ❌ / ⚠️ checklist row.
    checklist_risks = _compute_checklist_scores(report)

    # Convert to safety scores (0-100, higher = safer)
    report["privacyScore"]    = max(0, 100 - checklist_risks["privacy"])
    report["privilegeScore"]  = max(0, 100 - checklist_risks["privilege"])
    report["integrityScore"]  = max(0, 100 - checklist_risks["integrity"])
    report["supplyChainScore"] = max(0, 100 - checklist_risks["supplychain"])
    report["failureScore"]    = max(0, 100 - checklist_risks["failure"])

    # Calculate overall safety score (average of 5 dimensions)
    report["overallScore"] = int((
        report["privacyScore"]   + report["privilegeScore"] +
        report["integrityScore"] + report["supplyChainScore"] +
        report["failureScore"]
    ) / 5)

    # Warnings are suppressed — runtime data (memory/logs) is intentionally not
    # collected from the server; scores fall back to static analysis only.
    report["warnings"] = []

    report["suggestions"] = build_suggestions(report)
    report["verdict"] = compute_verdict(report)
    return report


def _compute_checklist_scores(report: Dict[str, Any]) -> Dict[str, int]:
    """
    Compute risk scores (0–100, higher = more risky) directly from checklist
    findings so every deduction maps 1-to-1 to a visible ❌ / ⚠️ checklist row.

    Dimension mapping (exclusive — each checklist item feeds exactly one score):

    🔏 Privacy      ← 4A: credential_exfil/request · 4E: log hygiene · 4F: config key / env vars
    🔐 Privilege    ← 4A: soul_write / openclaw_config_write (identity & config tampering only)
    🛡️ Integrity    ← 4A: eval_obfuscation / exec_compile · 4B: obfuscation · 4D: sensitive data in source
    🔗 Supply Chain ← 4A: dynamic installs / ip_exfil · 4C: high-risk tools · 4F: CLI deps
    ✅ Stability    ← 4G: manifest completeness (SKILL.md, name, version, description)
    """
    permissions   = report.get("permissions", [])
    skill_entries = [e for e in permissions if e.get("type") == "skill"]
    code_risks    = report.get("codeRisks") or {}

    # Instant-reject labels (❌ Critical)
    ir_labels: set = {item["label"] for item in code_risks.get("instantRejects", [])}

    # Obfuscation hits count (⚠️)
    ob_count: int = len(code_risks.get("obfuscation", []))

    # High-risk tools (⚠️)
    hr_tools: set = set()
    for entry in skill_entries:
        hr_tools.update(entry.get("highRiskTools", []))

    # Notes / config keys across all skill entries
    all_notes: List[str] = []
    all_cfg_keys: List[str] = []
    for entry in skill_entries:
        all_notes.extend(entry.get("notes", []))
        all_cfg_keys.extend(entry.get("configKeys", []))
    cfg_keys_lower = [k.lower() for k in all_cfg_keys]
    skill_name = skill_entries[0].get("name", "") if skill_entries else ""

    # 4D: Sensitive data patterns found in source code (❌)
    # 优先从 skill_entries 的 notes 中提取（SKILL.md body 扫描结果）
    body_hits: set = {n.replace("Body matches ", "").strip()
                      for n in all_notes if n.startswith("Body matches ")}
    # 补充：从 codeRisks.sensitiveData 中合并（无 SKILL.md 时由 scan_paths 扫描所得）
    for item in code_risks.get("sensitiveData", []):
        body_hits.add(item.get("label", "").strip())
    body_hits.discard("")

    # 4E: Log hygiene issues (⚠️)
    skill_log_hits = report.get("skillLogHits", [])
    log_categories: set = {hit.get("label", "") for hit in skill_log_hits}

    # 4F: Config / credential notes
    sensitive_key_notes = [
        n for n in all_notes
        if "Sensitive config key" in n or "Configured credentials detected" in n
    ]
    env_notes_local = [n for n in all_notes if n.startswith("Environment variables:")]
    cli_notes_local  = [n for n in all_notes if n.startswith("CLI dependencies:")]

    # ── 🔏 Privacy (data-exposure risks) ────────────────────────────────────
    risk_privacy = 0
    # 4A: credential exfiltration / prompting (❌)
    if "credential_exfil"   in ir_labels: risk_privacy += 40
    if "credential_request" in ir_labels: risk_privacy += 25
    # 4E: sensitive data found in log files (⚠️, each distinct category)
    risk_privacy += min(30, len(log_categories) * 15)
    # 4F: sensitive config key names (❌)
    if sensitive_key_notes: risk_privacy += 15
    # 4F: env var names that contain sensitive keywords (⚠️)
    if env_notes_local:
        all_env_vars: List[str] = []
        for n in env_notes_local:
            all_env_vars.extend(v.strip() for v in n.replace("Environment variables:", "").split(","))
        sensitive_env_count = sum(
            1 for v in all_env_vars
            if any(kw in v.lower() for kw in ["key", "secret", "token", "password", "private"])
        )
        risk_privacy += min(10, sensitive_env_count * 5)

    # ── 🔐 Privilege (identity / runtime-config tampering) ───────────────────
    risk_privilege = 0
    # 4A: writes to AI identity file or runtime config (❌)
    if "soul_write"            in ir_labels: risk_privilege += 40
    if "openclaw_config_write" in ir_labels: risk_privilege += 30

    # ── 🛡️ Integrity (code trustworthiness) ──────────────────────────────────
    risk_integrity = 0
    # 4A: dynamic code execution via eval / exec (❌)
    if "eval_obfuscation" in ir_labels: risk_integrity += 40
    if "exec_compile"     in ir_labels: risk_integrity += 35
    # 4B: obfuscation patterns detected (⚠️, each pattern)
    risk_integrity += min(30, ob_count * 15)
    # 4D: sensitive / secret data hardcoded in source (❌, each distinct type)
    risk_integrity += min(60, len(body_hits) * 25)

    # ── 🔗 Supply Chain (dependency & network risks) ─────────────────────────
    risk_supply = 0
    # 4A: dynamic package installs / raw-IP exfiltration (❌)
    if "dynamic_pip_install" in ir_labels: risk_supply += 35
    if "dynamic_npm_install" in ir_labels: risk_supply += 35
    if "ip_exfil"            in ir_labels: risk_supply += 25
    # 4C: high-risk tool usage (⚠️, each detected tool)
    risk_supply += min(40, len(hr_tools) * 12)
    # 4F: CLI / binary dependencies declared (⚠️, each binary)
    if cli_notes_local:
        cli_bins: List[str] = []
        for n in cli_notes_local:
            cli_bins.extend(v.strip() for v in n.replace("CLI dependencies:", "").split(","))
        risk_supply += min(15, len(cli_bins) * 5)

    # ── ✅ Stability (manifest completeness) ──────────────────────────────────
    risk_failure = 0
    has_skills = len(skill_entries) > 0
    # 4G: manifest integrity (❌)
    if not has_skills:
        risk_failure += 30                                    # no SKILL.md at all
    else:
        if not skill_name:                       risk_failure += 15  # missing name
        if "version"     not in cfg_keys_lower:  risk_failure += 10  # missing version
        if "description" not in cfg_keys_lower:  risk_failure += 5   # missing description

    return {
        "privacy":    min(100, risk_privacy),
        "privilege":  min(100, risk_privilege),
        "integrity":  min(100, risk_integrity),
        "supplychain": min(100, risk_supply),
        "failure":    min(100, risk_failure),
    }


def _aggregate_static_scores(skills: List[Dict[str, Any]]) -> Dict[str, int]:
    """Aggregate static analysis scores from external skills."""
    if not skills:
        return {"privacy": 0, "privilege": 0, "memory": 0, "token": 0, "failure": 0}

    all_scores = {
        "privacy": [],
        "privilege": [],
        "memory": [],
        "token": [],
        "failure": [],
    }

    for skill in skills:
        ext_scores = skill.get("externalScores", {})
        if ext_scores:
            for key in all_scores:
                if key in ext_scores and ext_scores[key] is not None:
                    all_scores[key].append(ext_scores[key])

    # Aggregate hit-keyword lists across all skills
    all_hits: Dict[str, List[str]] = {
        "privacy": [], "privilege": [], "memory": [], "token": [], "failure": []
    }
    for skill in skills:
        ext = skill.get("externalScores", {})
        for dim in all_hits:
            all_hits[dim].extend(ext.get(f"_{dim}_hits", []))

    # Calculate average risk for each dimension; base is now 0, so clean skills score 100.
    result: Dict[str, Any] = {}
    for key, values in all_scores.items():
        result[key] = int(sum(values) / len(values)) if values else 0

    # Attach de-duplicated hit lists for report rendering
    for dim, hits in all_hits.items():
        result[f"_{dim}_hits"] = sorted(set(hits))

    return result


def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def save_report(report: Dict[str, Any], output: Path) -> None:
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    _secure_write(output, payload)


def to_markdown(report: Dict[str, Any], lang: str = "en") -> str:
    """Render the audit report as a professional, checklist-driven Markdown document.

    Each security check is listed individually with a ✅ / ❌ / ⚠️ status so
    the reader can see at a glance what was verified and why anything failed.
    """

    # ── helpers ───────────────────────────────────────────────────────────────
    def _c(s: str) -> str:
        """Escape pipe so it doesn't break Markdown tables."""
        return str(s).replace("|", "｜")

    def _badge(score: int) -> str:
        if score >= 80: return "🟢 Excellent"
        if score >= 60: return "🟡 Good"
        if score >= 40: return "🟠 Fair"
        return "🔴 Needs Improvement"

    lines: List[str] = []
    check_num = [0]  # mutable counter so nested helper can increment it

    def _section(header: str, items: List[tuple]) -> None:
        """
        Append a checklist section.
        items: list of (description, status, detail)
          status True  → ✅ Pass
          status False → ❌ Fail
          status None  → ⚠️ Warning
        """
        lines.append(f"### {header}")
        lines.append("")
        lines.append("| # | Check Item | Status | Details |")
        lines.append("| :---: | --- | :---: | --- |")
        for desc, passed, detail in items:
            check_num[0] += 1
            if passed is True:
                status_str = "✅ Pass"
            elif passed is False:
                status_str = "❌ Fail"
            else:
                status_str = "⚠️ Warning"
            detail_str = _c(detail) if detail else "—"
            lines.append(f"| {check_num[0]} | {_c(desc)} | {status_str} | {detail_str} |")
        lines.append("")

    # ── pre-compute lookups ───────────────────────────────────────────────────
    permissions   = report.get("permissions", [])
    skill_entries = [e for e in permissions if e.get("type") == "skill"]
    code_risks    = report.get("codeRisks") or {}

    # Instant-reject map:  label → first matching file path
    ir_map: Dict[str, str] = {
        item["label"]: item["path"] for item in code_risks.get("instantRejects", [])
    }
    # Obfuscation map: label → first matching file path
    ob_map: Dict[str, str] = {
        item["label"]: item["path"] for item in code_risks.get("obfuscation", [])
    }

    # High-risk tool map: tool → list of (file, keyword) tuples (aggregated)
    hr_map: Dict[str, List[tuple]] = {}
    for entry in skill_entries:
        for tool in entry.get("highRiskTools", []):
            hr_map.setdefault(tool, [])
        for tool, details in (entry.get("highRiskDetails") or {}).items():
            hr_map.setdefault(tool, []).extend(details)

    # Flatten notes / config keys across all skill entries
    all_notes: List[str] = []
    all_cfg_keys: List[str] = []
    for entry in skill_entries:
        all_notes.extend(entry.get("notes", []))
        all_cfg_keys.extend(entry.get("configKeys", []))

    # Pattern labels found in skill body ("Body matches X")
    body_hits: set = {n.replace("Body matches ", "").strip()
                      for n in all_notes if n.startswith("Body matches ")}

    # Pattern labels found in skill log files
    skill_log_hits: List[Dict[str, str]] = report.get("skillLogHits", [])
    log_hit_map: Dict[str, List[Dict]] = {}
    for hit in skill_log_hits:
        log_hit_map.setdefault(hit.get("label", "?"), []).append(hit)

    # Config / credential notes
    sensitive_key_notes = [
        n for n in all_notes
        if "Sensitive config key" in n or "Configured credentials detected" in n
    ]
    env_notes = [n for n in all_notes if n.startswith("Environment variables:")]
    cli_notes = [n for n in all_notes if n.startswith("CLI dependencies:")]

    # ── 1. Title ──────────────────────────────────────────────────────────────
    skill_names = [e.get("name", "") for e in skill_entries if e.get("name")]
    title_suffix = f" — {', '.join(skill_names)}" if skill_names else ""
    lines += [
        f"# Skill Security Audit Report{title_suffix}",
        f"Generated: {report.get('generatedAt', '—')}",
        "",
    ]

    # ── 2. Verdict ────────────────────────────────────────────────────────────
    verdict = report.get("verdict", "CAUTION")
    v_map = {
        "SAFE":    ("🟢", "Safe to Install"),
        "CAUTION": ("⚠️",  "Install with Caution"),
        "REJECT":  ("❌", "Do NOT Install"),
    }
    v_emoji, v_label = v_map.get(verdict, ("⚠️", "Install with Caution"))
    lines += [
        "## Security Verdict",
        f"### {v_emoji} {v_label}",
        "",
    ]

    # ── 3. Score Overview ─────────────────────────────────────────────────────
    overall = report.get("overallScore", 0)
    static = report.get("staticScores", {})

    def _reason(score: int, *parts_thunks: tuple) -> str:
        """Return deduction reason string; '—' if perfect score."""
        if score >= 100:
            return "—"
        parts = [msg for cond, msg in parts_thunks if cond]
        return _c("; ".join(parts)) if parts else "See checklist below"

    # Pre-compute env/cli hit details for reason strings
    _env_sensitive: List[str] = []
    for _n in env_notes:
        _evars = [v.strip() for v in _n.replace("Environment variables:", "").split(",")]
        _env_sensitive.extend(v for v in _evars
                              if any(kw in v.lower() for kw in ["key", "secret", "token", "password", "private"]))

    _cli_bins: List[str] = []
    for _n in cli_notes:
        _cli_bins.extend(v.strip() for v in _n.replace("CLI dependencies:", "").split(","))

    p_score  = report.get("privacyScore",    0)
    pr_score = report.get("privilegeScore",  0)
    in_score = report.get("integrityScore",  0)
    sc_score = report.get("supplyChainScore", 0)
    st_score = report.get("failureScore",    0)

    # Pre-build reason strings (avoid backslashes inside f-string expressions)
    _log_labels    = _c(", ".join(sorted(log_hit_map)[:2]))
    _env_sens_str  = _c(", ".join(_env_sensitive[:2]))
    _body_str      = _c(", ".join(sorted(body_hits)[:2]))
    _hr_str        = _c(", ".join(sorted(hr_map)[:3]))
    _cli_str       = _c(", ".join(_cli_bins[:3]))
    _ob_cnt        = len(ob_map)
    _st_cfg        = [k.lower() for k in (skill_entries[0].get("configKeys") or [])] if skill_entries else []
    _st_name       = skill_entries[0].get("name", "") if skill_entries else ""

    _r_privacy = _reason(p_score,
        ("credential_exfil"   in ir_map, "credential exfiltration (Critical ❌)"),
        ("credential_request" in ir_map, "credential prompt via `input()` (Critical ❌)"),
        (bool(log_hit_map),       f"sensitive data in logs: {_log_labels} (⚠️)"),
        (bool(sensitive_key_notes), "sensitive config key (❌)"),
        (bool(_env_sensitive),    f"sensitive env var: {_env_sens_str} (⚠️)"),
    )
    _r_privilege = _reason(pr_score,
        ("soul_write"            in ir_map, "writes to agent identity file `SOUL.md` (Critical ❌)"),
        ("openclaw_config_write" in ir_map, "writes to `openclaw.json` runtime config (Critical ❌)"),
    )
    _r_integrity = _reason(in_score,
        ("eval_obfuscation" in ir_map, "obfuscated eval execution (Critical ❌)"),
        ("exec_compile"     in ir_map, "dynamic `exec(compile(...))` (Critical ❌)"),
        (bool(ob_map),   f"{_ob_cnt} obfuscation pattern(s) detected (⚠️)"),
        (bool(body_hits), f"hardcoded secrets: {_body_str} (❌)"),
    )
    _r_supply = _reason(sc_score,
        ("dynamic_pip_install" in ir_map, "dynamic `pip install` (Critical ❌)"),
        ("dynamic_npm_install" in ir_map, "dynamic `npm install` (Critical ❌)"),
        ("ip_exfil"            in ir_map, "HTTP request to raw IP address (Critical ❌)"),
        (bool(hr_map),   f"high-risk tools: {_hr_str} (⚠️)"),
        (bool(_cli_bins), f"CLI dependencies: {_cli_str} (⚠️)"),
    )
    _r_stability = _reason(st_score,
        (not skill_entries,                           "no `SKILL.md` found (❌)"),
        (bool(skill_entries) and not _st_name,        "missing `name` field (❌)"),
        (bool(skill_entries) and "version"     not in _st_cfg, "missing `version` field (❌)"),
        (bool(skill_entries) and "description" not in _st_cfg, "missing `description` field (❌)"),
    )

    lines += [
        "## Risk Scores",
        "",
        "| Dimension | Score | Rating | Reason for Deduction |",
        "| --- | :---: | --- | --- |",
        f"| 🏆 **Overall Security** | **{overall}/100** | **{_badge(overall)}** | — |",
        f"| 🔏 Privacy      | {p_score}/100  | {_badge(p_score)}  | {_r_privacy}    |",
        f"| 🔐 Privilege    | {pr_score}/100 | {_badge(pr_score)} | {_r_privilege}  |",
        f"| 🛡️ Integrity    | {in_score}/100 | {_badge(in_score)} | {_r_integrity}  |",
        f"| 🔗 Supply Chain | {sc_score}/100 | {_badge(sc_score)} | {_r_supply}     |",
        f"| ✅ Stability    | {st_score}/100 | {_badge(st_score)} | {_r_stability}  |",
        "",
        "> Score legend: 80–100 = Excellent | 60–79 = Good | 40–59 = Fair | <40 = Needs Improvement",
        "",
        "---",
        "",
    ]

    # ── 4. Detailed Security Checklist ───────────────────────────────────────
    lines += [
        "## 🔍 Detailed Security Checklist",
        "",
        "> Each item below was actively inspected. "
        "**✅ Pass** = no issue found. "
        "**❌ Fail** = critical problem requiring immediate attention. "
        "**⚠️ Warning** = risk detected that needs human review.",
        "",
    ]

    # ── 4A. Critical Security Checks (instant-reject) ────────────────────────
    critical_defs = [
        ("eval_obfuscation",      "No obfuscated `eval` execution (`eval(base64.b64decode(...))`)"),
        ("exec_compile",          "No dynamic code compilation (`exec(compile(...))`)"),
        ("dynamic_pip_install",   "No dynamic Python package install (`subprocess … pip install`)"),
        ("dynamic_npm_install",   "No dynamic Node package install (`subprocess … npm install`)"),
        ("ip_exfil",              "No HTTP requests sent directly to raw IP addresses"),
        ("credential_exfil",      "No credentials / secrets POSTed to external endpoints"),
        ("soul_write",            "No unauthorised writes to `SOUL.md` (agent identity file)"),
        ("openclaw_config_write", "No unauthorised writes to `openclaw.json` (runtime config)"),
        ("credential_request",    "No credential prompting via `input()` at runtime"),
    ]
    _section(
        "🚨 Critical Security Checks (Instant Reject)",
        [
            (desc, False,
             f"**CRITICAL** — detected in `{ir_map[lbl]}`; installation must be REJECTED")
            if lbl in ir_map
            else (desc, True, "")
            for lbl, desc in critical_defs
        ],
    )

    # ── 4B. Code Obfuscation Detection ───────────────────────────────────────
    obfusc_defs = [
        ("base64_exec", "No `base64.b64decode()` execution patterns (payload hiding)"),
        ("hex_dense",   "No dense hex-byte sequences (≥ 10 consecutive `\\xNN` bytes)"),
        ("chr_concat",  "No `chr()` concatenation chains (≥ 5 chained `chr()` calls)"),
    ]
    _section(
        "🔍 Code Obfuscation Detection",
        [
            (desc, None,
             f"Obfuscation pattern detected in `{ob_map[lbl]}` — manual code review required")
            if lbl in ob_map
            else (desc, True, "")
            for lbl, desc in obfusc_defs
        ],
    )

    # ── 4C. High-Risk Tool Detection ─────────────────────────────────────────
    hr_defs = [
        ("exec",    "No shell execution (`subprocess` / `os.system` / `Popen`)"),
        ("browser", "No headless browser automation (`playwright` / `selenium`)"),
        ("message", "No external messaging operations (`message.send` / `send_message`)"),
        ("nodes",   "No remote node / device control (`nodes.` / `node_client`)"),
        ("cron",    "No scheduled task / cron job registration (`schedule` / `apscheduler`)"),
        ("canvas",  "No canvas / dashboard manipulation (`canvas.` / `canvas_`)"),
        ("gateway", "No outbound network calls (`requests` / `httpx` / `aiohttp` / WebSocket)"),
    ]

    def _hr_detail(tool: str) -> str:
        hits = hr_map.get(tool, [])
        if not hits:
            return "Detected (no keyword detail available)"
        parts = [f"`{p}` (keyword: `{k}`)" for p, k in hits[:3]]
        extra = f" … +{len(hits) - 3} more" if len(hits) > 3 else ""
        return "Matched — " + "; ".join(parts) + extra

    _section(
        "⚠️ High-Risk Tool Detection",
        [
            (desc, None, _hr_detail(tool) + " — verify this usage is intentional and safe")
            if tool in hr_map
            else (desc, True, "")
            for tool, desc in hr_defs
        ],
    )

    # ── 4D. Sensitive Data in Source Code ────────────────────────────────────
    src_sensitive_defs = [
        ("API Key",        "No OpenAI / generic API key patterns (`sk-…`)"),
        ("Ethereum Key",   "No Ethereum private key (0x + 64 hex chars)"),
        ("Mnemonic",       "No mnemonic seed phrase (12–24 word sequence)"),
        ("Private Block",  "No PEM private key block (`-----BEGIN … PRIVATE KEY-----`)"),
        ("AWS Access Key", "No AWS access key (`AKIA…`)"),
        ("JWT",            "No embedded JWT token (`eyJ…`)"),
        ("Database URL",   "No DB connection string (`postgres://`, `mysql://`, …)"),
    ]
    _section(
        "🔑 Sensitive Data in Source Code",
        [
            (desc, False,
             f"Pattern `{lbl}` matched in skill source — rotate/remove immediately")
            if lbl in body_hits
            else (desc, True, "")
            for lbl, desc in src_sensitive_defs
        ],
    )

    # ── 4E. Sensitive Data in Log Files ──────────────────────────────────────
    log_sensitive_defs = [
        ("API Key",       "No API key patterns in embedded log files"),
        ("Private Key",   "No private key patterns in embedded log files"),
        ("Personal Info", "No PII (phone number / e-mail) in embedded log files"),
        ("Password",      "No password patterns in embedded log files"),
    ]
    log_items: List[tuple] = []
    for lbl, desc in log_sensitive_defs:
        if lbl in log_hit_map:
            first_hit = log_hit_map[lbl][0]
            raw_line = first_hit.get("line", "")
            snippet = (raw_line[:80] + "…") if len(raw_line) > 80 else raw_line
            log_items.append((
                desc, None,
                f"Found in `{first_hit.get('path', '?')}` — snippet: `{_c(snippet)}`"
            ))
        else:
            log_items.append((desc, True, ""))
    _section("📋 Log & Data Hygiene", log_items)

    # ── 4F. Configuration & Environment Security ─────────────────────────────
    # env_notes and cli_notes are pre-computed in the section above
    cfg_items: List[tuple] = []

    # Sensitive key names in front matter
    if sensitive_key_notes:
        cfg_items.append((
            "No sensitive config keys (`key` / `secret` / `token` / `password` / `api` / `private`)",
            False,
            "; ".join(_c(n) for n in sensitive_key_notes[:3]),
        ))
    else:
        cfg_items.append((
            "No sensitive config keys (`key` / `secret` / `token` / `password` / `api` / `private`)",
            True, "",
        ))

    # Environment variables
    if env_notes:
        cfg_items.append((
            "Environment variables declared in front matter (review each one)",
            None, "; ".join(_c(n) for n in env_notes),
        ))
    else:
        cfg_items.append((
            "Environment variables declared in front matter",
            True, "None declared",
        ))

    # CLI / binary dependencies
    if cli_notes:
        cfg_items.append((
            "CLI / binary dependencies declared in front matter (review each one)",
            None, "; ".join(_c(n) for n in cli_notes),
        ))
    else:
        cfg_items.append((
            "CLI / binary dependencies declared in front matter",
            True, "None declared",
        ))

    _section("⚙️ Configuration & Environment Security", cfg_items)

    # ── 4G. Skill Manifest Integrity ─────────────────────────────────────────
    mfst_items: List[tuple] = []
    has_skills = len(skill_entries) > 0
    mfst_items.append((
        "`SKILL.md` file present in the uploaded package",
        has_skills,
        "" if has_skills else "No `SKILL.md` found — the package cannot be fully audited",
    ))
    if has_skills:
        first = skill_entries[0]
        cfg_keys = first.get("configKeys") or []
        cfg_keys_lower = [k.lower() for k in cfg_keys]
        skill_name = first.get("name") or ""

        mfst_items.append((
            "Valid YAML front matter found in `SKILL.md`",
            bool(cfg_keys),
            f"Fields detected: `{'`, `'.join(cfg_keys)}`" if cfg_keys else "No front matter block found",
        ))
        mfst_items.append((
            "`name` field declared in front matter",
            bool(skill_name),
            f"`name: {skill_name}`" if skill_name else "Missing `name` field — add it for traceability",
        ))
        mfst_items.append((
            "`description` field declared in front matter",
            "description" in cfg_keys_lower,
            "" if "description" in cfg_keys_lower
            else "Missing `description` — add a short purpose statement",
        ))
        mfst_items.append((
            "`version` field declared in front matter",
            "version" in cfg_keys_lower,
            "" if "version" in cfg_keys_lower
            else "Missing `version` — add a semver string (e.g. `1.0.0`)",
        ))
    _section("📄 Skill Manifest Integrity", mfst_items)

    # ── 5. Key Recommendations ────────────────────────────────────────────────
    lines += ["---", "", "## 🔧 Key Recommendations", ""]
    for sug in _render_suggestions(report.get("suggestions", []), "en"):
        lines.append(f"- {sug}")
    lines.append("")

    # ── 6. Skill Package Overview ─────────────────────────────────────────────
    if skill_entries:
        lines += [
            "---",
            "",
            "## 📦 Skill Package Overview",
            "",
            "| Skill | High-Risk Tools Detected | Risk Level |",
            "| --- | --- | --- |",
        ]
        for entry in skill_entries:
            tools_str = ", ".join(entry.get("highRiskTools", [])) or "None"
            rl = _risk_label(entry.get("riskScore", 0))
            icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(rl, "")
            lines.append(
                f"| {_c(entry.get('name', '-'))} | {tools_str} | {icon} {rl} |"
            )
        lines.append("")

    # ── 7. AI Review (optional) ───────────────────────────────────────────────
    ai_review = report.get("aiReview")
    if ai_review:
        lines += ["---", "", "## 🤖 AI Review", ""]
        if ai_review.get("status") == "ok":
            lines.append(ai_review.get("summary", "").strip() or "(empty)")
        else:
            lines.append(
                f"> ⚠️ AI review failed: {ai_review.get('reason', 'unknown')}"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan OpenClaw workspace for agent/skill risks.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Optional JSON report path")
    parser.add_argument("--markdown", type=Path, help="Optional Markdown report path")
    parser.add_argument("--lang", choices=["en", "zh"], default="en", help="Report language (default: en)")
    parser.add_argument("--ai-review", action="store_true", help="Send skill contents to an AI reviewer (requires OPENAI_API_KEY)")
    parser.add_argument("--ai-model", default=os.getenv("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini"), help="Model to use when --ai-review is enabled")
    parser.add_argument("--skill-path", action="append", default=[], help="Local skill paths (file or directory)")
    parser.add_argument("--skill-url", action="append", default=[], help="Remote skill URLs")
    parser.add_argument("--agent-path", action="append", default=[], help="Local agent JSON files or openclaw.json excerpts")
    parser.add_argument("--agent-url", action="append", default=[], help="Remote agent JSON URLs")
    args = parser.parse_args()

    extra_skills = load_external_skills(args.skill_path, args.skill_url)
    extra_agents = load_external_agents(args.agent_path, args.agent_url)
    # 始终把原始路径传入，确保即使没有 SKILL.md 也能完整扫描代码风险
    report = generate_report(
        extra_skills=extra_skills,
        extra_agents=extra_agents,
        scan_paths=args.skill_path,
    )
    if args.ai_review:
        report["aiReview"] = run_ai_review(extra_skills, args.ai_model, args.lang)
    if args.output:
        save_report(report, args.output)
        print(f"✅ JSON report saved to {args.output.name}")
    if args.markdown:
        _secure_write(args.markdown, to_markdown(report, args.lang))
        print(f"✅ Markdown report saved to {args.markdown.name}")
    if not args.output and not args.markdown:
        print("Audit completed, but no output path was provided.")


if __name__ == "__main__":
    main()
