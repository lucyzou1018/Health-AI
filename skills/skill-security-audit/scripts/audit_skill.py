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
MNEMONIC_KEYWORDS = ("mnemonic", "seed phrase", "seed")

# ── Instant-reject patterns: any match → verdict=REJECT ─────────────────────
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

# ── Obfuscation detection ─────────────────────────────────────────────────────
OBFUSCATION_PATTERNS: Dict[str, Any] = {
    "base64_exec":  re.compile(r'base64\.b64decode\s*\(', re.IGNORECASE),
    "hex_dense":    re.compile(r'(\\x[0-9a-fA-F]{2}){10,}'),
    "chr_concat":   re.compile(r'(chr\s*\(\s*\d+\s*\)\s*\+\s*){5,}'),
}

# ── Side-effects: external write detection ────────────────────────────────────
SIDE_EFFECT_PATTERNS: Dict[str, Any] = {
    "file_write":  re.compile(r'open\s*\([^)]+,\s*["\'][wa][^"\']*["\']', re.IGNORECASE),
    "path_write":  re.compile(r'\.(write_text|write_bytes)\s*\(', re.IGNORECASE),
    "env_write":   re.compile(r'os\.environ\s*\[|os\.putenv\s*\(', re.IGNORECASE),
    "net_mutate":  re.compile(r'\.(post|put|patch|delete)\s*\(\s*["\']https?://', re.IGNORECASE),
    "fs_modify":   re.compile(r'(os\.(remove|unlink|makedirs|rename)|shutil\.(rmtree|move|copy2?))\s*\(', re.IGNORECASE),
    "db_write":    re.compile(r'(execute|executemany)\s*\([^)]{0,200}(INSERT|UPDATE|DELETE|DROP)\b', re.IGNORECASE | re.DOTALL),
}

# ── Data Access: sensitive read detection ─────────────────────────────────────
DATA_ACCESS_PATTERNS: Dict[str, Any] = {
    "sensitive_path":  re.compile(r'["\']/(etc|proc|sys)/|~/\.(ssh|aws|gnupg)/', re.IGNORECASE),
    "env_secret_read": re.compile(r'os\.(getenv|environ\.get)\s*\(\s*["\'][^"\'"]*(key|secret|token|password|api)[^"\']*["\']', re.IGNORECASE),
    "cred_file_read":  re.compile(r'open\s*\([^)]*\.(pem|key|p12|pfx|crt|jks)[^)"\']*["\']r', re.IGNORECASE),
    "ssh_access":      re.compile(r'\b(id_rsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts)\b', re.IGNORECASE),
    "aws_cred":        re.compile(r'(\.aws/credentials|boto3\.Session|aws_access_key_id)', re.IGNORECASE),
}

# ── Tool Call Depth: deep call-chain detection ────────────────────────────────
# Method chain .a().b().c().d() depth >= 4
_TOOL_CHAIN_PAT = re.compile(r'(\.\w+\s*\([^)]*\)){4,}')
# Nested function calls f(g(h(i(...)))) depth >= 4
_TOOL_NESTED_PAT = re.compile(r'\w+\s*\([^()]*\w+\s*\([^()]*\w+\s*\([^()]*\w+\s*\(')


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


def _load_skill_text_from_path(raw_path: str) -> Tuple[str, str]:
    path = Path(raw_path).expanduser()
    candidate = path
    if path.is_dir():
        candidate = path / "SKILL.md"
    if not candidate.exists():
        raise FileNotFoundError(f"SKILL.md not found: {candidate}")
    text = candidate.read_text(encoding="utf-8", errors="ignore")
    return candidate.stem, text


def _validate_url(url: str) -> None:
    """Block non-HTTP schemes and internal/private addresses to prevent SSRF."""
    import ipaddress as _ipaddress
    import socket as _socket

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}. Only http/https allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname.")
    # Resolve hostname and reject private/loopback/link-local IPs
    try:
        resolved_ips = _socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in resolved_ips:
            ip = _ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"URL resolves to internal address ({ip}), request blocked.")
    except _socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {hostname}")


def _fetch_text_from_url(url: str) -> str:
    _validate_url(url)
    try:
        context = ssl.create_default_context()
        with urlopen(url, context=context, timeout=30) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="ignore")
    except Exception:
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "30", url],
            capture_output=True, text=True,
        )
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
        except Exception:
            pass
    for url in url_inputs or []:
        if not url:
            continue
        try:
            name_hint, text = _load_skill_text_from_url(url)
            entries.append(_analyze_external_skill(name_hint, text, url))
        except (URLError, OSError):
            pass
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
        except Exception:
            pass
    for url in url_inputs or []:
        if not url:
            continue
        try:
            _, data = _load_agent_json_from_url(url)
            _extend(data, url)
        except (URLError, OSError, json.JSONDecodeError):
            pass
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
        pass  # permissions are broader than recommended 600


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
    seen: set = set()
    all_paths: List[Path] = []
    for pattern in ("*.md", "*.json", "*.yaml", "*.yml", "*.txt"):
        for p in directory.glob(pattern):
            if p not in seen:
                seen.add(p)
                all_paths.append(p)
    for path in all_paths:
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
            file_issues.append("File exceeds 1MB — consider archiving")
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

    # Files over this threshold are tail-sampled to avoid blocking the audit on huge logs
    MAX_SCAN_BYTES = 512_000   # 512 KB
    TAIL_LINES     = 1_000     # scan only the last 1000 lines when the limit is exceeded

    keywords = ("error", "exception", "traceback", "failed")
    for path in directory.glob("*.log"):
        errors = 0
        lines = 0
        try:
            stat_info = path.stat()
            file_size = stat_info.st_size

            if file_size > MAX_SCAN_BYTES:
                # Large file: read only the last TAIL_LINES lines; metadata is recorded normally
                from collections import deque
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    tail = list(deque(fh, maxlen=TAIL_LINES))
                scan_lines = tail
                # Line/error counts are based on the sample — marked as estimates
                lines = TAIL_LINES  # represent with sampled line count (noted)
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


def _render_suggestions(suggestions: List[Dict[str, Any]], lang: str) -> List[str]:
    rendered: List[str] = []
    for item in suggestions:
        stype = item.get("type")
        if stype == "memory_sensitive":
            files = item.get("files", [])
            summary = "; ".join(
                f"{Path(entry['path']).name} ({', '.join(entry.get('issues', []))})" for entry in files
            )
            rendered.append(f"Scrub or relocate sensitive content in: {summary}")
        elif stype == "memory_missing":
            rendered.append("Provide a memory/ directory so privacy scans can run.")
        elif stype == "tool":
            tool = item.get("tool", "-")
            skill = item.get("skill", "skill")
            hint = TOOL_REMEDIATION_HINTS.get(tool, f"Add guardrails before invoking {tool}.")
            rendered.append(f"{skill} – {hint}")
        elif stype == "memory_size":
            size_text = human_size(item.get("size", 0))
            rendered.append(f"Memory footprint is {size_text}; archive or summarize files over 1MB.")
        elif stype == "token":
            model = item.get("model")
            tokens = item.get("tokens")
            rendered.append(f"Model {model} consumed {tokens} tokens recently; enforce budgets or switch to cheaper models.")
        elif stype == "log_errors":
            path = item.get("path")
            errors = item.get("errors")
            lines = item.get("lines")
            rendered.append(f"{path} logged {errors} errors across {lines} lines; investigate and add retries/timeouts.")
        elif stype == "none":
            rendered.append("No remediation required based on current telemetry.")
    return rendered


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


def _build_skill_bundle(paths: List[Path], max_files: int = 200) -> str:
    """
    Concatenate the full contents of all files in the skill package into a
    single string to send to the LLM.

    No character limit is applied: mainstream models (GPT-4o / Grok) support
    128k tokens (~500k characters), which is well above the typical skill
    package size. If a future over-large package triggers context_length_exceeded,
    add chunking logic here as needed.
    """
    collected: List[str] = []
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
            text = file_path.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            continue
        if not text:
            continue
        collected.append(f"### {file_path}\n{text}")

    return "\n\n".join(collected)


def run_ai_review(skill_entries: List[Dict[str, Any]], model: str, lang: str, detail: bool = False) -> Dict[str, Any]:
    """Run AI code review and return per-dimension risk scores (0-100) and overall risk level.
    When detail=True, also request a list of specific findings from the LLM.
    """
    _EMPTY = {"status": "skipped", "reason": "no local skill paths",
              "hasRisk": False, "riskLevel": "none",
              "privacyRisk": 0, "privilegeRisk": 0, "integrityRisk": 0,
              "dependencyRisk": 0, "stabilityRisk": 0, "findings": []}

    paths = []
    for entry in skill_entries or []:
        origin = entry.get("originPath")
        if origin:
            p = Path(origin)
            if p.exists():
                paths.append(p)
    if not paths:
        return _EMPTY

    try:
        from openai import OpenAI
    except Exception as exc:
        return {**_EMPTY, "status": "error", "reason": f"openai package missing: {exc}"}

    # Supports OPENAI_API_KEY and XAI_API_KEY (xAI / Grok)
    openai_key = os.getenv("OPENAI_API_KEY")
    xai_key    = os.getenv("XAI_API_KEY")
    if not openai_key and not xai_key:
        return {**_EMPTY, "status": "error", "reason": "No API key configured (set OPENAI_API_KEY or XAI_API_KEY)"}

    bundle = _build_skill_bundle(paths)
    if not bundle:
        return {**_EMPTY, "reason": "skill files empty"}

    if openai_key:
        client = OpenAI(api_key=openai_key)
        model_name = model
    else:
        client = OpenAI(api_key=xai_key, base_url="https://api.x.ai/v1")
        model_name = model if model.startswith("grok") else "grok-3-mini"

    _findings_schema = (
        ',\n  "findings": ["<one-line description of specific risk>", ...] '
        '(up to 5 items; empty array [] if no risk found)'
        if detail else ""
    )
    system_prompt = (
        "You are a strict security auditor for AI agent skill packages. "
        "Analyze the provided skill files. "
        "Return ONLY a valid JSON object with NO markdown fences and NO extra text:\n"
        "{\n"
        '  "riskLevel": "none|low|medium|high",\n'
        '  "privacyRisk": <integer 0-100>,\n'
        '  "privilegeRisk": <integer 0-100>,\n'
        '  "integrityRisk": <integer 0-100>,\n'
        '  "dependencyRisk": <integer 0-100>,\n'
        f'  "stabilityRisk": <integer 0-100>{_findings_schema}\n'
        "}\n"
        "Risk scale: 0=clean, 1-30=low, 31-60=medium, 61-100=high. "
        "riskLevel must match the highest individual score range."
    )
    user_prompt = "Analyze the following skill package for security risks:\n\n" + bundle

    def _parse_result(raw: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response; returns None on parse failure."""
        import re as _re
        json_match = _re.search(r'\{[\s\S]+?\}', raw)
        if not json_match:
            return None
        parsed = json.loads(json_match.group())
        risk_level   = str(parsed.get("riskLevel", "none")).lower()
        privacy_r    = max(0, min(100, int(parsed.get("privacyRisk",    0))))
        privilege_r  = max(0, min(100, int(parsed.get("privilegeRisk",  0))))
        integrity_r  = max(0, min(100, int(parsed.get("integrityRisk",  0))))
        dependency_r = max(0, min(100, int(parsed.get("dependencyRisk", 0))))
        stability_r  = max(0, min(100, int(parsed.get("stabilityRisk",  0))))
        has_risk = risk_level != "none" or max(
            privacy_r, privilege_r, integrity_r, dependency_r, stability_r) > 0
        raw_findings = parsed.get("findings", [])
        findings = [str(f) for f in raw_findings if f] if isinstance(raw_findings, list) else []
        return {
            "status":         "ok",
            "model":          model_name,
            "riskLevel":      risk_level,
            "hasRisk":        has_risk,
            "privacyRisk":    privacy_r,
            "privilegeRisk":  privilege_r,
            "integrityRisk":  integrity_r,
            "dependencyRisk": dependency_r,
            "stabilityRisk":  stability_r,
            "findings":       findings,
        }

    def _call_responses_api() -> Optional[str]:
        """Try the OpenAI Responses API (added in SDK v2, suitable for gpt-4.1 / o-series models)."""
        try:
            resp = client.responses.create(
                model=model_name,
                instructions=system_prompt,
                input=user_prompt,
            )
            # SDK v2: resp.output_text or resp.output[0].content[0].text
            if hasattr(resp, "output_text"):
                return (resp.output_text or "").strip()
            if hasattr(resp, "output") and resp.output:
                item = resp.output[0]
                if hasattr(item, "content") and item.content:
                    return (item.content[0].text or "").strip()
        except Exception:
            pass
        return None

    # ── Path 1: Chat Completions (gpt-4o / gpt-4.1 / grok and other chat models) ──
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0,
        )
        raw = (response.choices[0].message.content or "").strip()
        result = _parse_result(raw)
        return result if result else {**_EMPTY, "status": "ok", "model": model_name}

    except Exception as chat_exc:
        chat_err = str(chat_exc)

        # ── Path 2: Legacy Completions (codex / instruct and other older completion models) ──
        if "not a chat model" in chat_err or "v1/completions" in chat_err:
            try:
                legacy_response = client.completions.create(
                    model=model_name,
                    prompt=system_prompt + "\n\n" + user_prompt,
                    max_tokens=256,
                    temperature=0,
                )
                raw = (legacy_response.choices[0].text or "").strip()
                result = _parse_result(raw)
                if result:
                    return result
                # Legacy completions also failed; fall through to Responses API
            except Exception:
                pass

            # ── Path 3: Responses API (SDK v2, gpt-4.1 / o-series models) ─────────
            raw = _call_responses_api()
            if raw is not None:
                result = _parse_result(raw)
                return result if result else {**_EMPTY, "status": "ok", "model": model_name}

            return {**_EMPTY, "status": "error",
                    "reason": f"Model '{model_name}' is not supported by any available API endpoint; check your SKILL_AUDIT_AI_MODEL configuration"}

        # ── Chat Completions returned another error; try Responses API before failing ──
        raw = _call_responses_api()
        if raw is not None:
            result = _parse_result(raw)
            return result if result else {**_EMPTY, "status": "ok", "model": model_name}

        return {**_EMPTY, "status": "error", "reason": f"[model={model_name}] {chat_err}"}


def _risk_label(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def detect_code_risks(base_path: Optional[Path]) -> Dict[str, Any]:
    """Detect instant-reject flags, obfuscated code, supply-chain attack risks, and hardcoded
    sensitive data in source. Also detects: Side-Effects (external writes), Data Access
    (sensitive reads), and Tool Call Depth (call-chain depth).
    """
    result: Dict[str, Any] = {
        "instantRejects": [],
        "obfuscation": [],
        "sensitiveData": [],
        "sideEffects": [],
        "dataAccess": [],
        "toolCallDepth": [],
    }
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
            # Hardcoded sensitive data in source (API Key / private key / JWT etc.)
            for label, pat in SENSITIVE_PATTERNS.items():
                if pat.search(text):
                    result["sensitiveData"].append({"label": label, "path": rel})
            # Side-Effects: external write operations
            for label, pat in SIDE_EFFECT_PATTERNS.items():
                if pat.search(text):
                    # file_write: exclude /tmp writes (lower risk)
                    if label == "file_write" and "/tmp" in text.lower():
                        continue
                    result["sideEffects"].append({"label": label, "path": rel})
            # Data Access: sensitive data reads
            for label, pat in DATA_ACCESS_PATTERNS.items():
                if pat.search(text):
                    result["dataAccess"].append({"label": label, "path": rel})
            # Tool Call Depth: method chain depth >= 4
            if _TOOL_CHAIN_PAT.search(text) or _TOOL_NESTED_PAT.search(text):
                result["toolCallDepth"].append({"label": "deep_call_chain", "path": rel})
    # Deduplicate (keep one entry per label)
    for key in ("sensitiveData", "sideEffects", "dataAccess", "toolCallDepth"):
        result[key] = list({item["label"]: item for item in result[key]}.values())
    return result


def compute_verdict(report: Dict[str, Any]) -> str:
    """Return final security verdict: SAFE / CAUTION / REJECT."""
    code_risks = report.get("codeRisks", {})
    if code_risks.get("instantRejects"):
        return "REJECT"
    overall = report.get("overallScore", 0)
    if overall >= 70:
        return "SAFE"
    if overall >= 45:
        return "CAUTION"
    return "REJECT"


def generate_report(
    extra_skills: Optional[List[Dict[str, Any]]] = None,
    extra_agents: Optional[List[Dict[str, Any]]] = None,
    scan_paths: Optional[List[str]] = None,
    ai_model: Optional[str] = None,
    ai_detail: bool = False,
) -> Dict[str, Any]:
    """
    scan_paths: list of raw input directories (code scan always runs regardless of whether
    SKILL.md is present). When an uploaded ZIP contains no SKILL.md, load_external_skills()
    returns an empty list and the code scan would be skipped. Passing raw directories via
    scan_paths ensures the scan cannot be bypassed.
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
    aggregate_code_risks: Dict[str, Any] = {
        "instantRejects": [], "obfuscation": [], "sensitiveData": [],
        "sideEffects": [], "dataAccess": [], "toolCallDepth": [],
    }

    # Track already-scanned paths to avoid scanning the same directory twice
    _scanned: set = set()

    def _merge_risks(risks: Dict[str, Any]) -> None:
        for key in ("instantRejects", "obfuscation", "sensitiveData",
                    "sideEffects", "dataAccess", "toolCallDepth"):
            aggregate_code_risks[key].extend(risks.get(key, []))

    for entry in skills:
        origin = entry.get("originPath")
        if origin:
            origin_path = Path(origin).resolve()
            if origin_path.exists():
                _scanned.add(str(origin_path))
                skill_log_hits.extend(scan_skill_logs(origin_path))
                _merge_risks(detect_code_risks(origin_path))

    # Run code scan on all scan_paths (even if SKILL.md is missing)
    for raw in scan_paths or []:
        try:
            p = Path(raw).expanduser().resolve()
        except Exception:
            continue
        if not p.exists() or str(p) in _scanned:
            continue
        _scanned.add(str(p))
        skill_log_hits.extend(scan_skill_logs(p))
        _merge_risks(detect_code_risks(p))

    # Global deduplication (keep one entry per label)
    for _key in ("sensitiveData", "sideEffects", "dataAccess", "toolCallDepth"):
        aggregate_code_risks[_key] = list(
            {item["label"]: item for item in aggregate_code_risks[_key]}.values()
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

    # ── AI code review (mandatory check; runs before scoring and affects dimension scores) ──
    _model = ai_model or os.getenv("SKILL_AUDIT_AI_MODEL", "")
    report["aiReview"] = (
        run_ai_review(skills, _model, "en", detail=ai_detail)
        if _model
        else {"status": "skipped", "reason": "No AI model configured (set SKILL_AUDIT_AI_MODEL environment variable)",
              "hasRisk": False, "riskLevel": "none",
              "privacyRisk": 0, "privilegeRisk": 0, "integrityRisk": 0,
              "dependencyRisk": 0, "stabilityRisk": 0, "findings": []}
    )

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
                       · Data Access: sensitive path / env secret / cred file / SSH / AWS reads
    🔐 Privilege    ← 4A: soul_write / openclaw_config_write (identity & config tampering only)
                       · Side-Effects: file write / env write / net POST-PUT-DELETE / db write / fs modify
    🛡️ Integrity    ← 4A: eval_obfuscation / exec_compile · 4B: obfuscation · 4D: sensitive data in source
                       · Tool Call Depth: method chain / nested call depth ≥ 4
    🔗 Dependency Risk ← 4A: dynamic installs / ip_exfil · 4C: high-risk tools · 4F: CLI deps
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
    # Primary: extract from skill_entries notes (SKILL.md body scan results)
    body_hits: set = {n.replace("Body matches ", "").strip()
                      for n in all_notes if n.startswith("Body matches ")}
    # Supplement: merge from codeRisks.sensitiveData (from scan_paths when no SKILL.md)
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

    # New check results
    side_effect_labels: set = {item["label"] for item in code_risks.get("sideEffects", [])}
    data_access_labels: set = {item["label"] for item in code_risks.get("dataAccess", [])}
    tool_depth_count: int   = len(code_risks.get("toolCallDepth", []))

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
    # Data Access: reading sensitive system paths / credentials / SSH keys (⚠️)
    _da_weights = {"sensitive_path": 20, "env_secret_read": 15,
                   "cred_file_read": 25, "ssh_access": 20, "aws_cred": 20}
    risk_privacy += min(40, sum(_da_weights.get(lbl, 10) for lbl in data_access_labels))

    # ── 🔐 Privilege (identity / runtime-config tampering) ───────────────────
    risk_privilege = 0
    # 4A: writes to AI identity file or runtime config (❌)
    if "soul_write"            in ir_labels: risk_privilege += 40
    if "openclaw_config_write" in ir_labels: risk_privilege += 30
    # Side-Effects: external write operations (⚠️)
    _se_weights = {"file_write": 10, "path_write": 10, "env_write": 20,
                   "net_mutate": 15, "fs_modify": 10, "db_write": 15}
    risk_privilege += min(40, sum(_se_weights.get(lbl, 10) for lbl in side_effect_labels))

    # ── 🛡️ Integrity (code trustworthiness) ──────────────────────────────────
    risk_integrity = 0
    # 4A: dynamic code execution via eval / exec (❌)
    if "eval_obfuscation" in ir_labels: risk_integrity += 40
    if "exec_compile"     in ir_labels: risk_integrity += 35
    # 4B: obfuscation patterns detected (⚠️, each pattern)
    risk_integrity += min(30, ob_count * 15)
    # 4D: sensitive / secret data hardcoded in source (❌, each distinct type)
    risk_integrity += min(60, len(body_hits) * 25)
    # Tool Call Depth: deeply nested/chained calls (⚠️)
    risk_integrity += min(20, tool_depth_count * 10)

    # ── 🔗 Dependency Risk (dependency & network risks) ──────────────────────
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

    # ── 🤖 AI code review deductions (only triggered for medium / high risk; low does not deduct) ──
    # riskLevel "low" represents negligible risk — not enough to affect scores, avoiding
    # the illusion of a uniform 1-point deduction across all dimensions.
    ai_review = report.get("aiReview") or {}
    _ai_risk_level = ai_review.get("riskLevel", "none")
    if ai_review.get("status") == "ok" and _ai_risk_level in ("medium", "high"):
        risk_privacy   += min(25, ai_review.get("privacyRisk",    0) // 4)
        risk_privilege += min(25, ai_review.get("privilegeRisk",  0) // 4)
        risk_integrity += min(25, ai_review.get("integrityRisk",  0) // 4)
        risk_supply    += min(25, ai_review.get("dependencyRisk", 0) // 4)
        risk_failure   += min(25, ai_review.get("stabilityRisk",  0) // 4)

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


def to_markdown(report: Dict[str, Any], lang: str = "en", ai_detail: bool = False) -> str:
    """Render the audit report as a professional, checklist-driven Markdown document.

    Each security check is listed individually with a ✅ / ❌ / ⚠️ status so
    the reader can see at a glance what was verified and why anything failed.
    """

    # ── helpers ───────────────────────────────────────────────────────────────
    def _c(s: str) -> str:
        """Escape pipe so it doesn't break Markdown tables."""
        return str(s).replace("|", "\uff5c")

    def _badge(score: int) -> str:
        if score >= 80: return "🟢 Excellent"
        if score >= 60: return "🟡 Good"
        if score >= 40: return "🟠 Caution"
        return "🔴 Risk"

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
    # Side-Effects map: label → file path
    se_map: Dict[str, str] = {
        item["label"]: item["path"] for item in code_risks.get("sideEffects", [])
    }
    # Data Access map: label → file path
    da_map: Dict[str, str] = {
        item["label"]: item["path"] for item in code_risks.get("dataAccess", [])
    }
    # Tool Call Depth list
    tc_list: List[Dict[str, str]] = code_risks.get("toolCallDepth", [])

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
    _se_str        = _c(", ".join(sorted(se_map)[:3]))
    _da_str        = _c(", ".join(sorted(da_map)[:3]))

    _r_privacy = _reason(p_score,
        ("credential_exfil"   in ir_map, "credential exfiltration (Critical ❌)"),
        ("credential_request" in ir_map, "credential prompt via `input()` (Critical ❌)"),
        (bool(log_hit_map),       f"sensitive data in logs: {_log_labels} (⚠️)"),
        (bool(sensitive_key_notes), "sensitive config key (❌)"),
        (bool(_env_sensitive),    f"sensitive env var: {_env_sens_str} (⚠️)"),
        (bool(da_map),            f"sensitive data access: {_da_str} (⚠️)"),
    )
    _r_privilege = _reason(pr_score,
        ("soul_write"            in ir_map, "writes to agent identity file `SOUL.md` (Critical ❌)"),
        ("openclaw_config_write" in ir_map, "writes to `openclaw.json` runtime config (Critical ❌)"),
        (bool(se_map),            f"external write operations: {_se_str} (⚠️)"),
    )
    _r_integrity = _reason(in_score,
        ("eval_obfuscation" in ir_map, "obfuscated eval execution (Critical ❌)"),
        ("exec_compile"     in ir_map, "dynamic `exec(compile(...))` (Critical ❌)"),
        (bool(ob_map),   f"{_ob_cnt} obfuscation pattern(s) detected (⚠️)"),
        (bool(body_hits), f"hardcoded secrets: {_body_str} (❌)"),
        (bool(tc_list),   f"{len(tc_list)} deep call chain(s) detected (⚠️)"),
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
        f"| 🔗 Dependency Risk | {sc_score}/100 | {_badge(sc_score)} | {_r_supply}     |",
        f"| ✅ Stability    | {st_score}/100 | {_badge(st_score)} | {_r_stability}  |",
        "",
        "> Score legend: 80–100 = Excellent | 60–79 = Good | 40–59 = Caution | <40 = Risk",
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

    # ── 4E. Side-Effects Detection ───────────────────────────────────────────
    se_defs = [
        ("file_write", "No file write operations (`open` in write/append mode)"),
        ("path_write", "No `Path.write_text` / `write_bytes` operations"),
        ("env_write",  "No environment variable modification (`os.environ` assignment / `os.putenv`)"),
        ("net_mutate", "No network write operations (HTTP POST / PUT / PATCH / DELETE)"),
        ("fs_modify",  "No filesystem modifications (`os.remove` / `makedirs` / `shutil.move` etc.)"),
        ("db_write",   "No database write operations (INSERT / UPDATE / DELETE / DROP)"),
    ]
    _section(
        "💥 Side-Effects Detection",
        [
            (desc, None, f"Detected in `{se_map[lbl]}` — verify this write is intentional and scoped")
            if lbl in se_map
            else (desc, True, "")
            for lbl, desc in se_defs
        ],
    )

    # ── 4F. Data Access Analysis ─────────────────────────────────────────────
    da_defs = [
        ("sensitive_path",  "No access to sensitive system paths (`/etc/`, `~/.ssh/`, `~/.aws/`, `/proc/`)"),
        ("env_secret_read", "No reading of secret environment variables (key / secret / token / password)"),
        ("cred_file_read",  "No reading of credential files (`.pem` / `.key` / `.crt` / `.p12`)"),
        ("ssh_access",      "No SSH key file access (`id_rsa` / `id_ecdsa` / `authorized_keys`)"),
        ("aws_cred",        "No AWS credential access (`~/.aws/credentials` / `boto3.Session`)"),
    ]
    _section(
        "🗄️ Data Access Analysis",
        [
            (desc, None, f"Detected in `{da_map[lbl]}` — confirm this access is required and authorised")
            if lbl in da_map
            else (desc, True, "")
            for lbl, desc in da_defs
        ],
    )

    # ── 4G. Tool Call Depth ───────────────────────────────────────────────────
    if tc_list:
        tc_items = [
            (
                f"Deep call chain in `{item['path']}` (method chain or nested calls depth ≥ 4)",
                None,
                "Complex call depth may obscure behaviour — simplify or add inline comments",
            )
            for item in tc_list
        ]
    else:
        tc_items = [("No excessively deep call chains detected (depth < 4)", True, "")]
    _section("🔁 Tool Call Depth", tc_items)

    # ── 4H. Sensitive Data in Log Files ──────────────────────────────────────
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

    # ── 4I. Configuration & Environment Security ─────────────────────────────
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

    # ── 4J. Skill Manifest Integrity ─────────────────────────────────────────
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

    # ── 7. AI Code Review (mandatory check) ─────────────────────────────────
    ai_review = report.get("aiReview") or {}
    lines += ["---", "", "## 🤖 AI Code Review", ""]
    ai_status = ai_review.get("status", "skipped")
    if ai_status == "ok":
        # Risk level icon mapping
        _rl_icon = {"none": "🟢", "low": "🟡", "medium": "🟠", "high": "🔴"}
        _rl = ai_review.get("riskLevel", "none").lower()
        _rl_display = f"{_rl_icon.get(_rl, '⚪')} {_rl.capitalize()}"

        if ai_review.get("hasRisk"):
            lines += [
                "| Check | Status | Risk Level |",
                "| --- | :---: | :---: |",
                f"| AI Code Security Review | ⚠️ Risk Detected | {_rl_display} |",
                "",
            ]
            if ai_detail:
                # Detail mode: show per-dimension risk scores and specific findings
                lines += [
                    "| Dimension | Risk Score |",
                    "| --- | :---: |",
                    f"| 🔏 Privacy | {ai_review.get('privacyRisk', 0)}/100 |",
                    f"| 🔐 Privilege | {ai_review.get('privilegeRisk', 0)}/100 |",
                    f"| 🛡️ Integrity | {ai_review.get('integrityRisk', 0)}/100 |",
                    f"| 🔗 Dependency Risk | {ai_review.get('dependencyRisk', 0)}/100 |",
                    f"| ✅ Stability | {ai_review.get('stabilityRisk', 0)}/100 |",
                    "",
                ]
                findings = ai_review.get("findings") or []
                if findings:
                    lines.append("**Findings:**")
                    for f in findings[:5]:
                        lines.append(f"- {f}")
                    lines.append("")
            lines.append("> AI review identified potential security risks. Risk scores have been applied to the dimension scores above.")
        else:
            lines += [
                "| Check | Status | Risk Level |",
                "| --- | :---: | :---: |",
                f"| AI Code Security Review | ✅ Pass | {_rl_display} |",
            ]
    elif ai_status == "error":
        lines.append(f"> ⚠️ AI review unavailable: {ai_review.get('reason', 'unknown')}")
    else:
        lines.append(f"> ℹ️ AI review skipped: {ai_review.get('reason', 'SKILL_AUDIT_AI_MODEL not configured')}")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan OpenClaw workspace for agent/skill risks.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Optional JSON report path")
    parser.add_argument("--markdown", type=Path, help="Optional Markdown report path")
    parser.add_argument("--lang", choices=["en", "zh"], default="en", help="Report language (default: en)")
    parser.add_argument("--ai-review", action="store_true", help="Send skill contents to an AI reviewer (requires OPENAI_API_KEY)")
    parser.add_argument("--ai-model", default=os.getenv("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini"), help="Model to use when --ai-review is enabled")
    parser.add_argument("--ai-detail", action="store_true",
                        default=os.getenv("SKILL_AUDIT_AI_DETAIL", "").lower() in ("1", "true", "yes"),
                        help="Show detailed AI review findings in report (env: SKILL_AUDIT_AI_DETAIL)")
    parser.add_argument("--skill-path", action="append", default=[], help="Local skill paths (file or directory)")
    parser.add_argument("--skill-url", action="append", default=[], help="Remote skill URLs")
    parser.add_argument("--agent-path", action="append", default=[], help="Local agent JSON files or openclaw.json excerpts")
    parser.add_argument("--agent-url", action="append", default=[], help="Remote agent JSON URLs")
    args = parser.parse_args()

    extra_skills = load_external_skills(args.skill_path, args.skill_url)
    extra_agents = load_external_agents(args.agent_path, args.agent_url)
    # Always pass raw paths so code risk scanning is complete even without SKILL.md
    # ai_model is always passed in (determined by SKILL_AUDIT_AI_MODEL env var or --ai-model flag)
    report = generate_report(
        extra_skills=extra_skills,
        extra_agents=extra_agents,
        scan_paths=args.skill_path,
        ai_model=args.ai_model,
        ai_detail=args.ai_detail,
    )
    if args.output:
        save_report(report, args.output)
    if args.markdown:
        _secure_write(args.markdown, to_markdown(report, args.lang, args.ai_detail))


if __name__ == "__main__":
    main()
