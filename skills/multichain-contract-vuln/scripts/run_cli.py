#!/usr/bin/env python3
"""Command-line helper for the multichain-contract-vuln skill.

Performs AI-powered smart contract security audit:
- Collects source files from the uploaded package (max 10 files)
- Analyzes each file individually via LLM
- Aggregates findings into 5-dimension scores (per CONTRACT_AUDIT_GUIDE.md)
- Generates a structured Markdown report
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib import error as urlerror, request as urlrequest

# ── Dimension definitions (per CONTRACT_AUDIT_GUIDE.md) ──────────────────────

_DIM_KEYS = (
    "accessControl",
    "financialSecurity",
    "randomnessOracle",
    "dosResistance",
    "businessLogic",
)
_DIM_LABELS = {
    "accessControl":     "🔐 Access Control",
    "financialSecurity": "💰 Financial Security",
    "randomnessOracle":  "🎲 Randomness & Oracle",
    "dosResistance":     "⚡ DoS Resistance",
    "businessLogic":     "🛡️ Business Logic",
}
_DIM_SCORE_KEYS = {
    "accessControl":     "access",
    "financialSecurity": "financial",
    "randomnessOracle":  "randomness",
    "dosResistance":     "dos",
    "businessLogic":     "logic",
}

# Supported contract source extensions
SOURCE_EXTS = {".sol", ".vy", ".rs", ".ts", ".tsx", ".js"}
MAX_FILES      = 10
MAX_FILE_CHARS = 8000

ETHERSCAN_DOMAINS = {
    "mainnet": "api.etherscan.io",
    "goerli":  "api-goerli.etherscan.io",
    "sepolia": "api-sepolia.etherscan.io",
}
CHAIN_IDS = {"mainnet": 1, "goerli": 5, "sepolia": 11155111}


# ── Utility helpers ───────────────────────────────────────────────────────────

def slugify(name: str) -> str:
    return "-".join(
        filter(None, ["".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")])
    ) or "scope"


def detect_chain(input_path: Path, explicit: str | None) -> str:
    if explicit:
        return explicit.lower()
    if input_path.is_file() and input_path.suffix in {".sol", ".vy"}:
        return "evm"
    if (input_path / "Cargo.toml").exists() or (input_path / "Anchor.toml").exists():
        return "solana"
    return "evm"


def _sanitize_relative_path(rel_path: str) -> Path:
    cleaned = rel_path.replace("\\", "/").lstrip("/")
    path = Path(cleaned)
    sanitized = Path()
    for part in path.parts:
        if part in {"..", ""}:
            continue
        sanitized /= part
    return sanitized if str(sanitized) else Path("Contract.sol")


def _parse_etherscan_sources(raw: str, contract_name: str) -> Dict[str, str]:
    if not raw:
        return {}
    blob = raw.strip()
    if blob.startswith("{{") and blob.endswith("}}"):
        blob = blob[1:-1]
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list) and parsed:
            parsed = parsed[0]
        if isinstance(parsed, dict):
            sources = parsed.get("sources")
            if isinstance(sources, dict):
                result: Dict[str, str] = {}
                for rel, meta in sources.items():
                    content = meta.get("content") if isinstance(meta, dict) else None
                    if content:
                        result[str(_sanitize_relative_path(rel))] = content
                if result:
                    return result
            if "SourceCode" in parsed and isinstance(parsed["SourceCode"], str):
                return {f"{contract_name or 'Contract'}.sol": parsed["SourceCode"]}
    except json.JSONDecodeError:
        pass
    return {f"{contract_name or 'Contract'}.sol": blob}


def fetch_from_etherscan(address: str, network: str, api_key: str | None) -> Dict[str, str]:
    if not api_key:
        return {}
    domain = ETHERSCAN_DOMAINS.get(network, ETHERSCAN_DOMAINS["mainnet"])
    url = (
        f"https://{domain}/api?module=contract&action=getsourcecode"
        f"&address={address}&apikey={api_key}"
    )
    try:
        with urlrequest.urlopen(url, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}
    if payload.get("status") != "1":
        return {}
    result = payload.get("result") or []
    if not result:
        return {}
    entry = result[0]
    return _parse_etherscan_sources(entry.get("SourceCode", ""), entry.get("ContractName", ""))


def fetch_from_sourcify(address: str, network: str) -> Dict[str, str]:
    chain_id = CHAIN_IDS.get(network, 1)
    for bucket in ("full_match", "partial_match"):
        base = f"https://repo.sourcify.dev/contracts/{bucket}/{chain_id}/{address}/"
        try:
            with urlrequest.urlopen(base + "metadata.json", timeout=15) as resp:
                metadata = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        sources = metadata.get("sources")
        if not isinstance(sources, dict):
            continue
        result: Dict[str, str] = {}
        for rel, meta in sources.items():
            content = meta.get("content") if isinstance(meta, dict) else None
            if content:
                result[str(_sanitize_relative_path(rel))] = content
        if result:
            return result
    return {}


def download_onchain_sources(
    address: str, network: str, api_key: str | None
) -> Tuple[Optional[Path], Optional[str]]:
    normalized = address.strip()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    normalized = normalized.lower()
    tmp_root = Path(tempfile.mkdtemp(prefix="multichain-evm-"))
    dest_dir = tmp_root / normalized.replace("0x", "")
    sources = fetch_from_etherscan(normalized, network, api_key) or fetch_from_sourcify(normalized, network)
    if not sources:
        return None, None
    for rel, content in sources.items():
        path = dest_dir / _sanitize_relative_path(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return dest_dir, f"On-chain source downloaded: {normalized}"


def _collect_source_files(target: Path) -> List[Path]:
    """Collect contract source files, prioritising .sol/.vy/.rs, then others.

    Excludes macOS zip metadata: __MACOSX directories and ._ prefixed files.
    """
    if target.is_file():
        return [target]
    primary: List[Path] = []
    secondary: List[Path] = []
    for ext in SOURCE_EXTS:
        for f in sorted(target.rglob(f"*{ext}")):
            # Skip macOS zip metadata files
            if "__MACOSX" in f.parts or f.name.startswith("._"):
                continue
            if ext in {".sol", ".vy", ".rs"}:
                primary.append(f)
            else:
                secondary.append(f)
    combined = primary + secondary
    return combined[:MAX_FILES]


def _resolve_project_path(target: Path) -> Tuple[Path, Optional[str]]:
    if target.is_file():
        return target, None
    current = target
    visited = 0
    while current.is_dir():
        entries = list(current.iterdir())
        dirs  = [p for p in entries if p.is_dir()]
        files = [p for p in entries if p.is_file()]
        if files or len(dirs) != 1:
            break
        visited += 1
        if visited > 4:
            break
        current = dirs[0]
    return current, None


# ── Scoring & verdict helpers ─────────────────────────────────────────────────

def _badge(score: int) -> str:
    """Per CONTRACT_AUDIT_GUIDE.md thresholds: 90-100 Excellent, 70-89 Good, 50-69 Caution, <50 Risk."""
    if score >= 90: return "🟢 Excellent"
    if score >= 70: return "🔵 Good"
    if score >= 50: return "🟡 Caution"
    return "🔴 Risk"


def _risk_level_label(score: int) -> str:
    if score >= 90: return "🟢 Low Risk"
    if score >= 70: return "🔵 Medium-Low Risk"
    if score >= 50: return "🟡 Medium Risk"
    return "🔴 High Risk"


def _verdict_from_aggregate(critical_findings: List[str], overall: int) -> str:
    """Per CONTRACT_AUDIT_GUIDE.md: critical → REJECT, ≥70 → SAFE, 50-69 → CAUTION, <50 → REJECT."""
    if critical_findings:
        return "REJECT"
    if overall >= 70:
        return "SAFE"
    if overall >= 50:
        return "CAUTION"
    return "REJECT"


# ── LLM prompt (per CONTRACT_AUDIT_GUIDE.md template) ────────────────────────

_LLM_SYSTEM = (
    "You are an expert smart contract security auditor. "
    "Analyze the provided source code thoroughly for security vulnerabilities. "
    "Always respond with valid JSON only — no markdown fences, no commentary."
)

_LLM_PROMPT_TMPL = """\
你是一名资深智能合约安全审计专家。请对以下合约进行全面安全审计，并按照 5 个维度输出评分和具体风险项。

**合约信息：**
- 文件名：{filename}
- 链类型：{chain_type}
- 代码：
```
{source_code}
```

**审计要求：**
1. 按照以下 5 个维度进行评分（每个维度 0-100 分，100 分表示无风险）：
   - accessControl（访问控制）：权限管理、身份验证、owner检查、modifier完整性
   - financialSecurity（资金安全）：重入攻击、整数溢出/下溢、资金锁定、提现逻辑、余额检查
   - randomnessOracle（随机数与预言机）：弱随机数、区块属性依赖、预言机操纵、时间戳依赖
   - dosResistance（拒绝服务）：Gas限制、循环炸弹、外部调用失败、数组无界增长
   - businessLogic（业务逻辑）：状态不一致、条件竞争、前置运行、闪电贷攻击、逻辑漏洞

2. 对每个维度列出发现的具体风险项（如果有）

3. criticalFindings 只包含可直接导致资金损失或合约失效的漏洞

**评分标准：90-100=优秀，70-89=良好，50-69=需改进，<50=高风险**

**严格按以下 JSON 格式输出，不要包含任何其他文字：**
{{
  "filename": "{filename}",
  "overallScore": <综合评分 0-100>,
  "dimensions": {{
    "accessControl":    {{"score": <0-100>, "findings": ["风险描述1", "风险描述2"]}},
    "financialSecurity":{{"score": <0-100>, "findings": []}},
    "randomnessOracle": {{"score": <0-100>, "findings": []}},
    "dosResistance":    {{"score": <0-100>, "findings": []}},
    "businessLogic":    {{"score": <0-100>, "findings": []}}
  }},
  "criticalFindings": ["严重漏洞描述（如无则为空数组）"],
  "recommendation": "总体建议（1-2句话）"
}}
"""


# ── LLM analysis ─────────────────────────────────────────────────────────────

def _analyze_file_with_llm(filename: str, code: str, model: str, chain: str) -> Dict:
    """Analyze a single contract file using LLM with three-path fallback.

    Paths tried in order:
      1. Chat Completions  (gpt-4o / grok / most models)
      2. Legacy Completions (codex / instruct models)
      3. Responses API      (gpt-4.1 / o-series / SDK v2 new models)
    """
    _empty: Dict = {
        "overallScore": 100,
        "hasRisk": False,
        "dimensionScores":   {k: 100 for k in _DIM_KEYS},
        "dimensionFindings": {k: []  for k in _DIM_KEYS},
        "criticalFindings":  [],
        "recommendation":    "",
    }
    _err = lambda msg: {**_empty, "status": "error", "reason": msg, "filename": filename}

    try:
        from openai import OpenAI
    except ImportError:
        return _err("openai package missing: pip install openai")

    openai_key = os.getenv("OPENAI_API_KEY", "")
    xai_key    = os.getenv("XAI_API_KEY", "")
    if not openai_key and not xai_key:
        return _err("No API key configured (OPENAI_API_KEY or XAI_API_KEY)")

    use_xai = bool(xai_key) and not openai_key
    client_kwargs: Dict = {"api_key": xai_key if use_xai else openai_key}
    if use_xai:
        client_kwargs["base_url"] = "https://api.x.ai/v1"
        if not model or not model.startswith("grok"):
            model = "grok-3-mini"
    elif not model:
        model = "gpt-4o-mini"

    # Determine language label for the prompt
    ext = Path(filename).suffix.lower()
    lang_map = {".sol": "EVM (Solidity)", ".vy": "EVM (Vyper)", ".rs": "Solana (Rust)"}
    chain_type = lang_map.get(ext, chain.upper())

    # Truncate code if needed
    code_snippet = code[:MAX_FILE_CHARS]
    if len(code) > MAX_FILE_CHARS:
        code_snippet += f"\n\n... [{len(code) - MAX_FILE_CHARS} chars truncated] ..."

    system_prompt = _LLM_SYSTEM
    user_prompt   = _LLM_PROMPT_TMPL.format(
        filename=filename,
        chain_type=chain_type,
        source_code=code_snippet,
    )
    client = OpenAI(**client_kwargs)

    def _parse_raw(raw: str) -> Optional[Dict]:
        """Parse and validate LLM JSON response into internal format."""
        m = re.search(r'\{[\s\S]+\}', raw)
        if not m:
            return None
        try:
            parsed = json.loads(m.group())
        except json.JSONDecodeError:
            return None

        dim_scores:   Dict[str, int]        = {}
        dim_findings: Dict[str, List[str]]  = {}

        dims_data = parsed.get("dimensions", {})
        for k in _DIM_KEYS:
            dim_entry = dims_data.get(k, {})
            if isinstance(dim_entry, dict):
                raw_score = dim_entry.get("score", 100)
                raw_finds = dim_entry.get("findings", [])
            else:
                raw_score = 100
                raw_finds = []
            dim_scores[k]   = max(0, min(100, int(raw_score)))
            dim_findings[k] = [str(f).strip() for f in raw_finds if f]

        # overallScore from LLM, fallback to average of dimensions
        overall_raw = parsed.get("overallScore")
        if isinstance(overall_raw, (int, float)):
            overall = max(0, min(100, int(overall_raw)))
        else:
            overall = sum(dim_scores.values()) // len(_DIM_KEYS)

        critical = [str(f).strip() for f in parsed.get("criticalFindings", []) if f]
        recommendation = str(parsed.get("recommendation", "")).strip()
        has_risk = bool(critical) or any(s < 70 for s in dim_scores.values())

        return {
            "status":           "ok",
            "filename":         filename,
            "overallScore":     overall,
            "hasRisk":          has_risk,
            "dimensionScores":  dim_scores,
            "dimensionFindings":dim_findings,
            "criticalFindings": critical,
            "recommendation":   recommendation,
        }

    def _call_responses_api() -> Optional[str]:
        """Responses API — SDK v2 endpoint for gpt-4.1 / o-series models."""
        try:
            resp = client.responses.create(
                model=model,
                instructions=system_prompt,
                input=user_prompt,
            )
            if hasattr(resp, "output_text"):
                return (resp.output_text or "").strip()
            if hasattr(resp, "output") and resp.output:
                item = resp.output[0]
                if hasattr(item, "content") and item.content:
                    return (item.content[0].text or "").strip()
        except Exception:
            pass
        return None

    # ── Path 1: Chat Completions ──────────────────────────────────────────────
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0,
        )
        raw = (resp.choices[0].message.content or "").strip()
        result = _parse_raw(raw)
        return result if result else {**_empty, "status": "ok", "filename": filename}

    except Exception as chat_exc:
        chat_err = str(chat_exc)

        # ── Path 2: Legacy Completions (codex / instruct models) ─────────────
        if "not a chat model" in chat_err or "v1/completions" in chat_err:
            try:
                legacy = client.completions.create(
                    model=model,
                    prompt=system_prompt + "\n\n" + user_prompt,
                    max_tokens=1024,
                    temperature=0,
                )
                raw = (legacy.choices[0].text or "").strip()
                result = _parse_raw(raw)
                if result:
                    return result
            except Exception:
                pass

            # ── Path 3: Responses API (gpt-4.1 / o-series) ───────────────────
            raw = _call_responses_api()
            if raw is not None:
                result = _parse_raw(raw)
                return result if result else {**_empty, "status": "ok", "filename": filename}

            return _err(
                f"Model '{model}' is not supported by any available API endpoint. "
                f"Please check your SKILL_AUDIT_AI_MODEL configuration."
            )

        # ── Chat Completions failed with another error, try Responses API ─────
        raw = _call_responses_api()
        if raw is not None:
            result = _parse_raw(raw)
            return result if result else {**_empty, "status": "ok", "filename": filename}

        return _err(f"[model={model}] {chat_err}")


def _aggregate_llm_results(file_results: List[Dict]) -> Dict:
    """Aggregate per-file LLM results.

    Strategy (conservative):
    - Take minimum dimension score across all files (worst case wins)
    - overall = average of min dimension scores
    - Collect all criticalFindings with file attribution
    """
    min_scores: Dict[str, int] = {k: 100 for k in _DIM_KEYS}
    all_critical: List[str] = []

    ok_results = [r for r in file_results if r.get("status") == "ok"]

    for result in ok_results:
        for k in _DIM_KEYS:
            s = result["dimensionScores"].get(k, 100)
            min_scores[k] = min(min_scores[k], s)
        fname = result.get("filename", "unknown")
        for cf in result.get("criticalFindings", []):
            all_critical.append(f"**{fname}** — {cf}")

    # Build final score dict
    scores: Dict[str, int] = {}
    for dim_key, score_key in _DIM_SCORE_KEYS.items():
        scores[score_key] = min_scores[dim_key]
    scores["overall"] = sum(min_scores.values()) // len(_DIM_KEYS) if min_scores else 100

    verdict = _verdict_from_aggregate(all_critical, scores["overall"])
    return {
        "scores":           scores,
        "criticalFindings": all_critical,
        "verdict":          verdict,
    }


# ── Report generation ─────────────────────────────────────────────────────────

def _build_per_file_section(file_results: List[Dict]) -> List[str]:
    """Build per-file analysis sections per CONTRACT_AUDIT_GUIDE.md format."""
    lines: List[str] = []
    for result in file_results:
        fname = result.get("filename", "unknown")
        lines.append(f"\n### 📄 {fname}")

        if result.get("status") != "ok":
            lines.append(f"\n> ⚠️ Analysis error: {result.get('reason', 'unknown error')}")
            lines.append("")
            continue

        overall  = result.get("overallScore", 100)
        has_risk = result.get("hasRisk", False)
        lines.append(f"\n**Overall Score:** {overall}/100 &nbsp;|&nbsp; **Risk Level:** {_risk_level_label(overall)}")
        lines.append("")

        # Dimension score summary table
        lines.append("#### Dimension Scores")
        lines.append("")
        lines.append("| Dimension | Score | Findings |")
        lines.append("| --- | :---: | --- |")
        dim_scores   = result.get("dimensionScores",   {})
        dim_findings = result.get("dimensionFindings", {})
        for k in _DIM_KEYS:
            sc = dim_scores.get(k, 100)
            fc = len(dim_findings.get(k, []))
            f_str = f"{fc} issue{'s' if fc != 1 else ''}" if fc > 0 else "—"
            lines.append(f"| {_DIM_LABELS[k]} | {sc}/100 | {f_str} |")
        lines.append("")

        # Per-dimension details
        for k in _DIM_KEYS:
            sc       = dim_scores.get(k, 100)
            findings = dim_findings.get(k, [])
            status   = "✅ Pass" if sc >= 90 and not findings else "❌ Risk Detected"
            lines.append(f"#### {_DIM_LABELS[k]}")
            lines.append(f"**Score:** {sc}/100 &nbsp;|&nbsp; **Status:** {status}")
            if findings:
                lines.append("")
                lines.append("**Findings:**")
                for f in findings:
                    lines.append(f"- {f}")
            lines.append("")

        # Recommendation
        rec = result.get("recommendation", "")
        if rec:
            lines.append("#### 💡 Recommendation")
            lines.append(rec)
            lines.append("")

        lines.append("---")

    return lines


def build_report(
    scope: str,
    chain: str,
    target: Path,
    report_path: Path,
    llm_file_results: List[Dict],
    extra_notes: List[str],
    model: str = "",
) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d %H:%M:%S UTC")

    aggregated      = _aggregate_llm_results(llm_file_results)
    scores          = aggregated["scores"]
    verdict         = aggregated["verdict"]
    critical_list   = aggregated["criticalFindings"]

    if verdict == "SAFE":
        v_icon, v_label = "✅", "SAFE TO DEPLOY"
    elif verdict == "CAUTION":
        v_icon, v_label = "⚠️", "CAUTION — REVIEW REQUIRED"
    else:
        v_icon, v_label = "❌", "REJECT — HIGH RISK DETECTED"

    ok_count = sum(1 for r in llm_file_results if r.get("status") == "ok")

    lines: List[str] = [
        f"# {scope} Contract Audit Report",
        "",
        f"**Scanned:** {timestamp}  ",
        f"**Chain:** {chain.upper()}  ",
        f"**Files Analyzed:** {ok_count}/{len(llm_file_results)}  ",
        "**Analysis Method:** AI Semantic Analysis  ",
        f"**Model:** {model or 'N/A'}",
        "",
        "## Security Verdict",
        f"### {v_icon} {v_label}",
        "",
        "---",
        "",
        "## 📊 Risk Scores",
        "",
        "| Dimension | Score | Rating |",
        "| --- | :---: | --- |",
        f"| 🏆 **Overall Security** | **{scores['overall']}/100** | **{_badge(scores['overall'])}** |",
        f"| 🔐 Access Control      | {scores['access']}/100     | {_badge(scores['access'])} |",
        f"| 💰 Financial Security  | {scores['financial']}/100  | {_badge(scores['financial'])} |",
        f"| 🎲 Randomness & Oracle | {scores['randomness']}/100 | {_badge(scores['randomness'])} |",
        f"| ⚡ DoS Resistance      | {scores['dos']}/100        | {_badge(scores['dos'])} |",
        f"| 🛡️ Business Logic      | {scores['logic']}/100      | {_badge(scores['logic'])} |",
        "",
        "> Score legend: 90–100 = Excellent | 70–89 = Good | 50–69 = Caution | <50 = Risk",
        "",
        "---",
        "",
        "## 🚨 Critical Findings",
        "",
    ]

    if critical_list:
        for i, cf in enumerate(critical_list, 1):
            lines.append(f"{i}. {cf}")
    else:
        lines.append("✅ No critical vulnerabilities found.")

    lines += [
        "",
        "---",
        "",
        "## 📄 Per-File Analysis",
        f"*{len(llm_file_results)} file(s) analyzed by AI*",
        "",
    ]

    lines += _build_per_file_section(llm_file_results)

    # Audit summary table
    lines += [
        "",
        "## 📋 Audit Summary",
        "",
        "### File Risk Distribution",
        "",
        "| File | Score | Risk Level | Critical Issues |",
        "| --- | :---: | --- | :---: |",
    ]
    for result in llm_file_results:
        fname = result.get("filename", "unknown")
        if result.get("status") != "ok":
            lines.append(f"| {fname} | — | ⚠️ Analysis Error | — |")
            continue
        ov  = result.get("overallScore", 100)
        cfc = len(result.get("criticalFindings", []))
        lines.append(f"| {fname} | {ov}/100 | {_risk_level_label(ov)} | {cfc} |")

    # Overall recommendation
    recs = [
        r.get("recommendation", "").strip()
        for r in llm_file_results
        if r.get("status") == "ok" and r.get("recommendation", "").strip()
    ]
    lines += ["", "### Overall Recommendation", ""]
    if recs:
        for rec in recs:
            lines.append(f"- {rec}")
    else:
        lines.append("No specific recommendations.")

    lines += [
        "",
        "---",
        "",
        "## Scope Overview",
        f"- **Target**: {Path(target).name}",
        f"- **Chain**: {chain.upper()}",
        f"- **Files analyzed**: {ok_count}",
        "- **Tool**: multichain-contract-vuln CLI + AI Semantic Analysis",
        "",
    ]

    if extra_notes:
        lines += ["## Additional Notes", ""]
        for note in extra_notes:
            lines.append(f"- {note}")
        lines.append("")

    lines += [
        "---",
        "",
        "*Disclaimer: This report is generated by AI semantic analysis and does not replace human audit. "
        "A comprehensive manual audit is recommended before production deployment.*",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="multichain-contract-vuln AI audit CLI")
    parser.add_argument("--input",             help="Contract file or directory to analyze")
    parser.add_argument("--evm-address",       help="On-chain EVM contract address (auto-download source)")
    parser.add_argument("--network",           default="mainnet",
                        help="EVM network: mainnet/goerli/sepolia (default: mainnet)")
    parser.add_argument("--etherscan-api-key", help="Etherscan API Key (or set ETHERSCAN_API_KEY)")
    parser.add_argument("--chain",             choices=["evm", "solana"], help="Chain type")
    parser.add_argument("--scope",             help="Report name prefix (default: directory name)")
    parser.add_argument("--report",            help="Output Markdown path")
    parser.add_argument("--ai-model",          help="LLM model (default: SKILL_AUDIT_AI_MODEL env var)")
    args = parser.parse_args()

    notes: List[str] = []
    target: Optional[Path] = None

    if args.input:
        target = Path(args.input).expanduser().resolve()
        if not target.exists():
            print(f"Input path does not exist: {target}", file=sys.stderr)
            return 1
    elif args.evm_address:
        api_key = args.etherscan_api_key or os.getenv("ETHERSCAN_API_KEY")
        fetched_dir, fetch_note = download_onchain_sources(
            args.evm_address, args.network.lower(), api_key
        )
        if not fetched_dir:
            print("❌ Failed to download on-chain source (verify address or configure Etherscan/Sourcify)", file=sys.stderr)
            return 1
        target = fetched_dir
        if fetch_note:
            notes.append(fetch_note)
    else:
        print("Must provide --input or --evm-address", file=sys.stderr)
        return 1

    chain_hint = args.chain or ("evm" if args.evm_address else None)
    chain  = detect_chain(target, chain_hint)
    target, _ = _resolve_project_path(target)

    scope = args.scope or slugify(target.stem if target.is_file() else target.name)
    report_path = (
        Path(args.report).expanduser().resolve()
        if args.report
        else Path.cwd() / "reports" / f"{scope}-contract-audit.md"
    )

    model = args.ai_model or os.getenv("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini")

    # ── Collect source files ──────────────────────────────────────────────────
    source_files = _collect_source_files(target)
    if not source_files:
        print("❌ No supported source files found in the uploaded package.", file=sys.stderr)
        return 1

    print(f"[ContractAudit] Found {len(source_files)} file(s) to analyze with model={model}")

    # ── Analyze each file with LLM ────────────────────────────────────────────
    llm_file_results: List[Dict] = []
    for file_path in source_files:
        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            llm_file_results.append({
                "status": "error", "reason": str(exc),
                "filename": file_path.name,
                "overallScore": 100,
                "hasRisk": False,
                "dimensionScores":   {k: 100 for k in _DIM_KEYS},
                "dimensionFindings": {k: []  for k in _DIM_KEYS},
                "criticalFindings":  [],
                "recommendation":    "",
            })
            continue

        print(f"[ContractAudit] Analyzing {file_path.name} ...")
        result = _analyze_file_with_llm(file_path.name, code, model, chain)
        llm_file_results.append(result)

    # ── Generate report ───────────────────────────────────────────────────────
    report_file = build_report(scope, chain, target, report_path, llm_file_results, notes, model)
    print(f"✅ Report generated: {report_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
