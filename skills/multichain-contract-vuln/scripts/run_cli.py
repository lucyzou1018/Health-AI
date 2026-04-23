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
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib import request as urlrequest

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
SOURCE_EXTS = {".sol", ".vy", ".rs"}
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


# ── Solana on-chain source fetching via OtterSec Verify + GitHub ─────────────

_OSEC_VERIFY_URL = "https://verify.osec.io/status/{program_id}"
_GITHUB_ARCHIVE_URL = "https://github.com/{slug}/archive/{ref}.zip"
_GITHUB_SEARCH_URL  = (
    "https://api.github.com/search/code"
    "?q=declare_id+%22{program_id}%22+language%3ARust&per_page=5"
)
_SOLANA_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_SOLANA_MAX_FILES = 10
import ssl as _ssl
import zipfile as _zipfile
from urllib.parse import quote as _url_quote


def _http_get_json_solana(url: str) -> dict:
    """Fetch JSON from *url* using stdlib only (no requests)."""
    req = urlrequest.Request(url, headers={"User-Agent": "CodeAutrix/1.0"})
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with urlrequest.urlopen(req, timeout=20, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"HTTP GET failed for {url}: {exc}") from exc


def _http_get_bytes_solana(url: str, timeout: int = 45) -> bytes:
    """Download raw bytes from *url* following redirects."""
    req = urlrequest.Request(url, headers={"User-Agent": "CodeAutrix/1.0"})
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with urlrequest.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except Exception as exc:
        raise RuntimeError(f"HTTP GET failed for {url}: {exc}") from exc


def _github_slug(repo_url: str) -> Optional[str]:
    m = re.match(r"https?://github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+?)(?:\.git)?(?:[/?#].*)?$", repo_url)
    return m.group(1) if m else None


def _extract_rs_from_zip(zip_bytes: bytes) -> Dict[str, str]:
    """Extract .rs files from a GitHub archive, stripping the top-level dir prefix."""
    files: Dict[str, str] = {}
    try:
        with _zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            prefix = (names[0].split("/")[0] + "/") if names else ""

            def _priority(n: str) -> int:
                ln = n.lower()
                if "/tests/" in ln or ln.split("/")[-1].startswith("test_"):
                    return 2
                if "/target/" in ln or "/node_modules/" in ln:
                    return 3
                return 1

            rs = sorted(
                [n for n in names if n.endswith(".rs") and not n.endswith("/")
                 and "/__MACOSX/" not in n and "/." not in n.split("/")[-1]],
                key=_priority,
            )[:_SOLANA_MAX_FILES]

            for entry in rs:
                rel = entry[len(prefix):] if entry.startswith(prefix) else entry
                if not rel:
                    continue
                # Strip path traversal
                parts = [p for p in rel.replace("\\", "/").split("/") if p and p not in (".", "..")]
                rel = "/".join(parts) or entry.split("/")[-1]
                try:
                    files[rel] = zf.read(entry).decode("utf-8", errors="ignore")
                except Exception:
                    pass
    except _zipfile.BadZipFile:
        pass
    return files


def _osec_query_soft(program_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Query OtterSec Verify. Returns (repo_url, commit, error_msg) — never raises."""
    osec_url = _OSEC_VERIFY_URL.format(program_id=program_id)
    print(f"[Solana] Stage 1 — OtterSec Verify: {osec_url}", file=sys.stderr)
    try:
        data = _http_get_json_solana(osec_url)
    except RuntimeError as exc:
        return None, None, f"OtterSec API error: {exc}"
    if not data.get("is_verified"):
        return None, None, f"Program {program_id[:8]}… is not verified on OtterSec"
    repo_url = (data.get("repo_url") or data.get("github") or "").strip().rstrip("/")
    commit   = (data.get("commit") or "").strip()
    if not repo_url:
        return None, None, f"OtterSec returned no GitHub URL for {program_id[:8]}…"
    return repo_url, commit, None


def _github_search_soft(program_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Search GitHub for declare_id!("{program_id}") in Rust files.

    Returns (repo_url, error_msg). Supports GITHUB_TOKEN env var.
    """
    search_url = _GITHUB_SEARCH_URL.format(program_id=_url_quote(program_id))
    print(f"[Solana] Stage 2 — GitHub Code Search: {search_url}", file=sys.stderr)
    headers = {
        "User-Agent": "CodeAutrix/1.0",
        "Accept":     "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urlrequest.Request(search_url, headers=headers)
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with urlrequest.urlopen(req, timeout=20, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"GitHub Search API failed: {exc}"
    for item in (data.get("items") or []):
        repo = item.get("repository") or {}
        url  = (repo.get("html_url") or "").strip().rstrip("/")
        if url and "github.com" in url:
            print(f"[Solana] GitHub matched: {url} (file: {item.get('path', '?')})", file=sys.stderr)
            return url, None
    return None, (
        f"No public repo found for declare_id!(\"{program_id[:8]}…\"). "
        "The program may not be open-source or the repository is private."
    )


def download_onchain_sources_solana(
    program_id: str,
) -> Tuple[Optional[Path], Optional[str]]:
    """Fetch Solana program source via two-stage lookup: OtterSec → GitHub Search.

    Stage 1 (OtterSec): pinned commit, strongest source ↔ bytecode correspondence.
    Stage 2 (GitHub):   any open-source repo declaring the same program ID.

    Returns (directory_with_rs_files, status_note) or (None, None) on failure.
    """
    program_id = program_id.strip()
    if not _SOLANA_ADDR_RE.match(program_id):
        print(f"[Solana] Invalid program ID (expected base58, 32–44 chars): {program_id}", file=sys.stderr)
        return None, None

    # ── Stage 1: OtterSec ────────────────────────────────────────────────────
    repo_url, commit, osec_err = _osec_query_soft(program_id)
    source_tag = "OtterSec-verified"

    if repo_url is None:
        print(f"[Solana] OtterSec: {osec_err} — falling back to GitHub search…", file=sys.stderr)

        # ── Stage 2: GitHub Code Search ───────────────────────────────────────
        repo_url, search_err = _github_search_soft(program_id)
        commit     = ""
        source_tag = "GitHub (unverified)"

        if repo_url is None:
            print(
                f"[Solana] Could not locate source for {program_id[:8]}…\n"
                f"  OtterSec: {osec_err}\n"
                f"  GitHub:   {search_err}",
                file=sys.stderr,
            )
            return None, None

    slug = _github_slug(repo_url)
    if not slug:
        print(f"[Solana] Cannot parse GitHub URL: {repo_url}", file=sys.stderr)
        return None, None

    # ── Download archive ──────────────────────────────────────────────────────
    refs = list(dict.fromkeys(filter(None, [commit, "main", "master"])))
    zip_bytes: Optional[bytes] = None
    used_ref = ""
    for ref in refs:
        archive_url = _GITHUB_ARCHIVE_URL.format(slug=slug, ref=ref)
        print(f"[Solana] Downloading archive: {archive_url}", file=sys.stderr)
        try:
            zip_bytes = _http_get_bytes_solana(archive_url)
            used_ref = ref
            break
        except RuntimeError as exc:
            print(f"[Solana] Archive download failed ({ref}): {exc}", file=sys.stderr)

    if not zip_bytes:
        print(f"[Solana] Could not download source archive from {repo_url}", file=sys.stderr)
        return None, None

    # ── Extract .rs files ─────────────────────────────────────────────────────
    rs_files = _extract_rs_from_zip(zip_bytes)
    if not rs_files:
        print(f"[Solana] No .rs files found in {repo_url}@{used_ref}", file=sys.stderr)
        return None, None

    # ── Write to temp directory ───────────────────────────────────────────────
    tmp_root = Path(tempfile.mkdtemp(prefix="multichain-solana-"))
    dest_dir = tmp_root / program_id[:10]
    for rel, content in rs_files.items():
        out = dest_dir / _sanitize_relative_path(rel)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")

    note = (
        f"Solana source fetched ({source_tag}): {program_id[:8]}… | "
        f"repo={repo_url} | ref={used_ref} | files={len(rs_files)}"
    )
    print(f"[Solana] {note}", file=sys.stderr)
    return dest_dir, note


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
You are a senior smart contract security auditor. Perform a thorough security audit of the contract below and score it across 5 dimensions. All output must be in English.

**Contract Info:**
- Filename: {filename}
- Chain Type: {chain_type}
- Source Code:
```
{source_code}
```

**Audit Requirements:**
1. For each of the 5 dimensions below, first identify concrete issues in the code, then derive the score from those findings:
   - accessControl: Permission management, authentication, owner checks, modifier completeness
   - financialSecurity: Reentrancy, integer overflow/underflow, fund locking, withdrawal logic, balance checks
   - randomnessOracle: Weak randomness, block attribute dependency, oracle manipulation, timestamp dependency
   - dosResistance: Gas limits, loop bombs, external call failures, unbounded array growth
   - businessLogic: State inconsistency, race conditions, front-running, flash loan attacks, logic flaws

2. The score for each dimension MUST be consistent with its findings:
   - Score = 100 only if there are zero findings for that dimension.
   - Score < 100 requires at least one specific finding describing what was found and why points were deducted.
   - Do NOT deduct points without documenting the reason in findings. Write all findings in English.

3. criticalFindings must only include vulnerabilities that directly lead to loss of funds or contract failure. Write in English.

**Scoring guide (derived from findings severity): 90–100 = no/trivial issues | 70–89 = minor issues | 50–69 = moderate issues | <50 = critical issues**

**Respond ONLY with the following JSON — no markdown fences, no additional text:**
{{
  "filename": "{filename}",
  "overallScore": <integer 0-100>,
  "dimensions": {{
    "accessControl":    {{"score": <0-100>, "findings": ["finding description"]}},
    "financialSecurity":{{"score": <0-100>, "findings": []}},
    "randomnessOracle": {{"score": <0-100>, "findings": []}},
    "dosResistance":    {{"score": <0-100>, "findings": []}},
    "businessLogic":    {{"score": <0-100>, "findings": []}}
  }},
  "criticalFindings": ["critical vulnerability description, or empty array if none"],
  "recommendation": "Overall recommendation in 1-2 sentences."
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
        # Strip markdown code fences (```json ... ``` or ``` ... ```)
        text = re.sub(r'```[a-zA-Z]*\n?', '', raw).strip()

        # Extract balanced JSON object using brace counting,
        # avoiding the greedy-regex pitfall of grabbing extra trailing content.
        start = text.find('{')
        if start < 0:
            return None
        depth = 0
        in_str = False
        escaped = False
        end = -1
        for i, ch in enumerate(text[start:], start):
            if escaped:
                escaped = False
                continue
            if ch == '\\' and in_str:
                escaped = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end < 0:
            return None
        candidate = text[start:end + 1]

        # Fix common LLM JSON quirks: trailing commas before } or ]
        candidate = re.sub(r',\s*([}\]])', r'\1', candidate)

        try:
            parsed = json.loads(candidate)
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
        """Responses API — SDK v2 endpoint for gpt-4.1 / o-series models.
        Tries temperature=0 first for determinism; falls back without it for
        models that do not accept the temperature parameter (e.g. codex variants).
        """
        def _extract(resp) -> Optional[str]:
            if hasattr(resp, "output_text"):
                return (resp.output_text or "").strip() or None
            if hasattr(resp, "output") and resp.output:
                item = resp.output[0]
                if hasattr(item, "content") and item.content:
                    return (item.content[0].text or "").strip() or None
            return None

        # First attempt: with temperature=0 for deterministic output
        try:
            resp = client.responses.create(
                model=model,
                instructions=system_prompt,
                input=user_prompt,
                temperature=0,
            )
            result = _extract(resp)
            if result is not None:
                return result
        except Exception:
            pass

        # Second attempt: without temperature (some models reject the parameter)
        try:
            resp = client.responses.create(
                model=model,
                instructions=system_prompt,
                input=user_prompt,
            )
            return _extract(resp)
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
        return result if result else _err(f"LLM returned unparseable response: {raw[:100]}")

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
                return result if result else _err(f"LLM returned unparseable response: {raw[:100]}")

            return _err(
                f"Model '{model}' is not supported by any available API endpoint. "
                f"Please check your SKILL_AUDIT_AI_MODEL configuration."
            )

        # ── Chat Completions failed with another error, try Responses API ─────
        raw = _call_responses_api()
        if raw is not None:
            result = _parse_raw(raw)
            return result if result else _err(f"LLM returned unparseable response: {raw[:100]}")

        return _err(f"[model={model}] {chat_err}")


def _aggregate_llm_results(file_results: List[Dict]) -> Dict:
    """Aggregate per-file LLM results.

    Strategy (conservative):
    - Take minimum dimension score across all files (worst case wins)
    - overall = average of min dimension scores
    - Collect all criticalFindings with file attribution
    - If ALL files failed (no ok results), return analysis_failed=True so
      the caller can surface a proper error instead of fake 100/100 scores.
    """
    min_scores: Dict[str, int] = {k: 100 for k in _DIM_KEYS}
    all_critical: List[str] = []

    ok_results = [r for r in file_results if r.get("status") == "ok"]

    # ── All files failed — surface as analysis failure, not perfect scores ──
    if not ok_results:
        error_reasons = [
            r.get("reason", "unknown error")
            for r in file_results if r.get("status") != "ok"
        ]
        return {
            "analysis_failed": True,
            "error_reason":    error_reasons[0] if error_reasons else "AI analysis failed",
            "scores":          {score_key: 0 for score_key in _DIM_SCORE_KEYS.values()} | {"overall": 0},
            "criticalFindings": [],
            "verdict":          "ERROR",
        }

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
    scores["overall"] = sum(min_scores.values()) // len(_DIM_KEYS) if min_scores else 0

    verdict = _verdict_from_aggregate(all_critical, scores["overall"])
    return {
        "analysis_failed":  False,
        "scores":           scores,
        "criticalFindings": all_critical,
        "verdict":          verdict,
    }


# ── Report generation ─────────────────────────────────────────────────────────

def _display_fname(fname: str, onchain_meta: Optional[Dict]) -> str:
    """Return display name for a contract file.

    For on-chain audits where Etherscan defaulted the filename to 'Contract.sol',
    replace it with the actual on-chain address so the report is more meaningful.
    Real filenames (e.g. 'TetherToken.sol') are always kept as-is.
    """
    if (
        onchain_meta
        and onchain_meta.get("source") == "explorer"
        and fname == "Contract.sol"
    ):
        addr = onchain_meta.get("address", "").strip()
        if addr:
            return addr
    return fname


def _build_per_file_section(file_results: List[Dict], onchain_meta: Optional[Dict] = None) -> List[str]:
    """Build per-file analysis sections per CONTRACT_AUDIT_GUIDE.md format."""
    lines: List[str] = []
    for result in file_results:
        fname = _display_fname(result.get("filename", "unknown"), onchain_meta)
        lines.append(f"\n### 📄 {fname}")

        if result.get("status") != "ok":
            lines.append(f"\n> ⚠️ Analysis error: {result.get('reason', 'unknown error')}")
            lines.append("")
            continue

        overall  = result.get("overallScore", 100)
        has_risk = result.get("hasRisk", False)
        lines.append(f"\n**Overall Score:** {overall}/100  |  **Risk Level:** {_risk_level_label(overall)}")
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
            lines.append(f"**Score:** {sc}/100  |  **Status:** {status}")
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
    onchain_meta: Optional[Dict] = None,
) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d %H:%M:%S UTC")

    aggregated      = _aggregate_llm_results(llm_file_results)
    scores          = aggregated["scores"]
    verdict         = aggregated["verdict"]
    critical_list   = aggregated["criticalFindings"]
    analysis_failed = aggregated.get("analysis_failed", False)

    ok_count = sum(1 for r in llm_file_results if r.get("status") == "ok")

    # ── All files failed: write an error report instead of fake scores ────────
    if analysis_failed:
        error_reason = aggregated.get("error_reason", "AI analysis failed")
        error_lines: List[str] = [
            f"# {scope} Contract Audit Report",
            "",
            f"**Scanned:** {timestamp}  ",
            f"**Chain:** {chain.upper()}  ",
            f"**Files Analyzed:** {ok_count}/{len(llm_file_results)}  ",
            "**Analysis Method:** AI Semantic Analysis  ",
            f"**Model:** {model or 'N/A'}",
            "",
            "## ⚠️ Analysis Failed",
            "",
            "> The AI analysis could not be completed. Scores have not been generated.",
            "> Please try again. If the problem persists, check your API key and network connection.",
            "",
            f"**Error:** `{error_reason}`",
            "",
            "---",
            "",
            "## 📄 Per-File Details",
            "",
        ]
        error_lines += _build_per_file_section(llm_file_results, onchain_meta)
        report_path.write_text("\n".join(error_lines), encoding="utf-8")
        return report_path

    # On-chain audits: replace the generic "Contract.sol" placeholder in the
    # critical findings list (built by _aggregate_llm_results) with the actual
    # on-chain address, so the report is unambiguous about what was audited.
    is_onchain = bool(onchain_meta and onchain_meta.get("source") == "explorer")
    if is_onchain:
        _addr = (onchain_meta or {}).get("address", "").strip()
        if _addr:
            critical_list = [
                cf.replace("**Contract.sol**", f"**{_addr}**")
                for cf in critical_list
            ]

    if verdict == "SAFE":
        v_icon, v_label = "✅", "SAFE TO USE" if is_onchain else "SAFE TO DEPLOY"
    elif verdict == "CAUTION":
        v_icon, v_label = "⚠️", "CAUTION — REVIEW REQUIRED"
    else:
        v_icon, v_label = "❌", "REJECT — HIGH RISK DETECTED"

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
        "## 📊 Total Risk Scores",
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

    lines += _build_per_file_section(llm_file_results, onchain_meta)

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
        fname = _display_fname(result.get("filename", "unknown"), onchain_meta)
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
    parser.add_argument("--solana-address",    help="On-chain Solana program ID (auto-download source via OtterSec + GitHub)")
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
            return 1
    elif args.evm_address:
        api_key = args.etherscan_api_key or os.getenv("ETHERSCAN_API_KEY")
        fetched_dir, fetch_note = download_onchain_sources(
            args.evm_address, args.network.lower(), api_key
        )
        if not fetched_dir:
            return 1
        target = fetched_dir
        if fetch_note:
            notes.append(fetch_note)
    elif args.solana_address:
        fetched_dir, fetch_note = download_onchain_sources_solana(args.solana_address)
        if not fetched_dir:
            print(
                f"[Error] Could not fetch Solana program source for {args.solana_address}. "
                "Make sure the program is verified on OtterSec (https://verify.osec.io).",
                file=sys.stderr,
            )
            return 1
        target = fetched_dir
        if fetch_note:
            notes.append(fetch_note)
    else:
        return 1

    chain_hint = args.chain or ("solana" if args.solana_address else "evm" if args.evm_address else None)
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
        return 1

    # ── Analyze each file with LLM (parallel) ────────────────────────────────
    # LLM calls are I/O-bound; run them concurrently to reduce total wait time.
    # Concurrency is capped at MAX_FILES (10) which is already a small number.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _analyze_one(file_path: Path) -> Dict:
        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            return {
                "status": "error", "reason": str(exc),
                "filename": file_path.name,
                "overallScore": 100,
                "hasRisk": False,
                "dimensionScores":   {k: 100 for k in _DIM_KEYS},
                "dimensionFindings": {k: []  for k in _DIM_KEYS},
                "criticalFindings":  [],
                "recommendation":    "",
            }
        return _analyze_file_with_llm(file_path.name, code, model, chain)

    # Preserve original file order in results
    ordered: Dict[int, Dict] = {}
    with ThreadPoolExecutor(max_workers=min(len(source_files), MAX_FILES)) as pool:
        futures = {pool.submit(_analyze_one, fp): i for i, fp in enumerate(source_files)}
        for fut in as_completed(futures):
            ordered[futures[fut]] = fut.result()
    llm_file_results: List[Dict] = [ordered[i] for i in range(len(source_files))]

    # ── Read on-chain metadata sidecar (present when source came from /api/contracts/from-chain) ──
    onchain_meta: Optional[Dict] = None
    meta_candidates = [
        target / "codeautrix_fetch_metadata.json",          # file-mode: metadata next to sources
        target.parent / "codeautrix_fetch_metadata.json",   # one level up (edge cases)
    ]
    for meta_path in meta_candidates:
        if meta_path.exists():
            try:
                onchain_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass
            break

    # ── Generate report ───────────────────────────────────────────────────────
    build_report(scope, chain, target, report_path, llm_file_results, notes, model,
                 onchain_meta=onchain_meta)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
