"""Fetch verified contract source code from public block explorers.

For EVM chains we use the Etherscan V2 unified API (one API key works across
all supported chains, differentiated by ``chainid``). For Solana, we query the
OtterSec Verify API (https://verify.osec.io) to obtain the verified GitHub
repository URL, then download the source archive and repack it as a ZIP.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import ssl
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions — main.py translates these into specific HTTP responses.
# ---------------------------------------------------------------------------

class ExplorerError(Exception):
    """Base error for any failure while fetching contract source."""


class UnsupportedChainError(ExplorerError):
    """Chain is not supported by the current fetcher implementation."""


class ContractNotVerifiedError(ExplorerError):
    """Contract exists on-chain but source code is not verified/published."""


class ContractNotFoundError(ExplorerError):
    """No contract exists at that address on that chain."""


class ExplorerConfigError(ExplorerError):
    """Missing / invalid API key or misconfigured environment."""


# ---------------------------------------------------------------------------
# Chain registry — Etherscan V2 uses a single API root and chainid param.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvmChainSpec:
    slug: str           # UI-facing identifier
    display: str        # human-readable label
    chain_id: int       # EVM chain id (used by Etherscan V2)


EVM_CHAINS: Dict[str, EvmChainSpec] = {
    "ethereum":    EvmChainSpec("ethereum",    "Ethereum Mainnet",        1),
    "bsc":         EvmChainSpec("bsc",         "BNB Smart Chain",         56),
    "bsc-testnet": EvmChainSpec("bsc-testnet", "BNB Smart Chain Testnet", 97),
    "polygon":     EvmChainSpec("polygon",     "Polygon",                 137),
    "arbitrum":    EvmChainSpec("arbitrum",    "Arbitrum One",            42161),
    "optimism":    EvmChainSpec("optimism",    "Optimism",                10),
    "base":        EvmChainSpec("base",        "Base",                    8453),
}

SOLANA_SLUG = "solana"

# Etherscan V2 unified endpoint — one key covers all supported EVM chains.
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

# OtterSec Verify API — returns verification status + GitHub repo for Solana programs.
OSEC_VERIFY_URL = "https://verify.osec.io/status/{program_id}"
# GitHub archive download template.
_GITHUB_ARCHIVE_URL = "https://github.com/{slug}/archive/{ref}.zip"
# GitHub Code Search API — used as fallback when OtterSec has no record.
# Searches for `declare_id!("{program_id}")` in Rust files on GitHub.
_GITHUB_SEARCH_URL = "https://api.github.com/search/code?q=declare_id+%22{program_id}%22+language%3ARust&per_page=5"
# Maximum number of Rust source files to include.
_SOLANA_MAX_FILES = 10


# ---------------------------------------------------------------------------
# Address validation.
# ---------------------------------------------------------------------------

_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Solana addresses are base58, length 32–44 characters (no 0, O, I, l).
_SOLANA_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def validate_address(chain: str, address: str) -> None:
    if chain in EVM_CHAINS:
        if not _EVM_ADDR_RE.match(address or ""):
            raise ExplorerError(
                "Invalid EVM address. Expected a 0x-prefixed 40-hex-char string."
            )
    elif chain == SOLANA_SLUG:
        if not _SOLANA_ADDR_RE.match(address or ""):
            raise ExplorerError(
                "Invalid Solana address. Expected a base58 string (32–44 chars)."
            )
    else:
        raise UnsupportedChainError(f"Unsupported chain: {chain}")


# ---------------------------------------------------------------------------
# HTTP helper — stdlib only, short timeout.
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT_SEC = 20


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "CodeAutrix/1.0"})
    # Use a permissive SSL context to avoid ECONNRESET / cert issues on macOS.
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC, context=ssl_ctx) as resp:
            raw = resp.read()
    except Exception as exc:  # network, DNS, timeout, HTTP error
        raise ExplorerError(f"Explorer request failed: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ExplorerError("Explorer returned non-JSON response") from exc


# ---------------------------------------------------------------------------
# Parsing Etherscan source-code responses.
# ---------------------------------------------------------------------------

def _sanitize_filename(name: str) -> str:
    """Keep the path structure (contracts/Foo.sol) but strip anything unsafe."""
    # Disallow absolute paths and traversal.
    name = name.replace("\\", "/").lstrip("/")
    parts = []
    for seg in name.split("/"):
        if seg in ("", ".", ".."):
            continue
        # Only allow a conservative set of chars.
        seg = re.sub(r"[^A-Za-z0-9._\-]+", "_", seg)
        parts.append(seg)
    return "/".join(parts) or "Contract.sol"


def _parse_source_code_field(source_code: str) -> Dict[str, str]:
    """Etherscan returns ``SourceCode`` in one of three shapes.

    1. Plain Solidity string (single-file contract).
    2. JSON string: ``{"file.sol": {"content": "..."}, ...}`` (multi-file).
    3. Double-brace JSON string: the Solidity Standard Input JSON
       (``{{"language": "Solidity", "sources": {"File.sol": {"content": "..."}}}}``).

    Returns a mapping of ``relative_path -> content``.
    """
    if not source_code:
        return {}

    stripped = source_code.strip()

    # Case 3: standard JSON input wrapped in extra braces.
    if stripped.startswith("{{") and stripped.endswith("}}"):
        inner = stripped[1:-1]
        try:
            obj = json.loads(inner)
        except json.JSONDecodeError:
            return {"Contract.sol": source_code}
        sources = obj.get("sources") if isinstance(obj, dict) else None
        if isinstance(sources, dict):
            return {
                _sanitize_filename(path): (meta or {}).get("content", "")
                for path, meta in sources.items()
                if isinstance(meta, dict)
            }
        return {"Contract.sol": source_code}

    # Case 2: plain JSON object mapping filename -> {"content": ...}.
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            return {"Contract.sol": source_code}
        if isinstance(obj, dict):
            files: Dict[str, str] = {}
            for path, meta in obj.items():
                if isinstance(meta, dict) and "content" in meta:
                    files[_sanitize_filename(path)] = meta["content"]
            if files:
                return files

    # Case 1: flat Solidity text.
    return {"Contract.sol": source_code}


# ---------------------------------------------------------------------------
# Fetcher result container.
# ---------------------------------------------------------------------------

@dataclass
class FetchedContract:
    chain: str
    address: str
    contract_name: str
    zip_filename: str
    zip_bytes: bytes


# ---------------------------------------------------------------------------
# Public entrypoint.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Solana source fetching via OtterSec Verify + GitHub.
# ---------------------------------------------------------------------------

def _http_get_bytes(url: str, timeout: int = 30) -> bytes:
    """Download raw bytes from *url*, following redirects (stdlib urlopen does this)."""
    req = urllib.request.Request(url, headers={"User-Agent": "CodeAutrix/1.0"})
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            return resp.read()
    except Exception as exc:
        raise ExplorerError(f"HTTP GET failed for {url}: {exc}") from exc


def _osec_verify_query(program_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Query OtterSec Verify. Returns (repo_url, commit, error_msg).

    Never raises — errors are returned as the third tuple element so the caller
    can gracefully fall through to the GitHub-search fallback.
    """
    url = OSEC_VERIFY_URL.format(program_id=program_id)
    logger.info("Querying OtterSec Verify API: %s", url)
    try:
        data = _http_get_json(url)
    except ExplorerError as exc:
        return None, None, f"OtterSec Verify API unreachable: {exc}"

    if not data.get("is_verified"):
        return None, None, f"Program {program_id[:8]}… is not verified on OtterSec"

    repo_url: str = (data.get("repo_url") or data.get("github") or "").strip().rstrip("/")
    commit: str = (data.get("commit") or "").strip()

    if not repo_url:
        return None, None, f"Program {program_id[:8]}… verified on OtterSec but has no GitHub URL"

    return repo_url, commit, None


def _github_search_solana_repo(program_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Search GitHub Code Search for a Rust file declaring the given program ID.

    Uses the ``declare_id!("<program_id>")`` anchor macro pattern, which every
    Anchor/native Solana program must include to identify itself on-chain.

    Returns (repo_url, error_msg). Supports an optional ``GITHUB_TOKEN`` env var
    to avoid the unauthenticated rate limit (10 req/min).
    """
    search_url = _GITHUB_SEARCH_URL.format(program_id=urllib.parse.quote(program_id))
    headers = {
        "User-Agent":  "CodeAutrix/1.0",
        "Accept":      "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    logger.info("Searching GitHub for Solana program: %s", program_id[:8])
    req = urllib.request.Request(search_url, headers=headers)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC, context=ssl_ctx) as resp:
            raw = resp.read()
    except Exception as exc:
        return None, f"GitHub Search API request failed: {exc}"

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return None, "GitHub Search API returned non-JSON response"

    items = data.get("items") or []
    if not items:
        return None, (
            f"No public GitHub repository found containing declare_id!(\"{program_id[:8]}…\"). "
            "The program source may not be open-source, or the repository is private."
        )

    # Pick the result with the highest repo score (items are already relevance-ranked).
    for item in items:
        repo = item.get("repository") or {}
        html_url = (repo.get("html_url") or "").strip().rstrip("/")
        if html_url and "github.com" in html_url:
            logger.info(
                "GitHub search matched repo: %s (file: %s)",
                html_url, item.get("path", "?"),
            )
            return html_url, None

    return None, "GitHub Search returned results but none had a usable repository URL"


def _github_slug_from_url(repo_url: str) -> Optional[str]:
    """Extract 'owner/repo' from a GitHub URL, or None if the URL is not a GitHub URL."""
    m = re.match(r"https?://github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+?)(?:\.git)?(?:[/?#].*)?$", repo_url)
    return m.group(1) if m else None


def _download_github_source(repo_url: str, commit: str) -> bytes:
    """Download source archive from GitHub for the given repo + ref.

    Tries the exact commit first, then ``main`` and ``master`` as fallbacks.
    Returns raw ZIP bytes.
    """
    slug = _github_slug_from_url(repo_url)
    if not slug:
        raise ExplorerError(
            f"Cannot parse GitHub repository URL: {repo_url}. "
            "Expected format: https://github.com/owner/repo"
        )

    refs_to_try = list(dict.fromkeys(filter(None, [commit, "main", "master"])))
    last_exc: Optional[Exception] = None
    for ref in refs_to_try:
        archive_url = _GITHUB_ARCHIVE_URL.format(slug=slug, ref=ref)
        logger.info("Downloading GitHub source archive: %s", archive_url)
        try:
            return _http_get_bytes(archive_url, timeout=45)
        except ExplorerError as exc:
            last_exc = exc
            logger.warning("Failed to download %s: %s", archive_url, exc)

    raise ExplorerError(
        f"Could not download source archive from {repo_url} "
        f"(tried refs: {refs_to_try}). Last error: {last_exc}"
    )


def _extract_rust_sources(zip_bytes: bytes) -> Dict[str, str]:
    """Extract Rust (.rs) source files from a GitHub archive ZIP.

    GitHub archives always have a single top-level directory (``repo-ref/``).
    We strip that prefix and return a mapping of ``relative_path -> content``.
    Limits to ``_SOLANA_MAX_FILES`` files to match the EVM pipeline behaviour.
    """
    files: Dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            all_names = zf.namelist()

            # Detect and strip the top-level directory prefix.
            prefix = ""
            if all_names:
                first_part = all_names[0].split("/")[0]
                if first_part:
                    prefix = first_part + "/"

            rs_entries = [
                n for n in all_names
                if n.endswith(".rs")
                and not n.endswith("/")
                and "/__MACOSX/" not in n
                and "/." not in n.split("/")[-1]  # skip hidden files like ._foo.rs
            ]

            # Prioritise program/src files over test and build artefacts.
            def _priority(name: str) -> int:
                lname = name.lower()
                if "/tests/" in lname or "test_" in lname.split("/")[-1]:
                    return 2
                if "/target/" in lname or "/node_modules/" in lname:
                    return 3
                return 1

            rs_entries.sort(key=_priority)
            rs_entries = rs_entries[:_SOLANA_MAX_FILES]

            for entry in rs_entries:
                rel = entry[len(prefix):] if entry.startswith(prefix) else entry
                if not rel:
                    continue
                rel = _sanitize_filename(rel)
                try:
                    content = zf.read(entry).decode("utf-8", errors="ignore")
                    files[rel] = content
                except Exception as exc:
                    logger.warning("Could not read archive entry %s: %s", entry, exc)

    except zipfile.BadZipFile as exc:
        raise ExplorerError(f"Downloaded archive is not a valid ZIP file: {exc}") from exc

    return files


def _fetch_solana_contract(address: str) -> "FetchedContract":
    """Fetch Solana program source code via a two-stage lookup.

    Stage 1 — OtterSec Verify (preferred):
      Programs submitted via ``solana-verifiable-build`` have a pinned commit,
      giving the strongest source ↔ on-chain bytecode correspondence.

    Stage 2 — GitHub Code Search (fallback):
      Searches GitHub for ``declare_id!("<address>")`` in Rust files.
      Works for open-source programs that haven't gone through OtterSec,
      but does not guarantee the source matches the deployed binary.

    Both stages ultimately download a GitHub archive and extract .rs files.
    """
    # ── Stage 1: OtterSec Verify ─────────────────────────────────────────────
    repo_url, commit, osec_err = _osec_verify_query(address)
    source_tag = "OtterSec-verified"

    if repo_url is None:
        logger.info("OtterSec lookup failed (%s); trying GitHub Code Search…", osec_err)

        # ── Stage 2: GitHub Code Search ───────────────────────────────────────
        repo_url, search_err = _github_search_solana_repo(address)
        commit = ""
        source_tag = "GitHub (unverified)"

        if repo_url is None:
            raise ContractNotVerifiedError(
                f"Could not locate source code for program {address[:8]}…\n\n"
                f"• OtterSec: {osec_err}\n"
                f"• GitHub search: {search_err}\n\n"
                "Options:\n"
                "1. Upload the source files manually.\n"
                "2. Verify the program on OtterSec (https://verify.osec.io) for future automatic fetching.\n"
                "3. Set a GITHUB_TOKEN env var on the server to avoid GitHub API rate limits."
            )

    # ── Download archive + extract .rs files ─────────────────────────────────
    try:
        zip_bytes_raw = _download_github_source(repo_url, commit)
    except ExplorerError as exc:
        raise ExplorerError(
            f"Could not download source archive from {repo_url}: {exc}"
        ) from exc

    rs_files = _extract_rust_sources(zip_bytes_raw)
    if not rs_files:
        raise ContractNotVerifiedError(
            f"No Rust source files (.rs) found in repository {repo_url}. "
            "Please upload the source files manually."
        )

    slug = _github_slug_from_url(repo_url)
    contract_name = (slug.split("/")[-1] if slug else None) or address[:8]

    metadata_extra = {
        "repo_url": repo_url,
        "commit": commit,
        "sourceTag": source_tag,
    }
    zip_filename, out_zip_bytes = _pack_zip(
        SOLANA_SLUG, address, contract_name, rs_files, metadata_extra
    )
    logger.info(
        "Solana contract packed: program=%s repo=%s source=%s files=%d",
        address, repo_url, source_tag, len(rs_files),
    )
    return FetchedContract(
        chain=SOLANA_SLUG,
        address=address,
        contract_name=contract_name,
        zip_filename=zip_filename,
        zip_bytes=out_zip_bytes,
    )


# ---------------------------------------------------------------------------
# Public entrypoint.
# ---------------------------------------------------------------------------

def fetch_verified_contract(chain: str, address: str) -> FetchedContract:
    """Fetch a verified contract's source files and return them zipped.

    Raises one of the ``ExplorerError`` subclasses on failure.
    """
    validate_address(chain, address)

    if chain == SOLANA_SLUG:
        return _fetch_solana_contract(address)

    if chain not in EVM_CHAINS:
        raise UnsupportedChainError(f"Unsupported chain: {chain}")

    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        raise ExplorerConfigError(
            "ETHERSCAN_API_KEY is not configured on the server. "
            "Admin: set this env var to enable on-chain contract fetching."
        )

    spec = EVM_CHAINS[chain]

    params = {
        "chainid": str(spec.chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    url = ETHERSCAN_V2_URL + "?" + urllib.parse.urlencode(params)
    logger.info("Fetching contract source from Etherscan V2: chain=%s chainid=%s address=%s",
                chain, spec.chain_id, address)
    data = _http_get_json(url)

    # Etherscan shape: {"status":"1","message":"OK","result":[{...}]}
    status = str(data.get("status", ""))
    result = data.get("result")

    # Error responses come through with status="0" and a string in result/message.
    if status != "1" or not isinstance(result, list) or not result:
        # Show both message and result so the real cause is visible in the UI.
        detail = result if isinstance(result, str) else data.get("message", "Unknown error")
        logger.error("Explorer API error response: %s", data)
        raise ExplorerError(f"Explorer error: {detail}")

    entry = result[0] or {}
    source_code = entry.get("SourceCode", "") or ""
    contract_name = entry.get("ContractName", "") or "Contract"

    if not source_code:
        # Etherscan returns an entry with empty SourceCode when the contract
        # exists but isn't verified; or when the address isn't a contract at all.
        abi = entry.get("ABI", "")
        if isinstance(abi, str) and abi.startswith("Contract source code not verified"):
            raise ContractNotVerifiedError(
                f"Contract at {address} is deployed but source is not verified on "
                f"{spec.display}. Please upload the source files instead."
            )
        raise ContractNotFoundError(
            f"No verified contract found at {address} on {spec.display}."
        )

    files = _parse_source_code_field(source_code)
    if not files:
        raise ContractNotVerifiedError(
            f"Could not parse source code for contract at {address} on {spec.display}."
        )

    zip_filename, zip_bytes = _pack_zip(chain, address, contract_name, files, entry)
    return FetchedContract(
        chain=chain,
        address=address,
        contract_name=contract_name,
        zip_filename=zip_filename,
        zip_bytes=zip_bytes,
    )


# ---------------------------------------------------------------------------
# Zip packaging.
# ---------------------------------------------------------------------------

def _pack_zip(
    chain: str,
    address: str,
    contract_name: str,
    files: Dict[str, str],
    raw_entry: dict,
) -> Tuple[str, bytes]:
    safe_name = re.sub(r"[^A-Za-z0-9._\-]+", "_", contract_name) or "Contract"
    zip_filename = f"{chain}_{address[:10]}_{safe_name}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Source files.
        for relpath, content in files.items():
            # zipfile's writestr is safe with forward-slash paths.
            zf.writestr(relpath, content or "")

        # Metadata sidecar so the audit skill knows provenance.
        metadata: Dict[str, str] = {
            "source": "explorer",
            "chain": chain,
            "address": address,
            "contractName": contract_name,
            # EVM-specific fields (empty for Solana contracts).
            "compilerVersion": raw_entry.get("CompilerVersion", ""),
            "optimizationUsed": raw_entry.get("OptimizationUsed", ""),
            "runs": raw_entry.get("Runs", ""),
            "licenseType": raw_entry.get("LicenseType", ""),
            "proxy": raw_entry.get("Proxy", ""),
            "implementation": raw_entry.get("Implementation", ""),
            # Solana-specific fields (empty for EVM contracts).
            "repoUrl":   raw_entry.get("repo_url", ""),
            "commit":    raw_entry.get("commit", ""),
            "sourceTag": raw_entry.get("sourceTag", ""),
        }
        zf.writestr("codeautrix_fetch_metadata.json", json.dumps(metadata, indent=2))

    return zip_filename, buf.getvalue()
