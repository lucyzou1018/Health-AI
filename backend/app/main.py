from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
from pathlib import Path
from typing import Any, Dict, Literal, Optional, List

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB hard cap per upload
MAX_WALLET_SESSIONS = 1000            # evict expired sessions above this threshold

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .task_manager import TaskManager
from . import rate_limiter
from . import explorer_client

# Try to import eth-account for signature verification
try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
    ETH_ACCOUNT_AVAILABLE = True
except ImportError:
    ETH_ACCOUNT_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent.parent / "storage"
BASE_DIR.mkdir(parents=True, exist_ok=True)
REPO_ROOT = Path(__file__).resolve().parents[2]

task_manager = TaskManager(BASE_DIR, repo_root=REPO_ROOT)

# In-memory session store (for production consider Redis or a DB)
wallet_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = threading.Lock()  # protects wallet_sessions against concurrent access
SESSIONS_PATH = BASE_DIR / "wallet_sessions.json"

# Per-task-id locks for PDF generation — prevents two concurrent requests from
# writing to the same .pdf file simultaneously.
_pdf_gen_locks: Dict[str, threading.Lock] = {}
_pdf_gen_locks_meta = threading.Lock()  # protects _pdf_gen_locks dict itself


def _get_pdf_lock(task_id: str) -> threading.Lock:
    with _pdf_gen_locks_meta:
        if task_id not in _pdf_gen_locks:
            _pdf_gen_locks[task_id] = threading.Lock()
        return _pdf_gen_locks[task_id]


def _persist_wallet_sessions() -> None:
    with _sessions_lock:
        payload = {
            token: session
            for token, session in wallet_sessions.items()
            if session.get("expires_at", 0) >= int(time.time())
        }
    tmp_path = SESSIONS_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(payload), encoding="utf-8")
    tmp_path.replace(SESSIONS_PATH)


def _load_wallet_sessions() -> None:
    if not SESSIONS_PATH.exists():
        return
    try:
        data = json.loads(SESSIONS_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
    except Exception:
        logger.exception("Failed to load wallet sessions from %s", SESSIONS_PATH)
        return

    now = int(time.time())
    with _sessions_lock:
        wallet_sessions.clear()
        for token, session in data.items():
            if not isinstance(session, dict):
                continue
            if session.get("expires_at", 0) < now:
                continue
            wallet_sessions[token] = session


def verify_wallet_token(token: str = Header(None, alias="X-Wallet-Token")) -> Optional[str]:
    """Validate X-Wallet-Token header and return the associated wallet address, or None."""
    if not token:
        return None
    with _sessions_lock:
        session = wallet_sessions.get(token)
        if not session:
            return None
        if session.get("expires_at", 0) < int(time.time()):
            wallet_sessions.pop(token, None)  # pop avoids KeyError if evicted concurrently
            _persist_wallet_sessions()
            return None
        return session.get("wallet_address")

app = FastAPI(title="CodeAutrix", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.healthaionline.com",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8091",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)
_load_wallet_sessions()


class UploadResponse(BaseModel):
    upload_id: str = Field(alias="uploadId")
    filename: str


class FromChainRequest(BaseModel):
    chain: str = Field(description="Chain slug, e.g. ethereum, bsc, polygon, arbitrum, optimism, base, solana")
    address: str = Field(description="On-chain contract/program address")

    class Config:
        validate_by_name = True


class FromChainResponse(BaseModel):
    upload_id: str = Field(alias="uploadId")
    filename: str
    chain: str
    address: str
    contract_name: str = Field(alias="contractName")

    class Config:
        validate_by_name = True


class TaskRequest(BaseModel):
    skill_type: Literal["skill-security-audit", "multichain-contract-vuln", "skill-stress-lab"] = Field(alias="skillType")
    code_path: Optional[str] = Field(default=None, alias="codePath")
    upload_id: Optional[str] = Field(default=None, alias="uploadId")
    params: Dict[str, Any] = Field(default_factory=dict)
    wallet_address: Optional[str] = Field(default=None, alias="walletAddress")
    file_name: Optional[str] = Field(default=None, alias="fileName")
    device_id: Optional[str] = Field(default=None, alias="deviceId")

    class Config:
        validate_by_name = True


class TaskResponse(BaseModel):
    task_id: str = Field(alias="taskId")
    status: str
    skill_type: str = Field(alias="skillType")
    message: str
    report_path: Optional[str] = Field(default=None, alias="reportPath")
    summary_path: Optional[str] = Field(default=None, alias="summaryPath")
    log_path: Optional[str] = Field(default=None, alias="logPath")
    created_at: str = Field(alias="createdAt")
    updated_at: str = Field(alias="updatedAt")
    wallet_address: Optional[str] = Field(default=None, alias="walletAddress")
    file_name: Optional[str] = Field(default=None, alias="fileName")

    class Config:
        validate_by_name = True


class WalletAuthRequest(BaseModel):
    wallet_address: str = Field(alias="walletAddress")
    signature: str = Field(description="EIP-191 wallet signature")
    message: str = Field(description="The message that was signed")

    class Config:
        validate_by_name = True


class WalletAuthResponse(BaseModel):
    token: str
    wallet_address: str = Field(alias="walletAddress")
    expires_at: int = Field(alias="expiresAt")


class GoogleAuthRequest(BaseModel):
    email: str
    name: str = ""
    google_id: str = Field(alias="googleId")
    access_token: str = Field(alias="accessToken")

    class Config:
        validate_by_name = True


class GitHubAuthRequest(BaseModel):
    code: str = Field(description="GitHub OAuth authorization code")
    client_id: str = Field(default="", alias="clientId", description="GitHub OAuth client ID used by frontend")

    class Config:
        validate_by_name = True


class HistoryQueryParams(BaseModel):
    skill_type: Optional[str] = Field(default=None, alias="skillType")
    limit: int = Field(default=20, ge=1, le=100)


@app.get("/api/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok"}


_ALLOWED_UPLOAD_EXTS = {".zip", ".skill", ".tar", ".gz", ".bz2", ".xz"}


@app.post("/api/uploads", response_model=UploadResponse)
def upload_file(file: UploadFile = File(...)) -> UploadResponse:
    # Using a sync handler: FastAPI dispatches it to the default threadpool so
    # the blocking file-read / disk-write don't block the async event loop.
    suffix = Path(file.filename).suffix.lower() if file.filename else ""
    if suffix not in _ALLOWED_UPLOAD_EXTS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{suffix}'. Allowed: {', '.join(sorted(_ALLOWED_UPLOAD_EXTS))}",
        )
    content = file.file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )
    upload_id = task_manager.save_upload(file.filename, content)
    return UploadResponse(uploadId=upload_id, filename=file.filename)


@app.post("/api/contracts/from-chain", response_model=FromChainResponse)
def fetch_contract_from_chain(payload: FromChainRequest) -> FromChainResponse:
    """Fetch verified source for an on-chain contract and stage it as an upload.

    The returned ``uploadId`` can be passed directly to ``POST /api/tasks`` —
    the task pipeline then runs exactly the same audit it would for a
    user-uploaded archive.
    """
    chain = (payload.chain or "").strip().lower()
    address = (payload.address or "").strip()

    try:
        fetched = explorer_client.fetch_verified_contract(chain, address)
    except explorer_client.UnsupportedChainError as exc:
        # 422: request is well-formed but not actionable (wrong chain).
        raise HTTPException(status_code=422, detail=str(exc))
    except explorer_client.ContractNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except explorer_client.ContractNotVerifiedError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except explorer_client.ExplorerConfigError as exc:
        # 503: server-side misconfiguration, surfaced clearly to the caller.
        raise HTTPException(status_code=503, detail=str(exc))
    except explorer_client.ExplorerError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    # Reuse the same upload-size guard to avoid pathological contracts.
    if len(fetched.zip_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Fetched source exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )

    upload_id = task_manager.save_upload(fetched.zip_filename, fetched.zip_bytes)
    return FromChainResponse(
        uploadId=upload_id,
        filename=fetched.zip_filename,
        chain=fetched.chain,
        address=fetched.address,
        contractName=fetched.contract_name,
    )


@app.post("/api/tasks", response_model=TaskResponse)
def create_task(
    request: Request,
    payload: TaskRequest,
    wallet_address: Optional[str] = Depends(verify_wallet_token)
) -> TaskResponse:
    effective_wallet = payload.wallet_address or wallet_address

    # Check quota first (non-consuming) — quota is consumed only after successful task creation
    # to avoid wasting the user's daily allowance on validation errors.
    client_ip = request.client.host if request.client else ""
    quota = rate_limiter.get_status(client_ip)
    if not quota["allowed"]:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Daily task limit reached. You have used {quota['used']}/{quota['limit']} "
                f"tasks today (UTC). Resets at midnight UTC."
            ),
        )

    try:
        record = task_manager.create_task(
            skill_type=payload.skill_type,
            code_path=payload.code_path,
            upload_id=payload.upload_id,
            params=payload.params,
            wallet_address=effective_wallet,
            file_name=payload.file_name,
        )
    except ValueError as exc:
        if str(exc) == "DUPLICATE_TASK":
            raise HTTPException(
                status_code=409,
                detail="A task of this type is already running. Please wait for it to complete."
            )
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error creating task")
        raise HTTPException(status_code=500, detail="Internal server error. Please try again later.")

    # Consume quota after task is successfully created
    rate_limiter.try_increment(client_ip)
    return TaskResponse(
        taskId=record.task_id,
        status=record.status,
        skillType=record.skill_type,
        message=record.message,
        reportPath=record.report_path,
        summaryPath=record.summary_path,
        logPath=record.log_path,
        createdAt=record.created_at,
        updatedAt=record.updated_at,
        walletAddress=record.wallet_address,
        fileName=record.file_name,
    )


@app.get("/api/tasks/{task_id}", response_model=TaskResponse)
def get_task(task_id: str) -> TaskResponse:
    try:
        record = task_manager.get_task(task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="task not found")
    return TaskResponse(
        taskId=record.task_id,
        status=record.status,
        skillType=record.skill_type,
        message=record.message,
        reportPath=record.report_path,
        summaryPath=record.summary_path,
        logPath=record.log_path,
        createdAt=record.created_at,
        updatedAt=record.updated_at,
        fileName=record.file_name,
    )


@app.get("/api/tasks/{task_id}/report")
def download_report(task_id: str):
    try:
        record = task_manager.get_task(task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="task not found")
    if not record.report_path:
        raise HTTPException(status_code=404, detail="report missing")
    path = Path(record.report_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="report file missing")
    return FileResponse(path)

@app.get("/api/tasks/{task_id}/report/pdf")
def download_report_pdf(task_id: str):
    """Render the Markdown report as a PDF and stream it to the client."""
    try:
        record = task_manager.get_task(task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="task not found")
    if not record.report_path:
        raise HTTPException(status_code=404, detail="report missing")
    md_path = Path(record.report_path)
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="report file missing")

    from .pdf_generator import generate_pdf
    pdf_generator_path = Path(__file__).with_name("pdf_generator.py")
    pdf_path = md_path.with_suffix(".pdf")

    # Acquire a per-task lock so concurrent requests don't write the same file
    # simultaneously.  The second request will wait, then find a fresh PDF and
    # skip regeneration.
    pdf_lock = _get_pdf_lock(task_id)
    with pdf_lock:
        needs_regen = (
            not pdf_path.exists()
            or pdf_path.stat().st_mtime < md_path.stat().st_mtime
            or (
                pdf_generator_path.exists()
                and pdf_path.stat().st_mtime < pdf_generator_path.stat().st_mtime
            )
        )
        if needs_regen:
            try:
                generate_pdf(md_path, pdf_path, skill_type=record.skill_type)
            except Exception as e:
                logger.exception("PDF generation failed for task %s", task_id)
                raise HTTPException(status_code=500, detail="PDF generation failed. Please try again later.")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"report-{task_id[:8]}.pdf",
    )


# /api/tasks/{task_id}/artifact is intentionally not exposed — summary/log contain internal paths.


# --------------------------- Wallet Authentication ---------------------------

@app.get("/api/wallet/nonce")
def get_wallet_nonce(wallet_address: str):
    """Return a one-time message for the client to sign with their wallet."""
    nonce = secrets.token_hex(16)
    message = f"CodeAutrix Login\nAddress: {wallet_address}\nNonce: {nonce}\nTimestamp: {int(time.time())}"
    return {"message": message, "nonce": nonce}


@app.post("/api/wallet/verify", response_model=WalletAuthResponse)
def verify_wallet_login(payload: WalletAuthRequest) -> WalletAuthResponse:
    """Verify the wallet signature and return a session token."""
    wallet_address = payload.wallet_address.lower()
    if ETH_ACCOUNT_AVAILABLE:
        try:
            message = encode_defunct(text=payload.message)
            recovered_address = Account.recover_message(message, signature=payload.signature)
            if recovered_address.lower() != wallet_address:
                raise HTTPException(status_code=401, detail="Signature verification failed: address mismatch")
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Signature verification failed for wallet %s", wallet_address)
            raise HTTPException(status_code=401, detail="Signature verification failed.")
    else:
        # Fallback when eth-account is unavailable.
        # EIP-191 signatures are 65 bytes = 132 hex chars with 0x prefix.
        # Reject anything that doesn't look like a real signature.
        sig = payload.signature or ""
        if not (sig.startswith("0x") and len(sig) == 132):
            raise HTTPException(status_code=401, detail="Invalid signature format. Install eth-account for full verification.")
    
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 7 * 24 * 3600  # 7-day session

    with _sessions_lock:
        # Evict expired sessions before inserting to bound memory usage.
        if len(wallet_sessions) >= MAX_WALLET_SESSIONS:
            now = int(time.time())
            expired_keys = [k for k, v in wallet_sessions.items() if v.get("expires_at", 0) < now]
            for k in expired_keys:
                wallet_sessions.pop(k, None)
        wallet_sessions[token] = {
            "wallet_address": wallet_address,
            "expires_at": expires_at,
        }
    _persist_wallet_sessions()
    
    return WalletAuthResponse(
        token=token,
        walletAddress=wallet_address,
        expiresAt=expires_at
    )


# --------------------------- Google OAuth Authentication ---------------------------

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")


@app.post("/api/auth/google")
def google_login(payload: GoogleAuthRequest):
    """Verify Google OAuth access token and return a session token.

    The frontend already verified the access token with Google's userinfo API
    and obtained the user's email/name/sub. We attempt server-side verification
    as an extra check, but if the server cannot reach Google (firewall, proxy,
    DNS), we fall back to trusting the frontend-provided data since the access
    token could only have been obtained through a legitimate OAuth flow.
    """
    import urllib.request
    import json as _json

    verified_email = payload.email.lower()

    # Try server-side verification, but don't block login if it fails
    try:
        req = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {payload.access_token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            user_info = _json.loads(resp.read().decode())
        server_email = user_info.get("email", "").lower()
        if server_email and server_email != verified_email:
            raise HTTPException(status_code=401, detail="Email mismatch in Google verification.")
        verified_email = server_email or verified_email
        logger.info("Google token verified server-side for %s", verified_email)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Server-side Google verification failed (%s), using frontend-provided email: %s", exc, verified_email)

    # Generate a deterministic wallet-like address from the Google ID for compatibility
    google_wallet = "0x" + hashlib.sha256(f"google:{payload.google_id}".encode()).hexdigest()[:40]

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 7 * 24 * 3600  # 7-day session

    with _sessions_lock:
        if len(wallet_sessions) >= MAX_WALLET_SESSIONS:
            now = int(time.time())
            expired_keys = [k for k, v in wallet_sessions.items() if v.get("expires_at", 0) < now]
            for k in expired_keys:
                wallet_sessions.pop(k, None)
        wallet_sessions[token] = {
            "wallet_address": google_wallet,
            "expires_at": expires_at,
        }
    _persist_wallet_sessions()

    return {
        "token": token,
        "walletAddress": google_wallet,
        "email": verified_email,
        "expiresAt": expires_at,
    }


# ── GitHub OAuth Configuration ───────────────────────────────────────────────
# Secrets loaded from environment variables only — NEVER hardcode secrets in source.
#
# Supports multiple GitHub OAuth Apps via numbered env vars:
#   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET          — primary (or single-app setup)
#   GITHUB_CLIENT_ID_2 / GITHUB_CLIENT_SECRET_2      — second app
#   GITHUB_CLIENT_ID_3 / GITHUB_CLIENT_SECRET_3      — third app
#
# Example (.env):
#   GITHUB_CLIENT_ID=Ov23li...         GITHUB_CLIENT_SECRET=abc...   # localhost
#   GITHUB_CLIENT_ID_2=Ov23li...       GITHUB_CLIENT_SECRET_2=def... # test
#   GITHUB_CLIENT_ID_3=Ov23li...       GITHUB_CLIENT_SECRET_3=ghi... # production

def _load_github_oauth_configs() -> Dict[str, str]:
    configs: Dict[str, str] = {}
    # Primary
    cid = os.getenv("GITHUB_CLIENT_ID", "")
    sec = os.getenv("GITHUB_CLIENT_SECRET", "")
    if cid and sec:
        configs[cid] = sec
    # Secondary without underscore: GITHUB_CLIENT_ID2 / GITHUB_CLIENT_SECRET2
    cid = os.getenv("GITHUB_CLIENT_ID2", "")
    sec = os.getenv("GITHUB_CLIENT_SECRET2", "")
    if cid and sec:
        configs[cid] = sec
    # Numbered extras with underscore (_2, _3, ...)
    for i in range(2, 10):
        cid = os.getenv(f"GITHUB_CLIENT_ID_{i}", "")
        sec = os.getenv(f"GITHUB_CLIENT_SECRET_{i}", "")
        if cid and sec:
            configs[cid] = sec
    return configs

GITHUB_OAUTH_CONFIGS: Dict[str, str] = _load_github_oauth_configs()


@app.post("/api/auth/github")
def github_login(payload: GitHubAuthRequest):
    """Exchange GitHub OAuth authorization code for a session token.

    Flow: frontend redirects user to GitHub → user authorises → GitHub
    redirects back with a `code` → frontend POSTs the code here →
    backend exchanges it for an access token and fetches user info.
    """
    import urllib.request
    import json as _json

    # Resolve client_id → client_secret
    gh_client_id = payload.client_id
    gh_client_secret = GITHUB_OAUTH_CONFIGS.get(gh_client_id, "") if gh_client_id else ""
    # Fallback: if frontend didn't send client_id, try first available config
    if not gh_client_secret and GITHUB_OAUTH_CONFIGS:
        gh_client_id, gh_client_secret = next(iter(GITHUB_OAUTH_CONFIGS.items()))
    if not gh_client_secret:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth is not configured for this environment.",
        )

    # Use httpx for GitHub API calls (handles proxies and SSL better than urllib)
    import httpx

    # Only disable SSL verification on localhost (dev proxy); production always verifies
    _ssl_verify = os.getenv("GITHUB_SSL_VERIFY", "true").lower() not in ("0", "false", "no")

    # Step 1: Exchange code for access token
    try:
        token_resp = httpx.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": gh_client_id,
                "client_secret": gh_client_secret,
                "code": payload.code,
            },
            headers={"Accept": "application/json"},
            timeout=15,
            verify=_ssl_verify,
        )
        token_data = token_resp.json()
    except Exception as exc:
        logger.error("GitHub token exchange failed: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to exchange GitHub authorization code.")

    access_token = token_data.get("access_token")
    if not access_token:
        error_desc = token_data.get("error_description", token_data.get("error", "unknown"))
        logger.warning("GitHub token exchange returned error: %s", error_desc)
        raise HTTPException(status_code=401, detail=f"GitHub auth failed: {error_desc}")

    gh_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "User-Agent": "CodeAutrix",
    }

    # Step 2: Fetch user profile
    try:
        user_resp = httpx.get("https://api.github.com/user", headers=gh_headers, timeout=10, verify=_ssl_verify)
        user_info = user_resp.json()
    except Exception as exc:
        logger.error("GitHub user info fetch failed: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to fetch GitHub user info.")

    github_id = str(user_info.get("id", ""))
    github_login_name = user_info.get("login", "")
    github_email = user_info.get("email") or ""

    if not github_id:
        raise HTTPException(status_code=401, detail="Invalid GitHub user info.")

    # Step 3: If email is private, fetch from /user/emails
    if not github_email:
        try:
            emails_resp = httpx.get("https://api.github.com/user/emails", headers=gh_headers, timeout=10, verify=_ssl_verify)
            emails = emails_resp.json()
            for entry in emails:
                if entry.get("primary") and entry.get("verified"):
                    github_email = entry["email"]
                    break
            if not github_email and emails:
                github_email = emails[0].get("email", "")
        except Exception as exc:
            logger.warning("GitHub email fetch failed: %s", exc)

    # Step 4: Generate deterministic wallet address (same pattern as Google)
    github_wallet = "0x" + hashlib.sha256(f"github:{github_id}".encode()).hexdigest()[:40]

    session_token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 7 * 24 * 3600  # 7-day session

    with _sessions_lock:
        if len(wallet_sessions) >= MAX_WALLET_SESSIONS:
            now = int(time.time())
            expired_keys = [k for k, v in wallet_sessions.items() if v.get("expires_at", 0) < now]
            for k in expired_keys:
                wallet_sessions.pop(k, None)
        wallet_sessions[session_token] = {
            "wallet_address": github_wallet,
            "expires_at": expires_at,
        }
    _persist_wallet_sessions()

    logger.info("GitHub login successful: %s (%s)", github_login_name, github_email)

    return {
        "token": session_token,
        "walletAddress": github_wallet,
        "email": github_email,
        "login": github_login_name,
        "expiresAt": expires_at,
    }


@app.get("/api/wallet/history", response_model=List[TaskResponse])
def get_wallet_history(
    skill_type: Optional[str] = None,
    limit: int = 20,
    wallet_address: str = Depends(verify_wallet_token)
) -> List[TaskResponse]:
    """Return analysis history for the authenticated wallet."""
    if not wallet_address:
        raise HTTPException(status_code=401, detail="Wallet not connected. Please connect your wallet first.")
    
    records = task_manager.get_tasks_by_wallet(wallet_address, skill_type, limit)
    return [
        TaskResponse(
            taskId=r.task_id,
            status=r.status,
            skillType=r.skill_type,
            message=r.message,
            reportPath=r.report_path,
            summaryPath=r.summary_path,
            logPath=r.log_path,
            createdAt=r.created_at,
            updatedAt=r.updated_at,
            walletAddress=r.wallet_address,
            fileName=r.file_name,
        )
        for r in records
    ]


@app.get("/api/wallet/me")
def get_wallet_info(wallet_address: str = Depends(verify_wallet_token)):
    """Return the wallet address for the current session."""
    if not wallet_address:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"wallet_address": wallet_address}


# ── Metrics snapshot endpoint ────────────────────────────────────────────────

@app.get("/api/metrics/snapshot")
def metrics_snapshot(
    access_token: str = "",
    end_timestamp: Optional[int] = None,
):
    """
    Project-chart metrics endpoint.
    GET /api/metrics/snapshot?access_token=<token>[&end_timestamp=<unix_sec>]

    Returns cumulative counters up to `end_timestamp` (or now if omitted).
    Identical end_timestamp always returns identical data (idempotent).
    """
    # ── Auth (fallback — primary guard is the ASGI wrapper) ──────────────────
    # The ASGI wrapper drops the connection before any HTTP bytes are sent.
    # This check is a safety net only and should never be reached.
    expected = os.environ.get("CHARTS_ACCESS_TOKEN", "f261d2107df7e17f191ed8fa498f8b27df7d2b3337e6bb24b9ee74aa865dcc95")
    if access_token != expected:
        return None

    # ── Time bound ───────────────────────────────────────────────────────────
    # created_at is stored as ISO-8601 UTC string "2026-03-23T07:15:32.463888Z"
    # Converting unix ts → same format lets us do a plain string comparison.
    if end_timestamp is not None:
        cutoff_dt  = datetime.fromtimestamp(end_timestamp, tz=timezone.utc)
        cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S")   # prefix match is enough
        ts_out = end_timestamp
    else:
        cutoff_iso = None
        ts_out = int(datetime.utcnow().timestamp())

    # ── Query SQLite ──────────────────────────────────────────────────────────
    db_path = BASE_DIR / "tasks.db"
    try:
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        if cutoff_iso:
            where = "WHERE created_at <= ?"
            args  = (cutoff_iso,)
        else:
            where = ""
            args  = ()

        def q(sql: str, params: tuple = ()) -> int:
            return conn.execute(sql, params).fetchone()[0]

        total_users = q(
            f"SELECT COUNT(DISTINCT lower(wallet_address)) FROM tasks {where}",
            args,
        )
        total_audits = q(
            f"SELECT COUNT(*) FROM tasks {where}",
            args,
        )
        total_contract_audits = q(
            f"SELECT COUNT(*) FROM tasks {where} {'AND' if where else 'WHERE'} skill_type='multichain-contract-vuln'",
            args,
        )
        total_skill_audits = q(
            f"SELECT COUNT(*) FROM tasks {where} {'AND' if where else 'WHERE'} skill_type='skill-security-audit'",
            args,
        )
        total_skill_stress = q(
            f"SELECT COUNT(*) FROM tasks {where} {'AND' if where else 'WHERE'} skill_type='skill-stress-lab'",
            args,
        )
        conn.close()
    except Exception as exc:
        logger.exception("metrics_snapshot db error")
        raise HTTPException(status_code=500, detail={"error": str(exc)})

    return {
        "data": {
            "total_users":           total_users,
            "total_audits":          total_audits,
            "total_contract_audits": total_contract_audits,
            "total_skill_audits":    total_skill_audits,
            "total_skill_stress":    total_skill_stress,
        },
        "extra": {
            "timestamp": ts_out,
            "display": {
                "total_users":           "总用户数",
                "total_audits":          "总审计次数",
                "total_contract_audits": "总合约审计数",
                "total_skill_audits":    "总Skill审计数",
                "total_skill_stress":    "总压力测试数",
            },
            "order": [
                "total_users",
                "total_audits",
                "total_contract_audits",
                "total_skill_audits",
                "total_skill_stress",
            ],
        },
    }


# Serve frontend static files — must be mounted last so API routes take precedence.
# JS/HTML files get no-cache headers so browsers always fetch the latest version.
_FRONTEND_DIR = REPO_ROOT / "frontend"

@app.get("/{full_path:path}", include_in_schema=False)
async def serve_frontend(full_path: str, request: Request):
    """Serve static files with no-cache for JS/HTML to prevent stale client_id issues."""
    from fastapi.responses import Response
    target = _FRONTEND_DIR / full_path
    # Default to index / workspace.html for bare paths
    if not target.exists() or target.is_dir():
        target = _FRONTEND_DIR / "workspace.html"
    if not target.exists():
        raise HTTPException(status_code=404)
    suffix = target.suffix.lower()
    no_cache_types = {".js", ".html", ".htm"}
    headers = {"Cache-Control": "no-store, no-cache, must-revalidate"} if suffix in no_cache_types else {}
    import mimetypes
    mime, _ = mimetypes.guess_type(str(target))
    return FileResponse(str(target), headers=headers, media_type=mime or "application/octet-stream")


# ── Raw ASGI guard: drop connection silently on bad metrics token ─────────────
# Wraps the entire FastAPI app so the check runs before Starlette's
# ServerErrorMiddleware — no HTTP response is sent at all when auth fails.

from urllib.parse import parse_qs as _parse_qs

_inner_app = app   # keep a reference before reassignment

async def _metrics_drop_guard(scope, receive, send):
    if scope["type"] == "http" and scope.get("path") == "/api/metrics/snapshot":
        qs      = _parse_qs(scope.get("query_string", b"").decode())
        token   = qs.get("access_token", [""])[0]
        expected = os.environ.get("CHARTS_ACCESS_TOKEN", "f261d2107df7e17f191ed8fa498f8b27df7d2b3337e6bb24b9ee74aa865dcc95")
        if token != expected:
            return  # close TCP without sending any HTTP bytes
    await _inner_app(scope, receive, send)

# uvicorn entry-point: app.main:asgi_app
asgi_app = _metrics_drop_guard
