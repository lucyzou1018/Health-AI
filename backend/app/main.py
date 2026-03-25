from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, Literal, Optional, List

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB hard cap per upload
MAX_WALLET_SESSIONS = 1000            # evict expired sessions above this threshold

from fastapi import FastAPI, File, HTTPException, UploadFile, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .task_manager import SUPPORTED_SKILLS, TaskManager

# Try to import eth-account for signature verification
try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
    ETH_ACCOUNT_AVAILABLE = True
except ImportError:
    ETH_ACCOUNT_AVAILABLE = False
    print("Warning: eth-account not available, wallet verification will be simplified")

BASE_DIR = Path(__file__).resolve().parent.parent / "storage"
BASE_DIR.mkdir(parents=True, exist_ok=True)
REPO_ROOT = Path(__file__).resolve().parents[2]

task_manager = TaskManager(BASE_DIR, repo_root=REPO_ROOT)

# 简单的内存会话存储 (生产环境应使用 Redis)
wallet_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = threading.Lock()  # protects wallet_sessions against concurrent access

# Per-task-id locks for PDF generation — prevents two concurrent requests from
# writing to the same .pdf file simultaneously.
_pdf_gen_locks: Dict[str, threading.Lock] = {}
_pdf_gen_locks_meta = threading.Lock()  # protects _pdf_gen_locks dict itself


def _get_pdf_lock(task_id: str) -> threading.Lock:
    with _pdf_gen_locks_meta:
        if task_id not in _pdf_gen_locks:
            _pdf_gen_locks[task_id] = threading.Lock()
        return _pdf_gen_locks[task_id]


def verify_wallet_token(token: str = Header(None, alias="X-Wallet-Token")) -> Optional[str]:
    """验证钱包 token，返回钱包地址"""
    if not token:
        return None
    with _sessions_lock:
        session = wallet_sessions.get(token)
        if not session:
            return None
        if session.get("expires_at", 0) < int(time.time()):
            wallet_sessions.pop(token, None)  # pop avoids KeyError if evicted concurrently
            return None
        return session.get("wallet_address")

app = FastAPI(title="Health AI", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class UploadResponse(BaseModel):
    upload_id: str = Field(alias="uploadId")
    filename: str


class TaskRequest(BaseModel):
    skill_type: Literal["skill-security-audit", "multichain-contract-vuln", "skill-stress-lab"] = Field(alias="skillType")
    code_path: Optional[str] = Field(default=None, alias="codePath")
    upload_id: Optional[str] = Field(default=None, alias="uploadId")
    params: Dict[str, Any] = Field(default_factory=dict)
    wallet_address: Optional[str] = Field(default=None, alias="walletAddress")
    file_name: Optional[str] = Field(default=None, alias="fileName")

    class Config:
        allow_population_by_field_name = True


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
        allow_population_by_field_name = True


class WalletAuthRequest(BaseModel):
    wallet_address: str = Field(alias="walletAddress")
    signature: str = Field(description="用户签名消息")
    message: str = Field(description="签名的消息内容")

    class Config:
        allow_population_by_field_name = True


class WalletAuthResponse(BaseModel):
    token: str
    wallet_address: str = Field(alias="walletAddress")
    expires_at: int = Field(alias="expiresAt")


class HistoryQueryParams(BaseModel):
    skill_type: Optional[str] = Field(default=None, alias="skillType")
    limit: int = Field(default=20, ge=1, le=100)


@app.get("/api/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/uploads", response_model=UploadResponse)
def upload_file(file: UploadFile = File(...)) -> UploadResponse:
    # Using a sync handler: FastAPI dispatches it to the default threadpool so
    # the blocking file-read / disk-write don't block the async event loop.
    content = file.file.read()  # sync read from the underlying SpooledTemporaryFile
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )
    upload_id = task_manager.save_upload(file.filename, content)
    return UploadResponse(uploadId=upload_id, filename=file.filename)


@app.post("/api/tasks", response_model=TaskResponse)
def create_task(
    payload: TaskRequest,
    wallet_address: Optional[str] = Depends(verify_wallet_token)
) -> TaskResponse:
    # 优先使用 payload 中的钱包地址，否则使用 token 验证的地址
    effective_wallet = payload.wallet_address or wallet_address

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
    except Exception as exc:  # pragma: no cover - 调试信息
        raise HTTPException(status_code=500, detail=str(exc))
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
    """将 markdown 报告实时渲染成 PDF 并返回"""
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
    pdf_path = md_path.with_suffix(".pdf")

    # Acquire a per-task lock so concurrent requests don't write the same file
    # simultaneously.  The second request will wait, then find a fresh PDF and
    # skip regeneration.
    pdf_lock = _get_pdf_lock(task_id)
    with pdf_lock:
        needs_regen = (
            not pdf_path.exists()
            or pdf_path.stat().st_mtime < md_path.stat().st_mtime
        )
        if needs_regen:
            try:
                generate_pdf(md_path, pdf_path)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"report-{task_id[:8]}.pdf",
    )


# /api/tasks/{task_id}/artifact 接口已禁用（summary/log 含服务器内部信息，不对外暴露）


# --------------------------- Wallet Authentication ---------------------------

@app.get("/api/wallet/nonce")
def get_wallet_nonce(wallet_address: str):
    """获取用于签名的 nonce"""
    nonce = secrets.token_hex(16)
    message = f"Health AI Login\nAddress: {wallet_address}\nNonce: {nonce}\nTimestamp: {int(time.time())}"
    return {"message": message, "nonce": nonce}


@app.post("/api/wallet/verify", response_model=WalletAuthResponse)
def verify_wallet_login(payload: WalletAuthRequest) -> WalletAuthResponse:
    """验证钱包签名并返回 token"""
    wallet_address = payload.wallet_address.lower()
    
    # 验证签名
    if ETH_ACCOUNT_AVAILABLE:
        try:
            message = encode_defunct(text=payload.message)
            recovered_address = Account.recover_message(message, signature=payload.signature)
            if recovered_address.lower() != wallet_address:
                raise HTTPException(status_code=401, detail="签名验证失败")
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"签名验证失败: {str(e)}")
    else:
        # 简化模式：仅检查签名格式（生产环境应使用 eth-account）
        if not payload.signature or len(payload.signature) < 10:
            raise HTTPException(status_code=401, detail="无效签名")
    
    # 生成 session token
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 7 * 24 * 3600  # 7 天有效期

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
    
    return WalletAuthResponse(
        token=token,
        walletAddress=wallet_address,
        expiresAt=expires_at
    )


@app.get("/api/wallet/history", response_model=List[TaskResponse])
def get_wallet_history(
    skill_type: Optional[str] = None,
    limit: int = 20,
    wallet_address: str = Depends(verify_wallet_token)
) -> List[TaskResponse]:
    """获取当前登录钱包的分析历史"""
    if not wallet_address:
        raise HTTPException(status_code=401, detail="请先连接钱包")
    
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
    """获取当前登录钱包信息"""
    if not wallet_address:
        raise HTTPException(status_code=401, detail="未登录")
    return {"wallet_address": wallet_address}


FRONTEND_DIR = REPO_ROOT / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
