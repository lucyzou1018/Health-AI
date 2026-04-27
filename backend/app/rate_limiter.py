"""
Daily task rate-limiter.

Toggle: set DAILY_TASK_LIMIT_ENABLED=false to disable (enabled by default).
Rule:   each client IP may submit at most DAILY_LIMIT tasks per UTC calendar day (all skill types combined).
Pro users (verified on-chain) are exempt from the daily limit when the limit is enabled.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_lock = Lock()
_STORAGE_PATH = Path(__file__).resolve().parent.parent / "storage" / "rate_limits.json"

DAILY_LIMIT = 3


def _is_enabled() -> bool:
    return os.getenv("DAILY_TASK_LIMIT_ENABLED", "true").lower() not in ("0", "false", "no")


# ── On-chain Pro check ────────────────────────────────────────────────────────
# selector: keccak256("walletStatus(address)") = 0x4d6d0af8
# returns (bool active, uint256 remainingSeconds)

_SUBSCRIPTION_CONTRACT = {
    "testnet": {
        "rpcs": [
            "https://data-seed-prebsc-1-s1.binance.org:8545",
            "https://data-seed-prebsc-2-s1.binance.org:8545",
            "https://bsc-testnet.publicnode.com",
            "https://bsc-testnet-rpc.publicnode.com",
        ],
        # 从环境变量读取，fallback 为空（无合约地址时跳过链上查询）
        "address": os.getenv("SUBSCRIPTION_CONTRACT_TESTNET", ""),
    },
    "mainnet": {
        "rpcs": [
            "https://bsc-dataseed.binance.org",
            "https://bsc-dataseed1.binance.org",
            "https://bsc-dataseed2.binance.org",
            "https://bsc.publicnode.com",
        ],
        "address": os.getenv("SUBSCRIPTION_CONTRACT_MAINNET", ""),
    },
}

# 返回值含义：
#   True  — 链上确认为 Pro
#   False — 链上确认为 Free（active=false）
#   None  — 无法连接链（网络问题）
def _check_pro_on_chain(wallet_address: str) -> Optional[bool]:
    is_testnet = os.getenv("SUBSCRIPTION_ENV", "mainnet").lower() == "testnet"
    cfg        = _SUBSCRIPTION_CONTRACT["testnet" if is_testnet else "mainnet"]

    if not cfg["address"]:
        return None

    addr_hex  = wallet_address.lower().replace("0x", "").zfill(64)
    call_data = "0x4d6d0af8" + addr_hex
    payload   = json.dumps({
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": cfg["address"], "data": call_data}, "latest"], "id": 1,
    }).encode()

    last_err: Optional[Exception] = None
    for rpc_url in cfg["rpcs"]:
        try:
            req = urllib.request.Request(
                rpc_url, data=payload,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                result = json.loads(resp.read().decode())
            hex_result = result.get("result", "")
            if result.get("error") or not hex_result or hex_result == "0x":
                return False
            if len(hex_result) < 130:
                return False
            return int(hex_result[2:66], 16) == 1
        except Exception as e:
            last_err = e
            continue

    logger.warning("[rate_limiter] chain check failed for %s: %s",
                   wallet_address[:10], last_err)
    return None


def _is_pro_on_chain(wallet_address: Optional[str]) -> Optional[bool]:
    if not wallet_address:
        return False
    return _check_pro_on_chain(wallet_address)


def _identity_hash(provider: str, login_id: str) -> str:
    """Compute keccak256(provider + ':' + login_id) as 32-byte hex (no 0x prefix)."""
    try:
        from Crypto.Hash import keccak as _keccak
        k = _keccak.new(digest_bits=256)
        k.update((provider + ":" + login_id).encode("utf-8"))
        return k.hexdigest()
    except ImportError:
        return ""


def _is_pro_identity_on_chain(provider: str, login_id: str) -> Optional[bool]:
    """
    Check identityStatus(keccak256(provider:login_id)) on chain.
    selector: keccak256("identityStatus(bytes32)") = 0xa5ce8e58
    """
    if not provider or not login_id:
        return False
    id_hash = _identity_hash(provider, login_id)
    if not id_hash:
        return None  # pycryptodome not installed

    is_testnet = os.getenv("SUBSCRIPTION_ENV", "mainnet").lower() == "testnet"
    cfg        = _SUBSCRIPTION_CONTRACT["testnet" if is_testnet else "mainnet"]
    if not cfg["address"]:
        return None

    call_data = "0xa5ce8e58" + id_hash  # identityStatus(bytes32)
    payload   = json.dumps({
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": cfg["address"], "data": call_data}, "latest"], "id": 1,
    }).encode()

    last_err: Optional[Exception] = None
    for rpc_url in cfg["rpcs"]:
        try:
            req = urllib.request.Request(
                rpc_url, data=payload,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                result = json.loads(resp.read().decode())
            hex_result = result.get("result", "")
            if result.get("error") or not hex_result or hex_result == "0x":
                return False
            if len(hex_result) < 130:
                return False
            return int(hex_result[2:66], 16) == 1
        except Exception as e:
            last_err = e
            continue

    logger.warning("[rate_limiter] identity chain check failed for %s:%s: %s",
                   provider, login_id[:6], last_err)
    return None


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _load() -> Dict[str, Any]:
    if _STORAGE_PATH.exists():
        try:
            return json.loads(_STORAGE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _prune(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove stale date entries (older than today) to keep the file compact."""
    today = _today_utc()
    return {
        ip: {date: count for date, count in dates.items() if date >= today}
        for ip, dates in data.items()
        if any(date >= today for date in dates)
    }


def _save(data: Dict[str, Any]) -> None:
    _STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORAGE_PATH.write_text(json.dumps(_prune(data), indent=2, ensure_ascii=False), encoding="utf-8")


def _is_pro(wallet_address: Optional[str], login_type: str = "wallet", login_id: str = "") -> bool:
    """统一 Pro 判断：wallet 用 walletStatus，Google/GitHub 用 identityStatus。"""
    if login_type == "google":
        return _is_pro_identity_on_chain("google", login_id) is True
    if login_type == "github":
        return _is_pro_identity_on_chain("github", login_id) is True
    return _is_pro_on_chain(wallet_address) is True


def get_status(
    client_ip: str,
    wallet_address: Optional[str] = None,
    login_type: str = "wallet",
    login_id: str = "",
) -> Dict[str, Any]:
    """
    Return the IP's daily quota usage without consuming a slot.
    Pro users verified on-chain (wallet or identity) are exempt from the limit.
    """
    if not _is_enabled():
        return {"enabled": False, "used": 0, "limit": DAILY_LIMIT, "remaining": DAILY_LIMIT, "allowed": True}

    if _is_pro(wallet_address, login_type, login_id):
        return {"enabled": True, "pro": True, "used": 0, "limit": DAILY_LIMIT, "remaining": DAILY_LIMIT, "allowed": True}

    if not client_ip:
        return {"enabled": True, "used": 0, "limit": DAILY_LIMIT, "remaining": DAILY_LIMIT, "allowed": True}

    today = _today_utc()
    with _lock:
        used = _load().get(client_ip, {}).get(today, 0)

    remaining = max(0, DAILY_LIMIT - used)
    return {"enabled": True, "pro": False, "used": used, "limit": DAILY_LIMIT, "remaining": remaining, "allowed": used < DAILY_LIMIT, "date": today}


def try_increment(
    client_ip: str,
    wallet_address: Optional[str] = None,
    login_type: str = "wallet",
    login_id: str = "",
) -> bool:
    """
    Attempt to consume one daily quota slot.
    Pro users on-chain always return True without consuming a slot.
    """
    if not _is_enabled() or not client_ip:
        return True

    if _is_pro(wallet_address, login_type, login_id):
        return True

    today = _today_utc()
    with _lock:
        data = _load()
        ip_data = data.get(client_ip, {})
        used = ip_data.get(today, 0)
        if used >= DAILY_LIMIT:
            return False
        ip_data[today] = used + 1
        data[client_ip] = ip_data
        _save(data)
        return True
