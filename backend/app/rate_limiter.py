"""
Daily task rate-limiter.

Toggle: set DAILY_TASK_LIMIT_ENABLED=true (disabled by default).
Rule:   each client IP may submit at most DAILY_LIMIT tasks per UTC calendar day (all skill types combined).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict

_lock = Lock()
_STORAGE_PATH = Path(__file__).resolve().parent.parent / "storage" / "rate_limits.json"

DAILY_LIMIT = 3


def _is_enabled() -> bool:
    return os.getenv("DAILY_TASK_LIMIT_ENABLED", "").lower() in ("1", "true", "yes")


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


def get_status(client_ip: str) -> Dict[str, Any]:
    """Return the IP's daily quota usage without consuming a slot."""
    if not _is_enabled():
        return {"enabled": False, "used": 0, "limit": DAILY_LIMIT, "remaining": DAILY_LIMIT, "allowed": True}
    if not client_ip:
        return {"enabled": True, "used": 0, "limit": DAILY_LIMIT, "remaining": DAILY_LIMIT, "allowed": True}

    today = _today_utc()
    with _lock:
        used = _load().get(client_ip, {}).get(today, 0)

    remaining = max(0, DAILY_LIMIT - used)
    return {"enabled": True, "used": used, "limit": DAILY_LIMIT, "remaining": remaining, "allowed": used < DAILY_LIMIT, "date": today}


def try_increment(client_ip: str) -> bool:
    """
    Attempt to consume one daily quota slot.
    Returns True if allowed (slot recorded); False if the daily limit is already reached.
    """
    if not _is_enabled() or not client_ip:
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
