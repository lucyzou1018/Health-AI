"""
每日任务提交限流模块。

开关：环境变量 DAILY_TASK_LIMIT_ENABLED=true（默认关闭）。
规则：同一设备每 UTC 自然日最多提交 3 个任务（三种类型合计）。
设备识别：由前端生成的设备指纹哈希（device_id）标识，与钱包地址无关。
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


def _save(data: Dict[str, Any]) -> None:
    _STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORAGE_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def get_status(device_id: str) -> Dict[str, Any]:
    """返回设备今日配额使用情况，不消耗配额。"""
    if not _is_enabled():
        return {
            "enabled": False,
            "used": 0,
            "limit": DAILY_LIMIT,
            "remaining": DAILY_LIMIT,
            "allowed": True,
        }
    if not device_id:
        return {
            "enabled": True,
            "used": 0,
            "limit": DAILY_LIMIT,
            "remaining": DAILY_LIMIT,
            "allowed": True,
        }

    today = _today_utc()
    with _lock:
        data = _load()
        used = data.get(device_id, {}).get(today, 0)

    remaining = max(0, DAILY_LIMIT - used)
    return {
        "enabled": True,
        "used": used,
        "limit": DAILY_LIMIT,
        "remaining": remaining,
        "allowed": used < DAILY_LIMIT,
        "date": today,
    }


def try_increment(device_id: str) -> bool:
    """
    尝试消耗一次今日配额。
    返回 True 表示允许并已记录；返回 False 表示已达上限，不记录。
    """
    if not _is_enabled():
        return True
    if not device_id:
        return True

    today = _today_utc()
    with _lock:
        data = _load()
        device_data = data.get(device_id, {})
        used = device_data.get(today, 0)

        if used >= DAILY_LIMIT:
            return False

        device_data[today] = used + 1
        data[device_id] = device_data
        _save(data)
        return True
