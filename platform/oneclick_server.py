"""FastAPI server exposing one-click audit endpoints for external platforms."""

from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_audit_module():
    module_path = REPO_ROOT / "skills" / "agent-audit" / "scripts" / "audit_scan.py"
    spec = importlib.util.spec_from_file_location("audit_scan", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载 {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit_scan = _load_audit_module()
DEFAULT_OUTPUT = audit_scan.DEFAULT_OUTPUT
DEFAULT_MARKDOWN = DEFAULT_OUTPUT.with_suffix(".md")

def generate_report():  # type: ignore[override]
    return audit_scan.generate_report()


def save_report(report, output: Path) -> None:  # type: ignore[override]
    audit_scan.save_report(report, output)


def to_markdown(report):  # type: ignore[override]
    return audit_scan.to_markdown(report)


API_TOKEN = os.environ.get("AUDIT_PLATFORM_TOKEN")
CACHE: dict[str, Optional[object]] = {"timestamp": None, "report": None, "markdown": None}


class AuditOptions(BaseModel):
    save_json: bool = False
    save_markdown: bool = False
    json_path: Optional[str] = None
    markdown_path: Optional[str] = None
    force_refresh: bool = False
    cache_ttl_seconds: int = 30


def _get_cached(ttl: int) -> tuple[Optional[dict], Optional[str]]:
    ts = CACHE["timestamp"]
    if not isinstance(ts, datetime):
        return None, None
    if datetime.utcnow() - ts > timedelta(seconds=max(ttl, 0)):
        return None, None
    return CACHE["report"], CACHE["markdown"]


def _set_cache(report: dict, markdown: str) -> None:
    CACHE["timestamp"] = datetime.utcnow()
    CACHE["report"] = report
    CACHE["markdown"] = markdown


def verify_token(authorization: str = Header(None)) -> None:
    if not API_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少认证 token")
    token = authorization.split(" ", 1)[1].strip()
    if token != API_TOKEN:
        raise HTTPException(status_code=403, detail="认证失败")


app = FastAPI(
    title="Agent Audit Platform Server",
    description="Expose the local audit scanner over HTTP so an external platform 可以一键触发体检。",
)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/audit", dependencies=[Depends(verify_token)])
async def run_audit(options: AuditOptions | None = None) -> dict[str, object]:
    opts = options or AuditOptions()
    if not opts.force_refresh:
        cached_report, cached_markdown = _get_cached(opts.cache_ttl_seconds)
        if cached_report and cached_markdown:
            return {"report": cached_report, "markdown": cached_markdown, "cache": True}

    report = generate_report()
    markdown = to_markdown(report)
    _set_cache(report, markdown)

    response: dict[str, object] = {"report": report, "markdown": markdown, "cache": False}

    if opts.save_json:
        json_path = Path(opts.json_path).expanduser() if opts.json_path else DEFAULT_OUTPUT
        save_report(report, json_path)
        response["jsonPath"] = str(json_path)

    if opts.save_markdown:
        markdown_path = Path(opts.markdown_path).expanduser() if opts.markdown_path else DEFAULT_MARKDOWN
        markdown_path.write_text(markdown)
        response["markdownPath"] = str(markdown_path)

    return response


@app.post("/audit/plain", dependencies=[Depends(verify_token)])
async def run_plain(options: AuditOptions | None = None) -> dict[str, str]:
    opts = options or AuditOptions()
    if not opts.force_refresh:
        cached_report, cached_markdown = _get_cached(opts.cache_ttl_seconds)
        if cached_markdown:
            return {"markdown": cached_markdown, "cache": True}

    report = generate_report()
    markdown = to_markdown(report)
    _set_cache(report, markdown)
    return {"markdown": markdown, "cache": False}
