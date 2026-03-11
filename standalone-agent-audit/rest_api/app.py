from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

# 复用 pip package 中的核心逻辑
ROOT = Path(__file__).resolve().parents[1]
PIP_SRC = ROOT / "pip_package"
if str(PIP_SRC) not in sys.path:
    sys.path.append(str(PIP_SRC))

from agent_audit_cli.core import run_audit, to_markdown  # noqa: E402


API_TOKEN = os.environ.get("AGENT_AUDIT_API_TOKEN")


class AuditRequest(BaseModel):
    config: str
    memory: str
    logs: str
    return_markdown: bool = False


def verify_token(authorization: str = Header(None)) -> None:
    if not API_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少认证 token")
    token = authorization.split(" ", 1)[1].strip()
    if token != API_TOKEN:
        raise HTTPException(status_code=403, detail="认证失败")


app = FastAPI(title="Agent Audit API")


@app.post("/run", dependencies=[Depends(verify_token)])
def run_audit_endpoint(payload: AuditRequest) -> dict[str, Any]:
    report = run_audit(Path(payload.config), Path(payload.memory), Path(payload.logs))
    response: dict[str, Any] = {"report": report}
    if payload.return_markdown:
        response["markdown"] = to_markdown(report)
    return response
