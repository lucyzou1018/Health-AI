from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .task_manager import SUPPORTED_SKILLS, TaskManager

BASE_DIR = Path(__file__).resolve().parent.parent / "storage"
BASE_DIR.mkdir(parents=True, exist_ok=True)

task_manager = TaskManager(BASE_DIR)

app = FastAPI(title="Health AI", version="0.1.0")
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
    skill_type: Literal["agent-audit", "multichain-contract-vuln", "skill-stress-lab"] = Field(alias="skillType")
    code_path: Optional[str] = Field(default=None, alias="codePath")
    upload_id: Optional[str] = Field(default=None, alias="uploadId")
    params: Dict[str, Any] = Field(default_factory=dict)

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

    class Config:
        allow_population_by_field_name = True


@app.get("/api/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/uploads", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)) -> UploadResponse:
    content = await file.read()
    upload_id = task_manager.save_upload(file.filename, content)
    return UploadResponse(uploadId=upload_id, filename=file.filename)


@app.post("/api/tasks", response_model=TaskResponse)
def create_task(payload: TaskRequest) -> TaskResponse:
    try:
        record = task_manager.create_task(
            skill_type=payload.skill_type,
            code_path=payload.code_path,
            upload_id=payload.upload_id,
            params=payload.params,
        )
    except (FileNotFoundError, ValueError) as exc:
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
