#!/usr/bin/env python3
"""Task manager for Health AI web service."""
from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

SUPPORTED_SKILLS = {
    "agent-audit",
    "multichain-contract-vuln",
    "skill-stress-lab",
}


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class TaskRecord:
    task_id: str
    skill_type: str
    status: str
    created_at: str
    updated_at: str
    message: str = ""
    report_path: Optional[str] = None
    summary_path: Optional[str] = None
    log_path: Optional[str] = None
    params: Dict[str, Any] = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return payload


class TaskManager:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.upload_dir = base_dir / "uploads"
        self.tasks_dir = base_dir / "tasks"
        self.index_path = base_dir / "tasks_index.json"
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        self.tasks: Dict[str, TaskRecord] = {}
        self._load_index()

    # --------------------------- persistence ---------------------------
    def _load_index(self) -> None:
        if not self.index_path.exists():
            return
        try:
            data = json.loads(self.index_path.read_text())
            for task_id, payload in data.items():
                self.tasks[task_id] = TaskRecord(**payload)
        except Exception:
            self.tasks = {}

    def _save_index(self) -> None:
        payload = {task_id: record.to_dict() for task_id, record in self.tasks.items()}
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
        tmp.replace(self.index_path)

    # --------------------------- uploads ---------------------------
    def save_upload(self, filename: str, content: bytes) -> str:
        upload_id = uuid.uuid4().hex
        dest = self.upload_dir / f"{upload_id}_{filename}"
        dest.write_bytes(content)
        return upload_id

    def _extract_upload(self, upload_id: str, dest: Path) -> None:
        matches = list(self.upload_dir.glob(f"{upload_id}_*"))
        if not matches:
            raise FileNotFoundError("Upload not found")
        src = matches[0]
        dest.mkdir(parents=True, exist_ok=True)
        suffix = src.suffix.lower()
        if suffix in {".zip", ".tar", ".gz", ".bz2", ".xz"}:
            shutil.unpack_archive(str(src), dest)
        else:
            target = dest / src.name
            shutil.copyfile(src, target)

    # --------------------------- tasks ---------------------------
    def create_task(
        self,
        skill_type: str,
        code_path: Optional[str],
        upload_id: Optional[str],
        params: Optional[Dict[str, Any]] = None,
    ) -> TaskRecord:
        if skill_type not in SUPPORTED_SKILLS:
            raise ValueError(f"unsupported skill_type: {skill_type}")
        if not code_path and not upload_id:
            raise ValueError("codePath 或 uploadId 必须至少提供一个")
        task_id = uuid.uuid4().hex
        record = TaskRecord(
            task_id=task_id,
            skill_type=skill_type,
            status="pending",
            created_at=_now(),
            updated_at=_now(),
            params=params or {},
        )
        self.tasks[task_id] = record
        self._save_index()
        try:
            workspace = self.tasks_dir / task_id
            input_dir = workspace / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            if code_path:
                self._copy_code(Path(code_path), input_dir)
            if upload_id:
                self._extract_upload(upload_id, input_dir)
            self._run_skill(record, workspace, input_dir)
            record.status = "completed"
            record.updated_at = _now()
            self._save_index()
        except Exception as exc:
            record.status = "failed"
            record.updated_at = _now()
            record.message = str(exc)
            self._save_index()
            raise
        return record

    def get_task(self, task_id: str) -> TaskRecord:
        if task_id not in self.tasks:
            raise KeyError("task not found")
        return self.tasks[task_id]

    # --------------------------- helpers ---------------------------
    def _copy_code(self, source: Path, dest: Path) -> None:
        src = source.expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"代码路径不存在：{src}")
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / src.name)

    def _run_skill(self, record: TaskRecord, workspace: Path, input_dir: Path) -> None:
        report_dir = workspace / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        log_file = report_dir / "run.log"
        summary_file = report_dir / "summary.json"

        if record.skill_type == "agent-audit":
            result = self._mock_agent_audit(input_dir, report_dir)
        elif record.skill_type == "multichain-contract-vuln":
            result = self._mock_contract_audit(input_dir, report_dir)
        else:
            result = self._mock_stress_test(input_dir, report_dir, record.params or {})

        summary_file.write_text(json.dumps(result, ensure_ascii=False, indent=2))
        log_file.write_text("Task completed successfully.\n")
        record.report_path = str(result.get("report"))
        record.summary_path = str(summary_file)
        record.log_path = str(log_file)
        record.message = result.get("message", "")

    # --------------------------- mock runners ---------------------------
    def _mock_agent_audit(self, code_dir: Path, report_dir: Path) -> Dict[str, Any]:
        report_path = report_dir / "agent_audit.md"
        report_path.write_text(
            "# Agent Audit (placeholder)\n\n"
            f"- 扫描目录：{code_dir}\n"
            "- 发现风险：请替换为真实审计结果。\n"
        )
        return {
            "report": str(report_path),
            "summary": {
                "privacyRisk": 0,
                "privilegeRisk": 0,
                "memoryRisk": 0,
                "tokenRisk": 0,
                "failureRisk": 0,
            },
            "message": "已生成占位报告，接入真实 audit_scan 后即可输出正式内容。",
        }

    def _mock_contract_audit(self, code_dir: Path, report_dir: Path) -> Dict[str, Any]:
        report_path = report_dir / "contract_audit.md"
        report_path.write_text(
            """# Contract Scan (placeholder)\n\n"
            + "待集成 multichain-contract-vuln 脚本。"\n
        )
        return {
            "report": str(report_path),
            "summary": {"issues": []},
            "message": "占位合约报告，后续接入 run_cli.py。",
        }

    def _mock_stress_test(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        report_path = report_dir / "stress_report.md"
        runs = params.get("runs", 10)
        concurrency = params.get("concurrency", 1)
        report_path.write_text(
            "# Stress Test (placeholder)\n\n"
            f"- runs: {runs}\n"
            f"- concurrency: {concurrency}\n"
            "请接入 stress_runner.py 以输出真实指标。\n"
        )
        return {
            "report": str(report_path),
            "summary": {"runs": runs, "concurrency": concurrency},
            "message": "占位压测报告，接入 stress_runner.py 后可展示真实结果。",
        }
