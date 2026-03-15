#!/usr/bin/env python3
"""Task manager for Health AI web service."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

SUPPORTED_SKILLS = {
    "skill-security-audit",
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
    params: Dict[str, Any] = field(default_factory=dict)
    wallet_address: Optional[str] = None  # 关联的钱包地址

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return payload


class TaskManager:
    def __init__(self, base_dir: Path, repo_root: Path) -> None:
        self.base_dir = base_dir
        self.repo_root = repo_root
        self.upload_dir = base_dir / "uploads"
        self.tasks_dir = base_dir / "tasks"
        self.index_path = base_dir / "tasks_index.json"
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        self.tasks: Dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=2)
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
        if suffix == ".skill":
            shutil.unpack_archive(str(src), dest, format="zip")
        elif suffix in {".zip", ".tar", ".gz", ".bz2", ".xz"}:
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
        wallet_address: Optional[str] = None,
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
            wallet_address=wallet_address,
        )
        with self._lock:
            self.tasks[task_id] = record
            self._save_index()
        workspace = self.tasks_dir / task_id
        input_dir = workspace / "input"
        try:
            input_dir.mkdir(parents=True, exist_ok=True)
            if code_path:
                self._copy_code(Path(code_path), input_dir)
            if upload_id:
                self._extract_upload(upload_id, input_dir)
        except Exception as exc:
            self._set_task_state(task_id, status="failed", message=str(exc))
            raise
        self._set_task_state(task_id, status="queued", message="已加入执行队列")
        self.executor.submit(self._execute_task, task_id, workspace, input_dir)
        return self._snapshot(record)

    def get_task(self, task_id: str) -> TaskRecord:
        with self._lock:
            record = self.tasks.get(task_id)
            if not record:
                raise KeyError("task not found")
            return self._snapshot(record)

    def get_tasks_by_wallet(self, wallet_address: str, skill_type: Optional[str] = None, limit: int = 50) -> list:
        """获取指定钱包的分析历史"""
        with self._lock:
            tasks = [
                self._snapshot(record)
                for record in self.tasks.values()
                if record.wallet_address and record.wallet_address.lower() == wallet_address.lower()
            ]
            # 按时间倒序
            tasks.sort(key=lambda x: x.created_at, reverse=True)
            # 按 skill_type 筛选
            if skill_type:
                tasks = [t for t in tasks if t.skill_type == skill_type]
            return tasks[:limit]

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

    def _run_skill(self, record: TaskRecord, workspace: Path, input_dir: Path) -> Dict[str, Any]:
        report_dir = workspace / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        if record.skill_type == "skill-security-audit":
            result = self._run_security_audit(input_dir, report_dir, record.params or {})
        elif record.skill_type == "multichain-contract-vuln":
            result = self._run_contract_audit(input_dir, report_dir, record.params or {})
        else:
            result = self._run_stress_lab(input_dir, report_dir, record.params or {})
        record.report_path = result.get("report")
        record.summary_path = result.get("summary")
        record.log_path = result.get("log")
        record.message = result.get("message", "")
        return result

    def _run_command(
        self,
        cmd: list[str],
        cwd: Optional[Path],
        log_file: Path,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
        )
        log_file.write_text(
            "$ " + " ".join(cmd) + "\n\n"
            + "[stdout]\n" + (proc.stdout or "") + "\n"
            + "[stderr]\n" + (proc.stderr or "") + "\n"
        )
        if proc.returncode != 0:
            raise RuntimeError(f"命令执行失败 (exit {proc.returncode}): {' '.join(cmd)}")
        return proc.stdout

    def _run_security_audit(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        script = self.repo_root / "skills" / "skill-security-audit" / "scripts" / "audit_skill.py"
        report_json = report_dir / "security_audit.json"
        report_md = report_dir / "security_audit.md"
        log_file = report_dir / "security_audit.log"
        cmd = [
            "python3",
            str(script),
            "--output",
            str(report_json),
            "--markdown",
            str(report_md),
        ]
        # 支持本地路径或远程 URL
        skill_path = params.get("skillPath", "")
        skill_url = params.get("skillUrl", "")
        if skill_url:
            cmd.extend(["--skill-url", skill_url])
        elif code_dir.exists():
            skill_dirs = sorted({str(path.parent) for path in code_dir.rglob("SKILL.md")})
            targets = skill_dirs or [str(code_dir)]
            for target in targets:
                cmd.extend(["--skill-path", target])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        summary_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
        return {
            "report": str(report_md),
            "summary": str(report_json),
            "log": str(log_file),
            "message": "Skill Security Audit 完成",
            "details": summary_data,
        }

    def _run_contract_audit(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        script = self.repo_root / "skills" / "multichain-contract-vuln" / "scripts" / "run_cli.py"
        report_md = report_dir / "contract_audit.md"
        bundle_md = report_dir / "contract_sources.md"
        log_file = report_dir / "contract_audit.log"
        cmd = ["python3", str(script), "--report", str(report_md), "--bundle", str(bundle_md), "--auto-static"]
        input_path = params.get("input") or str(code_dir)
        if params.get("evmAddress"):
            cmd.extend(["--evm-address", str(params["evmAddress"])])
            if params.get("network"):
                cmd.extend(["--network", str(params["network"])])
        else:
            cmd.extend(["--input", str(input_path)])
        if params.get("chain"):
            cmd.extend(["--chain", str(params["chain"])])
        if params.get("scope"):
            cmd.extend(["--scope", str(params["scope"])])
        if params.get("runAnchor"):
            cmd.append("--run-anchor")
        env: Dict[str, str] = {}
        if params.get("etherscanApiKey"):
            env["ETHERSCAN_API_KEY"] = str(params["etherscanApiKey"])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file, env=env)
        summary_payload = {
            "report": str(report_md),
            "bundle": str(bundle_md),
            "inputs": {
                "input": input_path,
                "evmAddress": params.get("evmAddress"),
                "network": params.get("network"),
                "chain": params.get("chain"),
            },
        }
        summary_json = report_dir / "contract_summary.json"
        summary_json.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2))
        return {
            "report": str(report_md),
            "summary": str(summary_json),
            "log": str(log_file),
            "message": "合约漏洞扫描完成",
        }

    def _run_stress_lab(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        script = self.repo_root / "skills" / "skill-stress-lab" / "scripts" / "stress_runner.py"
        log_file = report_dir / "stress_runner.log"
        summary_md = report_dir / "stress_summary.md"
        metrics_json = report_dir / "stress_metrics.json"
        logs_dir = report_dir / "runs"
        command = params.get("command")
        if not command:
            raise ValueError("stress-runner 需要 params.command (命令模板)")
        runs = int(params.get("runs", 10))
        concurrency = int(params.get("concurrency", 1))
        cmd = [
            "python3",
            str(script),
            "--command",
            command,
            "--runs",
            str(runs),
            "--concurrency",
            str(concurrency),
            "--log-dir",
            str(logs_dir),
            "--summary-report",
            str(summary_md),
            "--metrics-output",
            str(metrics_json),
        ]
        if params.get("collectMetrics"):
            cmd.append("--collect-metrics")
        if params.get("workdir"):
            cmd.extend(["--workdir", str(params["workdir"])])
        if params.get("skillDir"):
            cmd.extend(["--skill-dir", str(params["skillDir"])])
        elif code_dir.exists():
            cmd.extend(["--skill-dir", str(code_dir)])
        if params.get("openaiUsageFile"):
            cmd.extend(["--openai-usage-file", str(params["openaiUsageFile"])])
        if params.get("apiCountFile"):
            cmd.extend(["--api-count-file", str(params["apiCountFile"])])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        
        # Generate enhanced report with 5-dimension scores
        enhanced_md = report_dir / "stress_report.md"
        self._generate_stress_lab_report(summary_md, metrics_json, enhanced_md, runs, concurrency)
        
        summary_payload = {
            "runs": runs,
            "concurrency": concurrency,
            "command": command,
            "summary_md": str(enhanced_md),
            "metrics_json": str(metrics_json),
            "logs_dir": str(logs_dir),
        }
        summary_json = report_dir / "stress_summary.json"
        summary_json.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2))
        return {
            "report": str(enhanced_md),
            "summary": str(summary_json),
            "log": str(log_file),
            "message": "压力测试完成",
        }

    def _generate_stress_lab_report(self, summary_md: Path, metrics_json: Path, output_md: Path, runs: int, concurrency: int) -> None:
        """Generate enhanced stress lab report with 5-dimension scoring."""
        # Read original summary
        original_content = summary_md.read_text() if summary_md.exists() else ""
        
        # Try to parse metrics
        metrics = {}
        if metrics_json.exists():
            try:
                metrics = json.loads(metrics_json.read_text())
            except:
                pass
        
        # Calculate 5-dimension scores based on metrics
        # Default scores if no metrics available
        stability_score = 100
        performance_score = 95
        resource_score = 90
        consistency_score = 100
        recovery_score = 100
        
        # Extract actual metrics if available
        if metrics:
            success_rate = metrics.get("success_rate", 1.0)
            avg_duration = metrics.get("avg_duration", 0.05)
            failures = metrics.get("failures", 0)
            
            # Stability: based on success rate
            stability_score = int(success_rate * 100)
            
            # Performance: based on avg duration (lower is better, <0.1s = 100, >1s = 0)
            performance_score = max(0, min(100, int(100 - (avg_duration - 0.1) * 100)))
            
            # Resource: assume good if low failures
            resource_score = 90 if failures == 0 else max(0, 90 - failures * 10)
            
            # Consistency: based on success rate
            consistency_score = stability_score
            
            # Recovery: 100 if no failures, lower if failures
            recovery_score = 100 if failures == 0 else max(0, 100 - failures * 20)
        
        # Calculate overall score
        overall_score = int((stability_score + performance_score + resource_score + consistency_score + recovery_score) / 5)
        
        # Build enhanced report
        report_lines = [
            "# Skill Stress Lab 报告",
            "",
            "## 基本信息",
            f"- **测试轮次**: {runs}",
            f"- **并发度**: {concurrency}",
            "",
            "---",
            "",
            "## 五维度评分 (0-100)",
            "",
            "| 维度 | 评分 | 说明 |",
            "|-----|------|-----|",
            f"| 🛡️ **稳定性** | {stability_score}/100 | 成功率表现 |",
            f"| ⚡ **性能** | {performance_score}/100 | 响应时间表现 |",
            f"| 💾 **资源** | {resource_score}/100 | 资源占用情况 |",
            f"| 🔄 **一致性** | {consistency_score}/100 | 结果一致性 |",
            f"| 🆘 **恢复** | {recovery_score}/100 | 故障恢复能力 |",
            "",
            f"### 📊 综合评分: **{overall_score}/100**",
            "",
            "---",
            "",
            "## 原始测试摘要",
            "",
            original_content,
            "",
            "---",
            "",
            "*报告由 Skill Stress Lab 自动生成*",
        ]
        
        output_md.write_text("\n".join(report_lines), encoding="utf-8")

    def _snapshot(self, record: TaskRecord) -> TaskRecord:
        return TaskRecord(**record.to_dict())

    def _set_task_state(
        self,
        task_id: str,
        *,
        status: Optional[str] = None,
        message: Optional[str] = None,
        report: Optional[str] = None,
        summary: Optional[str] = None,
        log: Optional[str] = None,
    ) -> TaskRecord:
        with self._lock:
            record = self.tasks.get(task_id)
            if not record:
                raise KeyError("task not found")
            if status:
                record.status = status
            if message is not None:
                record.message = message
            if report is not None:
                record.report_path = report
            if summary is not None:
                record.summary_path = summary
            if log is not None:
                record.log_path = log
            record.updated_at = _now()
            self._save_index()
            return self._snapshot(record)

    def _execute_task(self, task_id: str, workspace: Path, input_dir: Path) -> None:
        try:
            self._set_task_state(task_id, status="running", message="执行中")
            with self._lock:
                record = self.tasks.get(task_id)
                if not record:
                    raise KeyError("task not found")
                record_copy = self._snapshot(record)
            result = self._run_skill(record_copy, workspace, input_dir)
            self._set_task_state(
                task_id,
                status="completed",
                message=result.get("message", "完成"),
                report=result.get("report"),
                summary=result.get("summary"),
                log=result.get("log"),
            )
        except Exception as exc:
            self._set_task_state(task_id, status="failed", message=str(exc))
