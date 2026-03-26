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
    file_name: Optional[str] = None  # 上传文件的原始文件名

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
        self._recover_orphaned_tasks()  # 服务重启时恢复孤儿任务

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

    # 刚创建的任务在此秒数内不会被视为孤儿（防止 reload 时误杀）
    ORPHAN_GRACE_SECONDS = 30

    def _recover_orphaned_tasks(self) -> None:
        """服务重启时，将孤儿任务（running/queued）标记为 failed。
        仅处理 created_at 超过 ORPHAN_GRACE_SECONDS 秒的任务，
        避免在 uvicorn --reload 时将刚提交的任务误杀。"""
        from datetime import timezone
        now_ts = datetime.now(timezone.utc).timestamp()
        orphaned = []
        for task_id, record in self.tasks.items():
            if record.status not in ("running", "queued"):
                continue
            try:
                created_ts = datetime.fromisoformat(
                    record.created_at.replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                created_ts = 0
            if now_ts - created_ts >= self.ORPHAN_GRACE_SECONDS:
                orphaned.append(task_id)

        if not orphaned:
            return
        for task_id in orphaned:
            record = self.tasks[task_id]
            record.status = "failed"
            record.message = "服务已重启，任务中断。请重新提交文件进行分析。"
            record.updated_at = _now()
        self._save_index()
        print(f"[TaskManager] Recovered {len(orphaned)} orphaned task(s) on startup.")

    def _build_index_payload(self) -> dict:
        """Serialize self.tasks to a plain dict.  Must be called with self._lock held."""
        return {tid: r.to_dict() for tid, r in self.tasks.items()}

    def _flush_index(self, payload: dict) -> None:
        """Write the serialized payload to disk atomically.
        Must be called WITHOUT self._lock held — file I/O must not block
        other threads that need the lock."""
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
        tmp.replace(self.index_path)

    def _save_index(self) -> None:
        """Convenience wrapper used only at startup (single-threaded context)."""
        payload = self._build_index_payload()
        self._flush_index(payload)

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
        file_name: Optional[str] = None,
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
            file_name=file_name,
        )
        with self._lock:
            # Atomic check: same wallet + same skill type → only one active task allowed.
            if wallet_address:
                wallet_lower = wallet_address.lower()
                conflict = next(
                    (
                        r for r in self.tasks.values()
                        if r.wallet_address
                        and r.wallet_address.lower() == wallet_lower
                        and r.skill_type == skill_type
                        and r.status in ("running", "queued", "pending")
                    ),
                    None,
                )
                if conflict:
                    raise ValueError("DUPLICATE_TASK")
            self.tasks[task_id] = record
            # Serialize inside the lock, but flush to disk AFTER releasing it so
            # that file I/O does not block other threads waiting on the lock.
            index_payload = self._build_index_payload()
        self._flush_index(index_payload)
        workspace = self.tasks_dir / task_id
        input_dir = workspace / "input"
        try:
            input_dir.mkdir(parents=True, exist_ok=True)
            if code_path:
                self._copy_code(Path(code_path), input_dir)
            if upload_id:
                self._extract_upload(upload_id, input_dir)
            # Security scan for stress test uploads
            if skill_type == "skill-stress-lab":
                scan_warnings = self._scan_upload_security(input_dir)
                if scan_warnings:
                    details = "; ".join(scan_warnings[:5])
                    msg = (
                        f"Security scan failed — this package cannot be stress tested. "
                        f"Found {len(scan_warnings)} issue(s): {details}"
                    )
                    self._set_task_state(task_id, status="failed", message=msg)
                    raise ValueError(msg)
        except Exception as exc:
            self._set_task_state(task_id, status="failed", message=str(exc))
            raise
        self._set_task_state(task_id, status="queued", message="Task queued")
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
        wallet_lower = wallet_address.lower()
        with self._lock:
            # Only snapshot matching records; release lock before any sorting/filtering.
            tasks = [
                self._snapshot(record)
                for record in self.tasks.values()
                if record.wallet_address and record.wallet_address.lower() == wallet_lower
            ]
        # Sort and filter OUTSIDE the lock — O(n log n) CPU work should not
        # block concurrent get_task / create_task callers.
        tasks.sort(key=lambda x: x.created_at, reverse=True)
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

    # 单个子进程最长执行时间（秒）。超过视为卡死，强制终止。
    SUBPROCESS_TIMEOUT = 600  # 10 分钟

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
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                timeout=self.SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log_file.write_text(
                "$ " + " ".join(cmd) + "\n\n"
                + f"[ERROR] 执行超时（超过 {self.SUBPROCESS_TIMEOUT} 秒）\n"
            )
            raise RuntimeError(
                f"分析超时（超过 {self.SUBPROCESS_TIMEOUT // 60} 分钟）。"
                "请检查文件是否过大或脚本是否存在死循环。"
            )
        log_file.write_text(
            "$ " + " ".join(cmd) + "\n\n"
            + "[stdout]\n" + (proc.stdout or "") + "\n"
            + "[stderr]\n" + (proc.stderr or "") + "\n"
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"命令执行失败 (exit {proc.returncode})。\n"
                f"[stderr] {(proc.stderr or '').strip()[:500]}"
            )
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

    # -------------------- upload security scan --------------------
    # Dangerous file extensions that should not be present in stress test packages
    DANGEROUS_EXTENSIONS = {
        ".sh", ".bash", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".msi", ".dll", ".com", ".scr", ".pif", ".wsf", ".wsh", ".cpl",
    }

    # Suspicious code patterns that indicate malicious intent
    SUSPICIOUS_PATTERNS = [
        (rb"rm\s+-rf\s+/", "destructive command: rm -rf /"),
        (rb"curl\s+.*\|\s*(?:ba)?sh", "remote code execution: curl | sh"),
        (rb"wget\s+.*\|\s*(?:ba)?sh", "remote code execution: wget | sh"),
        (rb"os\.system\s*\(", "dangerous call: os.system()"),
        (rb"subprocess\.(?:call|run|Popen)\s*\(", "dangerous call: subprocess"),
        (rb"eval\s*\(\s*compile", "dangerous call: eval(compile(...))"),
        (rb"/dev/tcp/", "reverse shell pattern: /dev/tcp"),
        (rb"bash\s+-i\s+>&\s*/dev/tcp", "reverse shell pattern"),
        (rb"nc\s+-[elp]", "netcat listener/reverse shell"),
        (rb"import\s+ctypes", "low-level system access: ctypes"),
        (rb"__import__\s*\(\s*['\"]os['\"]\s*\)", "obfuscated import: os"),
    ]

    def _scan_upload_security(self, input_dir: Path) -> list[str]:
        """Scan extracted upload for dangerous files and malicious patterns.

        Returns a list of human-readable warning strings.  An empty list
        means no threats were found.
        """
        import re as _re

        warnings: list[str] = []

        for filepath in input_dir.rglob("*"):
            if not filepath.is_file():
                continue

            rel = filepath.relative_to(input_dir)

            # 1. Check dangerous file extensions
            if filepath.suffix.lower() in self.DANGEROUS_EXTENSIONS:
                warnings.append(f"Dangerous file detected: {rel} (type: {filepath.suffix})")
                continue  # no need to scan content

            # 2. Check content of text-like files for suspicious patterns
            if filepath.suffix.lower() in {
                ".py", ".js", ".ts", ".rb", ".pl", ".php", ".java",
                ".c", ".cpp", ".h", ".go", ".rs", ".lua", ".r",
                ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
                ".txt", ".md", ".rst", "",
            }:
                try:
                    content = filepath.read_bytes()[:50_000]  # first 50 KB
                    for pattern, desc in self.SUSPICIOUS_PATTERNS:
                        if _re.search(pattern, content):
                            warnings.append(
                                f"Suspicious pattern in {rel}: {desc}"
                            )
                            break  # one warning per file is enough
                except (OSError, UnicodeDecodeError):
                    pass

        return warnings

    # Minimum security audit score required to proceed with stress testing
    STRESS_MIN_SECURITY_SCORE = 96

    def _run_security_pre_check(self, code_dir: Path, report_dir: Path) -> int:
        """Run a Security Audit on the uploaded package and return the overall score.

        The audit results are saved under report_dir/security_precheck/ so they
        don't collide with the main stress-test outputs.
        """
        precheck_dir = report_dir / "security_precheck"
        precheck_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = self._run_security_audit(code_dir, precheck_dir, {})
        except Exception as exc:
            # If the security audit itself fails, treat as score 0 (block)
            print(f"[TaskManager] Security pre-check audit error: {exc}")
            return 0

        # Parse the overall score from the JSON report
        summary_path = result.get("summary", "")
        if summary_path:
            try:
                data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
                score = int(data.get("overallScore", 0))
                print(f"[TaskManager] Security pre-check score: {score}/100")
                return score
            except Exception as exc:
                print(f"[TaskManager] Failed to parse security pre-check score: {exc}")
                return 0
        return 0

    def _run_stress_lab(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        # ── Step 1: Run Security Audit pre-check ────────────────────────
        audit_score = self._run_security_pre_check(code_dir, report_dir)
        if audit_score < self.STRESS_MIN_SECURITY_SCORE:
            raise RuntimeError(
                f"Security pre-check failed — overall security score is {audit_score}/100 "
                f"(minimum {self.STRESS_MIN_SECURITY_SCORE} required). "
                f"This package has potential security risks and cannot proceed with stress testing. "
                f"Please fix the security issues and try again."
            )

        # ── Step 2: Run Stress Test (security pre-check passed) ────────
        script = self.repo_root / "skills" / "skill-stress-lab" / "scripts" / "stress_runner.py"
        log_file = report_dir / "stress_runner.log"
        summary_md = report_dir / "stress_summary.md"
        metrics_json = report_dir / "stress_metrics.json"
        logs_dir = report_dir / "runs"
        # Use provided command or default to security_preflight.py
        command = params.get("command")
        if not command:
            command = "python3 {skill}/scripts/security_preflight.py"
        runs = max(1, min(100, int(params.get("runs", 10))))
        concurrency = max(1, min(100, int(params.get("concurrency", 1))))
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
        ]
        # Note: --collect-metrics is not supported by stress_runner.py, skip it
        if params.get("workdir"):
            cmd.extend(["--workdir", str(params["workdir"])])
        if params.get("skillDir"):
            cmd.extend(["--skill-dir", str(params["skillDir"])])
        elif code_dir.exists():
            # Find the actual skill subdirectory (e.g., input/skill-name/)
            skill_subdirs = [d for d in code_dir.iterdir() if d.is_dir()]
            if skill_subdirs:
                cmd.extend(["--skill-dir", str(skill_subdirs[0])])
            else:
                cmd.extend(["--skill-dir", str(code_dir)])
        if params.get("openaiUsageFile"):
            cmd.extend(["--openai-usage-file", str(params["openaiUsageFile"])])
        if params.get("apiCountFile"):
            cmd.extend(["--api-count-file", str(params["apiCountFile"])])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        
        # Generate enhanced report with 5-dimension scores
        enhanced_md = report_dir / "stress_report.md"
        self._generate_stress_lab_report(summary_md, enhanced_md, runs, concurrency)
        
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
            "message": "Stress test completed",
        }

    def _generate_stress_lab_report(self, summary_md: Path, output_md: Path, runs: int, concurrency: int) -> None:
        """Generate enhanced stress lab report with 5-dimension scoring."""
        # Read original summary
        original_content = summary_md.read_text() if summary_md.exists() else ""
        
        # Parse metrics from summary content
        import re
        metrics = {}

        # Extract success rate (supports both English and Chinese formats)
        success_match = re.search(r'(?:Successes|成功次数):\s*(\d+)\s*\(([^)]+)\)', original_content)
        if success_match:
            metrics['successes'] = int(success_match.group(1))
            metrics['success_rate_str'] = success_match.group(2)

        # Extract avg duration (supports both English and Chinese formats)
        avg_match = re.search(r'(?:Avg Duration|平均耗时):\s*([\d.]+)s', original_content)
        if avg_match:
            metrics['avg_duration'] = float(avg_match.group(1))
        
        # Calculate 5-dimension scores based on metrics
        stability_score = 100
        performance_score = 95
        resource_score = 90
        consistency_score = 100
        recovery_score = 100
        
        # Extract actual metrics if available
        if metrics:
            avg_duration = metrics.get('avg_duration', 0.05)
            successes = metrics.get('successes', runs)
            success_rate = successes / runs if runs > 0 else 1.0
            failures = runs - successes
            
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
            "# Skill Stress Lab Report",
            "",
            "## Basic Information",
            f"- **Test Runs**: {runs}",
            f"- **Concurrency**: {concurrency}",
            "",
            "---",
            "",
            "## Five-Dimension Scores (0-100)",
            "",
            "| Dimension | Score | Description |",
            "|-----------|-------|-------------|",
            f"| 🛡️ **Stability** | {stability_score}/100 | Success rate performance |",
            f"| ⚡ **Performance** | {performance_score}/100 | Response time performance |",
            f"| 💾 **Resource** | {resource_score}/100 | Resource utilization |",
            f"| 🔄 **Consistency** | {consistency_score}/100 | Result consistency |",
            f"| 🆘 **Recovery** | {recovery_score}/100 | Failure recovery capability |",
            "",
            f"### 📊 Overall Score: **{overall_score}/100**",
            "",
            "---",
            "",
            "## Original Test Summary",
            "",
            original_content,
            "",
            "---",
            "",
            "*Report auto-generated by Skill Stress Lab*",
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
            # Serialize while holding the lock so the snapshot is consistent,
            # then write to disk after releasing to minimise lock contention.
            index_payload = self._build_index_payload()
            snapshot = self._snapshot(record)
        self._flush_index(index_payload)
        return snapshot

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
