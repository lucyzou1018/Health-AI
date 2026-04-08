#!/usr/bin/env python3
"""Task manager for CodeAutrix web service."""
from __future__ import annotations

import json
import os
import re
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
    wallet_address: Optional[str] = None
    file_name: Optional[str] = None

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
        self._recover_orphaned_tasks()

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

    # Tasks created within this window are not considered orphans, so uvicorn
    # --reload does not accidentally fail tasks that were just submitted.
    ORPHAN_GRACE_SECONDS = 30

    def _recover_orphaned_tasks(self) -> None:
        """On startup, mark stuck running/queued tasks as failed.
        Tasks created within ORPHAN_GRACE_SECONDS are skipped to avoid
        killing tasks that were submitted right before a hot-reload."""
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
            record.message = "Service restarted — task was interrupted. Please re-submit."
            record.updated_at = _now()
        self._save_index()

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
        if suffix in {".skill", ".zip", ".tar", ".gz", ".bz2", ".xz"}:
            fmt = "zip" if suffix == ".skill" else None
            shutil.unpack_archive(str(src), dest, format=fmt)
            # Path traversal guard: ensure no extracted file escapes dest
            dest_resolved = dest.resolve()
            for extracted in dest.rglob("*"):
                if not str(extracted.resolve()).startswith(str(dest_resolved)):
                    raise ValueError(f"Archive contains unsafe path: {extracted.name}")
        else:
            shutil.copyfile(src, dest / src.name)

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
            raise ValueError("Either codePath or uploadId must be provided")
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
            # Security check for stress test is now handled by the Security Audit
            # pre-check inside _run_stress_lab (score >= 96 required).
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
        """Return analysis history for the given wallet address."""
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
            raise FileNotFoundError(f"Code path does not exist: {src}")
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

    SUBPROCESS_TIMEOUT = 600  # 10 minutes; processes exceeding this are killed

    def _run_command(
        self,
        cmd: list[str],
        cwd: Optional[Path],
        log_file: Path,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Only pass essential environment variables to subprocesses to prevent
        # accidental leakage of secrets (e.g. OPENAI_API_KEY) through errors.
        _ALLOWED_ENV_KEYS = {
            "PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE",
            "PYTHONPATH", "VIRTUAL_ENV", "TMPDIR", "TMP", "TEMP",
            # Keys the analysis scripts explicitly need:
            "OPENAI_API_KEY", "XAI_API_KEY", "SKILL_AUDIT_AI_MODEL",
            "SKILL_AUDIT_AI_DETAIL", "ETHERSCAN_API_KEY",
            "DAILY_TASK_LIMIT_ENABLED",
        }
        merged_env = {k: v for k, v in os.environ.items() if k in _ALLOWED_ENV_KEYS}
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
                + f"[ERROR] Timed out after {self.SUBPROCESS_TIMEOUT} seconds\n"
            )
            raise RuntimeError(
                f"Analysis timed out (exceeded {self.SUBPROCESS_TIMEOUT // 60} minutes). "
                "The file may be too large or the script encountered an infinite loop."
            )
        log_file.write_text(
            "$ " + " ".join(cmd) + "\n\n"
            + "[stdout]\n" + (proc.stdout or "") + "\n"
            + "[stderr]\n" + (proc.stderr or "") + "\n"
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "").strip()[:1000] or "Script exited with non-zero status")
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
        skill_path = params.get("skillPath", "")
        skill_url = params.get("skillUrl", "")
        if skill_url:
            cmd.extend(["--skill-url", skill_url])
        elif code_dir.exists():
            skill_dirs = sorted({str(path.parent) for path in code_dir.rglob("SKILL.md")})
            targets = skill_dirs or [str(code_dir)]
            for target in targets:
                cmd.extend(["--skill-path", target])
        # AI model is configurable via SKILL_AUDIT_AI_MODEL env var (default: gpt-4o-mini)
        ai_model = os.environ.get("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini")
        cmd.extend(["--ai-model", ai_model])
        # Set SKILL_AUDIT_AI_DETAIL=true to include per-dimension risk scores in the report
        if os.environ.get("SKILL_AUDIT_AI_DETAIL", "").lower() in ("1", "true", "yes"):
            cmd.append("--ai-detail")
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        summary_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
        return {
            "report": str(report_md),
            "summary": str(report_json),
            "log": str(log_file),
            "message": "Skill Security Audit completed.",
            "details": summary_data,
        }

    def _run_contract_audit(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        # File count limit only applies to uploaded packages; skip for on-chain address mode.
        if not params.get("evmAddress"):
            # Count only contract source files; exclude macOS __MACOSX metadata and ._-prefixed files.
            _CONTRACT_EXTS = {".sol", ".vy", ".rs"}
            _MAX_CONTRACT_FILES = 10
            _all_files = [
                f for f in code_dir.rglob("*")
                if f.is_file()
                and f.suffix.lower() in _CONTRACT_EXTS
                and "__MACOSX" not in f.parts
                and not f.name.startswith("._")
            ]
            if len(_all_files) > _MAX_CONTRACT_FILES:
                raise RuntimeError(
                    f"ZIP package contains {len(_all_files)} contract files, "
                    f"exceeding the {_MAX_CONTRACT_FILES}-file limit. "
                    f"Please reduce the number of files and re-upload."
                )

        script = self.repo_root / "skills" / "multichain-contract-vuln" / "scripts" / "run_cli.py"
        report_md = report_dir / "contract_audit.md"
        log_file = report_dir / "contract_audit.log"
        ai_model = os.environ.get("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini")
        cmd = ["python3", str(script), "--report", str(report_md), "--ai-model", ai_model]
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
        env: Dict[str, str] = {}
        if params.get("etherscanApiKey"):
            env["ETHERSCAN_API_KEY"] = str(params["etherscanApiKey"])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file, env=env)
        summary_json = report_dir / "contract_summary.json"
        summary_json.write_text(json.dumps({
            "report": str(report_md),
            "inputs": {
                "input": input_path,
                "evmAddress": params.get("evmAddress"),
                "network": params.get("network"),
                "chain": params.get("chain"),
            },
        }, ensure_ascii=False, indent=2))
        return {
            "report": str(report_md),
            "summary": str(summary_json),
            "log": str(log_file),
            "message": "Contract audit completed.",
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

    # Minimum security audit score required to proceed with stress testing
    STRESS_MIN_SECURITY_SCORE = 95

    def _find_skill_dir(self, code_dir: Path, params: dict) -> Path:
        """Resolve the skill directory from params or by scanning code_dir."""
        if params.get("skillDir"):
            return Path(params["skillDir"])
        if code_dir.exists():
            subdirs = [d for d in code_dir.iterdir() if d.is_dir()]
            if subdirs:
                return subdirs[0]
        return code_dir

    # Primary entry script names — these represent the skill's MAIN
    # functionality (not utility scripts like security_preflight.py).
    _PRIMARY_ENTRY_NAMES = [
        "scripts/run_cli.py",
        "scripts/runner.py",
        "scripts/main.py",
        "scripts/run.py",
        "scripts/audit_skill.py",
        "scripts/audit_scan.py",
        "main.py",
        "run.py",
        "__main__.py",
    ]

    def _detect_primary_entry(self, skill_dir: Path) -> str | None:
        """Find the skill's primary entry script.

        Only checks well-known main entry names.  Does NOT fall back to
        arbitrary utility scripts — if the main entry is not found the
        skill is considered parameter-dependent and will be rejected.
        """
        for candidate in self._PRIMARY_ENTRY_NAMES:
            if (skill_dir / candidate).is_file():
                return f"python3 {{skill}}/{candidate}"
        return None

    def _run_security_pre_check(self, code_dir: Path, report_dir: Path) -> dict:
        """Run a Security Audit on the uploaded package and return score + AI review.

        Returns dict with keys: score (int), aiReview (dict).
        The audit results are saved under report_dir/security_precheck/.
        """
        precheck_dir = report_dir / "security_precheck"
        precheck_dir.mkdir(parents=True, exist_ok=True)
        empty_ai = {"status": "skipped", "hasRisk": False, "riskLevel": "none",
                     "privacyRisk": 0, "privilegeRisk": 0, "integrityRisk": 0,
                     "dependencyRisk": 0, "stabilityRisk": 0}
        try:
            result = self._run_security_audit(code_dir, precheck_dir, {})
        except Exception:
            return {"score": 0, "aiReview": empty_ai}

        summary_path = result.get("summary", "")
        if summary_path:
            try:
                data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
                score = int(data.get("overallScore", 0))
                ai_review = data.get("aiReview", empty_ai) or empty_ai
                return {"score": score, "aiReview": ai_review}
            except Exception:
                return {"score": 0, "aiReview": empty_ai}
        return {"score": 0, "aiReview": empty_ai}

    # Patterns to detect mandatory arguments in Python source code
    _RE_REQUIRED_TRUE = re.compile(r'add_argument\s*\([^)]*required\s*=\s*True', re.DOTALL)
    _RE_POSITIONAL_ARG = re.compile(r'add_argument\s*\(\s*["\'](?!-)[^"\']+["\']')
    # Patterns for manual validation: "if not args.xxx" → exit/return/error
    _RE_MANUAL_REQUIRED = re.compile(
        r'(?:if\s+not\s+args\.\w+|'                   # if not args.xxx
        r'must\s+provide|'                              # "must provide"
        r'parser\.error\s*\(|'                          # parser.error(...)
        r'(?:--\w[\w-]+)\s+is\s+required)',             # "--xxx is required"
        re.IGNORECASE,
    )

    def _has_mandatory_args(self, script_path: Path) -> bool:
        """Static analysis: check if a Python script has mandatory CLI arguments.

        Scans the source code for:
        1. argparse: add_argument(..., required=True)
        2. argparse: add_argument("positional_arg") (no --)
        3. Manual checks: "if not args.xxx", parser.error(...)
        Returns True if mandatory arguments are found.
        """
        try:
            source = script_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return True  # Can't read → assume needs args

        if self._RE_REQUIRED_TRUE.search(source):
            return True
        if self._RE_POSITIONAL_ARG.search(source):
            return True
        if self._RE_MANUAL_REQUIRED.search(source):
            return True

        return False

    def _run_stress_lab(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        # ── Step 1: Check for mandatory parameters (static analysis) ─────
        skill_dir = self._find_skill_dir(code_dir, params)

        command = params.get("command")  # allow explicit override
        if not command:
            entry = self._detect_primary_entry(skill_dir)
            if not entry:
                raise RuntimeError(
                    "The uploaded Skill package does not contain any executable scripts. "
                    "Stress Test requires a Skill with runnable Python code."
                )
            # Extract the actual file path from the command template
            # e.g. "python3 {skill}/scripts/run_cli.py" → skill_dir / "scripts/run_cli.py"
            rel_path = entry.replace("python3 {skill}/", "")
            script_path = skill_dir / rel_path

            if self._has_mandatory_args(script_path):
                raise RuntimeError(
                    "The current version of Stress Test does not support "
                    "Skills with mandatory arguments yet."
                )
            command = entry

        # ── Step 2: Security Audit pre-check ─────────────────────────────
        #   Only reached if the skill can run without extra arguments.
        precheck = self._run_security_pre_check(code_dir, report_dir)
        audit_score = precheck["score"]
        ai_review = precheck["aiReview"]
        if audit_score < self.STRESS_MIN_SECURITY_SCORE:
            raise RuntimeError(
                "This Skill contains high-risk operations and is not eligible for stress testing. "
                "Please resolve the security issues before retrying."
            )

        # ── Step 3: Run Stress Test ──────────────────────────────────────
        script = self.repo_root / "skills" / "skill-stress-lab" / "scripts" / "stress_runner.py"
        log_file = report_dir / "stress_runner.log"
        summary_md = report_dir / "stress_summary.md"
        metrics_json = report_dir / "stress_metrics.json"
        logs_dir = report_dir / "runs"

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
            "--skill-dir",
            str(skill_dir),
        ]
        if params.get("openaiUsageFile"):
            cmd.extend(["--openai-usage-file", str(params["openaiUsageFile"])])
        if params.get("apiCountFile"):
            cmd.extend(["--api-count-file", str(params["apiCountFile"])])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        
        # Generate enhanced report with 5-dimension scores + AI review
        enhanced_md = report_dir / "stress_report.md"
        self._generate_stress_lab_report(summary_md, enhanced_md, runs, concurrency, ai_review)
        
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

    def _generate_stress_lab_report(self, summary_md: Path, output_md: Path, runs: int, concurrency: int, ai_review: dict | None = None) -> None:
        """Generate enhanced stress lab report with 5-dimension scoring + AI review."""
        original = summary_md.read_text() if summary_md.exists() else ""

        # ── Parse all metrics from stress_runner summary ─────────────
        total_runs = runs
        successes = 0
        avg_duration = 0.0
        p95_duration = 0.0
        min_duration = 0.0
        max_duration = 0.0
        std_deviation = 0.0
        skill_name = "-"
        failure_samples: list[str] = []

        m = re.search(r'Total Runs:\s*(\d+)', original)
        if m: total_runs = int(m.group(1))
        m = re.search(r'Successes:\s*(\d+)', original)
        if m: successes = int(m.group(1))
        m = re.search(r'Avg Duration:\s*([\d.]+)s', original)
        if m: avg_duration = float(m.group(1))
        m = re.search(r'P95 Duration:\s*([\d.]+)s', original)
        if m: p95_duration = float(m.group(1))
        m = re.search(r'Min Duration:\s*([\d.]+)s', original)
        if m: min_duration = float(m.group(1))
        m = re.search(r'Max Duration:\s*([\d.]+)s', original)
        if m: max_duration = float(m.group(1))
        m = re.search(r'Std Deviation:\s*([\d.]+)s', original)
        if m: std_deviation = float(m.group(1))
        m = re.search(r'Skill:\s*(\S+)', original)
        if m: skill_name = m.group(1)
        for fm in re.finditer(r'Run #(\d+) exit (\d+), duration ([\d.]+)s(?::\s*(.+))?', original):
            detail = f"Run #{fm.group(1)} (exit {fm.group(2)}, {fm.group(3)}s)"
            reason = (fm.group(4) or "").strip()
            if reason:
                detail += f": {reason}"
            failure_samples.append(detail)

        failures = total_runs - successes
        success_rate = successes / total_runs if total_runs > 0 else 0.0
        failure_rate = failures / total_runs if total_runs > 0 else 0.0
        has_data = successes > 0 or avg_duration > 0

        # ── Calculate 5-dimension scores ─────────────────────────────
        if has_data:
            stability_score = int(success_rate * 100)

            d = p95_duration if p95_duration > 0 else avg_duration
            if d <= 1:      performance_score = 100
            elif d <= 10:   performance_score = int(90 - (d - 1) * (30 / 9))
            elif d <= 30:   performance_score = int(60 - (d - 10))
            elif d <= 60:   performance_score = int(40 - (d - 30) * (15 / 30))
            else:           performance_score = max(10, int(25 - (d - 60) * 0.1))

            # consistency: timing regularity via coefficient of variation (low = more consistent)
            if avg_duration > 0:
                cv = std_deviation / avg_duration
                if   cv <= 0.05: consistency_score = 100
                elif cv <= 0.15: consistency_score = 90
                elif cv <= 0.30: consistency_score = 70
                elif cv <= 0.50: consistency_score = 50
                elif cv <= 1.00: consistency_score = 30
                else:            consistency_score = max(10, int(30 - (cv - 1.0) * 10))
            else:
                consistency_score = stability_score

            # resource: tail-latency ratio (P95 / avg — measures burst overhead)
            if avg_duration > 0 and p95_duration >= avg_duration:
                ratio = p95_duration / avg_duration
                if   ratio <= 1.5: resource_score = 95
                elif ratio <= 2.0: resource_score = 80
                elif ratio <= 3.0: resource_score = 60
                elif ratio <= 5.0: resource_score = 40
                else:              resource_score = max(10, int(40 - (ratio - 5) * 3))
            elif failure_rate == 0:   resource_score = 90
            elif failure_rate <= 0.1: resource_score = 80
            elif failure_rate <= 0.3: resource_score = 60
            elif failure_rate <= 0.5: resource_score = 40
            else:                     resource_score = max(10, int(40 - failure_rate * 30))

            if   failures == 0:       recovery_score = 100
            elif failure_rate <= 0.1: recovery_score = 85
            elif failure_rate <= 0.3: recovery_score = 65
            elif failure_rate <= 0.5: recovery_score = 45
            else:                     recovery_score = max(10, int(45 - failure_rate * 35))
        else:
            stability_score = performance_score = resource_score = consistency_score = recovery_score = 0

        # ── Apply AI code review deductions (same logic as security audit) ──
        ai = ai_review or {}
        ai_has_risk = ai.get("status") == "ok" and ai.get("hasRisk", False)
        if ai_has_risk:
            stability_score   = max(0, stability_score   - min(15, ai.get("stabilityRisk",  0) // 4))
            performance_score = max(0, performance_score - min(15, ai.get("privacyRisk",     0) // 4))
            resource_score    = max(0, resource_score    - min(15, ai.get("privilegeRisk",   0) // 4))
            consistency_score = max(0, consistency_score  - min(15, ai.get("integrityRisk",   0) // 4))
            recovery_score    = max(0, recovery_score    - min(15, ai.get("dependencyRisk",  0) // 4))

        overall_score = int((stability_score + performance_score + resource_score + consistency_score + recovery_score) / 5)

        # ── Rating helper ──────────────────────────────────────────
        def _rating(score: int) -> str:
            if score >= 80: return "🟢 Excellent"
            if score >= 60: return "🔵 Good"
            if score >= 40: return "🟡 Caution"
            return "🔴 Risk"

        # ── Compute per-dimension deduction reasons ──────────────────
        cv = (std_deviation / avg_duration) if avg_duration > 0 else 0.0
        tail_ratio = (p95_duration / avg_duration) if avg_duration > 0 and p95_duration >= avg_duration else None

        # Mapping: dimension → AI review risk field → human-readable label
        _AI_RISK_FIELD = {
            "stability":   ("stabilityRisk",  "stability risk"),
            "performance": ("privacyRisk",     "privacy risk"),
            "resource":    ("privilegeRisk",   "privilege risk"),
            "consistency": ("integrityRisk",   "integrity risk"),
            "recovery":    ("dependencyRisk",  "dependency risk"),
        }
        # Human-readable description of each risk level
        _RISK_LEVEL_LABEL = {"none": "none", "low": "low", "medium": "medium", "high": "high"}
        ai_risk_level = _RISK_LEVEL_LABEL.get(str(ai.get("riskLevel", "none")).lower(), "unknown")

        def _ai_deduct_reason(dim: str) -> str:
            """Return a detailed explanation for an AI-driven deduction, or '' if none."""
            if not ai_has_risk:
                return ""
            field, label = _AI_RISK_FIELD.get(dim, ("", ""))
            raw_val = ai.get(field, 0)
            deduct = min(15, raw_val // 4)
            if deduct <= 0:
                return ""
            # e.g. "security pre-check: integrityRisk=5 (low) → −1 pt"
            return (
                f"security pre-check flagged {label} = {raw_val}/100"
                f" (overall risk level: {ai_risk_level}) → −{deduct} pt(s)"
            )

        def _deduction(dim: str) -> str:
            """Return a one-line explanation for why this dimension lost points, or '' if perfect."""
            ai_reason = _ai_deduct_reason(dim)

            if dim == "stability":
                reasons = []
                if failures > 0:
                    reasons.append(f"{failures}/{total_runs} run(s) failed ({failure_rate*100:.1f}% failure rate)")
                if ai_reason:
                    reasons.append(ai_reason)
                return "; ".join(reasons) if reasons else ""

            if dim == "performance":
                d = p95_duration if p95_duration > 0 else avg_duration
                reasons = []
                if d > 1:
                    tier = (f"P95={p95_duration:.3f}s > 1 s threshold" if p95_duration > 0
                            else f"avg={avg_duration:.3f}s > 1 s threshold")
                    reasons.append(tier)
                    if d <= 10:
                        deduct = int((d - 1) * (30 / 9))
                        reasons.append(f"−{deduct} pt(s) from linear penalty (1–10 s band)")
                    elif d <= 30:
                        reasons.append(f"−{int(60 - (d-10))} pt(s) (10–30 s band)")
                if ai_reason:
                    reasons.append(ai_reason)
                return "; ".join(reasons) if reasons else ""

            if dim == "resource":
                reasons = []
                if tail_ratio is not None:
                    if tail_ratio > 1.5:
                        reasons.append(f"P95/avg tail ratio = {tail_ratio:.2f}x (threshold: ≤1.5x for 95)")
                    else:
                        reasons.append(f"P95/avg tail ratio = {tail_ratio:.2f}x → capped at 95 (ratio ≤1.5x)")
                elif failure_rate > 0:
                    reasons.append(f"failure-based fallback: {failure_rate*100:.1f}% failure rate")
                if ai_reason:
                    reasons.append(ai_reason)
                return "; ".join(reasons) if reasons else ""

            if dim == "consistency":
                reasons = []
                if avg_duration > 0 and cv > 0.05:
                    reasons.append(
                        f"CV = {cv:.3f} (std={std_deviation:.3f}s / avg={avg_duration:.3f}s)"
                        f"; threshold: ≤0.05 for 100"
                    )
                if ai_reason:
                    reasons.append(ai_reason)
                return "; ".join(reasons) if reasons else ""

            if dim == "recovery":
                reasons = []
                if failures > 0:
                    reasons.append(f"{failures} failure(s) detected — perfect score requires 0 failures")
                if ai_reason:
                    reasons.append(ai_reason)
                return "; ".join(reasons) if reasons else ""

            return ""

        dim_scores_map = {
            "stability":   stability_score,
            "performance": performance_score,
            "resource":    resource_score,
            "consistency": consistency_score,
            "recovery":    recovery_score,
        }

        # ── Build clean report ───────────────────────────────────────
        # NOTE: Frontend report.html parses with regex like "Test Runs: N",
        #       "Successes: N (XX%)", "Avg Duration: X.Xs", "Stability ... N/100".
        #       Use plain "Key: Value" format so frontend regex can extract values.
        test_status = "Pass" if failures == 0 and has_data else ("Fail" if has_data else "N/A")
        status_icon = "✅" if test_status == "Pass" else ("❌" if test_status == "Fail" else "⚪")
        lines = [
            "# Skill Stress Lab Report",
            "",
            "## Test Configuration",
            "",
            "| Item | Value |",
            "|------|-------|",
            f"| Test Runs | {total_runs} |",
            f"| Concurrency | {concurrency} |",
            f"| Skill | {skill_name} |",
            "",
            "## Performance Metrics",
            "",
            "| Metric | Value | Status |",
            "|--------|-------|--------|",
            f"| **Success Rate** | **{successes}/{total_runs} ({success_rate*100:.1f}%)** | {status_icon} {test_status} |",
            f"| Avg Duration | {avg_duration:.2f}s | {'✅ Pass' if avg_duration <= 10 else '❌ Fail'} |",
            f"| P95 Duration | {p95_duration:.2f}s | {'✅ Pass' if p95_duration <= 30 else '❌ Fail'} |",
            f"| Min Duration | {min_duration:.2f}s | ✅ Pass |",
            f"| Max Duration | {max_duration:.2f}s | {'✅ Pass' if max_duration <= 60 else '❌ Fail'} |",
            f"| Std Deviation | {std_deviation:.2f}s | {'✅ Pass' if std_deviation <= 5 else '❌ Fail'} |",
            "",
            "## Five-Dimension Scores",
            "",
            f"| Dimension | Score | Rating | Description |",
            f"|-----------|-------|--------|-------------|",
            f"| 🛡️ Stability | {stability_score}/100 | {_rating(stability_score)} | Success rate under concurrent load |",
            f"| ⚡ Performance | {performance_score}/100 | {_rating(performance_score)} | Response time (P95-based) |",
            f"| 💾 Resource | {resource_score}/100 | {_rating(resource_score)} | Resource efficiency under load |",
            f"| 🔄 Consistency | {consistency_score}/100 | {_rating(consistency_score)} | Result repeatability |",
            f"| 🆘 Recovery | {recovery_score}/100 | {_rating(recovery_score)} | Failure tolerance and recovery |",
            "",
            f"**Overall Score: {overall_score}/100** ({_rating(overall_score)})",
        ]

        # ── Score Analysis: deduction reasons for non-100 dimensions ──
        deduction_lines = []
        dim_labels = {
            "stability":   "🛡️ Stability",
            "performance": "⚡ Performance",
            "resource":    "💾 Resource",
            "consistency": "🔄 Consistency",
            "recovery":    "🆘 Recovery",
        }
        for dim, label in dim_labels.items():
            score = dim_scores_map[dim]
            if score < 100:
                reason = _deduction(dim)
                if reason:
                    deduction_lines.append(
                        f"- **{label} ({score}/100):** {reason}"
                    )
                else:
                    deduction_lines.append(
                        f"- **{label} ({score}/100):** scoring cap applied at this tier"
                    )

        if deduction_lines:
            lines += ["", "## Score Analysis", ""]
            lines += deduction_lines

        if failure_samples:
            lines += [
                "",
                "## Failure Details",
                "",
            ]
            for s in failure_samples[:5]:
                lines.append(f"- {s}")

        lines += [
            "",
            "*Report auto-generated by Skill Stress Lab*",
        ]

        output_md.write_text("\n".join(lines), encoding="utf-8")

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
            self._set_task_state(task_id, status="running", message="Running…")
            with self._lock:
                record = self.tasks.get(task_id)
                if not record:
                    raise KeyError("task not found")
                record_copy = self._snapshot(record)
            result = self._run_skill(record_copy, workspace, input_dir)
            self._set_task_state(
                task_id,
                status="completed",
                message=result.get("message", "Completed."),
                report=result.get("report"),
                summary=result.get("summary"),
                log=result.get("log"),
            )
        except Exception as exc:
            self._set_task_state(task_id, status="failed", message=str(exc))
