#!/usr/bin/env python3
"""Task manager for CodeAutrix web service — SQLite backend."""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

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
        return asdict(self)


# ─────────────────────────── DB helpers ────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id        TEXT PRIMARY KEY,
    skill_type     TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    message        TEXT NOT NULL DEFAULT '',
    report_path    TEXT,
    summary_path   TEXT,
    log_path       TEXT,
    params         TEXT NOT NULL DEFAULT '{}',
    wallet_address TEXT,
    file_name      TEXT
);
"""

_CREATE_INDEXES = [
    # fast history lookup per wallet
    "CREATE INDEX IF NOT EXISTS idx_wallet       ON tasks(wallet_address);",
    # duplicate-task check: wallet + skill_type + status
    "CREATE INDEX IF NOT EXISTS idx_wallet_skill_status ON tasks(wallet_address, skill_type, status);",
    # ordered history
    "CREATE INDEX IF NOT EXISTS idx_created_desc ON tasks(created_at DESC);",
    # orphan recovery on startup
    "CREATE INDEX IF NOT EXISTS idx_status       ON tasks(status);",
]

def _row_to_record(row: sqlite3.Row) -> TaskRecord:
    d = dict(row)
    d["params"] = json.loads(d.get("params") or "{}")
    return TaskRecord(**d)


def _record_to_row(r: TaskRecord) -> tuple:
    return (
        r.task_id, r.skill_type, r.status, r.created_at, r.updated_at,
        r.message or "",
        r.report_path, r.summary_path, r.log_path,
        json.dumps(r.params or {}, ensure_ascii=False),
        r.wallet_address, r.file_name,
    )


# ─────────────────────────── TaskManager ───────────────────────────────────

class TaskManager:
    def __init__(self, base_dir: Path, repo_root: Path) -> None:
        self.base_dir  = base_dir
        self.repo_root = repo_root
        self.upload_dir = base_dir / "uploads"
        self.tasks_dir  = base_dir / "tasks"
        self.db_path    = base_dir / "tasks.db"
        # Legacy JSON index path (kept for migration only)
        self.index_path = base_dir / "tasks_index.json"

        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.tasks_dir.mkdir(parents=True, exist_ok=True)

        # In-memory cache: only ACTIVE tasks (pending/queued/running)
        # Completed/failed tasks are read directly from SQLite on demand.
        self._active: Dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=2)

        self._init_db()
        self._migrate_json_if_needed()
        self._load_active_tasks()
        self._recover_orphaned_tasks()

    # ─────────────── DB init ────────────────────────────────────────────────

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        """Thread-safe SQLite connection in WAL mode."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute(_CREATE_TABLE)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)

    # ─────────────── Migration from JSON ───────────────────────────────────

    def _migrate_json_if_needed(self) -> None:
        """One-time import of tasks_index.json → SQLite on first run."""
        if not self.index_path.exists():
            return
        # Check if DB already has data
        with self._db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            if count > 0:
                return  # already migrated

        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except Exception:
            return

        imported = 0
        with self._db() as conn:
            for task_id, payload in data.items():
                try:
                    r = TaskRecord(**payload)
                    conn.execute(
                        """INSERT OR IGNORE INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        _record_to_row(r),
                    )
                    imported += 1
                except Exception:
                    pass

        # Backup the old JSON file
        bak = self.index_path.with_suffix(".json.bak")
        shutil.copy2(self.index_path, bak)
        print(f"[TaskManager] Migrated {imported} tasks from JSON → SQLite. Backup: {bak}")

    # ─────────────── Startup load ───────────────────────────────────────────

    def _load_active_tasks(self) -> None:
        """Load only pending/queued/running tasks into memory cache."""
        with self._db() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE status IN ('pending','queued','running')"
            ).fetchall()
        for row in rows:
            r = _row_to_record(row)
            self._active[r.task_id] = r

    # ─────────────── Orphan recovery ───────────────────────────────────────

    ORPHAN_GRACE_SECONDS = 30

    def _detect_completed_artifacts(self, task_id: str, record: TaskRecord) -> Optional[Dict[str, Optional[str]]]:
        workspace = self.tasks_dir / task_id / "report"
        if record.skill_type == "skill-security-audit":
            report_md   = workspace / "security_audit.md"
            report_json = workspace / "security_audit.json"
            log_file    = workspace / "security_audit.log"
            if report_md.exists() and report_json.exists():
                return {"report": str(report_md.resolve()), "summary": str(report_json.resolve()),
                        "log": str(log_file.resolve()) if log_file.exists() else None,
                        "message": "Skill Security Audit completed."}
        elif record.skill_type == "multichain-contract-vuln":
            report_md   = workspace / "contract_audit.md"
            summary_json = workspace / "contract_summary.json"
            log_file    = workspace / "contract_audit.log"
            if report_md.exists():
                return {"report": str(report_md.resolve()),
                        "summary": str(summary_json.resolve()) if summary_json.exists() else None,
                        "log": str(log_file.resolve()) if log_file.exists() else None,
                        "message": "Contract audit completed."}
        elif record.skill_type == "skill-stress-lab":
            report_md   = workspace / "stress_report.md"
            summary_json = workspace / "stress_summary.json"
            log_file    = workspace / "stress_runner.log"
            if report_md.exists():
                return {"report": str(report_md.resolve()),
                        "summary": str(summary_json.resolve()) if summary_json.exists() else None,
                        "log": str(log_file.resolve()) if log_file.exists() else None,
                        "message": "Stress test completed"}
        return None

    def _recover_orphaned_tasks(self) -> None:
        from datetime import timezone
        now_ts = datetime.now(timezone.utc).timestamp()

        to_recover: list[str] = []
        to_fail:    list[str] = []

        for task_id, record in list(self._active.items()):
            if record.status not in ("running", "queued"):
                continue
            try:
                created_ts = datetime.fromisoformat(
                    record.created_at.replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                created_ts = 0
            if now_ts - created_ts < self.ORPHAN_GRACE_SECONDS:
                continue

            recovered = self._detect_completed_artifacts(task_id, record)
            if recovered:
                to_recover.append(task_id)
                record.status       = "completed"
                record.message      = recovered["message"] or "Completed."
                record.report_path  = recovered["report"]
                record.summary_path = recovered["summary"]
                record.log_path     = recovered["log"]
                record.updated_at   = _now()
                self._db_upsert(record)
                self._active.pop(task_id, None)   # move out of active cache
            else:
                to_fail.append(task_id)

        for task_id in to_fail:
            record = self._active.pop(task_id, None)
            if record:
                record.status    = "failed"
                record.message   = "Service restarted — task was interrupted. Please re-submit."
                record.updated_at = _now()
                self._db_upsert(record)

    # ─────────────── DB primitives ──────────────────────────────────────────

    def _db_upsert(self, record: TaskRecord) -> None:
        with self._db() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                _record_to_row(record),
            )

    def _db_update_state(
        self,
        task_id: str,
        *,
        status:       Optional[str] = None,
        message:      Optional[str] = None,
        report_path:  Optional[str] = None,
        summary_path: Optional[str] = None,
        log_path:     Optional[str] = None,
        updated_at:   str,
    ) -> None:
        sets, vals = [], []
        if status       is not None: sets.append("status=?");       vals.append(status)
        if message      is not None: sets.append("message=?");      vals.append(message)
        if report_path  is not None: sets.append("report_path=?");  vals.append(report_path)
        if summary_path is not None: sets.append("summary_path=?"); vals.append(summary_path)
        if log_path     is not None: sets.append("log_path=?");     vals.append(log_path)
        sets.append("updated_at=?"); vals.append(updated_at)
        vals.append(task_id)
        with self._db() as conn:
            conn.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE task_id=?", vals)

    def _db_get(self, task_id: str) -> Optional[TaskRecord]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return _row_to_record(row) if row else None

    # ─────────────── uploads ────────────────────────────────────────────────

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
            dest_resolved = dest.resolve()
            for extracted in dest.rglob("*"):
                if not str(extracted.resolve()).startswith(str(dest_resolved)):
                    raise ValueError(f"Archive contains unsafe path: {extracted.name}")
        else:
            shutil.copyfile(src, dest / src.name)

    # ─────────────── public API ─────────────────────────────────────────────

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
            task_id=task_id, skill_type=skill_type, status="pending",
            created_at=_now(), updated_at=_now(),
            params=params or {}, wallet_address=wallet_address, file_name=file_name,
        )

        with self._lock:
            # Duplicate check: indexed query instead of full scan
            if wallet_address:
                wallet_lower = wallet_address.lower()
                with self._db() as conn:
                    conflict = conn.execute(
                        """SELECT task_id FROM tasks
                           WHERE lower(wallet_address)=?
                             AND skill_type=?
                             AND status IN ('running','queued','pending')
                           LIMIT 1""",
                        (wallet_lower, skill_type),
                    ).fetchone()
                if conflict:
                    raise ValueError("DUPLICATE_TASK")

            # Write to DB first, then memory cache
            self._db_upsert(record)
            self._active[task_id] = record

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

        self._set_task_state(task_id, status="queued", message="Task queued")
        self.executor.submit(self._execute_task, task_id, workspace, input_dir)
        return self._snapshot(record)

    def get_task(self, task_id: str) -> TaskRecord:
        self._recover_completed_task(task_id)
        # Check active cache first (O(1))
        with self._lock:
            record = self._active.get(task_id)
        if record:
            return self._snapshot(record)
        # Fall back to SQLite for completed/failed tasks
        record = self._db_get(task_id)
        if not record:
            raise KeyError("task not found")
        return record

    def get_tasks_by_wallet(
        self,
        wallet_address: str,
        skill_type: Optional[str] = None,
        limit: int = 50,
    ) -> list:
        """Indexed SQLite query — O(log n) regardless of total task count."""
        wallet_lower = wallet_address.lower()
        if skill_type:
            sql = """SELECT * FROM tasks
                     WHERE lower(wallet_address)=?
                       AND skill_type=?
                     ORDER BY created_at DESC
                     LIMIT ?"""
            args = (wallet_lower, skill_type, limit)
        else:
            sql = """SELECT * FROM tasks
                     WHERE lower(wallet_address)=?
                     ORDER BY created_at DESC
                     LIMIT ?"""
            args = (wallet_lower, limit)

        with self._db() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [_row_to_record(r) for r in rows]

    # ─────────────── internal helpers ───────────────────────────────────────

    def _copy_code(self, source: Path, dest: Path) -> None:
        src = source.expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"Code path does not exist: {src}")
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / src.name)

    def _snapshot(self, record: TaskRecord) -> TaskRecord:
        return TaskRecord(**record.to_dict())

    def _set_task_state(
        self,
        task_id: str,
        *,
        status:  Optional[str] = None,
        message: Optional[str] = None,
        report:  Optional[str] = None,
        summary: Optional[str] = None,
        log:     Optional[str] = None,
    ) -> TaskRecord:
        updated = _now()
        # Update SQLite (single-row UPDATE, not full table rewrite)
        self._db_update_state(
            task_id, status=status, message=message,
            report_path=report, summary_path=summary, log_path=log,
            updated_at=updated,
        )
        # Update memory cache
        with self._lock:
            record = self._active.get(task_id)
            if record:
                if status       is not None: record.status       = status
                if message      is not None: record.message      = message
                if report       is not None: record.report_path  = report
                if summary      is not None: record.summary_path = summary
                if log          is not None: record.log_path     = log
                record.updated_at = updated
                # Evict from active cache once terminal
                if status in ("completed", "failed"):
                    self._active.pop(task_id, None)
                    return self._snapshot(record)
                return self._snapshot(record)

        # Not in active cache → read back from DB
        r = self._db_get(task_id)
        if not r:
            raise KeyError("task not found")
        return r

    def _recover_completed_task(self, task_id: str) -> None:
        with self._lock:
            record = self._active.get(task_id)
        if not record or record.status not in ("running", "queued", "failed"):
            return
        recovered = self._detect_completed_artifacts(task_id, record)
        if not recovered:
            return
        self._set_task_state(
            task_id, status="completed",
            message=recovered["message"],
            report=recovered.get("report"),
            summary=recovered.get("summary"),
            log=recovered.get("log"),
        )

    # ─────────────── task execution ─────────────────────────────────────────

    SUBPROCESS_TIMEOUT = 600

    def _run_command(
        self,
        cmd: list[str],
        cwd: Optional[Path],
        log_file: Path,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _ALLOWED_ENV_KEYS = {
            "PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE",
            "PYTHONPATH", "VIRTUAL_ENV", "TMPDIR", "TMP", "TEMP",
            "OPENAI_API_KEY", "XAI_API_KEY", "SKILL_AUDIT_AI_MODEL",
            "SKILL_AUDIT_AI_DETAIL", "ETHERSCAN_API_KEY",
            "DAILY_TASK_LIMIT_ENABLED",
        }
        merged_env = {k: v for k, v in os.environ.items() if k in _ALLOWED_ENV_KEYS}
        if env:
            merged_env.update(env)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=str(cwd) if cwd else None,
                env=merged_env, timeout=self.SUBPROCESS_TIMEOUT,
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

    def _run_skill(self, record: TaskRecord, workspace: Path, input_dir: Path) -> Dict[str, Any]:
        report_dir = workspace / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        if record.skill_type == "skill-security-audit":
            result = self._run_security_audit(input_dir, report_dir, record.params or {})
        elif record.skill_type == "multichain-contract-vuln":
            result = self._run_contract_audit(input_dir, report_dir, record.params or {})
        else:
            result = self._run_stress_lab(input_dir, report_dir, record.params or {})
        record.report_path  = result.get("report")
        record.summary_path = result.get("summary")
        record.log_path     = result.get("log")
        record.message      = result.get("message", "")
        return result

    def _execute_task(self, task_id: str, workspace: Path, input_dir: Path) -> None:
        try:
            self._set_task_state(task_id, status="running", message="Running…")
            with self._lock:
                record = self._active.get(task_id)
                if not record:
                    record = self._db_get(task_id)
                if not record:
                    raise KeyError("task not found")
                record_copy = self._snapshot(record)
            result = self._run_skill(record_copy, workspace, input_dir)
            self._set_task_state(
                task_id, status="completed",
                message=result.get("message", "Completed."),
                report=result.get("report"),
                summary=result.get("summary"),
                log=result.get("log"),
            )
        except Exception as exc:
            self._set_task_state(task_id, status="failed", message=str(exc))

    # ─────────────── skill runners (unchanged) ───────────────────────────────

    def _run_security_audit(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        script     = self.repo_root / "skills" / "skill-security-audit" / "scripts" / "audit_skill.py"
        report_json = report_dir / "security_audit.json"
        report_md   = report_dir / "security_audit.md"
        log_file    = report_dir / "security_audit.log"
        cmd = ["python3", str(script), "--output", str(report_json), "--markdown", str(report_md)]
        skill_url = params.get("skillUrl", "")
        if skill_url:
            cmd.extend(["--skill-url", skill_url])
        elif code_dir.exists():
            skill_dirs = sorted({str(p.parent) for p in code_dir.rglob("SKILL.md")})
            for t in (skill_dirs or [str(code_dir)]):
                cmd.extend(["--skill-path", t])
        ai_model = os.environ.get("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini")
        cmd.extend(["--ai-model", ai_model])
        if os.environ.get("SKILL_AUDIT_AI_DETAIL", "").lower() in ("1", "true", "yes"):
            cmd.append("--ai-detail")
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)
        summary_data = json.loads(report_json.read_text(encoding="utf-8")) if report_json.exists() else {}
        return {"report": str(report_md), "summary": str(report_json),
                "log": str(log_file), "message": "Skill Security Audit completed.", "details": summary_data}

    def _run_contract_audit(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        if not params.get("evmAddress"):
            _CONTRACT_EXTS  = {".sol", ".vy", ".rs"}
            _MAX_CONTRACT_FILES = 10
            _all_files = [
                f for f in code_dir.rglob("*")
                if f.is_file() and f.suffix.lower() in _CONTRACT_EXTS
                and "__MACOSX" not in f.parts and not f.name.startswith("._")
            ]
            if len(_all_files) > _MAX_CONTRACT_FILES:
                raise RuntimeError(
                    f"ZIP package contains {len(_all_files)} contract files, "
                    f"exceeding the {_MAX_CONTRACT_FILES}-file limit. "
                    "Please reduce the number of files and re-upload."
                )
        script   = self.repo_root / "skills" / "multichain-contract-vuln" / "scripts" / "run_cli.py"
        report_md = report_dir / "contract_audit.md"
        log_file  = report_dir / "contract_audit.log"
        ai_model  = os.environ.get("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini")
        cmd = ["python3", str(script), "--report", str(report_md), "--ai-model", ai_model]
        input_path = params.get("input") or str(code_dir)
        if params.get("evmAddress"):
            cmd.extend(["--evm-address", str(params["evmAddress"])])
            if params.get("network"):
                cmd.extend(["--network", str(params["network"])])
        else:
            cmd.extend(["--input", str(input_path)])
        if params.get("chain"):  cmd.extend(["--chain",  str(params["chain"])])
        if params.get("scope"):  cmd.extend(["--scope",  str(params["scope"])])
        env: Dict[str, str] = {}
        if params.get("etherscanApiKey"):
            env["ETHERSCAN_API_KEY"] = str(params["etherscanApiKey"])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file, env=env)
        summary_json = report_dir / "contract_summary.json"
        summary_json.write_text(json.dumps({
            "report": str(report_md),
            "inputs": {"input": input_path, "evmAddress": params.get("evmAddress"),
                       "network": params.get("network"), "chain": params.get("chain")},
        }, ensure_ascii=False, indent=2))
        audit_msg = "Contract audit completed."
        if report_md.exists():
            try:
                head = report_md.read_text(encoding="utf-8", errors="ignore")[:600]
                if re.search(r"##\s+.*Analysis Failed", head, re.MULTILINE):
                    audit_msg = "Analysis failed."
            except Exception:
                pass
        return {"report": str(report_md), "summary": str(summary_json),
                "log": str(log_file), "message": audit_msg}

    # ─── stress lab (unchanged block) ───────────────────────────────────────

    DANGEROUS_EXTENSIONS = {
        ".sh", ".bash", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".msi", ".dll", ".com", ".scr", ".pif", ".wsf", ".wsh", ".cpl",
    }
    SUSPICIOUS_PATTERNS = [
        (rb"rm\s+-rf\s+/",                  "destructive command: rm -rf /"),
        (rb"curl\s+.*\|\s*(?:ba)?sh",       "remote code execution: curl | sh"),
        (rb"wget\s+.*\|\s*(?:ba)?sh",       "remote code execution: wget | sh"),
        (rb"os\.system\s*\(",               "dangerous call: os.system()"),
        (rb"subprocess\.(?:call|run|Popen)\s*\(", "dangerous call: subprocess"),
        (rb"eval\s*\(\s*compile",           "dangerous call: eval(compile(...))"),
        (rb"/dev/tcp/",                     "reverse shell pattern: /dev/tcp"),
        (rb"bash\s+-i\s+>&\s*/dev/tcp",    "reverse shell pattern"),
        (rb"nc\s+-[elp]",                   "netcat listener/reverse shell"),
        (rb"import\s+ctypes",               "low-level system access: ctypes"),
        (rb"__import__\s*\(\s*['\"]os['\"]\s*\)", "obfuscated import: os"),
    ]
    STRESS_MIN_SECURITY_SCORE = 95
    _PRIMARY_ENTRY_NAMES = [
        "scripts/run_cli.py", "scripts/runner.py", "scripts/main.py",
        "scripts/run.py", "scripts/audit_skill.py", "scripts/audit_scan.py",
        "main.py", "run.py", "__main__.py",
    ]
    _RE_REQUIRED_TRUE    = re.compile(r'add_argument\s*\([^)]*required\s*=\s*True', re.DOTALL)
    _RE_POSITIONAL_ARG   = re.compile(r'add_argument\s*\(\s*["\'](?!-)[^"\']+["\']')
    _RE_MANUAL_REQUIRED  = re.compile(
        r'(?:if\s+not\s+args\.\w+|must\s+provide|parser\.error\s*\(|(?:--\w[\w-]+)\s+is\s+required)',
        re.IGNORECASE,
    )

    def _find_skill_dir(self, code_dir: Path, params: dict) -> Path:
        if params.get("skillDir"):
            return Path(params["skillDir"])
        if code_dir.exists():
            subdirs = [d for d in code_dir.iterdir() if d.is_dir()]
            if subdirs:
                return subdirs[0]
        return code_dir

    def _detect_primary_entry(self, skill_dir: Path) -> str | None:
        for candidate in self._PRIMARY_ENTRY_NAMES:
            if (skill_dir / candidate).is_file():
                return f"python3 {{skill}}/{candidate}"
        return None

    def _has_mandatory_args(self, script_path: Path) -> bool:
        try:
            source = script_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return True
        if self._RE_REQUIRED_TRUE.search(source):  return True
        if self._RE_POSITIONAL_ARG.search(source):  return True
        if self._RE_MANUAL_REQUIRED.search(source): return True
        return False

    def _run_security_pre_check(self, code_dir: Path, report_dir: Path) -> dict:
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
                data     = json.loads(Path(summary_path).read_text(encoding="utf-8"))
                score    = int(data.get("overallScore", 0))
                ai_review = data.get("aiReview", empty_ai) or empty_ai
                return {"score": score, "aiReview": ai_review}
            except Exception:
                return {"score": 0, "aiReview": empty_ai}
        return {"score": 0, "aiReview": empty_ai}

    def _run_stress_lab(self, code_dir: Path, report_dir: Path, params: Dict[str, Any]) -> Dict[str, Any]:
        skill_dir = self._find_skill_dir(code_dir, params)
        command   = params.get("command")
        if not command:
            entry = self._detect_primary_entry(skill_dir)
            if not entry:
                raise RuntimeError(
                    "The uploaded Skill package does not contain any executable scripts. "
                    "Stress Test requires a Skill with runnable Python code."
                )
            rel_path    = entry.replace("python3 {skill}/", "")
            script_path = skill_dir / rel_path
            if self._has_mandatory_args(script_path):
                raise RuntimeError(
                    "The current version of Stress Test does not support "
                    "Skills with mandatory arguments yet."
                )
            command = entry

        precheck    = self._run_security_pre_check(code_dir, report_dir)
        audit_score = precheck["score"]
        ai_review   = precheck["aiReview"]
        if audit_score < self.STRESS_MIN_SECURITY_SCORE:
            raise RuntimeError(
                "This Skill contains high-risk operations and is not eligible for stress testing. "
                "Please resolve the security issues before retrying."
            )

        script      = self.repo_root / "skills" / "skill-stress-lab" / "scripts" / "stress_runner.py"
        log_file    = report_dir / "stress_runner.log"
        summary_md  = report_dir / "stress_summary.md"
        metrics_json = report_dir / "stress_metrics.json"
        logs_dir    = report_dir / "runs"
        runs        = max(1, min(100, int(params.get("runs", 10))))
        concurrency = max(1, min(100, int(params.get("concurrency", 1))))
        cmd = [
            "python3", str(script),
            "--command", command,
            "--runs", str(runs),
            "--concurrency", str(concurrency),
            "--log-dir", str(logs_dir),
            "--summary-report", str(summary_md),
            "--skill-dir", str(skill_dir),
        ]
        if params.get("openaiUsageFile"): cmd.extend(["--openai-usage-file", str(params["openaiUsageFile"])])
        if params.get("apiCountFile"):    cmd.extend(["--api-count-file",    str(params["apiCountFile"])])
        self._run_command(cmd, cwd=self.repo_root, log_file=log_file)

        enhanced_md = report_dir / "stress_report.md"
        self._generate_stress_lab_report(summary_md, enhanced_md, runs, concurrency, ai_review)

        summary_payload = {"runs": runs, "concurrency": concurrency, "command": command,
                           "summary_md": str(enhanced_md), "metrics_json": str(metrics_json),
                           "logs_dir": str(logs_dir)}
        summary_json = report_dir / "stress_summary.json"
        summary_json.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2))
        return {"report": str(enhanced_md), "summary": str(summary_json),
                "log": str(log_file), "message": "Stress test completed"}

    def _generate_stress_lab_report(self, summary_md: Path, output_md: Path, runs: int, concurrency: int, ai_review: dict | None = None) -> None:
        original = summary_md.read_text() if summary_md.exists() else ""
        total_runs = runs; successes = 0; avg_duration = p95_duration = min_duration = max_duration = std_deviation = 0.0
        skill_name = "-"; failure_samples: list[str] = []
        m = re.search(r'Total Runs:\s*(\d+)', original);        total_runs    = int(m.group(1))   if m else total_runs
        m = re.search(r'Successes:\s*(\d+)', original);         successes     = int(m.group(1))   if m else successes
        m = re.search(r'Avg Duration:\s*([\d.]+)s', original);  avg_duration  = float(m.group(1)) if m else avg_duration
        m = re.search(r'P95 Duration:\s*([\d.]+)s', original);  p95_duration  = float(m.group(1)) if m else p95_duration
        m = re.search(r'Min Duration:\s*([\d.]+)s', original);  min_duration  = float(m.group(1)) if m else min_duration
        m = re.search(r'Max Duration:\s*([\d.]+)s', original);  max_duration  = float(m.group(1)) if m else max_duration
        m = re.search(r'Std Deviation:\s*([\d.]+)s', original); std_deviation = float(m.group(1)) if m else std_deviation
        m = re.search(r'Skill:\s*(\S+)', original);             skill_name    = m.group(1)         if m else skill_name
        for fm in re.finditer(r'Run #(\d+) exit (\d+), duration ([\d.]+)s(?::\s*(.+))?', original):
            detail = f"Run #{fm.group(1)} (exit {fm.group(2)}, {fm.group(3)}s)"
            reason = (fm.group(4) or "").strip()
            if reason: detail += f": {reason}"
            failure_samples.append(detail)

        failures     = total_runs - successes
        success_rate = successes / total_runs if total_runs > 0 else 0.0
        failure_rate = failures  / total_runs if total_runs > 0 else 0.0
        has_data     = successes > 0 or avg_duration > 0

        if has_data:
            stability_score = int(success_rate * 100)
            d = p95_duration if p95_duration > 0 else avg_duration
            if d <= 1:    performance_score = 100
            elif d <= 10: performance_score = int(90 - (d - 1) * (30 / 9))
            elif d <= 30: performance_score = int(60 - (d - 10))
            elif d <= 60: performance_score = int(40 - (d - 30) * (15 / 30))
            else:         performance_score = max(10, int(25 - (d - 60) * 0.1))
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
            if avg_duration > 0 and p95_duration >= avg_duration:
                ratio = p95_duration / avg_duration
                if   ratio <= 1.5: resource_score = 95
                elif ratio <= 2.0: resource_score = 80
                elif ratio <= 3.0: resource_score = 60
                elif ratio <= 5.0: resource_score = 40
                else:              resource_score = max(10, int(40 - (ratio - 5) * 3))
            elif failure_rate == 0:    resource_score = 90
            elif failure_rate <= 0.1:  resource_score = 80
            elif failure_rate <= 0.3:  resource_score = 60
            elif failure_rate <= 0.5:  resource_score = 40
            else:                      resource_score = max(10, int(40 - failure_rate * 30))
            if   failures == 0:        recovery_score = 100
            elif failure_rate <= 0.1:  recovery_score = 85
            elif failure_rate <= 0.3:  recovery_score = 65
            elif failure_rate <= 0.5:  recovery_score = 45
            else:                      recovery_score = max(10, int(45 - failure_rate * 35))
        else:
            stability_score = performance_score = resource_score = consistency_score = recovery_score = 0

        ai = ai_review or {}
        ai_has_risk = ai.get("status") == "ok" and ai.get("hasRisk", False)
        if ai_has_risk:
            stability_score   = max(0, stability_score   - min(15, ai.get("stabilityRisk",  0) // 4))
            performance_score = max(0, performance_score - min(15, ai.get("privacyRisk",     0) // 4))
            resource_score    = max(0, resource_score    - min(15, ai.get("privilegeRisk",   0) // 4))
            consistency_score = max(0, consistency_score  - min(15, ai.get("integrityRisk",   0) // 4))
            recovery_score    = max(0, recovery_score    - min(15, ai.get("dependencyRisk",  0) // 4))
        overall_score = int((stability_score + performance_score + resource_score + consistency_score + recovery_score) / 5)

        def _rating(s: int) -> str:
            if s >= 80: return "🟢 Excellent"
            if s >= 60: return "🔵 Good"
            if s >= 40: return "🟡 Caution"
            return "🔴 Risk"

        cv         = (std_deviation / avg_duration) if avg_duration > 0 else 0.0
        tail_ratio = (p95_duration / avg_duration)  if avg_duration > 0 and p95_duration >= avg_duration else None
        _AI_RISK   = {"stability":("stabilityRisk","stability risk"),"performance":("privacyRisk","privacy risk"),
                      "resource":("privilegeRisk","privilege risk"),"consistency":("integrityRisk","integrity risk"),
                      "recovery":("dependencyRisk","dependency risk")}
        ai_risk_level = str(ai.get("riskLevel","none")).lower()

        def _ai_deduct(dim: str) -> str:
            if not ai_has_risk: return ""
            field, label = _AI_RISK.get(dim, ("",""))
            raw = ai.get(field, 0); deduct = min(15, raw // 4)
            return (f"security pre-check flagged {label} = {raw}/100 (overall risk level: {ai_risk_level}) → −{deduct} pt(s)"
                    if deduct > 0 else "")

        def _deduction(dim: str) -> str:
            ai_r = _ai_deduct(dim); r = []
            if dim == "stability":
                if failures > 0: r.append(f"{failures}/{total_runs} run(s) failed ({failure_rate*100:.1f}% failure rate)")
            elif dim == "performance":
                d = p95_duration if p95_duration > 0 else avg_duration
                if d > 1:
                    r.append(f"P95={p95_duration:.3f}s > 1 s threshold" if p95_duration > 0 else f"avg={avg_duration:.3f}s > 1 s threshold")
            elif dim == "resource":
                if tail_ratio is not None and tail_ratio > 1.5: r.append(f"P95/avg tail ratio = {tail_ratio:.2f}x")
                elif failure_rate > 0: r.append(f"failure-based fallback: {failure_rate*100:.1f}%")
            elif dim == "consistency":
                if avg_duration > 0 and cv > 0.05: r.append(f"CV = {cv:.3f}")
            elif dim == "recovery":
                if failures > 0: r.append(f"{failures} failure(s)")
            if ai_r: r.append(ai_r)
            return "; ".join(r) if r else ""

        dim_scores = {"stability": stability_score, "performance": performance_score,
                      "resource": resource_score, "consistency": consistency_score, "recovery": recovery_score}
        test_status = "Pass" if failures == 0 and has_data else ("Fail" if has_data else "N/A")
        si = "✅" if test_status == "Pass" else ("❌" if test_status == "Fail" else "⚪")
        lines = [
            "# Skill Stress Lab Report","","## Test Configuration","",
            "| Item | Value |","|------|-------|",
            f"| Test Runs | {total_runs} |",f"| Concurrency | {concurrency} |",f"| Skill | {skill_name} |","",
            "## Performance Metrics","",
            "| Metric | Value | Status |","|--------|-------|--------|",
            f"| **Success Rate** | **{successes}/{total_runs} ({success_rate*100:.1f}%)** | {si} {test_status} |",
            f"| Avg Duration | {avg_duration:.2f}s | {'✅ Pass' if avg_duration <= 10 else '❌ Fail'} |",
            f"| P95 Duration | {p95_duration:.2f}s | {'✅ Pass' if p95_duration <= 30 else '❌ Fail'} |",
            f"| Min Duration | {min_duration:.2f}s | ✅ Pass |",
            f"| Max Duration | {max_duration:.2f}s | {'✅ Pass' if max_duration <= 60 else '❌ Fail'} |",
            f"| Std Deviation | {std_deviation:.2f}s | {'✅ Pass' if std_deviation <= 5 else '❌ Fail'} |","",
            "## Five-Dimension Scores","",
            "| Dimension | Score | Rating | Description |","|-----------|-------|--------|-------------|",
            f"| 🛡️ Stability | {stability_score}/100 | {_rating(stability_score)} | Success rate under concurrent load |",
            f"| ⚡ Performance | {performance_score}/100 | {_rating(performance_score)} | Response time (P95-based) |",
            f"| 💾 Resource | {resource_score}/100 | {_rating(resource_score)} | Resource efficiency under load |",
            f"| 🔄 Consistency | {consistency_score}/100 | {_rating(consistency_score)} | Result repeatability |",
            f"| 🆘 Recovery | {recovery_score}/100 | {_rating(recovery_score)} | Failure tolerance and recovery |","",
            f"**Overall Score: {overall_score}/100** ({_rating(overall_score)})",
        ]
        deduction_lines = []
        dim_labels = {"stability":"🛡️ Stability","performance":"⚡ Performance",
                      "resource":"💾 Resource","consistency":"🔄 Consistency","recovery":"🆘 Recovery"}
        for dim, label in dim_labels.items():
            score = dim_scores[dim]
            if score < 100:
                reason = _deduction(dim)
                deduction_lines.append(
                    f"- **{label} ({score}/100):** {reason}" if reason
                    else f"- **{label} ({score}/100):** scoring cap applied at this tier"
                )
        if deduction_lines:
            lines += ["", "## Score Analysis", ""] + deduction_lines
        if failure_samples:
            lines += ["", "## Failure Details", ""] + [f"- {s}" for s in failure_samples[:5]]
        lines += ["", "*Report auto-generated by Skill Stress Lab*"]
        output_md.write_text("\n".join(lines), encoding="utf-8")
