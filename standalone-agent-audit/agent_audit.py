#!/usr/bin/env python3
"""Standalone Agent Audit scanner (thin wrapper around shared core)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIP_SRC = ROOT / "pip_package"
if str(PIP_SRC) not in sys.path:
    sys.path.append(str(PIP_SRC))

from agent_audit_cli.core import run_audit, to_markdown  # noqa: E402


def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone agent audit scanner")
    parser.add_argument("--config", type=Path, required=True, help="配置文件 openclaw.json 的路径")
    parser.add_argument("--memory", type=Path, required=True, help="memory 目录路径")
    parser.add_argument("--logs", type=Path, required=True, help="日志目录路径")
    parser.add_argument("--output", type=Path, default=Path("audit_report.json"), help="JSON 输出路径")
    parser.add_argument("--markdown", type=Path, help="可选的 Markdown 输出路径")
    args = parser.parse_args()

    report = run_audit(args.config, args.memory, args.logs)
    _secure_write(args.output, json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    print(f"✅ JSON 报告已生成：{args.output}")
    if args.markdown:
        _secure_write(args.markdown, to_markdown(report))
        print(f"✅ Markdown 报告已生成：{args.markdown}")


if __name__ == "__main__":
    main()
