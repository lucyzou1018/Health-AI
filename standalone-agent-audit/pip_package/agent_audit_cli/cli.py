from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import run_audit, to_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Audit CLI")
    parser.add_argument("--config", type=Path, required=True, help="openclaw.json 路径")
    parser.add_argument("--memory", type=Path, required=True, help="memory 目录")
    parser.add_argument("--logs", type=Path, required=True, help="日志目录")
    parser.add_argument("--output", type=Path, default=Path("audit_report.json"), help="JSON 输出")
    parser.add_argument("--markdown", type=Path, help="Markdown 输出，可选")
    args = parser.parse_args()

    report = run_audit(args.config, args.memory, args.logs)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"✅ JSON 报告：{args.output}")
    if args.markdown:
        args.markdown.write_text(to_markdown(report))
        print(f"✅ Markdown 报告：{args.markdown}")


if __name__ == "__main__":
    main()
