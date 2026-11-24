"""Command-line interface for scam-lens."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .analyzer import LIKELY_SCAM, NO_KNOWN_RED_FLAGS, SUSPICIOUS, Report, analyze
from .rules import list_packs, load_pack, load_pack_file

_LABEL = {
    NO_KNOWN_RED_FLAGS: "NO KNOWN RED FLAGS (this does not mean it is safe)",
    SUSPICIOUS: "SUSPICIOUS",
    LIKELY_SCAM: "LIKELY A SCAM",
}
_EXIT = {NO_KNOWN_RED_FLAGS: 0, SUSPICIOUS: 1, LIKELY_SCAM: 2}


def format_report(report: Report) -> str:
    lines = [f"Verdict: {_LABEL[report.verdict]}  (score {report.score})", ""]
    if report.findings:
        lines.append("Red flags found:")
        for f in report.findings:
            lines.append(f"  [{f.severity}] {f.title}")
            if f.evidence:
                lines.append(f"      matched: {f.evidence}")
            lines.append(f"      why it matters: {f.explanation}")
        lines.append("")
    else:
        lines += ["No known red flags were found in this message.", ""]
    if report.links:
        lines.append("Links in the message (do not open them to 'check'):")
        lines += [f"  - {u}" for u in report.links]
        lines.append("")
    lines.append(f"Rule packs used: {', '.join(report.packs)}")
    lines.append(report.disclaimer)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scam-lens",
        description="Explain, offline, why a message might be a scam. Nothing is sent over the network.",
    )
    p.add_argument("text", nargs="?", help="the message text (or use --file, or pipe it in on stdin)")
    p.add_argument("-f", "--file", help="read the message from a UTF-8 text file")
    p.add_argument("-p", "--pack", action="append", default=[], metavar="NAME",
                   help="rule pack to use; repeat to combine (default: global)")
    p.add_argument("--pack-file", action="append", default=[], metavar="PATH",
                   help="load an extra rule pack from a JSON file")
    p.add_argument("--list-packs", action="store_true", help="list bundled rule packs and exit")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--version", action="version", version=f"scam-lens {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_packs:
        for name in list_packs():
            print(f"{name}: {load_pack(name).description}")
        return 0

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    elif args.text is not None:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        _build_parser().print_usage(sys.stderr)
        print("error: provide message text, --file, or pipe text on stdin", file=sys.stderr)
        return 64

    try:
        packs = [load_pack(n) for n in (args.pack or ["global"])]
        packs += [load_pack_file(path) for path in args.pack_file]
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 64

    report = analyze(text, packs)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) if args.json else format_report(report))
    return _EXIT[report.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
