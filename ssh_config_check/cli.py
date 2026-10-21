import argparse
import json
from pathlib import Path
import sys
from . import __version__
from .analyzer import analyze, read_input

DEMO = """# Fictional teaching example, not a deployment template
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
StrictModes yes
KbdInteractiveAuthentication yes
LogLevel INFO
"""


def terminal_safe(value):
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(value))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline OpenSSH server configuration observations. No automatic changes.")
    parser.add_argument("--version", action="version", version=__version__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path, metavar="FILE", help="Read a file; inspect explicit global options only")
    source.add_argument("--effective", type=Path, metavar="FILE", help="Read previously captured sshd -T output")
    source.add_argument("--demo", action="store_true", help="Analyze a fictional configuration without host inspection")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--strict", action="store_true", help="Exit 2 on UNKNOWN, otherwise 1 on WARN, otherwise 0")
    args = parser.parse_args(argv)
    path = args.config or args.effective
    try:
        result = analyze(DEMO if args.demo else read_input(path),
                         effective=args.effective is not None, source="fictional demo" if args.demo else str(path))
    except (OSError, ValueError) as exc:
        print(f"Cannot analyze input: {terminal_safe(exc)}", file=sys.stderr)
        return 2
    result.update(tool_version=__version__, demo=args.demo)
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(f"ssh-config-check {__version__} | {terminal_safe(result['source'])}")
        print(f"Mode: {result['mode']} | Coverage: partial")
        for item in result["findings"]:
            location = f" (line {item['line']})" if item["line"] else ""
            print(f"\n[{item['status']}] {item['check']}{location}: {terminal_safe(item['value'])}")
            print(f"  Why: {terminal_safe(item['explanation'])}")
            print(f"  Next: {terminal_safe(item['suggestion'])}")
        for note in result["limitations"]:
            print(f"\nScope: {note}")
    if args.strict:
        return 2 if result["summary"].get("UNKNOWN") else 1 if result["summary"].get("WARN") else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
