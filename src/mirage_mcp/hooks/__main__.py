"""Entry point for agent hooks: `python -m mirage_mcp.hooks pre|post [--agent NAME]`.

Kept separate from the main CLI so each tool call imports as little as possible.
"""
import sys

from mirage_mcp.hooks.handler import run


def main(argv: list[str]) -> int:
    event = argv[0] if argv and argv[0] in {"pre", "post"} else "pre"
    hint = argv[argv.index("--agent") + 1] if "--agent" in argv and argv.index("--agent") + 1 < len(argv) else None
    try:
        output = run(event, sys.stdin.read(), hint)
    except Exception as exc:  # A hook must answer; an internal error is reported, never a crash.
        print(f"Elytra hook error: {exc}", file=sys.stderr)
        return 0
    if output:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
