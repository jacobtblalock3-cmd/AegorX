#!/usr/bin/env python3
"""Generate docs/CLI.md from the live argparse parser.

Run from the repo root:  python scripts/gen_cli_docs.py
The output is committed so drift between code and docs fails review.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.cli import build_parser  # noqa: E402


def _help(obj) -> str:
    return (getattr(obj, "help", None) or getattr(obj, "description", None) or "").strip()


def action_repr(a) -> str:
    if getattr(a, "choices", None):
        return "|".join(str(c) for c in a.choices)
    if a.metavar:
        return str(a.metavar)
    return a.dest.upper()


def emit(parser_obj, prefix: str, lines: list, fallback_help: str = "") -> None:
    title = f"`defentra {prefix}`" if prefix else "`defentra`"
    lines.append(f"## {title}")
    lines.append("")
    h = _help(parser_obj) or fallback_help
    if h:
        lines.append(f"_{h}_")
        lines.append("")

    opts = []
    positional = []
    subcmds = {}
    for a in parser_obj._actions:
        if a.__class__.__name__ == "_SubParsersAction":
            for name, p in a.choices.items():
                subcmds[name] = p
        elif a.option_strings:
            if a.dest == "help":
                continue
            flags = ", ".join(f"`{f}`" for f in a.option_strings)
            opts.append(f"- {flags} `{action_repr(a)}` — {_help(a)}")
        elif a.dest not in ("help",):
            positional.append(f"- `{a.dest.upper()}` — {_help(a)}")

    if subcmds:
        sub_helps = subparser_helps(next(a for a in parser_obj._actions if a.__class__.__name__ == "_SubParsersAction"))
        lines.append(
            "Subcommands: "
            + ", ".join(
                f"[`{prefix} {s}`](#{prefix.replace(' ', '-')}-{s})"
                + (f" — {sub_helps[s]}" if sub_helps.get(s) else "")
                for s in sorted(subcmds)
            )
        )
        lines.append("")
    for line in positional + opts:
        lines.append(line)
    if positional or opts:
        lines.append("")

    for name in sorted(subcmds):
        emit(
            subcmds[name],
            f"{prefix} {name}".strip(),
            lines,
            fallback_help=sub_helps.get(name, "") if subcmds else "",
        )


def subparser_helps(sub_action) -> dict:
    """Map subcommand name -> its help text (argparse keeps it off the parser)."""
    out = {}
    for choice_action in getattr(sub_action, "_choices_actions", []):
        dest = choice_action.dest or choice_action.metavar
        if isinstance(dest, str) and dest:
            out[dest] = (choice_action.help or "").strip()
    return out


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None, help="output path (default: docs/CLI.md)")
    args = ap.parse_args()

    parser = build_parser()
    lines = [
        "# Defentra CLI Reference",
        "",
        "Generated from the argparse tree by `scripts/gen_cli_docs.py` —",
        "do not edit by hand; regenerate instead.",
        "",
    ]

    sub_action = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
    names = sorted(sub_action.choices)
    top_helps = subparser_helps(sub_action)

    lines.append("Commands:")
    lines.append("")
    for name in names:
        anchor = name
        h = _help(sub_action.choices[name]) or top_helps.get(name, "")
        lines.append(f"- [`{name}`](#{anchor}) — {h}")
    lines.append("")

    global_opts = [
        a
        for a in parser._actions
        if a.option_strings and a.dest != "help"
    ]
    if global_opts:
        lines.append("## Global options")
        lines.append("")
        for a in global_opts:
            flags = ", ".join(f"`{f}`" for f in a.option_strings)
            lines.append(f"- {flags} — {_help(a)}")
        lines.append("")

    for name in names:
        if name == "ui":
            lines.append("## `defentra ui`")
            lines.append("")
            h = _help(sub_action.choices[name]) or top_helps.get(name, "")
            lines.append(f"_{h}_")
            lines.append("")
            continue
        emit(sub_action.choices[name], name, lines, fallback_help=top_helps.get(name, ""))

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "docs", "CLI.md"
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")
    print(f"wrote {os.path.normpath(out_path)} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
