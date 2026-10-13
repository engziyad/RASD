#!/usr/bin/env python3
"""
banner.py - the RASD signature, in the terminal and as an SVG for the README.

  python tools/banner.py                       print the banner (interactive terminals only)
  python tools/banner.py --force               print even when piped
  python tools/banner.py --svg docs/assets/banner.svg

Hidden automatically in CI, when output is piped, or with NO_BANNER=1.
NO_COLOR=1 prints it without colour. Uses 24-bit colour when the terminal
advertises it (COLORTERM=truecolor), otherwise the nearest 256-colour shade.
The two text lines carry the framework name and its five pillars.
"""
from __future__ import annotations

import argparse
import html
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VERSION  # noqa: E402

IVORY, GOLD, SAND, SILVER, SAGE, GRAY = "#e4dccb", "#d7af87", "#af875f", "#bcbcbc", "#87af87", "#8a8a8a"
XTERM = {IVORY: 187, GOLD: 180, SAND: 137, SILVER: 250, SAGE: 108, GRAY: 245}

# Palm and crossed swords, drawn with quadrant blocks (2x2 pixels per cell).
EMBLEM = [
    [["  ", None], ["▐▙▖", "#87af87"], ["  ", None], ["▗▟▌", "#87af87"], ["  ", None]],
    [["   ", None], ["▝█▖▗█▘", "#87af87"], ["   ", None]],
    [[" ", None], ["▗████████▖", "#87af87"], [" ", None]],
    [["▗▛▟██████▙▜▖", "#87af87"]],
    [["▝▗▌▟▜██▛▙▐▖▘", "#87af87"]],
    [[" ", None], ["▞", "#87af87"], [" ", None], ["▛▐▜▛▌▜", "#87af87"], [" ", None], ["▚", "#87af87"], [" ", None]],
    [[" ", None], ["▘▐▘▝▐▌▘▝▌▝", "#87af87"], [" ", None]],
    [["     ", None], ["▐▌", "#87af87"], ["     ", None]],
    [["▗▟▀▜▙", "#bcbcbc"], ["▐▌", "#87af87"], ["▟▛▀▙▖", "#bcbcbc"]],
    [["▀", "#bcbcbc"], ["   ", None], ["▝▜▛▘", "#bcbcbc"], ["   ", None], ["▀", "#bcbcbc"]],
    [["    ", None], ["▗██▖", "#bcbcbc"], ["    ", None]],
    [["   ", None], ["▗█", "#d7af87"], ["▘▝", "#bcbcbc"], ["█▖", "#d7af87"], ["   ", None]],
    [["  ", None], ["▗█▘", "#d7af87"], ["  ", None], ["▝█▖", "#d7af87"], ["  ", None]],
]

# RASD wordmark
NAME = [
    "█▀▀▄  ▄▀▀▄  ▄▀▀▀  █▀▀▄",
    "█  █  █  █  █     █  █",
    "█▄▄▀  █▀▀█  ▀▀▀▄  █  █",
    "█ ▀▄  █  █     █  █  █",
    "█  █  █  █  ▄▄▄▀  █▄▄▀",
]

# Saudi sword divider: silver blade, gold hilt with chain and curled pommel
SWORD = [
    [["▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄", "#bcbcbc"], ["▄█▄▄▄▄▄▄ ", "#d7af87"]],
    [["  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀", "#bcbcbc"], ["▜▌▖▄▖▖▖▐▛", "#d7af87"]],
]

TAGLINE = "Attack-to-Defense Validation Framework"
PILLARS = ("Red", "Detect", "DFIR", "Intel", "Purple")
COL = 18          # text column, right of the emblem


def pillars() -> list[tuple[str, str]]:
    """Red → Detect → DFIR → Intel → Purple, names in gray and arrows in sand."""
    segs: list[tuple[str, str]] = []
    for i, name in enumerate(PILLARS):
        if i:
            segs.append((" → ", SAND))
        segs.append((name, GRAY))
    return segs


def layout() -> list[list[tuple[str, str | None]]]:
    """Rows of (text, colour) segments, with absolute column placement resolved."""
    right: dict[int, list] = {}
    for k, r in enumerate(NAME):
        right[2 + k] = [(r, IVORY)]
    right[2].extend([("   ", None), (f"v{VERSION.rsplit('.', 1)[0]}", SAND)])
    right[8] = [tuple(s) for s in SWORD[0]]
    right[9] = [tuple(s) for s in SWORD[1]]
    right[10] = [(TAGLINE, IVORY)]
    right[11] = pillars()
    rows = []
    for i, emb in enumerate(EMBLEM):
        segs = [("  ", None)] + [tuple(s) for s in emb]
        width = 2 + sum(len(t) for t, _ in segs[1:])
        if i in right:
            segs.append((" " * (COL - width), None))
            segs.extend(right[i])
        rows.append(segs)
    return rows


def _ansi(hexcol: str | None, truecolor: bool) -> str:
    if not hexcol:
        return ""
    if truecolor:
        r, g, b = (int(hexcol[i:i + 2], 16) for i in (1, 3, 5))
        return f"\033[38;2;{r};{g};{b}m"
    return f"\033[38;5;{XTERM[hexcol]}m"


def render(color: bool = True) -> str:
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    out = [""]
    for row in layout():
        line = "".join((_ansi(c, truecolor) + t + "\033[0m") if (color and c) else t for t, c in row)
        out.append(line.rstrip())
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# SVG export: blocks become crisp rectangles, text stays text
# --------------------------------------------------------------------------- #
QUADS = {"▘": "1000", "▝": "0100", "▖": "0010", "▗": "0001", "▀": "1100", "▄": "0011", "▌": "1010",
         "▐": "0101", "▚": "1001", "▞": "0110", "▛": "1110", "▜": "1101", "▙": "1011", "▟": "0111", "█": "1111"}


def svg() -> str:
    cw, ch, pad = 9.6, 19.2, 22
    pw, ph = cw / 2, ch / 2
    rows = layout()
    cols = max(sum(len(t) for t, _ in r) for r in rows)
    W, H = cols * cw + 2 * pad, len(rows) * ch + 2 * pad
    pixels: dict[tuple[int, int], str] = {}
    texts = []
    for y, row in enumerate(rows):
        x, run, run_x, run_col = 0, "", 0, None
        def flush():
            if run.strip():
                texts.append((run_x, y, run, run_col))
        for text, colr in row:
            for chx in text:
                if chx in QUADS and colr:
                    flush(); run = ""
                    for qi, (dx, dy) in enumerate(((0, 0), (1, 0), (0, 1), (1, 1))):
                        if QUADS[chx][qi] == "1":
                            pixels[(2 * x + dx, 2 * y + dy)] = colr
                elif not (chx == " " and not run):
                    if not run or colr != run_col:
                        flush(); run, run_x, run_col = "", x, colr
                    run += chx
                x += 1
        flush()
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.0f} {H:.0f}" width="{W:.0f}" height="{H:.0f}" '
             f'role="img" aria-label="RASD - Attack-to-Defense Validation Framework">',
             '<rect width="100%" height="100%" rx="14" fill="#0d0d12"/>', '<g shape-rendering="crispEdges">']
    for py in sorted({p[1] for p in pixels}):
        xs = sorted(p[0] for p in pixels if p[1] == py)
        start = prev = xs[0]
        for px in xs[1:] + [None]:
            if px is not None and px == prev + 1 and pixels[(px, py)] == pixels[(start, py)]:
                prev = px
                continue
            parts.append(f'<rect x="{pad + start * pw:.1f}" y="{pad + py * ph:.1f}" width="{(prev - start + 1) * pw:.1f}" '
                         f'height="{ph:.1f}" fill="{pixels[(start, py)]}"/>')
            if px is not None:
                start = prev = px
    parts.append("</g>")
    for tx, ty, run, colr in texts:
        parts.append(f'<text x="{pad + tx * cw:.1f}" y="{pad + ty * ch + ch * 0.72:.1f}" fill="{colr}" '
                     f'font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="15" '
                     f'textLength="{len(run) * cw:.1f}" lengthAdjust="spacingAndGlyphs" xml:space="preserve">{html.escape(run)}</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--svg")
    args = ap.parse_args()
    if args.svg:
        Path(args.svg).parent.mkdir(parents=True, exist_ok=True)
        Path(args.svg).write_text(svg(), encoding="utf-8")
        print(f"[+] {args.svg}")
        return
    if not args.force and (os.getenv("NO_BANNER") == "1" or os.getenv("CI") == "true" or not sys.stdout.isatty()):
        return
    print(render(color=os.getenv("NO_COLOR") is None and (sys.stdout.isatty() or args.force)))


if __name__ == "__main__":
    main()
