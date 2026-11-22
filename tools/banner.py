#!/usr/bin/env python3
"""
banner.py - the RASD signature, in the terminal and as an SVG for the README.

  python tools/banner.py                       print the banner (interactive terminals only)
  python tools/banner.py --force               print even when piped
  python tools/banner.py --svg docs/assets/banner.svg

Hidden automatically in CI, when output is piped, or with NO_BANNER=1.
NO_COLOR=1 prints it without colour. Uses 24-bit colour when the terminal
advertises it (COLORTERM=truecolor), otherwise the nearest 256-colour shade.
The text lines carry the framework name, its three layers (Foundation, Assurance, Decision) and the author credit.

Under the banner, a knight rides the loading track from its left end to its right end: a horseman in
ghutra, agal and bisht on a grey Arabian horse, his sword raised. A terminal sees him gallop; --force
prints him where the ride ends. The banner itself is the same with him or without him.
"""
from __future__ import annotations

import argparse
import html
import os
import shutil
import sys
import time
from pathlib import Path
from typing import TextIO

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VERSION  # noqa: E402

IVORY, GOLD, SAND, SILVER, SAGE, GRAY = "#e4dccb", "#d7af87", "#af875f", "#bcbcbc", "#87af87", "#8a8a8a"
XTERM = {IVORY: 187, GOLD: 180, SAND: 137, SILVER: 250, SAGE: 108, GRAY: 245}

# Palm and crossed swords, drawn with quadrant blocks (2x2 pixels per cell).
EMBLEM: list[list[list]] = [
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
SWORD: list[list[list]] = [
    [["▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄", "#bcbcbc"], ["▄█▄▄▄▄▄▄ ", "#d7af87"]],
    [["  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀", "#bcbcbc"], ["▜▌▖▄▖▖▖▐▛", "#d7af87"]],
]

TAGLINE = "Continuous Detection Assurance Framework"
PILLARS = ("Foundation", "Assurance", "Decision")
COL = 18          # text column, right of the emblem
CREDIT = "By: @ZiyadSOC"


def pillars() -> list[tuple[str, str | None]]:
    """Foundation → Assurance → Decision, names in gray and arrows in sand."""
    segs: list[tuple[str, str | None]] = []
    for i, name in enumerate(PILLARS):
        if i:
            segs.append((" → ", SAND))
        segs.append((name, GRAY))
    return segs


def layout() -> list[list[tuple[str, str | None]]]:
    """Rows of (text, colour) segments, with absolute column placement resolved."""
    right: dict[int, list[tuple[str, str | None]]] = {}
    for k, r in enumerate(NAME):
        right[2 + k] = [(r, IVORY)]
    right[2].extend([("   ", None), (f"v{VERSION.rsplit('.', 1)[0]}", SAND)])
    right[8] = [(s[0], s[1]) for s in SWORD[0]]
    right[9] = [(s[0], s[1]) for s in SWORD[1]]
    right[10] = [(TAGLINE, IVORY)]
    right[11] = pillars()
    right[12] = [(CREDIT, GRAY)]
    rows: list[list[tuple[str, str | None]]] = []
    for i, emb in enumerate(EMBLEM):
        segs: list[tuple[str, str | None]] = [("  ", None), *((s[0], s[1]) for s in emb)]
        width = 2 + sum(len(t) for t, _ in segs[1:])
        if i in right:
            segs.append((" " * (COL - width), None))
            segs.extend(right[i])
        rows.append(segs)
    return rows


def _xterm(hexcol: str) -> int:
    """The 256-colour shade of a colour: the banner's own, or the nearest of the colour cube and the greys."""
    if hexcol in XTERM:
        return XTERM[hexcol]
    rgb = tuple(int(hexcol[i:i + 2], 16) for i in (1, 3, 5))
    steps = (0, 95, 135, 175, 215, 255)

    def nearest(v: int) -> int:
        return min(range(6), key=lambda k: abs(steps[k] - v))
    cube = [nearest(v) for v in rgb]
    grey = min(23, max(0, round((sum(rgb) / 3 - 8) / 10)))

    def distance(shade: tuple[int, ...]) -> int:
        return sum((a - b) ** 2 for a, b in zip(shade, rgb, strict=True))
    if distance(tuple(steps[k] for k in cube)) <= distance((8 + 10 * grey,) * 3):
        return 16 + 36 * cube[0] + 6 * cube[1] + cube[2]
    return 232 + grey


def _ansi(hexcol: str | None, truecolor: bool) -> str:
    if not hexcol:
        return ""
    if truecolor:
        r, g, b = (int(hexcol[i:i + 2], 16) for i in (1, 3, 5))
        return f"\033[38;2;{r};{g};{b}m"
    return f"\033[38;5;{_xterm(hexcol)}m"


def render(color: bool = True) -> str:
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    out = [""]
    for row in layout():
        line = "".join((_ansi(c, truecolor) + t + "\033[0m") if (color and c) else t for t, c in row)
        out.append(line.rstrip())
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# The knight on the loading track. Two gallop poses of 36 x 19 pixels, one letter a
# pixel; the twentieth pixel row is the track. An upper or lower half block makes
# two pixels of one character cell, so his pixels are square.
# --------------------------------------------------------------------------- #
KNIGHT_COLORS = {
    "h": "#d0d0d0", "g": "#949494", "d": "#626262",    # the grey horse, its far side and mane, the hooves
    "w": "#eeeeee", "k": "#1c1c1c", "s": "#d7875f",    # ghutra and thobe, the agal, the face and the hand
    "b": "#8b5e3c", "t": GOLD, "S": "#eeeeee",         # the bisht, its gold zari and the hilt, the blade
    "r": SAND,                                          # dust behind the hooves
}
KNIGHT: tuple[tuple[str, ...], ...] = (
    (
        ".........................SS.........",
        "...............www......SS.h........",
        "..............wkkkk...tS...gh.......",
        "..............wwwwss..st...ghhh.....",
        "............wwwwwws..w....ghhhkh....",
        "............wwwww...w....ghhhhhhh...",
        "...........w...bbbbw....ghhhhhhhhh..",
        "..........w...bbbbbt...ghhhhh.hhhhd.",
        ".............bbbbbbt..ghhhhh...hhdh.",
        "...gg.......bbbbbbbt.ghhhhh.........",
        "..ggggg..hhbbbbbbbthhhhhhh..........",
        ".gg..ggghhhttttttwhhhhhhhhh.........",
        ".......hhhhhhhhhhwhhhhhhhhh.........",
        ".......hhhhhhhhhhhwthhhhhh..........",
        ".........hhhhhhhhhhhhhhh............",
        ".........hh.gg.......gghh...........",
        "........hh...gg......gg.hhh.........",
        ".r.r..hh......gg....gg....hhh.......",
        "..r.dhh.........gd.dd.......hhd.....",
    ),
    (
        ".........................SS.........",
        "...............www......SS.h........",
        "..............wkkkk...tS...gh.......",
        "..............wwwwss..st...ghhh.....",
        "............wwwwwws..w....ghhhkh....",
        "............wwwww...w....ghhhhhhh...",
        "...........w...bbbbw....ghhhhhhhhh..",
        "..........w...bbbbbt...ghhhhh.hhhhd.",
        ".............bbbbbbt..ghhhhh...hhdh.",
        "...gg.......bbbbbbbt.ghhhhh.........",
        "..ggggg..hhbbbbbbbthhhhhhh..........",
        ".gg..ggghhhttttttwhhhhhhhhh.........",
        ".......hhhhhhhhhhwhhhhhhhhh.........",
        ".......hhhhhhhhhhhwthhhhhh..........",
        ".........hhhhhhhhhhhhhhh............",
        ".........hhgg......gg..hh...........",
        "..........hhgg......gg..hh..........",
        "...........hh.gg.....gg.hh..........",
        "............dd.dd.....ddd...........",
    ),
)
KNIGHT_WIDTH = len(KNIGHT[0][0])
RIDE_LINES = (len(KNIGHT[0]) + 1) // 2
TRACK, TRACK_AHEAD = SAND, "#4e4e4e"
Cell = tuple[str, "str | None", "str | None"]


def banner_width() -> int:
    return max(len(line) for line in render(color=False).splitlines())


def knight_cells(x: int, pose: int, width: int) -> list[list[Cell]]:
    """The knight with his left edge at column x of a track `width` cells long, as rows of (character,
    foreground, background) cells. The track is drawn behind him and dotted ahead of him."""
    pixels: list[list[str | None]] = [[None] * width for _ in range(2 * RIDE_LINES)]
    for py, line in enumerate(KNIGHT[pose]):
        for px, ch in enumerate(line):
            if ch != "." and 0 <= x + px < width:
                pixels[py][x + px] = KNIGHT_COLORS[ch]
    for px in range(width):
        if px < x + KNIGHT_WIDTH:
            pixels[-1][px] = TRACK
        elif px % 2 == 0:
            pixels[-1][px] = TRACK_AHEAD
    rows: list[list[Cell]] = []
    for cy in range(RIDE_LINES):
        row: list[Cell] = []
        for px in range(width):
            top, low = pixels[2 * cy][px], pixels[2 * cy + 1][px]
            if top and low:
                row.append(("█", top, None) if top == low else ("▀", top, low))
            elif top or low:
                row.append(("▀", top, None) if top else ("▄", low, None))
            else:
                row.append((" ", None, None))
        rows.append(row)
    return rows


def _sgr(fg: str | None, bg: str | None, truecolor: bool) -> str:
    codes = []
    for hexcol, plane in ((fg, 38), (bg, 48)):
        if hexcol and truecolor:
            r, g, b = (int(hexcol[i:i + 2], 16) for i in (1, 3, 5))
            codes.append(f"{plane};2;{r};{g};{b}")
        elif hexcol:
            codes.append(f"{plane};5;{_xterm(hexcol)}")
    return f"\033[{';'.join(codes)}m" if codes else ""


def knight_lines(x: int, pose: int, width: int, color: bool = True) -> list[str]:
    """The lines of one moment of the ride. Without colour a two-colour cell is a full block."""
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    lines = []
    for row in knight_cells(x, pose, width):
        if not color:
            lines.append("".join("█" if bg else ch for ch, _, bg in row).rstrip())
            continue
        parts, i = [], 0
        while i < len(row):
            j = i
            while j < len(row) and row[j][1:] == row[i][1:]:
                j += 1
            text, (_, fg, bg) = "".join(c[0] for c in row[i:j]), row[i]
            parts.append(_sgr(fg, bg, truecolor) + text + "\033[0m" if fg or bg else text)
            i = j
        lines.append("".join(parts).rstrip())
    return lines


def ride(color: bool = True, animate: bool = True, out: TextIO | None = None, delay: float = 0.035) -> None:
    """The knight rides the loading track from its left end to its right end, under the banner, a column a
    step and his legs changing pose as he goes. A terminal narrower than the banner gets no ride."""
    out = out or sys.stdout
    width = banner_width() - 2
    end = width - KNIGHT_WIDTH
    if not animate:
        out.write("".join(f"  {line}\n" for line in knight_lines(end, 0, width, color)) + "\n")
        return
    if shutil.get_terminal_size((0, 0)).columns < width + 2:
        return
    out.write("\033[?25l")
    try:
        for x in range(end + 1):
            if x:
                out.write(f"\033[{RIDE_LINES}A")
            pose = 0 if x == end else (x // 3) % 2
            out.write("".join(f"\r  {line}\033[K\n" for line in knight_lines(x, pose, width, color)))
            out.flush()
            time.sleep(delay)
    finally:
        out.write("\033[?25h")
        out.flush()
    out.write("\n")


def _enable_vt() -> None:
    """A Windows console draws the colour and cursor codes once its virtual-terminal processing is on."""
    if sys.platform != "win32":
        return
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)


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
    texts: list[tuple[int, int, str, str | None]] = []
    for y, row in enumerate(rows):
        x, run, run_x = 0, "", 0
        run_col: str | None = None
        for text, colr in row:
            for chx in text:
                if chx in QUADS and colr:
                    if run.strip():
                        texts.append((run_x, y, run, run_col))
                    run = ""
                    for qi, (dx, dy) in enumerate(((0, 0), (1, 0), (0, 1), (1, 1))):
                        if QUADS[chx][qi] == "1":
                            pixels[(2 * x + dx, 2 * y + dy)] = colr
                elif not (chx == " " and not run):
                    if not run or colr != run_col:
                        if run.strip():
                            texts.append((run_x, y, run, run_col))
                        run, run_x, run_col = "", x, colr
                    run += chx
                x += 1
        if run.strip():
            texts.append((run_x, y, run, run_col))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.0f} {H:.0f}" width="{W:.0f}" height="{H:.0f}" '
             f'role="img" aria-label="RASD - Continuous Detection Assurance Framework">',
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
        Path(args.svg).write_text(svg(), encoding="utf-8", newline="\n")
        print(f"[+] {args.svg}")
        return
    if not args.force and (os.getenv("NO_BANNER") == "1" or os.getenv("CI") == "true" or not sys.stdout.isatty()):
        return
    color = os.getenv("NO_COLOR") is None and (sys.stdout.isatty() or args.force)
    _enable_vt()
    print(render(color=color))
    ride(color=color, animate=sys.stdout.isatty() and os.getenv("TERM") != "dumb")


if __name__ == "__main__":
    main()
