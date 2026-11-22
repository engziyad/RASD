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

Under the banner, a knight rides the loading track from its left end to its right end: a horseman
masked in a red shemagh, with agal and a black bisht, his sword raised, on a grey Arabian mare. He
is a picture (sixel), so a terminal that draws pictures, like Windows Terminal, sees him gallop; any
other terminal sees the track fill. --force prints the track alone. The banner itself is the same
with him or without him.
"""
from __future__ import annotations

import argparse
import base64
import functools
import html
import os
import re
import shutil
import sys
import time
import zlib
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
# The knight on the loading track: a horseman masked in a red shemagh under his
# agal, in a black bisht trimmed in gold, his sword raised, on a grey Arabian mare
# in the colours told of Ubayyah, King Abdulaziz's mare: dappled grey, a dark mane
# and tail, a white blaze. He is a picture, not characters: four gallop poses of
# 100 x 100 pixels in 48 colours, sent as sixel images. At the VT340's 10 x 20
# pixel cell, which Windows Terminal draws sixel in, he covers 10 x 5 cells. A
# terminal that does not draw sixel sees the track fill.
# --------------------------------------------------------------------------- #
KNIGHT_PALETTE = (
    "#fcfcfc", "#f1f2f3", "#e4e7ea", "#dbdfe3", "#d2d6da", "#dbd0bf", "#c8ccd0", "#ead099",
    "#bfc3c7", "#b4b7bb", "#cdb1a8", "#e5b965", "#a6abb0", "#b2a09d", "#c79583", "#999fa5",
    "#8f9499", "#a08f86", "#ca9154", "#85898e", "#cf6461", "#977d73", "#787d83", "#af7b37",
    "#6e7277", "#a16155", "#d03f47", "#806b5c", "#63666a", "#936d2f", "#ca232c", "#55575b",
    "#745935", "#8f3c33", "#ab242b", "#484a4e", "#5a4629", "#7b1c20", "#393b40", "#682626",
    "#701317", "#442f21", "#2f3034", "#27272a", "#2e271c", "#361615", "#1d1d1e", "#131314",
)
KNIGHT_SIZE = (100, 100)
KNIGHT_POSES = (
    (  # in the air, her legs gathered under her
        "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"
    ),
    (  # a hind hoof lands and her forehand rises: where she stops
        "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"
    ),
    (  # her forelegs land
        "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"
    ),
    (  # she pushes off
        "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"
        "A+gxrRc="
    ),
)
KNIGHT_REST = 1
CELL = (10, 20)
TRACK, TRACK_AHEAD = SAND, "#4e4e4e"


def banner_width() -> int:
    return max(len(line) for line in render(color=False).splitlines())


@functools.cache
def knight_pixels(pose: int) -> tuple[tuple[int | None, ...], ...]:
    """One pose as rows of palette indices, None where the terminal shows through."""
    width, height = KNIGHT_SIZE
    raw = zlib.decompress(base64.b64decode("".join(KNIGHT_POSES[pose])))
    return tuple(tuple(None if v == 255 else v for v in raw[y * width:(y + 1) * width]) for y in range(height))


def _rle(run: str) -> str:
    """Sixel run-length coding: four or more of one character become !<count><character>."""
    out, i = [], 0
    while i < len(run):
        j = i
        while j < len(run) and run[j] == run[i]:
            j += 1
        out.append(f"!{j - i}{run[i]}" if j - i > 3 else run[i] * (j - i))
        i = j
    return "".join(out)


def sixel(pixels: tuple[tuple[int | None, ...], ...], palette: tuple[str, ...]) -> str:
    """A sixel image of palette-indexed pixels with square pixels (P1=9), clear where a pixel is None (P2=1).
    Palette entry i goes in colour register i + 1: register 0 is the VT340's background."""
    height, width = len(pixels), len(pixels[0])
    out = [f'\033P9;1q"1;1;{width};{height}']
    for i, colour in enumerate(palette, start=1):
        r, g, b = (round(int(colour[k:k + 2], 16) * 100 / 255) for k in (1, 3, 5))
        out.append(f"#{i};2;{r};{g};{b}")
    bands = []
    for top in range(0, height, 6):
        bits: dict[int, list[int]] = {}
        for k, row in enumerate(pixels[top:top + 6]):
            for x, c in enumerate(row):
                if c is not None:
                    bits.setdefault(c, [0] * width)[x] |= 1 << k
        bands.append("$".join(f"#{c + 1}" + _rle("".join(chr(63 + v) for v in bits[c]).rstrip("?")) for c in sorted(bits)))
    out.append("-".join(bands))
    out.append("\033\\")
    return "".join(out)


@functools.cache
def knight_sixel(pose: int, pad: int = 0) -> str:
    """One pose as a sixel image, `pad` clear pixel rows above him so his hooves meet the track."""
    return sixel(((None,) * KNIGHT_SIZE[0],) * pad + knight_pixels(pose), KNIGHT_PALETTE)


def track(filled: int, width: int, color: bool = True) -> str:
    """The loading track: `filled` cells laid behind the rider, then dotted to its end."""
    behind = "▔" * filled
    ahead = "".join("▔" if x % 2 == 0 else " " for x in range(filled, width)).rstrip()
    if not color:
        return behind + ahead
    truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    return "".join(_ansi(c, truecolor) + t + "\033[0m" for t, c in ((behind, TRACK), (ahead, TRACK_AHEAD)) if t)


def reports_sixel(reply: bytes) -> bool:
    """Whether a terminal's primary device attributes (its answer to CSI c) list sixel graphics, 4."""
    found = re.search(rb"\033\[\?([0-9;]*)c", reply)
    return found is not None and b"4" in found.group(1).split(b";")


def _ask_terminal(query: bytes, timeout: float = 0.3) -> bytes:
    """Send a query to the controlling terminal and read its answer, unechoed; nothing if it does not answer."""
    if sys.platform == "win32":
        return b""
    import select
    import termios
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return b""
    reply = b""
    try:
        saved = termios.tcgetattr(fd)
        quiet = termios.tcgetattr(fd)
        quiet[3] &= ~(termios.ICANON | termios.ECHO)
        termios.tcsetattr(fd, termios.TCSANOW, quiet)
        try:
            os.write(fd, query)
            deadline = time.monotonic() + timeout
            while not reply.endswith(b"c"):
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([fd], [], [], left)[0]:
                    break
                chunk = os.read(fd, 256)
                if not chunk:
                    break
                reply += chunk
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, saved)
    except (OSError, termios.error):
        pass
    finally:
        os.close(fd)
    return reply


def pictures() -> bool:
    """Whether this terminal draws sixel images: Windows Terminal does, and others say so when asked."""
    if os.getenv("WT_SESSION"):
        return True
    sys.stdout.flush()
    return reports_sixel(_ask_terminal(b"\033[c"))


def cell_size() -> tuple[int, int]:
    """The pixels of a character cell as the terminal reports them, or the VT340's 10 x 20 when it does not."""
    if sys.platform == "win32" or os.getenv("WT_SESSION"):
        return CELL
    try:
        import fcntl
        import struct
        import termios
        rows, cols, xpix, ypix = struct.unpack("HHHH", fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, bytes(8)))
    except (OSError, ValueError, ImportError):
        return CELL
    return (xpix // cols, ypix // rows) if rows and cols and xpix >= cols and ypix >= rows else CELL


def ride(color: bool = True, animate: bool = True, out: TextIO | None = None, images: bool | None = None,
         cell: tuple[int, int] | None = None, delay: float = 0.025) -> None:
    """The loading track under the banner, and the knight riding it from its left end to its right end.

    He gallops a cell at a time in a terminal that draws sixel images and stops at the end; any other
    terminal sees the track fill. Without animation, as when --force prints into a pipe, the track is
    printed laid out whole."""
    out = out or sys.stdout
    width = banner_width() - 2
    if not animate:
        out.write(f"  {track(width, width, color)}\n\n")
        return
    if shutil.get_terminal_size((0, 0)).columns < width + 2:
        return
    if images is None:
        images = color and pictures()
    cw, ch = cell or (cell_size() if images else CELL)
    rows = -(-KNIGHT_SIZE[1] // ch) if images else 0
    cells = -(-KNIGHT_SIZE[0] // cw) if images else 0
    end = width - cells
    out.write("\n" * rows + f"  {track(cells, width, color)}\n\033[?25l")
    try:
        for x in range(end + 1):
            frame = f"\033[{rows + 1}A\r" + "\033[2K\n" * rows + f"\r  {track(x + cells, width, color)}\033[K\n"
            if images:
                pose = KNIGHT_REST if x == end else (x // 2) % len(KNIGHT_POSES)
                frame += (f"\033[{rows + 1}A\r\033[{2 + x}C\0337{knight_sixel(pose, rows * ch - KNIGHT_SIZE[1])}\0338"
                          f"\033[{rows + 1}B\r")
            out.write(frame)
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
