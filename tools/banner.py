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
ghutra, agal and a black bisht on a white Arabian horse, his sword raised. He is a picture (sixel), so a
terminal that draws pictures, like Windows Terminal, sees him gallop; any other terminal sees the track
fill. --force prints the track alone. The banner itself is the same with him or without him.
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
# The knight on the loading track: a horseman in ghutra, agal and a black bisht
# trimmed in gold, on a white Arabian horse, his sword raised. He is a picture,
# not characters: two gallop poses of 100 x 80 pixels in 32 colours, sent as sixel
# images. At the VT340's 10 x 20 pixel cell, which Windows Terminal draws sixel in,
# he covers 10 x 4 cells. A terminal that does not draw sixel sees the track fill.
# --------------------------------------------------------------------------- #
KNIGHT_PALETTE = (
    "#fdfdfd", "#f5f6f3", "#f1f1ef", "#eaebeb", "#e3e4e5", "#d8dbdd", "#e5d4c3", "#cbcfd2",
    "#c1c3c5", "#e1c69e", "#b8b7b8", "#e2b96b", "#a4a6a7", "#bc9e8f", "#cd9362", "#939596",
    "#ac8071", "#c08a44", "#828484", "#a7773a", "#717172", "#a2493f", "#846636", "#5d5e5f",
    "#4b4b4c", "#624d2d", "#8d2222", "#393633", "#5a1a16", "#222121", "#151515", "#08080a",
)
KNIGHT_SIZE = (100, 80)
KNIGHT_POSES = (
    (  # galloping with his legs stretched, and where he stops
        "eNrtmel2ozgQRksbErIAsxhh08D7P6WnSgLHbmcxJsyPOaOTjt0k5lLbVyXlev1/fbqKwu96f6ek25VgBchiVwskgG72JBgAZvYk"
        "NBpA7Eq47k+wAHxPQnm9cmD7RvqcC1DVvhWdl2mxs2i0h7zcGXFuz/313Pf9nmacz+0wIqMfpx3tOPfed7h2Y4zT0PRdVbjmfH/Z"
        "X43+NcYwdRXqFECet/fCclXs1xDj5BHAICnztr/rIFYy+3uMBgkAaZnXN0OcEFxy81vhWBhZmd+8ZbXWEov/d+Sl6aax5+SsrCzz"
        "Moa90kppzpIjdxs7HqcoQDXFgEiPvhpmmZdMCsaPksFWkakEMG7GMUDM2J/HyLDSOMY4JBlIvr1pMMmaCSGdcPgyzi3dGMUIkiVm"
        "sJs7H62OIH3jp4jwjGKBCPx2lE7LDTnbW2OdKwprBnJXmyxkLgjBGHCQRwzZW5YMuEb8GidcKCU9vu18b2dPBQRnUqO3TAZiddzp"
        "9riGIb5ZvvfDNGUhl6WRLATDVcAxJAYhzVrAsNw/3Dy+kiVTR7+itBKBwfRVQggJWPZ6QS8GjMu6ocZoXAhGiAUy3NWRISpLsu9E"
        "pbFUsNo6HAiGtj0PFIEnQnjTB0aBBREZQuDn0Q4MSStFVX09G8cMZGF2atu6LGsERc6dPeQo5+lipRmWJS1Bjx6Aok2AVZ+KimMg"
        "VVhSSoEeiPMTguoWu+o4PtgzWRbKpPUp6SNmLD15wTDHjMGQKPgEoSDenRa9Qa0GtXRw5JDfPsxABiRn9GRdl8eMlg0ZcMwIKDMs"
        "lecqEVzhbWdDojVIYR9JSJhIGWZGerC+r+s8FSoxNgtp+OfSNsg75gDVM0ISYC4nIeVMecj0umyH2YxxMnBIDQf8R+ETEP3/50+Q"
        "yCR1TyWiuWQK85wbY6xBpQaGSMx88ejWtjzfMbICSO7pqdSj3LrnSleY5M7Juy1dZVFI0RgRUvLaFNX8XHXdj5HBDhYfioXU5VL9"
        "tCHFzKsqU/xdKyhB2Hlco1hIHWHJxaeypbBMNjlggGc1jJn7bYMD21TGf7rXQ5fhQ2KcsG6Ic7pcypJKxqaHywkNiIwfeyxU/uq+"
        "MpFymYfKJIy40CrLVrNDfTkJJmax+mGnQMLxpRrHuueLYshLXAnwQ3q54NVZ2LfMCRARbF78FBAngWoDyUlSKML1F4aBr34Q1PqG"
        "wNvNjCgfCf1AkA5uGXlgadRRWhlExiUTsbXHqxyqrYxlSbzZcQ7IJSMAxCfgsGUSmWtsMQNb6eUDwkSs8o0MfWdIeODkxsDcEiwq"
        "CRObJsMHZ9HK63qOSU6GRDM2bW6aJ4ZESFmfyrrMOcwMtmkAdR+MOKmht1Kbp+khSROYGRvz6i4eVHb0mmBPJi9xccfY4ixxyyut"
        "moLNSk4v1Jrw5mx7Yt3MULqIjeYuPnD7z5ZCLxaG0nEEsDxME2HYCZupRQPeH9YVRM3DDcaSzIpTu8f+KHzXFFaZqDbvRx3NIFUX"
        "D7v7Ig6TjqasAbt/FGbx9olk6EHCfLpfDX290AEi5LsbQRyRqUOYb87DKmUCRAp40wzqf1zr73zttLEaw4/z2Xtm0IZY/3BuaAhi"
        "JEL4O/WHDpD6x/MJ3Etg8VSYHsytzlu0QukXjkC0CantqI7cOqVSuP3SL30GDfHL2TtuXHA7+lq80XJpXjzCbTAkt2wH23n/kqTj"
        "uKHMyxttdyvSRoH23SuNieobzydWeNasKkE8KsQTAyytNYdRlV51PNZ4r61v9LrzLqvXGEJZ0Xfd2j9gab3yA69lxl/lvvYoZv05"
        "d/W9rP3O0rro9mY0xnu/uyX/BuO/u/4B1/ESTQ=="
    ),
    (  # his legs gathered under him
        "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"
    ),
)
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
    """A sixel image of palette-indexed pixels with square pixels (P1=9), clear where a pixel is None (P2=1)."""
    height, width = len(pixels), len(pixels[0])
    out = [f'\033P9;1q"1;1;{width};{height}']
    for i, colour in enumerate(palette):
        r, g, b = (round(int(colour[k:k + 2], 16) * 100 / 255) for k in (1, 3, 5))
        out.append(f"#{i};2;{r};{g};{b}")
    bands = []
    for top in range(0, height, 6):
        bits: dict[int, list[int]] = {}
        for k, row in enumerate(pixels[top:top + 6]):
            for x, c in enumerate(row):
                if c is not None:
                    bits.setdefault(c, [0] * width)[x] |= 1 << k
        bands.append("$".join(f"#{c}" + _rle("".join(chr(63 + v) for v in bits[c]).rstrip("?")) for c in sorted(bits)))
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
                pose = 0 if x == end else (x // 3) % 2
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
