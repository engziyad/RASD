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

Under the banner runs a loading track, and a knight rides it from left to right: he rears, lands,
gallops, draws his sword, waves it, points it forward and halts at the end. The frames are a sprite
sheet (tools/knight/ride.png) sent as sixel images, so a terminal with sixel graphics, such as Windows
Terminal 1.22 or later, shows the ride; any other terminal shows the track filling. NO_RIDE=1 prints
the finished track with no animation, as does --force when the output is piped. The banner above it does
not change.
"""
from __future__ import annotations

import argparse
import functools
import html
import json
import os
import re
import shutil
import struct
import sys
import time
import zlib
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple, TextIO

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
# The ride on the loading track.
#
# tools/knight/ride.png is an indexed sprite sheet (colour 0 is clear) and
# tools/knight/ride.json gives the frame size, the frame rate and the pixel
# position of every frame along the track. tools/knight/art draws both.
# --------------------------------------------------------------------------- #
KNIGHT = Path(__file__).resolve().parent / "knight"
CELL = (10, 20)
TRACK, TRACK_AHEAD = SAND, "#4e4e4e"
SYNC_ON, SYNC_OFF = "\033[?2026h", "\033[?2026l"


class Ride(NamedTuple):
    size: tuple[int, int]
    columns: int
    rate: int
    x: tuple[int, ...]
    palette: tuple[str, ...]
    rows: tuple[bytes, ...]

    def frame(self, i: int) -> list[bytes]:
        w, h = self.size
        x0, y0 = (i % self.columns) * w, (i // self.columns) * h
        return [row[x0:x0 + w] for row in self.rows[y0:y0 + h]]


def banner_width() -> int:
    return max(len(line) for line in render(color=False).splitlines())


def _unfilter(kind: int, line: bytes, prev: bytes) -> bytes:
    """Undo one PNG row filter, for pixels of one byte."""
    out = bytearray(line)
    for i in range(len(out)):
        left, up, corner = (out[i - 1] if i else 0), prev[i], (prev[i - 1] if i else 0)
        if kind == 1:
            guess = left
        elif kind == 2:
            guess = up
        elif kind == 3:
            guess = (left + up) // 2
        elif kind == 4:
            base = left + up - corner
            dl, du, dc = abs(base - left), abs(base - up), abs(base - corner)
            guess = left if dl <= du and dl <= dc else up if du <= dc else corner
        else:
            raise ValueError(f"unknown PNG filter {kind}")
        out[i] = (out[i] + guess) & 255
    return bytes(out)


def read_png(data: bytes) -> tuple[int, int, list[str], list[bytes]]:
    """Read an 8-bit indexed PNG: width, height, palette as #rrggbb, and one bytes object per pixel row."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    chunks: dict[bytes, bytes] = {}
    idat = []
    pos = 8
    while pos + 8 <= len(data):
        size, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + size]
        if kind == b"IDAT":
            idat.append(body)
        else:
            chunks[kind] = body
        pos += 12 + size
    width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", chunks[b"IHDR"])
    if (depth, colour, interlace) != (8, 3, 0):
        raise ValueError("expected an 8-bit indexed PNG that is not interlaced")
    plte = chunks[b"PLTE"]
    palette = [f"#{plte[i]:02x}{plte[i + 1]:02x}{plte[i + 2]:02x}" for i in range(0, len(plte), 3)]
    raw = zlib.decompress(b"".join(idat))
    stride = width + 1
    if len(raw) != stride * height:
        raise ValueError("PNG pixel data has the wrong length")
    rows: list[bytes] = []
    prev = bytes(width)
    for y in range(height):
        kind, line = raw[y * stride], raw[y * stride + 1:(y + 1) * stride]
        prev = _unfilter(kind, line, prev) if kind else line
        rows.append(prev)
    return width, height, palette, rows


@functools.cache
def load_ride() -> Ride:
    meta = json.loads((KNIGHT / "ride.json").read_text(encoding="utf-8"))
    width, height, palette, rows = read_png((KNIGHT / "ride.png").read_bytes())
    w, h = meta["frame"]
    count, columns = meta["count"], meta["columns"]
    if width != columns * w or height < -(-count // columns) * h or len(meta["x"]) != count:
        raise ValueError("ride.png and ride.json describe different frames")
    return Ride((w, h), columns, meta["rate"], tuple(meta["x"]), tuple(palette), tuple(rows))


@functools.cache
def _only(colour: int) -> bytes:
    """A translation table that keeps one palette index as 1 and turns every other index into 0."""
    return bytes(1 if v == colour else 0 for v in range(256))


def _rle(run: str) -> str:
    """Sixel run-length coding: four or more of one character become !<count><character>."""
    return re.sub(r"(.)\1{3,}", lambda m: f"!{len(m.group(0))}{m.group(1)}", run)


def sixel(rows: Sequence[bytes], palette: Sequence[str], pad: int = 0, top: int = 0) -> str:
    """Encode palette-indexed pixel rows as a sixel image with square pixels. Index 0 stays clear.

    `pad` clear columns are added on the left and `top` clear rows above, to place the picture inside a cell.
    Palette index i uses colour register i; register 0, the VT340's background, is never written."""
    width = len(rows[0])
    rows = [bytes(width)] * top + list(rows)
    out = [f'\033P9;1q"1;1;{width + pad};{len(rows)}']
    for c in sorted(set(b"".join(rows)) - {0}):
        r, g, b = (round(int(palette[c][k:k + 2], 16) * 100 / 255) for k in (1, 3, 5))
        out.append(f"#{c};2;{r};{g};{b}")
    lead = f"!{pad}?" if pad else ""
    floor = int.from_bytes(b"?" * width, "big")
    bands = []
    for y in range(0, len(rows), 6):
        band = rows[y:y + 6]
        parts = []
        for c in sorted(set(b"".join(band)) - {0}):
            bits = 0
            for k, row in enumerate(band):
                bits |= int.from_bytes(row.translate(_only(c)), "big") << k
            run = (bits + floor).to_bytes(width, "big").rstrip(b"?").decode("ascii")
            parts.append(f"#{c}{lead}{_rle(run)}")
        bands.append("$".join(parts))
    out.append("-".join(bands))
    out.append("\033\\")
    return "".join(out)


def track(filled: int, width: int, color: bool = True) -> str:
    """The loading track: `filled` solid cells, then dotted to its end."""
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
    """Whether this terminal draws sixel images.

    Windows Terminal is taken at its word (WT_SESSION is set): it has drawn sixel since version 1.22, and a
    Windows console cannot be asked. Any other terminal is asked for its device attributes."""
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
        import termios
        rows, cols, xpix, ypix = struct.unpack("HHHH", fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, bytes(8)))
    except (OSError, ValueError, ImportError):
        return CELL
    return (xpix // cols, ypix // rows) if rows and cols and xpix >= cols and ypix >= rows else CELL


def ride(color: bool = True, animate: bool = True, out: TextIO | None = None, images: bool | None = None,
         cell: tuple[int, int] | None = None, delay: float | None = None) -> None:
    """Draw the loading track under the banner and play the ride along it.

    With sixel graphics the frames move from the left end of the track to the right end at the rate they were
    drawn for. Without them, or on a screen too short for the frames, the track fills by itself. A terminal
    narrower than the banner gets nothing. With animate off the finished track is printed.
    `delay` replaces the wait between frames; tests pass 0."""
    out = out or sys.stdout
    width = banner_width() - 2
    if not animate:
        out.write(f"  {track(width, width, color)}\n\n")
        return
    screen = shutil.get_terminal_size((0, 0))
    if screen.columns < width + 2:
        return
    if images is None:
        images = color and pictures()
    knight = None
    if images:
        try:
            knight = load_ride()
        except (OSError, ValueError, KeyError, zlib.error):
            knight = None
    cw, ch = cell or (cell_size() if knight else CELL)
    if knight and 0 < screen.lines < -(-knight.size[1] // ch) + 3:
        knight = None
    if knight is None:
        out.write(f"  {track(0, width, color)}\n\033[?25l")
        try:
            for filled in range(width + 1):
                out.write(f"\033[1A\r  {track(filled, width, color)}\033[K\n")
                out.flush()
                time.sleep(0.017 if delay is None else delay)
        finally:
            out.write("\033[?25h")
            out.flush()
        out.write("\n")
        return
    fw, fh = knight.size
    rows = -(-fh // ch)
    top = rows * ch - fh
    span = max(width * cw - fw, 0)
    reach = knight.x[-1] or 1
    last = len(knight.x) - 1
    out.write("\n" * rows + f"  {track(0, width, color)}\n\033[?25l")
    started = time.monotonic()
    try:
        for i, x in enumerate(knight.x):
            col, pad = divmod(x * span // reach, cw)
            filled = width if i == last else min(width, col + fw * 2 // 3 // cw)
            out.write(f"{SYNC_ON}\033[{rows + 1}A\r" + "\033[2K\n" * rows + f"\r  {track(filled, width, color)}\033[K\n"
                      + f"\033[{rows + 1}A\r\033[{2 + col}C\0337{sixel(knight.frame(i), knight.palette, pad, top)}\0338"
                      + f"\033[{rows + 1}B\r{SYNC_OFF}")
            out.flush()
            if delay is None:
                wait = started + (i + 1) / knight.rate - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
            elif delay:
                time.sleep(delay)
    finally:
        out.write(f"{SYNC_OFF}\033[?25h")
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
    try:
        ride(color=color, animate=sys.stdout.isatty() and os.getenv("TERM") != "dumb" and os.getenv("NO_RIDE") != "1")
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
