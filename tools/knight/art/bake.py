"""Bake the ride into tools/knight/ride.png and ride.json.

Every frame of the timeline in rig.py is drawn by draw.py, rendered by headless Chrome at eight times the
final size, shrunk to the sprite size, and mapped to one palette shared by all frames. Run it after changing
the drawing or the timeline:

    python tools/knight/art/bake.py            chestnut horse (the default)
    python tools/knight/art/bake.py grey       grey horse

It needs Chrome or Chromium, Pillow and numpy. The banner that plays the result needs none of them.
"""
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

import numpy as np
from PIL import Image

import draw
import rig

OUT = Path(__file__).resolve().parent.parent
OVER = 8
COLUMNS = 10
PER_PAGE = 18
BACKDROP = np.array((12, 12, 12), float)
SOLID = 0.36


def chrome():
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit("bake.py needs Chrome or Chromium on the PATH")


def render_page(svgs, tile, columns, folder):
    """Render several SVGs in one browser page and return the screenshot."""
    rows = -(-len(svgs) // columns)
    w, h = tile
    cells = "".join(f'<div style="position:absolute;left:{(i % columns) * w}px;top:{(i // columns) * h}px;width:{w}px;'
                    f'height:{h}px">{s}</div>' for i, s in enumerate(svgs))
    page = Path(folder) / "page.html"
    shot = Path(folder) / "page.png"
    page.write_text(f'<html><body style="margin:0;background:transparent">{cells}</body></html>', encoding="utf-8")
    subprocess.run([chrome(), "--headless", "--no-sandbox", "--log-level=3", "--hide-scrollbars", "--force-device-scale-factor=1",
                    "--default-background-color=00000000", f"--window-size={columns * w},{rows * h}", f"--screenshot={shot}",
                    page.as_uri()], check=True, capture_output=True)
    return Image.open(shot).convert("RGBA")


def frame_times():
    return [min(i / rig.FPS, rig.T_END) for i in range(rig.FRAMES)]


def render_frames(coat):
    w, h = rig.SPRITE
    tile = (w * OVER, h * OVER)
    times = frame_times()
    frames = []
    with tempfile.TemporaryDirectory() as folder:
        for start in range(0, len(times), PER_PAGE):
            part = times[start:start + PER_PAGE]
            svgs = [draw.svg(rig.pose(t), rig.BOX, coat=coat, lod="sprite", uid=f"f{start + i}", size=tile) for i, t in enumerate(part)]
            page = render_page(svgs, tile, 6, folder)
            for i in range(len(part)):
                x0, y0 = (i % 6) * tile[0], (i // 6) * tile[1]
                big = page.crop((x0, y0, x0 + tile[0], y0 + tile[1]))
                frames.append(np.asarray(big.convert("RGBa").resize((w, h), Image.LANCZOS).convert("RGBA"), float))
    return frames


def shared_palette(frames, colours, rounds=40, seed=11):
    """Pick `colours` colours for all frames by k-means and map every solid pixel to one; index 0 is left clear."""
    solid, flat = [], []
    for a in frames:
        alpha = a[..., 3] / 255
        solid.append(alpha >= SOLID)
        flat.append(a[..., :3] * alpha[..., None] + BACKDROP * (1 - alpha[..., None]))
    points = np.concatenate([rgb[m] for rgb, m in zip(flat, solid, strict=True)])
    rng = np.random.default_rng(seed)
    pick = points[rng.choice(len(points), min(60000, len(points)), replace=False)]
    centres = [pick[rng.integers(len(pick))]]
    for _ in range(colours - 1):
        d = np.min(((pick[:, None, :] - np.array(centres)[None]) ** 2).sum(-1), axis=1)
        centres.append(pick[rng.choice(len(pick), p=d / d.sum())])
    cent = np.array(centres)
    for _ in range(rounds):
        label = ((pick[:, None, :] - cent[None]) ** 2).sum(-1).argmin(1)
        for j in range(colours):
            members = pick[label == j]
            if len(members):
                cent[j] = members.mean(0)
    cent = np.clip(np.round(cent), 0, 255)
    cent = cent[np.argsort(-cent.sum(1))]
    indexed = []
    for rgb, m in zip(flat, solid, strict=True):
        nearest = ((rgb[..., None, :] - cent[None, None]) ** 2).sum(-1).argmin(-1) + 1
        indexed.append(np.where(m, nearest, 0).astype(np.uint8))
    return cent.astype(int), indexed


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def write_png(path, pixels, palette):
    """Write an 8-bit indexed PNG with no row filters, so the banner can read it with zlib alone."""
    h, w = pixels.shape
    raw = b"".join(b"\x00" + pixels[y].tobytes() for y in range(h))
    plte = bytes((0, 0, 0)) + b"".join(bytes(int(v) for v in c) for c in palette)
    body = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0)) + chunk(b"PLTE", plte)
            + chunk(b"tRNS", b"\x00") + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
    Path(path).write_bytes(body)
    return len(body)


def positions():
    """Where each frame stands along the track, in pixels from its left end."""
    xs = [round(rig.travelled(t) * rig.PX) for t in frame_times()]
    xs[-1] = rig.TRACK_PX
    return xs


def bake(coat="chestnut", colours=60, out=OUT):
    frames = render_frames(coat)
    palette, indexed = shared_palette(frames, colours)
    w, h = rig.SPRITE
    rows = -(-len(indexed) // COLUMNS)
    sheet = np.zeros((rows * h, COLUMNS * w), np.uint8)
    for i, px in enumerate(indexed):
        sheet[(i // COLUMNS) * h:(i // COLUMNS + 1) * h, (i % COLUMNS) * w:(i % COLUMNS + 1) * w] = px
    size = write_png(Path(out) / "ride.png", sheet, palette)
    meta = {"frame": [w, h], "count": len(indexed), "columns": COLUMNS, "rate": rig.FPS, "cell": [10, 20], "x": positions()}
    Path(out, "ride.json").write_text(json.dumps(meta, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return size, len(indexed), len(palette)


if __name__ == "__main__":
    size, count, colours = bake(sys.argv[1] if len(sys.argv) > 1 else "chestnut")
    print(f"ride.png: {size} bytes, {count} frames, {colours} colours")
