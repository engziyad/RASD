# The knight on the loading track

After its banner, `rasd` draws a loading track. In a terminal that shows sixel graphics (Windows Terminal
1.22 or later, for one) a knight rides the track from left to right: the horse rears and lands, breaks into
a gallop, the rider draws his sword, waves it, levels it forward, and reins in at the end. Any other
terminal shows the track filling and nothing else.

The ride is 90 frames kept in `ride.png`, an indexed sprite sheet whose colour 0 is clear. `ride.json`
holds the frame size, the frame rate, and how far along the track each frame stands. `tools/banner.py`
reads both with the standard library and sends each frame as a sixel image.

The frames come from the three scripts in `art/`. `rig.py` is the skeleton and the timeline: it says where
every joint is at a given moment. `draw.py` turns such a pose into SVG. `bake.py` renders every frame in
headless Chrome, shrinks it to 140 by 120 pixels, maps all frames to one palette of 60 colours, and writes
`ride.png` and `ride.json`. To change the drawing, edit `rig.py` or `draw.py` and bake again:

```bash
python tools/knight/art/bake.py
```

Baking needs Chrome or Chromium, Pillow and numpy. Running RASD needs none of them. A test compares
`ride.json` with the timeline in `rig.py`, so frames baked from an older timeline fail the build.

`NO_RIDE=1` prints the finished track without the ride. `NO_BANNER=1` hides the banner and the track
with it.
