"""Turn a pose from rig.py into SVG.

Drawing order, back to front: dust, far legs, tail, scabbard, far arm, horse, mane, near legs, tack,
cloak, rider, head, sword, sword arm, reins.
"""
import math

from rig import (COATS, DUTY, FOOTFALL, HIP, INK, NECK, PF, PX, STRIDE, P, add, angle, capsule, clamp, ik, lerp, lock, mix, mul,
                 perp, poly, polar, quad, ribbon, rot, sample, smooth, spline, spread, sub, unit)

TRUNK = [(36, 153), (22, 147), (6, 143), (-12, 143.5), (-30, 146.5), (-48, 150), (-64, 150.5), (-78, 147.5), (-89, 140),
         (-95, 128), (-95, 114), (-89, 103), (-76, 96), (-58, 93), (-42, 95), (-22, 88.5), (2, 84), (26, 84), (44, 86.5),
         (57, 94), (65, 106), (66.5, 119), (61, 131), (51, 143)]
HEAD = [(-4, 0), (0, 4.2), (8, 7.6), (17, 7.0), (28, 2.2), (38, 2.2), (46, 3.4), (51, 1.2), (53.5, -3.5), (51, -8.5),
        (46, -11), (40, -10), (31, -12.5), (22, -17), (13, -20.5), (5, -18), (-1, -10)]
HEAD_SCALE = 1.14
EAR_NEAR = [(0, 3.5), (-2.8, 11), (-1.6, 18), (2.6, 12.5), (4.8, 5.2)]
EAR_FAR = [(-3.2, 2.5), (-6.8, 9.5), (-6.2, 16), (-2, 10.5), (0.6, 4)]
BLANKET = [(-24, 145.5), (-8, 143.5), (12, 144), (30, 150), (35, 128), (34, 106), (22, 101), (0, 100), (-22, 102), (-28, 122)]
SEAT = [(-14, 145), (-11, 153), (-2, 150), (12, 150), (20, 153.5), (24, 158.5), (27.5, 151), (24, 146), (0, 144)]
HOOF = [(-6.0, 0), (5.6, 0), (1.8, 7.6), (-4.6, 6.0)]
CORONET = (-1.5, 6.8)
PASTERN = (-5.0, 8.0)
SWORD = 84.0


def path(d, fill, opacity=1.0, extra=""):
    o = f' opacity="{opacity:.2f}"' if opacity < 1 else ""
    return f'<path d="{d}" fill="{fill}"{o}{extra}/>'


def line(points, stroke, width, opacity=1.0, curve=True, dash=None, cap="round"):
    d = spline(points, closed=False) if curve and len(points) > 2 else "M" + " L".join(P(p) for p in points)
    o = f' opacity="{opacity:.2f}"' if opacity < 1 else ""
    da = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{width:.1f}" stroke-linecap="{cap}" '
            f'stroke-linejoin="round"{o}{da}/>')


def disc(c, r, fill, opacity=1.0):
    o = f' opacity="{opacity:.2f}"' if opacity < 1 else ""
    return f'<circle cx="{c[0]:.1f}" cy="{-c[1]:.1f}" r="{r:.1f}" fill="{fill}"{o}/>'


def oval(c, rx, ry, turn, fill, opacity=1.0):
    o = f' opacity="{opacity:.2f}"' if opacity < 1 else ""
    return (f'<ellipse cx="{c[0]:.1f}" cy="{-c[1]:.1f}" rx="{rx:.1f}" ry="{ry:.1f}" fill="{fill}"{o} '
            f'transform="rotate({-turn:.1f} {c[0]:.1f} {-c[1]:.1f})"/>')


def ring(c, r, n=24):
    return poly([add(c, polar(360 * i / n, r)) for i in range(n)])


def gap(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def hoof_points(end, sole):
    coronet = sub(end, rot(PASTERN, sole))
    return coronet, [add(coronet, rot(sub(p, CORONET), sole)) for p in HOOF]


def leg_shapes(kind, leg):
    """The closed shapes of one leg from the top down, each as (path, part)."""
    top, mid, joint, end = leg["top"], leg["mid"], leg["joint"], leg["end"]
    coronet, hoof = hoof_points(end, leg["sole"])
    d = unit(sub(joint, mid))
    out = []
    if kind == "f":
        out.append((capsule(mix(top, mid, 0.22), mid, 40, 27), "mass"))
        out.append((capsule(mid, joint, 22.5, 12.8), "upper"))
        belly = add(mix(mid, joint, 0.28), mul(perp(d), 3.6))
        out.append((capsule(add(belly, mul(d, -8)), add(belly, mul(d, 10)), 16.5, 11.5), "upper"))
        out.append((capsule(add(joint, mul(d, -3.2)), add(joint, mul(d, 3.4)), 14.2, 13), "knee"))
        out.append((capsule(joint, end, 10, 9.2), "lower"))
        out.append((ring(end, 5.9), "lower"))
    else:
        out.append((capsule(top, mid, 56, 33), "mass"))
        out.append((capsule(mid, joint, 29, 13.5), "upper"))
        calf = add(mix(mid, joint, 0.26), mul(perp(d), -3.4))
        out.append((capsule(add(calf, mul(d, -7)), add(calf, mul(d, 11)), 21, 12.5), "upper"))
        point = add(joint, mul(perp(d), -3.4))
        out.append((capsule(add(point, mul(d, -6.5)), add(point, mul(d, 2)), 9, 9.8), "knee"))
        out.append((ring(joint, 7.5), "knee"))
        out.append((capsule(joint, end, 11.2, 10), "lower"))
        out.append((ring(end, 6.2), "lower"))
    out.append((capsule(end, coronet, 9.8, 9.6), "lower"))
    out.append((poly(hoof), "hoof"))
    return out


def neck_geo(body, nu, arch, head):
    base = body.w((46, 137))
    poll = add(base, polar(nu, NECK))
    end = add(poll, rot((-3, -9), head))
    d = unit(sub(end, base))
    ctrl = add(mix(base, end, 0.48), mul(perp(d), arch))
    spine = [quad(base, ctrl, end, k / 6) for k in range(7)]
    left = [25, 23.5, 20.5, 17, 13.8, 11.4, 10]
    right = [26, 22.5, 18, 14.2, 11.6, 9.8, 8.8]
    crest, dirs = [], []
    for i, p in enumerate(spine):
        dd = unit(sub(spine[min(i + 1, 6)], spine[max(i - 1, 0)]))
        dirs.append(dd)
        crest.append(add(p, mul(perp(dd), left[i] - 1.2)))
    return {"poll": poll, "spine": spine, "path": ribbon(spine, left, right, t=0.5), "crest": crest, "dir": d, "dirs": dirs,
            "right": right}


def sword_shapes(at, ang, upto, ink, small):
    """The sword with its guard at `at`, the blade running along `ang` for `upto` of its length."""
    def sw(p):
        return add(at, rot(p, ang))

    def curve(x):
        return 0.0016 * (x - 4) ** 2

    def half(x):
        return 2.4 if x < 58 else 2.4 * (SWORD - x) / (SWORD - 58)

    out = []
    reach = clamp(upto, 0.0, SWORD)
    if reach > 4:
        xs = [x for x in (3, 20, 40, 58, 72, SWORD) if x < reach] + [reach]
        top = [sw((x, curve(x) + half(x))) for x in xs]
        low = [sw((x, curve(x) - half(x))) for x in reversed(xs)]
        out.append(path(poly(top + low), ink["blade"]))
        out.append(line(low[::-1], ink["blade_lo"], 1.3 if not small else 2.0, curve=False))
    out.append(line([sw((2, -6.5)), sw((2, 6.5))], ink["gold"], 3.6))
    out.append(line([sw((-11, 0)), sw((1, 0))], ink["agal"], 4.8))
    out.append(line([sw((-7, 0)), sw((-5.4, 0))], ink["gold"], 5.2, cap="butt"))
    out.append(line([sw((-12, 0)), sw((-14.5, -3.6))], ink["gold"], 4.2))
    return out


def draw(ps, coat="chestnut", lod="big", uid="k"):
    c, ink = COATS[coat], INK
    body, legs, g, wind, phi = ps["body"], ps["legs"], ps["g"], ps["wind"], ps["phi"]
    w = body.w
    small = lod == "sprite"
    out = []
    defs = [f'<filter id="{uid}b1" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="1.2"/></filter>',
            f'<filter id="{uid}b2" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="2.2"/></filter>',
            f'<filter id="{uid}b4" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="4"/></filter>',
            f'<filter id="{uid}b7" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="7"/></filter>']

    def blur(shape, n):
        return f'<g filter="url(#{uid}b{n})">{shape}</g>'

    neck = neck_geo(body, ps["nu"], ps["arch"], ps["head"])
    poll, head = neck["poll"], ps["head"]

    def hw(p):
        return add(poll, rot(mul(p, HEAD_SCALE), head))

    trunk_d = spline([w(p) for p in TRUNK], closed=True, t=0.6)
    head_d = spline([hw(p) for p in HEAD], closed=True, t=0.55)

    # sand kicked up behind the hooves
    if g > 0.4:
        for leg, base in (("nh", HIP[0]), ("fh", HIP[0]), ("nf", PF[0])):
            age = (phi - FOOTFALL[leg] - DUTY[leg[1]]) % 1.0
            if age < 0.26:
                k = age / 0.26
                x = base - 41 - age * STRIDE
                puffs = "".join(disc((x + dx * (1 + k), dy * (0.5 + 1.5 * k)), rr * (0.5 + 1.1 * k), ink["dust"],
                                     0.5 * (1 - k) * g) for dx, dy, rr in ((0, 4, 5), (-8, 9, 6.5), (6, 11, 4.5)))
                out.append(blur(puffs, 2))

    # far legs
    for leg in ("fh", "ff"):
        for d, part in leg_shapes(leg[1], legs[leg]):
            out.append(path(d, c["hoof"] if part == "hoof" else (c["far_lo"] if part in ("lower", "knee") else c["far"])))

    # tail
    dock = w((-90, 139))
    lift = body.pitch * 0.35
    hang = [(0, 0), (-9, 9), (-20, 8), (-28, -8), (-32, -32), (-33, -58)]
    fly = [(0, 0), (-13, 14), (-34, 22), (-58, 17), (-80, 2), (-97, -20)]

    def tail_spine(shift, drop):
        pts = []
        for i, (a, b) in enumerate(zip(hang, fly, strict=True)):
            p = mix(rot(a, lift), b, wind)
            if i >= 2:
                p = add(p, (0, 3.2 * wind * math.sin(2 * math.pi * (phi * 2 + i * 0.17 + shift)) - drop * (i - 1)))
            pts.append(add(dock, p))
        return sample(pts, 5)

    for shift, drop, widths, col in ((0.35, 3.4, [6, 10, 13, 13, 9, 2], c["mane_lo"]), (0.0, 0.0, [8, 14, 20, 20, 14, 3], c["mane"]),
                                     (0.2, -2.2, [4, 7, 9, 9, 6, 1.5], c["mane_hi"])):
        ts = tail_spine(shift, drop)
        tw = [x / 2 for x in spread(widths, 5)]
        out.append(path(ribbon(ts, tw, tw, t=0.5), col, 1.0 if col != c["mane_hi"] else 0.75))

    # scabbard on the far hip, and the hilt while the sword rests in it
    hip = w((6, 157))
    lean, nod, stage = ps["lean"], ps["nod"], ps["stage"]
    sh = add(hip, polar(90 - lean, 55))
    axis = 13 + 4.0 * math.sin(2 * math.pi * phi) * g + 8 * smooth(ps["r"])
    mouth = add(hip, rot((14, 5), -lean * 0.3))
    sc = [add(mouth, add(polar(axis + 180, k), (0, -0.0010 * k * k))) for k in (0, 20, 42, 64, 86)]
    grip0 = add(mouth, polar(axis, 5.5))
    if stage <= 1.0:
        out.extend(sword_shapes(mouth, axis + 180, 0, ink, small))
    half = [3.4, 3.3, 3.1, 2.7, 1.6]
    out.append(path(ribbon(sc, half, half, t=0.5), ink["scab"]))
    out.append(line([add(p, mul(perp(polar(axis + 180, 1)), -1.2)) for p in sc[:4]], ink["scab_hi"], 1.4, 0.9))
    for k in (0, 1):
        out.append(line([add(sc[k], polar(axis + 90, 3.6)), add(sc[k], polar(axis - 90, 3.6))], ink["gold"], 4.4 if k == 0 else 3.0,
                        cap="butt"))
    out.append(line([add(sc[4], polar(axis + 180, -9)), add(sc[4], polar(axis + 180, 1))], ink["gold"], 4.6))
    out.append(line([add(sc[1], (0, 3)), add(hip, (2, 16))], ink["red_lo"], 1.6))

    # far arm on the reins
    far_sh = add(sh, rot((5, -3), -lean))
    left_hand = add(hip, add(rot((27, 9), -lean * 0.35), (0, 1.5 * math.sin(2 * math.pi * (phi - 0.1)) * g)))
    elbow, hand = ik(far_sh, left_hand, 32, 29, -1)
    out.append(path(capsule(far_sh, elbow, 12, 10), ink["bisht"]))
    out.append(path(capsule(elbow, hand, 9.5, 7.5), ink["thobe_lo"]))
    out.append(disc(hand, 3.9, ink["skin_lo"]))

    # horse: trunk, neck, head, and the masses of the near shoulder and quarter
    near_h, near_f = leg_shapes("h", legs["nh"]), leg_shapes("f", legs["nf"])
    defs.append(f'<clipPath id="{uid}horse"><path d="{trunk_d}"/><path d="{neck["path"]}"/><path d="{head_d}"/>'
                f'<path d="{near_h[0][0]}"/><path d="{near_f[0][0]}"/></clipPath>')
    out.append(path(spline([hw(p) for p in EAR_FAR], closed=True), c["shade"]))
    for d in (trunk_d, neck["path"], head_d, near_h[0][0], near_f[0][0]):
        out.append(path(d, c["base"]))

    sh_out = [f'<g clip-path="url(#{uid}horse)">']

    def soft(shape, n):
        sh_out.append(blur(shape, n))

    hipw, stw = legs["nh"]["top"], legs["nh"]["mid"]
    dq = unit(sub(stw, hipw))
    nq = perp(dq)
    shw, elw = legs["nf"]["top"], legs["nf"]["mid"]
    ds = unit(sub(elw, shw))
    ns = perp(ds)
    sp, nd, nr = neck["spine"], neck["dirs"], neck["right"]

    soft(path(spline([w(p) for p in ((-66, 100), (-34, 92), (0, 87), (30, 87.5), (56, 94), (42, 105), (0, 100.5), (-44, 104))]),
              c["deep"], 0.78), 4)
    soft(path(spline([w(p) for p in ((-84, 148), (-52, 152), (-20, 147), (10, 144.5), (34, 152), (10, 138.5), (-30, 139.5),
                                     (-74, 141))]), c["hi"], 0.62), 4)
    soft(oval(w((-8, 121)), 31, 13, body.pitch, c["light"], 0.7), 7)
    soft(oval(w((-12, 127)), 16, 6, body.pitch, c["hi"], 0.4), 4)
    soft(path(spline([w(p) for p in ((-46, 138), (-39, 115), (-36.5, 99), (-29, 114), (-35, 135))]), c["deep"], 0.34), 4)
    for x in (16, 5, -6):
        soft(line([w((x, 135)), w((x - 4, 104))], c["shade"], 2.8, 0.26), 2)
    # shoulder, arm and breast
    soft(line([w((38, 152)), w((51, 131)), w((62, 113))], c["deep"], 4.4, 0.62), 2)
    soft(oval(add(mix(shw, elw, 0.42), mul(ns, 3)), 12, 20, angle(ds) + 90, c["hi"], 0.55), 4)
    soft(line([add(shw, add(mul(ds, 8), mul(ns, -15))), add(shw, add(mul(ds, 28), mul(ns, -18))), add(elw, mul(ns, -10))],
              c["deep"], 3.8, 0.58), 2)
    soft(line([w((62, 115)), w((55, 100)), w((45, 90))], c["deep"], 3.8, 0.5), 2)
    soft(oval(w((58, 108)), 6, 10, body.pitch - 20, c["light"], 0.5), 4)
    # quarter, stifle and flank
    soft(oval(add(hipw, mul(nq, 5)), 20, 18, 0, c["hi"], 0.62), 7)
    soft(oval(add(hipw, add(mul(dq, -6), mul(nq, 2))), 9, 8, 0, c["hi"], 0.4), 4)
    soft(line([add(hipw, add(mul(dq, -20), mul(nq, -17))), add(hipw, add(mul(dq, 4), mul(nq, -24))), add(stw, mul(nq, -14))],
              c["deep"], 4.0, 0.55), 2)
    soft(line([add(hipw, add(mul(dq, -10), mul(nq, -4))), add(hipw, add(mul(dq, 12), mul(nq, -11))), add(stw, mul(nq, -6))],
              c["shade"], 3.0, 0.4), 2)
    soft(line([add(hipw, add(mul(dq, 0), mul(nq, 24))), add(stw, mul(nq, 15)), add(stw, add(mul(dq, 7), mul(nq, 5)))],
              c["deep"], 3.8, 0.55), 2)
    # neck: the groove under it, the muscle from poll to shoulder, the crest
    under = [add(sp[i], mul(perp(nd[i]), -(nr[i] - 4.6))) for i in range(1, 6)]
    soft(line(under, c["deep"], 3.8, 0.55), 2)
    middle = [add(sp[i], mul(perp(nd[i]), -1.5 + i * 0.5)) for i in range(6)]
    soft(line(middle, c["shade"], 3.0, 0.38), 2)
    soft(line(neck["crest"][1:6], c["hi"], 5.0, 0.62), 4)
    soft(line([sp[0], add(sp[0], mul(perp(neck["dir"]), -21))], c["deep"], 5.5, 0.38), 4)
    # head: muzzle, cheek, the ridge under the eye
    soft(path(spline([hw(p) for p in ((40, 3.5), (51, 1.2), (53.5, -3.5), (51, -8.5), (45, -11), (38, -6))]), c["muzzle"], 0.85), 2)
    soft(line([hw(p) for p in ((8.5, -3), (17.5, -10.5), (13, -19))], c["deep"], 2.8, 0.55), 2)
    soft(line([hw(p) for p in ((20, 0), (30, -2.5), (41, -3.5))], c["hi"], 2.4, 0.6), 2)
    soft(line([hw(p) for p in ((8, 6.6), (19, 5.8), (30, 2.0))], c["hi"], 2.6, 0.6), 2)
    soft(oval(hw((11.5, -11)), 8, 6.5, head, c["light"], 0.5), 4)
    soft(line([hw((24, -14)), hw((36, -11.5))], c["deep"], 2.4, 0.4), 2)
    sh_out.append("</g>")
    out.extend(sh_out)

    out.append(path(spline([hw(p) for p in EAR_NEAR], closed=True), c["base"]))
    out.append(line([hw((0.8, 5)), hw((-0.6, 13.5))], c["deep"], 1.8, 0.65))
    out.append(oval(hw((17.5, 1.8)), 3.3 if not small else 4.0, 2.4 if not small else 3.0, head, c["eye"]))
    if not small:
        out.append(disc(hw((18.4, 2.6)), 0.8, "#ffffff", 0.9))
        out.append(line([hw((13.2, 3.8)), hw((17.5, 4.9)), hw((21.8, 3.3))], c["deep"], 1.2, 0.85))
    out.append(oval(hw((48.6, -1.2)), 2.7, 1.5, head + 28, c["eye"]))
    out.append(line([hw((52.6, -6.4)), hw((45, -7.6))], c["eye"], 1.2, 0.85))

    # bridle
    out.append(line([hw((36.5, 3.0)), hw((38, -10.5))], ink["leather"], 2.0))
    out.append(line([hw((37, -3.5)), hw((16, -4.5)), hw((1.5, 2.5))], ink["leather"], 1.8))
    out.append(line([hw((6, 7.4)), hw((9, -2))], ink["leather"], 1.8))
    bit = hw((43.5, -9.5))
    out.append(disc(bit, 2.3, ink["gold"]))
    throat = hw((9, -18.5))
    for dx, col in ((-2.4, ink["red"]), (0.4, ink["white"]), (3.0, ink["red"])):
        out.append(line([throat, add(throat, (dx, -11))], col, 2.0))
    out.append(disc(throat, 2.2, ink["gold"]))

    # mane: locks from poll to withers, lying down the neck at rest and streaming when she runs
    crest = neck["crest"]
    n = 19
    roots, tips = [], []
    for i in range(n):
        k = i / (n - 1)
        pos = (1 - k) * 6
        a, b = crest[min(int(pos), 5)], crest[min(int(pos) + 1, 6)]
        root = mix(a, b, pos - min(int(pos), 5))
        d0 = unit((-0.30 - 0.12 * k, -1.0))
        d1 = rot((-1.0, 0.14), 7 * math.sin(2 * math.pi * (phi * 2 + i * 0.13)) + 12 - 20 * k)
        dd = unit(mix(d0, d1, wind))
        ln = lerp(25, 42, wind) * (0.6 + 0.48 * math.sin(math.pi * (0.12 + 0.8 * k))) * (1 + 0.10 * math.sin(i * 1.7))
        roots.append(root)
        tips.append(add(root, add(mul(dd, ln), (0, 3.0 * wind * math.sin(2 * math.pi * (phi * 2 + i * 0.2))))))
    inner = [mix(r0, t0, 0.62) for r0, t0 in zip(roots, tips, strict=True)]
    out.append(path(spline(roots + inner[::-1], closed=True, t=0.35), c["mane"]))
    for i in sorted(range(n), key=lambda j: (j % 3 == 1, j)):
        colr = (c["mane"], c["mane_hi"], c["mane_lo"])[i % 3]
        sag = (0, -3.0 + 6.0 * wind)
        root = mix(roots[i], roots[min(i + 1, n - 1)], 0.3)
        midp = add(mix(root, tips[i], 0.5), sag)
        out.append(path(lock([root, midp, tips[i]], 8.5 if i % 3 != 1 else 4.0, 0.4), colr, 1.0 if i % 3 != 1 else 0.7))
    f0 = hw((1.5, 5.0))
    fd = unit(mix(rot((0.9, -0.5), head), rot((-0.9, -0.1), head + 30), wind))
    out.append(path(lock([f0, add(f0, mul(fd, 6)), add(f0, add(mul(fd, 12), (0, -2.5 * wind)))], 6.5), c["mane"]))

    # near legs over the trunk
    for shapes in (near_h, near_f):
        for d, part in shapes[1:]:
            out.append(path(d, c["hoof"] if part == "hoof" else c["base"]))
    for kind, leg in (("h", legs["nh"]), ("f", legs["nf"])):
        mid, joint, end = leg["mid"], leg["joint"], leg["end"]
        dd = unit(sub(joint, mid))
        back = mul(perp(dd), -1.0)
        out.append(blur(line([add(mid, mul(back, 6.5)), add(joint, mul(back, 3.6))], c["shade"], 5.5, 0.6, curve=False), 2))
        d2 = unit(sub(end, joint))
        b2 = mul(perp(d2), -1.0)
        out.append(blur(line([add(joint, mul(b2, 2.6)), add(end, mul(b2, 2.6))], c["shade"], 3.0, 0.6, curve=False), 1))
        out.append(blur(line([add(joint, mul(b2, -2.2)), add(end, mul(b2, -2.2))], c["hi"], 1.6, 0.45, curve=False), 1))
        hi = add(mix(mid, joint, 0.28), mul(perp(dd), 4.4 if kind == "f" else 3.4))
        out.append(blur(line([add(hi, mul(dd, -7)), add(hi, mul(dd, 10))], c["hi"], 3.6, 0.6, curve=False), 2))
        out.append(blur(disc(add(joint, mul(perp(dd), 2.0)), 3.2, c["hi"], 0.4), 1))
        cor, _ = hoof_points(end, leg["sole"])
        out.append(line([add(cor, rot((-3.8, 0.2), leg["sole"])), add(cor, rot((3.6, 1.0), leg["sole"]))], c["deep"], 1.4, 0.85))

    # breast collar, girth, saddle cloth, saddle
    out.append(line([w((30, 133)), w((50, 123)), w((65, 113))], ink["leather"], 2.8))
    for bx, by in ((40, 128), (50, 122.5), (60, 116)):
        q = w((bx, by))
        out.append(line([q, add(q, (0.5 - 2 * wind, -10))], ink["red"], 2.2))
        out.append(disc(q, 1.8, ink["gold"]))
    out.append(line([w((9, 102)), w((10, 85.5))], ink["leather"], 3.2))
    out.append(path(spline([w(p) for p in BLANKET], closed=True, t=0.45), ink["cloth"]))
    out.append(blur(line([w((-20, 140)), w((0, 138)), w((26, 143))], ink["cloth_lo"], 5, 0.6), 2))
    out.append(line([w(p) for p in ((-25.8, 122), (-20.5, 105.6), (0, 103.6), (21, 104.6), (31.6, 108.6), (32.6, 127))], ink["gold"],
                    2.6 if not small else 3.4))
    out.append(line([w(p) for p in ((-22, 122), (-17.5, 109.2), (0, 107.4), (20, 108.4), (28, 111.6), (29, 127))], ink["agal"], 2.0))
    if not small:
        out.append(line([w(p) for p in ((-18.5, 122), (-14.5, 112.6), (0, 111), (19, 112), (24.6, 114.6), (25.6, 127))], ink["white"],
                        1.3, dash="1.6 2.2"))
    for i, bx in enumerate((-19, -9, 1, 11, 21)):
        q = w((bx, 101.5 - (0.6 if i in (0, 4) else 0)))
        out.append(line([q, add(q, (-2.5 * wind, -9))], (ink["red"], ink["agal"])[i % 2], 2.2))
        out.append(disc(q, 1.7, ink["gold"]))
    out.append(path(spline([w(p) for p in SEAT], closed=True, t=0.5), ink["leather"]))
    out.append(line([w((20, 153)), w((24, 158)), w((27, 151.5))], ink["gold"], 2.0))

    # bisht behind the rider
    flutter = [0, 0, 1.5, 3.0, 4.5, 4.5, 3.5, 2.0, 0]
    hang_b = [add(sh, (6, 5)), add(sh, (-12, 4)), add(sh, (-22, -13)), add(hip, (-26, 12)), add(hip, (-40, -8)), add(hip, (-44, -30)),
              add(hip, (-26, -42)), add(hip, (-8, -36)), add(hip, (2, -4))]
    fly_b = [add(sh, (6, 5)), add(sh, (-12, 7)), add(sh, (-40, 11)), add(sh, (-74, 6)), add(sh, (-112, -14)), add(sh, (-96, -27)),
             add(sh, (-72, -25)), add(sh, (-42, -40)), add(hip, (-9, 0))]
    cloak = []
    for i, (a, b) in enumerate(zip(hang_b, fly_b, strict=True)):
        p = mix(a, b, wind)
        cloak.append(add(p, (0, flutter[i] * wind * math.sin(2 * math.pi * (phi * 2 + i * 0.19)))))
    out.append(path(spline(cloak, closed=True, t=0.5), ink["bisht"]))
    out.append(line(cloak[1:5], ink["bisht_hi"], 1.6, 0.95))
    out.append(line(cloak[4:8], ink["gold"], 2.6 if not small else 3.4))
    for a, b, k in ((2, 7, 0.5), (3, 6, 0.45), (3, 5, 0.6)):
        out.append(line([mix(cloak[1], cloak[a], 0.75), mix(cloak[a], cloak[b], k * 0.6), mix(cloak[a], cloak[b], k * 1.5)],
                        ink["bisht_fold"], 2.6, 0.95))

    # rider's near leg
    def lw(q):
        return add(hip, rot(sub(w(q), hip), -0.5 * body.pitch))

    hipb, knee, ankle = (6, 157), (43.5, 130.5), (38.5, 88)
    out.append(line([w((21, 143)), lw((44, 77))], ink["leather"], 1.6, curve=False))
    out.append(path(capsule(lw(hipb), lw(knee), 25, 19), ink["thobe"]))
    out.append(path(capsule(lw(knee), lw(ankle), 16.5, 12.5), ink["thobe"]))
    out.append(line([lw((12, 148.5)), lw((31, 133)), lw((40, 122.5))], ink["thobe_lo"], 2.0, 0.9))
    out.append(line([lw((34.5, 124)), lw((32.5, 105)), lw((34, 91))], ink["thobe_lo"], 1.8, 0.9))
    foot = [lw(q) for q in ((32.5, 88.5), (42, 87.5), (55, 83), (61, 79.2), (60, 76.2), (32.5, 76.5))]
    out.append(path(spline(foot, closed=True, t=0.4), ink["skin"]))
    out.append(line([lw((32, 76.1)), lw((60.5, 75.9))], ink["leather"], 2.4, curve=False))
    out.append(line([lw((46.5, 85.5)), lw((49, 76.8))], ink["leather"], 1.9, curve=False))
    out.append(line([lw((37, 74.2)), lw((54, 74.2))], ink["gold"], 2.1, curve=False))

    # torso: the bisht over the thobe, its gold edge down the front
    up = polar(90 - lean, 1)
    back_n = perp(up)
    tsp = [hip, add(hip, mul(up, 18.5)), add(hip, mul(up, 37)), sh]
    fr = [13, 14, 13.5, 9.5]
    out.append(path(ribbon(tsp, [12, 13.5, 14, 12], fr, t=0.5), ink["bisht"]))
    front = [sub(p, mul(back_n, fr[i])) for i, p in enumerate(tsp)]
    inner_f = [sub(p, mul(back_n, fr[i] - 7.5)) for i, p in enumerate(tsp)]
    out.append(path(spline(front + inner_f[::-1], closed=True, t=0.4), ink["thobe"]))
    out.append(line(inner_f, ink["gold"], 2.8 if not small else 3.6))
    out.append(line([add(p, mul(back_n, 12.4)) for p in tsp[1:]], ink["bisht_hi"], 1.4, 0.9))
    out.append(line([add(sh, rot((-4, -2), -lean)), add(hip, rot((9, 12), -lean))], ink["red_lo"], 1.8, curve=False))

    # the sword arm: reins, hilt, the pull up out of the scabbard, the raise, the wave, the point forward, the salute
    sj = add(sh, rot((1, -3), -lean))
    rein_hand = add(left_hand, (-4, 2))
    high = add(sj, (16, 55))
    stops = [(sub(rein_hand, sj), 0.0), (sub(grip0, sj), 0.0), (sub(high, sj), angle(sub(mouth, high))), ((14, 33), 108.0),
             ((6, 31), 142.0), ((57, -3), 5.0), ((17, 30), 56.0)]
    i0 = int(clamp(math.floor(stage), 0, 5))
    k = smooth(stage - i0)
    target, ang = add(sj, mix(stops[i0][0], stops[i0 + 1][0], k)), lerp(stops[i0][1], stops[i0 + 1][1], k)
    visible = SWORD
    if 1.0 < stage <= 2.0:
        target = quad(grip0, add(sj, (34, 0)), high, k)
        ang = angle(sub(mouth, target))
        visible = gap(target, mouth) - 5.5
    ang += 34 * ps["wave"]
    target = add(target, (5 * ps["wave"], 2.5 * abs(ps["wave"])))
    elbow, hand = ik(sj, target, 33, 29.5, -1)

    # head: the shemagh over the crown, its end drawn across the nose and mouth, the agal over it
    tilt = lean * 0.45 + nod
    hc = add(sh, polar(90 - lean - 0.4 * nod, 21.5))

    def hl(q):
        return add(hc, rot(mul(q, 1.08), -tilt))

    if small:
        cell, bar = 3 / PX, 1 / PX
        defs.append(f'<pattern id="{uid}chk" width="{cell:.4f}" height="{cell:.4f}" patternUnits="userSpaceOnUse">'
                    f'<rect width="{cell:.4f}" height="{cell:.4f}" fill="{ink["white"]}"/>'
                    f'<rect width="{bar:.4f}" height="{cell:.4f}" fill="{ink["red"]}"/>'
                    f'<rect width="{cell:.4f}" height="{bar:.4f}" fill="{ink["red"]}"/></pattern>')
    else:
        cell = 3.0
        defs.append(f'<pattern id="{uid}chk" width="{cell}" height="{cell}" patternUnits="userSpaceOnUse" '
                    f'patternTransform="rotate({tilt:.1f})"><rect width="{cell}" height="{cell}" fill="{ink["white"]}"/>'
                    f'<path d="M0,0 L{cell},{cell} M{cell},0 L0,{cell}" stroke="{ink["red"]}" stroke-width="0.72"/></pattern>')
    chk = f"url(#{uid}chk)"
    hang_d = [(-12.6, 5), (-16, -6), (-19.5, -20), (-20.5, -37), (-11, -45), (0, -42), (2.5, -27), (0.5, -14), (-5, -11.5)]
    fly_d = [(-12.6, 5), (-26, 7.5), (-44, 6.5), (-62, 2), (-77, -7), (-66, -13.5), (-49, -9.5), (-29, -13), (-7, -12)]
    drape = []
    for i, (a, b) in enumerate(zip(hang_d, fly_d, strict=True)):
        q = mix(a, b, wind)
        if 2 <= i <= 6:
            q = add(q, (0, 3.2 * wind * math.sin(2 * math.pi * (phi * 2 + i * 0.23))))
        drape.append(hl(q))
    drape_d = spline(drape, closed=True, t=0.5)
    sway = 7.0 * wind
    panel = [hl(q) for q in ((-3.5, -11), (8.5, -11.5), (12 - sway * 0.3, -21), (10 - sway, -34), (2 - sway, -39.5),
                             (-5 - sway * 0.6, -31), (-5.5, -20))]
    panel_d = spline(panel, closed=True, t=0.5)
    crown = [(11.0, 5.6), (11.3, 8.6), (9.2, 12.8), (4, 15.4), (-2.5, 15.6), (-8.4, 13.3), (-12, 8.6), (-13, 2.4), (-12, -4.5),
             (-9, -10), (-4, -12.6), (2, -9), (4.6, 1.0), (5.0, 5.4)]
    crown_d = spline([hl(q) for q in crown], closed=True, t=0.5)
    mask = [(12.9, 0.5), (14.8, -3.4), (13.2, -6.4), (12.4, -9.4), (9.6, -12.6), (4, -14.8), (-3, -13.6), (-8.5, -9.5), (-10.8, -3),
            (-9.4, 3.4), (-2, 2.6), (5.2, -0.1), (11.3, -0.6)]
    mask_d = spline([hl(q) for q in mask], closed=True, t=0.5)
    peak_d = spline([hl(q) for q in ((6.5, 11.6), (10.6, 12.0), (13.2, 8.6), (11.2, 5.6), (7.5, 6.6))], closed=True, t=0.4)
    for name, d in (("drape", drape_d), ("panel", panel_d), ("crown", crown_d), ("mask", mask_d)):
        defs.append(f'<clipPath id="{uid}{name}"><path d="{d}"/></clipPath>')

    out.append(path(drape_d, chk))
    hem = [drape[2], drape[3], drape[4], drape[5], drape[6]]
    out.append(f'<g clip-path="url(#{uid}drape)">' + line(hem, ink["white"], 7.5) + line(hem, ink["red"], 1.6 if not small else 2.8)
               + blur(line([drape[1], mix(drape[2], drape[7], 0.5), mix(drape[3], drape[6], 0.5)], ink["white_lo"], 3.0, 0.85)
                      + line([mix(drape[0], drape[8], 0.5), mix(drape[1], drape[8], 0.6), mix(drape[2], drape[7], 0.8)],
                             ink["white_lo"], 2.4, 0.7), 1) + "</g>")
    if not small:
        nrm = unit(sub(mix(drape[3], drape[5], 0.5), mix(drape[2], drape[6], 0.5)))
        for kk in range(9):
            q = quad(drape[3], drape[4], drape[5], kk / 8)
            out.append(line([q, add(q, mul(nrm, 3.2))], ink["white"], 0.8, curve=False))
    # the open part of the face: brow, eye, the bridge of the nose
    face = [(11.0, 5.8), (11.7, 3.4), (12.9, 0.5), (11.2, -0.9), (4.6, -0.3), (2.4, 2.6), (4.2, 6.0)]
    if small:
        face = [(11.4, 6.2), (12.3, 3.4), (13.3, 0.2), (11.4, -2.2), (3.4, -1.4), (1.2, 2.8), (3.4, 6.6)]
    out.append(path(spline([hl(q) for q in face], closed=True, t=0.45), ink["skin"]))
    out.append(blur(line([hl((4.2, 1.0)), hl((8.5, 0.2)), hl((11.4, -0.4))], ink["skin_lo"], 1.6, 0.8), 1))
    out.append(line([hl((5.2, 5.0)), hl((8.2, 5.5)), hl((11.0, 4.8))], ink["agal"], 1.7 if not small else 2.1))
    out.append(oval(hl((8.5, 3.0)), 1.9 if not small else 2.2, 1.15 if not small else 1.5, -tilt, ink["agal"]))
    if not small:
        out.append(disc(hl((9.0, 3.3)), 0.45, "#ffffff", 0.85))
    out.append(path(crown_d, chk))
    out.append(f'<g clip-path="url(#{uid}crown)">'
               + blur(line([hl((-10.5, 10)), hl((-14, -2)), hl((-10.5, -10))], ink["white_lo"], 4.6, 0.85)
                      + line([hl((3.6, 5.6)), hl((2.8, 0)), hl((0, -8))], ink["white_lo"], 2.6, 0.7), 1) + "</g>")
    out.append(path(mask_d, chk))
    out.append(f'<g clip-path="url(#{uid}mask)">'
               + blur(line([hl((12.4, -9.6)), hl((6, -14.4)), hl((-4, -13.4))], ink["white_lo"], 4.0, 0.9)
                      + line([hl((13.6, -1.6)), hl((3, -3.4)), hl((-9, 1.0))], ink["white_lo"], 1.8, 0.85)
                      + line([hl((13.6, -6.2)), hl((3, -8.2)), hl((-9, -3.5))], ink["white_lo"], 1.8, 0.8), 1)
               + line([hl((12.9, 0.5)), hl((5.2, -0.1)), hl((-2, 2.6)), hl((-9.4, 3.4))], ink["red_lo"], 0.9 if not small else 1.6, 0.9)
               + "</g>")
    out.append(path(panel_d, chk))
    edge = [panel[2], panel[3], panel[4], panel[5]]
    out.append(f'<g clip-path="url(#{uid}panel)">' + line(edge, ink["white"], 6.5) + line(edge, ink["red"], 1.5 if not small else 2.6)
               + blur(line([panel[0], mix(panel[1], panel[6], 0.5), mix(panel[3], panel[5], 0.5)], ink["white_lo"], 2.6, 0.8), 1)
               + "</g>")
    out.append(path(peak_d, chk))
    out.append(line([hl((11.2, 5.5)), hl((13.2, 8.4))], ink["white_lo"], 1.0, 0.9, curve=False))
    for dy in (0.0, 3.7):
        band = [hl((11.4, 7.4 + dy)), hl((5, 9.4 + dy)), hl((-3, 9.6 + dy)), hl((-12.8, 5.6 + dy))]
        out.append(line(band, ink["agal"], 3.0 if not small else 3.3))
        if not small:
            out.append(line([hl((6, 9.5 + dy)), hl((1, 10.0 + dy)), hl((-5, 9.6 + dy))], ink["agal_hi"], 0.6, 0.8))

    if stage > 1.0:
        out.extend(sword_shapes(add(hand, polar(ang, 5.5)), ang, visible, ink, small))
    out.append(path(capsule(sj, elbow, 14.5, 12), ink["bisht"]))
    cuff = perp(unit(sub(elbow, sj)))
    out.append(line([add(elbow, mul(cuff, 5.5)), add(elbow, mul(cuff, -5.5))], ink["gold"], 2.4 if not small else 3.2, curve=False))
    out.append(path(capsule(elbow, hand, 10.8, 8.6), ink["thobe"]))
    out.append(disc(hand, 4.7, ink["skin"]))

    # reins
    out.append(line([bit, add(mix(bit, left_hand, 0.55), (0, -7 + 3 * g)), left_hand], ink["leather"], 1.5))
    return "<defs>" + "".join(defs) + "</defs>" + "".join(out)


def svg(ps, box, coat="chestnut", lod="big", uid="k", ground=None, size=None):
    x, top, wdt, hgt = box
    body = draw(ps, coat, lod, uid)
    floor = f'<rect x="{x}" y="0" width="{wdt}" height="1.6" fill="{ground}"/>' if ground else ""
    dims = f' width="{size[0]}" height="{size[1]}"' if size else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x} {-top} {wdt} {hgt}"{dims}>{floor}{body}</svg>'
