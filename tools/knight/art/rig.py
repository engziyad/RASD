"""The skeleton and the timeline of the ride.

pose(t) returns every joint of the horse and the rider at time t (seconds). draw.py turns a pose into SVG.
Units are centimetres for a horse 150 cm at the withers. x runs forward, y runs up, the ground is y = 0.
"""
import itertools
import math

STRIDE = 329.0
HIP = (-70.0, 122.0)
PF = (44.0, 138.0)
LU, LF, LC = 49.0, 40.0, 36.0
LFE, LG, LHC = 36.0, 46.0, 40.0
NECK = 84.0
FOOTFALL = {"fh": 0.00, "nh": 0.09, "ff": 0.30, "nf": 0.42}
DUTY = {"f": 84.0 / STRIDE, "h": 86.0 / STRIDE}

COATS = {
    "chestnut": {
        "base": "#ab4d24", "light": "#cf7b42", "hi": "#f2b680", "shade": "#742f14", "deep": "#3f1709",
        "far": "#6b2d16", "far_lo": "#4a1e0e", "mane": "#8a3814", "mane_hi": "#c96f36", "mane_lo": "#57220c",
        "hoof": "#31231d", "muzzle": "#45200f", "eye": "#140905", "sock": None,
    },
    "grey": {
        "base": "#cfd3d7", "light": "#e6e8ea", "hi": "#fafafa", "shade": "#9aa1a8", "deep": "#6c737a",
        "far": "#8b9299", "far_lo": "#636a71", "mane": "#2a2b2f", "mane_hi": "#55585d", "mane_lo": "#17181a",
        "hoof": "#303236", "muzzle": "#4c5055", "eye": "#111113", "sock": None,
    },
}
INK = {
    "thobe": "#f5f2ea", "thobe_lo": "#cbc5b6", "bisht": "#131312", "bisht_hi": "#403d3a", "bisht_fold": "#2a2826",
    "gold": "#d8a83e", "gold_lo": "#99732a", "skin": "#bf8759", "skin_lo": "#8f5f3b",
    "white": "#f7f5f0", "white_lo": "#d7d2c7", "red": "#c2262c", "red_lo": "#8c151b", "agal": "#0b0b0b", "agal_hi": "#3d3d3d",
    "blade": "#e9eef2", "blade_lo": "#97a2ab", "leather": "#4a2414", "scab": "#5c1c1a", "scab_hi": "#8a2d28",
    "strap": "#7d4c27", "wood": "#8a5a2e", "wood_hi": "#bd8a52", "steel": "#5f656e", "steel_hi": "#aeb5be", "beard": "#33241b", "fold": "#6b5a52",
    "cloth": "#a4252a", "cloth_lo": "#6e1418", "dust": "#c9a47a",
}


def add(a, b):
    return (a[0] + b[0], a[1] + b[1])


def sub(a, b):
    return (a[0] - b[0], a[1] - b[1])


def mul(a, k):
    return (a[0] * k, a[1] * k)


def length(a):
    return math.hypot(a[0], a[1])


def unit(a):
    n = length(a) or 1.0
    return (a[0] / n, a[1] / n)


def perp(a):
    return (-a[1], a[0])


def rot(a, deg):
    r = math.radians(deg)
    c, s = math.cos(r), math.sin(r)
    return (a[0] * c - a[1] * s, a[0] * s + a[1] * c)


def polar(deg, r):
    return (r * math.cos(math.radians(deg)), r * math.sin(math.radians(deg)))


def angle(a):
    return math.degrees(math.atan2(a[1], a[0]))


def lerp(a, b, t):
    return a + (b - a) * t


def mix(p, q, t):
    return (lerp(p[0], q[0], t), lerp(p[1], q[1], t))


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def smooth(t):
    t = clamp(t)
    return t * t * (3 - 2 * t)


def ramp(t, t0, t1):
    return smooth((t - t0) / (t1 - t0)) if t1 > t0 else float(t >= t1)


def keys(t, table):
    """Smooth interpolation through (time, value) pairs; values are numbers or tuples."""
    if t <= table[0][0]:
        return table[0][1]
    for (t0, v0), (t1, v1) in itertools.pairwise(table):
        if t <= t1:
            k = smooth((t - t0) / (t1 - t0))
            return mix(v0, v1, k) if isinstance(v0, tuple) else lerp(v0, v1, k)
    return table[-1][1]


def P(p):
    return f"{p[0]:.1f},{-p[1]:.1f}"


def spline(points, closed=True, t=0.5):
    n = len(points)
    segs = n if closed else n - 1
    d = "M" + P(points[0])
    for i in range(segs):
        p0 = points[(i - 1) % n] if (closed or i > 0) else points[i]
        p1 = points[i]
        p2 = points[(i + 1) % n]
        p3 = points[(i + 2) % n] if (closed or i + 2 < n) else points[(i + 1) % n]
        c1 = (p1[0] + (p2[0] - p0[0]) * t / 3, p1[1] + (p2[1] - p0[1]) * t / 3)
        c2 = (p2[0] - (p3[0] - p1[0]) * t / 3, p2[1] - (p3[1] - p1[1]) * t / 3)
        d += f" C{P(c1)} {P(c2)} {P(p2)}"
    return d + (" Z" if closed else "")


def poly(points):
    return "M" + " L".join(P(p) for p in points) + " Z"


def sample(points, steps=6):
    out = []
    n = len(points)
    for i in range(n - 1):
        p0, p1, p2, p3 = points[max(i - 1, 0)], points[i], points[i + 1], points[min(i + 2, n - 1)]
        for k in range(steps):
            u = k / steps
            out.append(tuple(0.5 * (2 * p1[j] + (-p0[j] + p2[j]) * u + (2 * p0[j] - 5 * p1[j] + 4 * p2[j] - p3[j]) * u * u
                                    + (-p0[j] + 3 * p1[j] - 3 * p2[j] + p3[j]) * u ** 3) for j in (0, 1)))
    out.append(points[-1])
    return out


def spread(vals, steps):
    out = []
    for i in range(len(vals) - 1):
        for k in range(steps):
            out.append(lerp(vals[i], vals[i + 1], k / steps))
    out.append(vals[-1])
    return out


def ribbon(spine, left, right, t=0.5):
    """A closed shape along a spine: `left` half-widths on the anticlockwise side, `right` on the other."""
    a, b = [], []
    n = len(spine)
    for i, p in enumerate(spine):
        d = unit(sub(spine[min(i + 1, n - 1)], spine[max(i - 1, 0)]))
        nrm = perp(d)
        a.append(add(p, mul(nrm, left[i])))
        b.append(sub(p, mul(nrm, right[i])))
    return spline(a + b[::-1], closed=True, t=t)


def lock(points, w0, w1=0.4, steps=5):
    s = sample(points, steps)
    n = len(s)
    w = [(w0 + (w1 - w0) * (i / (n - 1)) ** 0.8) / 2 for i in range(n)]
    return ribbon(s, w, w, t=0.4)


def capsule(a, b, wa, wb, n=12):
    d = unit(sub(b, a))
    pts = [add(b, mul(rot(d, 90 - 180 * i / n), wb / 2)) for i in range(n + 1)]
    pts += [add(a, mul(rot(d, -90 - 180 * i / n), wa / 2)) for i in range(n + 1)]
    return poly(pts)


def quad(a, c, b, t):
    return (lerp(lerp(a[0], c[0], t), lerp(c[0], b[0], t), t), lerp(lerp(a[1], c[1], t), lerp(c[1], b[1], t), t))


def ik(a, target, l1, l2, bend):
    """The middle joint of a two-bone chain from a towards target, bent to the anticlockwise side for bend = +1."""
    v = sub(target, a)
    full = length(v) or 1e-6
    d = clamp(full, abs(l1 - l2) + 0.5, l1 + l2 - 0.05)
    u = (v[0] / full, v[1] / full)
    along = (l1 * l1 + d * d - l2 * l2) / (2 * d)
    off = math.sqrt(max(l1 * l1 - along * along, 0.0))
    joint = add(add(a, mul(u, along)), mul(perp(u), bend * off))
    return joint, add(a, mul(u, d))


class Body:
    def __init__(self, hip, pitch):
        self.hip, self.pitch = hip, pitch

    def w(self, p):
        return add(self.hip, rot(sub(p, HIP), self.pitch))

    def b(self, p):
        return add(HIP, rot(sub(p, self.hip), -self.pitch))


PX = 0.34
SPRITE = (140, 120)
BOX = (-70 / PX, 119 / PX, SPRITE[0] / PX, SPRITE[1] / PX)
TRACK_PX = 570
V_FULL = TRACK_PX / PX / 3.575
T_END = 5.6
FPS = 16
FRAMES = 90


def speed(t):
    if t < 1.15:
        return 0.0
    if t < 1.95:
        return V_FULL * (t - 1.15) / 0.80
    if t < 4.85:
        return V_FULL
    if t < 5.40:
        return V_FULL * (5.40 - t) / 0.55
    return 0.0


def travelled(t, dt=0.002):
    x, s = 0.0, 0.0
    while s < t:
        x += speed(s + dt / 2) * dt
        s += dt
    return x


TRAVEL = travelled(T_END)


def gait_target(leg, phi, amp):
    kind = leg[1]
    u = (phi - FOOTFALL[leg]) % 1.0
    d = DUTY[kind]
    land, off, lift, base = (42.0, -42.0, 50.0, PF[0]) if kind == "f" else (46.0, -40.0, 32.0, HIP[0])
    if u < d:
        k = u / d
        x = land + (off - land) * k
        y = 14.5 - 5.0 * math.sin(math.pi * k)
        contact, v = 1.0, 0.0
    else:
        v = (u - d) / (1 - d)
        x = off + (land - off) * smooth(v) - 12.0 * math.sin(math.pi * clamp(v / 0.3)) * (1 - v)
        y = 14.5 + lift * math.sin(math.pi * v ** 0.8) ** 1.15
        contact = 0.0
    return (base + x * amp, lerp(14.5, y, amp)), contact * amp, v


def pose(t):
    t = clamp(t, 0.0, T_END)
    dist = travelled(t)
    r = max(keys(t, [(0.15, 0.0), (0.70, 1.0), (0.95, 1.0), (1.30, 0.0)]), keys(t, [(4.90, 0.0), (5.42, 0.52)]))
    g = min(ramp(t, 1.22, 1.80), 1 - ramp(t, 4.78, 5.30))
    phi = (0.47 + dist / STRIDE) % 1.0
    wind = clamp(speed(t) / V_FULL) * 0.9 + 0.1 * g
    e = smooth(r)
    ef = smooth(clamp(r * 1.25))

    pitch_r, hip_r = 50.0 * e, (HIP[0] - 4.0 * e, HIP[1] - 14.0 * e)
    pitch_g = 4.5 * math.cos(2 * math.pi * (phi - 0.10))
    hip_g = (HIP[0], 119.0 + 4.0 * math.cos(2 * math.pi * (phi - 0.50)))
    body_r = Body(hip_r, pitch_r)
    body = Body(mix(hip_r, hip_g, g), lerp(pitch_r, pitch_g, g))

    stand = {"nh": (-82.0, 14.5), "fh": (-68.0, 14.5), "nf": (40.0, 14.5), "ff": (50.0, 14.5)}
    reared = {"nh": (-66.0, 14.5), "fh": (-57.0, 14.5)}
    tucked = {"nf": (PF[0] + 44.0, PF[1] - 48.0), "ff": (PF[0] + 31.0, PF[1] - 60.0)}
    legs = {}
    for leg in ("fh", "ff", "nh", "nf"):
        kind = leg[1]
        rest = mix(stand[leg], reared[leg], e) if kind == "h" else body_r.w(mix(stand[leg], tucked[leg], ef))
        gt, contact, v = gait_target(leg, phi, 1.0)
        target = mix(rest, gt, g)
        ground = (1 - g) * (1.0 if kind == "h" else 1 - ef) + g * contact
        tb = body.b(target)
        if kind == "f":
            gamma = math.degrees(math.atan2(tb[0] - PF[0], PF[1] - tb[1]))
            alpha = clamp(-9.0 + 0.5 * gamma, -32.0, 52.0)
            top = body.w(PF)
            mid = body.w(add(PF, (LU * math.sin(math.radians(alpha)), -LU * math.cos(math.radians(alpha)))))
            joint, end = ik(mid, target, LF, LC, +1)
        else:
            gamma = math.degrees(math.atan2(tb[0] - HIP[0], HIP[1] - tb[1]))
            beta = clamp(30.0 + 0.5 * gamma, -8.0, 80.0)
            top = body.w(HIP)
            mid = body.w(add(HIP, (LFE * math.sin(math.radians(beta)), -LFE * math.cos(math.radians(beta)))))
            joint, end = ik(mid, target, LG, LHC, -1)
        flex = lerp(0.85 * ef if kind == "f" else 0.0, math.sin(math.pi * clamp(v / 0.75)), g)
        free = angle(sub(end, joint)) + 90.0 - 58.0 * flex
        sole = lerp(free, 0.0, clamp(ground))
        legs[leg] = {"top": top, "mid": mid, "joint": joint, "end": end, "sole": sole, "ground": ground}

    swing = math.sin(2 * math.pi * (phi - 0.35))
    nu = lerp(lerp(60.0, pitch_r + 30.0, e), 38.0 + 4.0 * swing, g)
    arch = lerp(lerp(11.0, 15.0, e), 7.0, g)
    head = lerp(lerp(-57.0, -80.0, e), -30.0 + 3.0 * swing, g)

    lean = lerp(2.0 + 9.0 * e, 5.0 + 2.5 * math.sin(2 * math.pi * (phi - 0.2)), g)
    lean += keys(t, [(3.66, 0.0), (3.90, 9.0), (4.80, 9.0), (5.15, 0.0)])
    nod = keys(t, [(3.66, 0.0), (3.90, 17.0), (4.14, 9.0), (4.80, 9.0), (5.15, 0.0)])
    stage = keys(t, [(2.28, 0.0), (2.60, 1.0), (2.96, 2.0), (3.18, 3.0), (3.70, 3.0), (3.86, 4.0), (4.12, 5.0), (4.85, 5.0),
                     (5.42, 6.0)])
    wave = math.sin(2 * math.pi * (t - 3.18) / 0.28) * ramp(t, 3.14, 3.24) * (1 - ramp(t, 3.62, 3.74))
    return {"t": t, "dist": dist, "phi": phi, "g": g, "r": r, "wind": wind, "body": body, "legs": legs,
            "nu": nu, "arch": arch, "head": head, "lean": lean, "nod": nod, "stage": stage, "wave": wave}
