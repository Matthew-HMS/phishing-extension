#!/usr/bin/env python3
"""Generate Phishing Guard toolbar/store icons (a shield + checkmark).

Renders at high resolution and downscales with LANCZOS for clean edges.
Run: python3 generate_icons.py
"""
import os
from PIL import Image, ImageDraw

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
SIZES = [16, 32, 48, 128]
SS = 8  # supersample factor

GREEN = (32, 138, 76, 255)       # shield fill
GREEN_DARK = (23, 105, 57, 255)  # shield border
WHITE = (255, 255, 255, 255)


def quad_bezier(p0, p1, p2, n=24):
    pts = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0]
        y = mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def shield_points(s):
    """Shield outline as a list of (x, y) on an s x s canvas."""
    def P(x, y):
        return (x * s, y * s)

    pts = [P(0.18, 0.17), P(0.82, 0.17), P(0.82, 0.50)]
    # right side curves down to the bottom point
    pts += quad_bezier(P(0.82, 0.50), P(0.80, 0.80), P(0.50, 0.92))
    # left side back up (mirror)
    pts += quad_bezier(P(0.50, 0.92), P(0.20, 0.80), P(0.18, 0.50))
    return pts


def draw_check(draw, s):
    w = int(0.085 * s)
    pts = [(0.33 * s, 0.52 * s), (0.45 * s, 0.64 * s), (0.69 * s, 0.37 * s)]
    draw.line(pts, fill=WHITE, width=w, joint="curve")
    # round the end caps
    r = w / 2
    for (x, y) in (pts[0], pts[2]):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=WHITE)


def render(size):
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pts = shield_points(s)
    d.polygon(pts, fill=GREEN, outline=GREEN_DARK, width=max(1, int(0.03 * s)))
    draw_check(d, s)
    return img.resize((size, size), Image.LANCZOS)


def main():
    for size in SIZES:
        path = os.path.join(OUT_DIR, f"icon{size}.png")
        render(size).save(path)
        print("wrote", path)


if __name__ == "__main__":
    main()
