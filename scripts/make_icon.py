"""Draw assets/vaultrust.ico: the app icon (a green rounded tile with a dark
padlock, as in src/ui/theme.rs `app_icon`) at every size Windows uses.

    python scripts/make_icon.py
"""
import math
import os

from PIL import Image

GREEN = (0x6F, 0xC2, 0x9B)
INK = (0x12, 0x11, 0x10)
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def draw(n: int) -> Image.Image:
    # Same geometry as theme.rs (designed on a 64 px grid), scaled, with
    # 4x4 supersampling for smooth edges.
    ss = 4
    s = n / 64.0
    img = Image.new("RGBA", (n, n))
    px = img.load()
    c = (n - 1) / 2.0
    for y in range(n):
        for x in range(n):
            cover = ink = 0
            for sy in range(ss):
                for sx in range(ss):
                    fx = x + (sx + 0.5) / ss - 0.5
                    fy = y + (sy + 0.5) / ss - 0.5
                    r = 14 * s
                    dx = abs(fx - c) - (c - r)
                    dy = abs(fy - c) - (c - r)
                    if math.hypot(max(dx, 0), max(dy, 0)) - r > 0:
                        continue
                    cover += 1
                    in_body = abs(fx - c) < 14 * s and c - 4 * s < fy < c + 16 * s
                    ring = math.hypot(fx - c, fy - (c - 6 * s))
                    in_shackle = fy < c - 2 * s and 7 * s <= ring < 11.5 * s
                    in_hole = math.hypot(fx - c, fy - (c + 4 * s)) < 3.5 * s or (
                        abs(fx - c) < 1.6 * s and c + 4 * s < fy < c + 10 * s
                    )
                    if (in_body and not in_hole) or in_shackle:
                        ink += 1
            if cover:
                t = ink / cover
                rgb = tuple(round(g * (1 - t) + k * t) for g, k in zip(GREEN, INK))
                px[x, y] = rgb + (round(255 * cover / (ss * ss)),)
    return img


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "assets", "vaultrust.ico")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    big = draw(256)
    big.save(out, format="ICO", sizes=[(n, n) for n in SIZES],
             append_images=[draw(n) for n in SIZES if n != 256])
    big.save(os.path.join(root, "assets", "vaultrust-256.png"))
    print("wrote", out)
