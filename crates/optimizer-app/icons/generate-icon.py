"""Regenerate icon.ico from the 512px master with crisp multi-resolution frames.

The Windows titlebar/taskbar pulls the small (16/32px) frame from the .ico. A
single large frame downscaled on the fly by Windows looks blurry, so we bake a
proper frame for each size using Pillow's high-quality resampling.

Run from the icons directory:  python generate-icon.py
"""
from PIL import Image

SRC = "128x128@2x.png"  # 512x512 master (all source PNGs are identical)
OUT = "icon.ico"
SIZES = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

src = Image.open(SRC).convert("RGBA")
src.save(OUT, format="ICO", sizes=SIZES)
print(f"Wrote {OUT} with frames: {', '.join(f'{w}x{h}' for w, h in SIZES)}")
