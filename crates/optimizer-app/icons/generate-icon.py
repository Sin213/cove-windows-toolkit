"""Regenerate icon.ico from the 512px master with crisp multi-resolution frames.

The Windows titlebar/taskbar pulls the small (16-48px) frame from the .ico. Two
things make those small frames look blurry if you're not careful:

  1. Letting the ICO encoder auto-downscale a single large frame. Quality varies
     and is usually softer than an explicit Lanczos resample.
  2. Downscaling a detailed logo with no sharpening — fine edges (the skull
     outline) go mushy.

So we render each frame ourselves: Lanczos downscale from the master, then a mild
UnsharpMask on the small sizes to restore edge contrast, and pack the frames into
the .ico manually so exactly these images ship (no re-encoding surprises).

Run from the icons directory:  python generate-icon.py
"""
import struct
from io import BytesIO
from PIL import Image, ImageFilter

SRC = "128x128@2x.png"  # 512x512 master (all source PNGs are identical)
OUT = "icon.ico"
SIZES = [16, 32, 48, 64, 128, 256]

src = Image.open(SRC).convert("RGBA")

frames = []
for s in SIZES:
    f = src.resize((s, s), Image.LANCZOS)
    # Restore edge crispness lost in the downscale on the small taskbar/titlebar
    # frames. Larger frames are already sharp and don't need it.
    if s <= 64:
        amount = 120 if s <= 32 else 80
        f = f.filter(ImageFilter.UnsharpMask(radius=1.0, percent=amount, threshold=0))
    frames.append((s, f))

# Pack the ICO by hand: ICONDIR header + one ICONDIRENTRY per frame + PNG payloads.
payloads = []
for s, f in frames:
    buf = BytesIO()
    f.save(buf, format="PNG")
    payloads.append((s, buf.getvalue()))

header = struct.pack("<HHH", 0, 1, len(payloads))
entries = b""
offset = 6 + 16 * len(payloads)
blob = b""
for s, data in payloads:
    w = h = 0 if s == 256 else s  # 0 means 256 in the ICO spec
    entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset)
    blob += data
    offset += len(data)

with open(OUT, "wb") as fh:
    fh.write(header + entries + blob)

print(f"Wrote {OUT} with crisp frames: {', '.join(f'{s}x{s}' for s in SIZES)}")
