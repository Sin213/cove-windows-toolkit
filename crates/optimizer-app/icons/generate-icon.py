"""Regenerate icon.ico from the 512px master with crisp, Windows-correct frames.

Three things matter for a sharp Windows taskbar/titlebar AND a non-generic NSIS
installer icon:

  1. Render each frame ourselves: Lanczos downscale from the master + a mild
     UnsharpMask on the small sizes to restore edge contrast (a detailed logo
     downscaled with no sharpening goes mushy).
  2. Store the SMALL frames (<=128px) as uncompressed BMP/DIB, not PNG. The
     Windows shell and NSIS's makensis cannot reliably decode PNG-compressed
     small frames -- the shell silently downscales the 256px frame instead
     (blurry taskbar) and NSIS rejects the icon entirely (generic installer
     icon). Only the 256px frame is allowed to be PNG.
  3. Pack the .ico by hand so exactly these frames ship, no encoder surprises.

Run from the icons directory:  python generate-icon.py
"""
import struct
from io import BytesIO
from PIL import Image, ImageFilter

SRC = "128x128@2x.png"  # 512x512 master (all source PNGs are identical)
OUT = "icon.ico"
SIZES = [16, 32, 48, 64, 128, 256]


def bmp_dib(img):
    """Encode an RGBA image as an ICO-flavoured BMP/DIB (32bpp, bottom-up, with a
    zeroed 1bpp AND mask -- transparency comes from the BGRA alpha channel)."""
    w, h = img.size
    bgra = img.tobytes("raw", "BGRA")  # top-down rows
    rb = w * 4
    rows = [bgra[i * rb:(i + 1) * rb] for i in range(h)]
    xor = b"".join(reversed(rows))  # ICO DIBs are bottom-up
    # BITMAPINFOHEADER: biHeight is doubled to cover XOR bitmap + AND mask.
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    and_stride = ((w + 31) // 32) * 4
    and_mask = b"\x00" * (and_stride * h)
    return header + xor + and_mask


master = Image.open(SRC).convert("RGBA")

frames = []
for s in SIZES:
    f = master.resize((s, s), Image.LANCZOS)
    if s <= 64:
        amount = 120 if s <= 32 else 80
        f = f.filter(ImageFilter.UnsharpMask(radius=1.0, percent=amount, threshold=0))
    frames.append((s, f))

payloads = []
for s, f in frames:
    if s >= 256:
        buf = BytesIO()
        f.save(buf, format="PNG")
        payloads.append((s, buf.getvalue()))
    else:
        payloads.append((s, bmp_dib(f)))

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

print(f"Wrote {OUT}: BMP frames {[s for s in SIZES if s < 256]} + PNG 256")
