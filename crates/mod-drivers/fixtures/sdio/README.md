# SDIO index fixtures — provenance

These fixtures back `crates/mod-drivers/tests/sdio_catalog.rs`. They contain **index
metadata only** (no driver binaries, no `.7z` packs). They are test fixtures — not
redistributed as part of Cove's product payload.

## Source

`valid_small.bin` is a byte-for-byte copy of one index file from the **26083-era
index set** the project maintainer downloaded from the official SDIO
(`Snappy Driver Installer Origin`) **Update torrent** via an "indexes only"
selective download (104 files, `indexes/SDIO/*.bin`).

| Item | Value |
|---|---|
| Distribution | SDIO_Update torrent (public, BitTorrent v1) |
| Download metadata file SHA-256 | `8b6607e6c7497331f7764ad30caeb2d6a3390ddbf8a665111566920c2dc3e559` |
| Torrent `infohash` (v1) | `2dc164468772eba6f12e01586f94f101c6806558` |
| Downloaded index path (user's set) | `indexes/SDIO/DP_Display_SDIO01_26082.bin` |
| Pack this index covers | `DP_Display_SDIO01_26082.7z` (Display / GPU — AMD/Parsec/Realtek) |

> **Note on artifact identity:** the downloaded 104-file set was verified for
> `SDW`/`0x205` headers and realistic decodable content, but it is **not**
> claimed to be byte-equal to the manifest of the `8b6607…` torrent download:
> that manifest lists `DP_Display_SDIO01_26082.bin` at 7,210 bytes while the
> artifact on disk (and the fixture) is 5,227 bytes. The canonical identity of
> the fixture is its own SHA-256 below. This README therefore records the true
> provenance of the bytes (user's selective index download of the current SDIO
> Update torrent) without asserting piece-level manifest parity that was not
> re-established.

## `valid_small.bin`

- Origin file stem: `DP_Display_SDIO01_26082`
- SHA-256: `C3FD4E3691514FA7921B3B7F7A4FC3B0E50C42A3F7E440EB72317B4D88FA86A4`
- Compressed (on-disk) size: 5,227 bytes
- Decompressed payload: 26,861 bytes
- Format: SDW / version 0x205 / LZMA-alone
- Contents: 4 INF records, 4 manufacturer groups, 272 model rows, 272 HWID rows.
- Concrete decoded expectations (verified): INF[0] path `amd\10x64\ati2mtag...`,
  file `u0202099.inf`, version `32.0.23033.5002`, provider "Advanced Micro Devices,
  Inc.", Class "Display", ClassGuid `{4D36E968-E325-11CE-BFC1-08002BE10318}`,
  CatalogFile `u0202099.cat`, catalog attr `2:10.0`. HWID[0] =
  `PCI\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1` → desc 0 → AMD Radeon 8060S.

## Negative fixtures

Each is derived mechanically from `valid_small.bin` (byte-level corruption). The
original byte values are preserved for the unmodified portions; only the documented
byte is changed so the corruption is reproducible.

| File | Derivation | Expected rejection |
|---|---|---|
| `truncated_header.bin` | `valid_small.bin` truncated to its first 5 bytes | parser rejects: file too short to hold container header (`BadBlockHeader`) |
| `bad_magic.bin` | `valid_small.bin` with byte 0 changed `'S'` → `'X'` | parser rejects: bad magic (`BadMagic`) |
| `corrupt_lzma.bin` | `valid_small.bin` with byte 100 XORed with `0xFF` (`0xc1` → `0x3e`) | LZMA decoder rejects stream (`Decompress`) |

> Note: byte offsets are into the **compressed** on-disk file (offset 0 = first byte of
> the file). The container header occupies bytes 0–7 and the LZMA-alone stream begins
> at byte 8.

## License / usage

These files are consumed at test time only. Cove's runtime does **not** ship them.
They originate from the publicly-distributed SDIO torrent; the SDIO project licenses
its application under GPL-3.0, but index `.bin` files themselves carry no separate
license text (see Tab 2a-2G research report, section 13). Cove neither redistributes
nor republishes them — they exist solely to validate the independent parser.
