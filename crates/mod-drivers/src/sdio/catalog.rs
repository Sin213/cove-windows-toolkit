//! SDIO index catalog parser (clean-room, offline-only).
//!
//! Implements the parser for the SDW/0x205 binary index format produced by
//! Snappy Driver Installer Origin (SDIO) r886. See the spec in
//! `crates/mod-drivers/fixtures/sdio/README.md`.
//!
//! This slice does **not** decode the hashtable for lookup. Correctness-first
//! matching is done with an in-memory `HashMap` built from the flat HWID record
//! array; the hashtable is structurally validated (consumed + integrity-checked)
//! but its contents are unused. Hash/APHash logic therefore belongs to a future
//! performance slice. Matching against live Windows devices is Tab 2a-3;
//! everything here is pure parsing + typed lookup of one pack.

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use crate::sdio::Result;
use crate::sdio::error::SdioError;

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

/// On-disk magic identifying an SDW index container.
pub const MAGIC: &[u8; 3] = b"SDW";
/// Accepted (and only) format version at the current SDIO r886 baseline.
pub const FORMAT_VERSION: u32 = 0x205;
/// `MAGIC` (3) + version (4) + flag (1).
pub const CONTAINER_PREFIX_LEN: usize = 8;
/// 1 (props) + 4 (dict size) + 8 (unpacked size) for the LZMA-alone header.
pub const LZMA_ALONE_HEADER_LEN: usize = 13;

// ---------------------------------------------------------------------------
// Parser bounds (normative — fail closed). See Tab 2a-2 spec.
// ---------------------------------------------------------------------------

pub const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_UNCOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_INF_RECORDS: usize = 200_000;
pub const MAX_MANUF_RECORDS: usize = 50_000;
pub const MAX_DESC_RECORDS: usize = 1_500_000;
pub const MAX_HWID_RECORDS: usize = 1_500_000;
pub const MAX_TEXT_POOL_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_STRING_LEN: usize = 4_096;
pub const MAX_PACK_FILENAME_LEN: usize = 256;
/// Bounded allocation guard for a manufacturer's section-name array. Real
/// packs stay well below this; it exists so `sections_n` from the record is
/// never used to size an allocation before a named cap is checked.
pub const MAX_SECTIONS_PER_MANUF: usize = 4_096;

// Fixed element strides of the six logical blocks.
const ELEM_INF: usize = 132;
const ELEM_MANUF: usize = 16;
const ELEM_DESC: usize = 24;
const ELEM_HWID: usize = 12;
const ELEM_HASHITEM: usize = 16;

// Field slots within `DataInfFile::fields` (order is part of the spec).
pub const FIELD_CLASS_GUID: usize = 0;
pub const FIELD_CLASS: usize = 1;
pub const FIELD_PROVIDER: usize = 2;
pub const FIELD_CATALOG_FILE: usize = 3;
pub const FIELD_CATALOG_FILE_NT: usize = 4;
pub const FIELD_CATALOG_FILE_NTX86: usize = 5;
pub const FIELD_CATALOG_FILE_NTIA64: usize = 6;
pub const FIELD_CATALOG_FILE_NTAMD64: usize = 7;
pub const FIELD_DRIVER_VER: usize = 8;
pub const FIELD_DRIVER_PACKAGE_DISPLAY_NAME: usize = 9;

// ---------------------------------------------------------------------------
// Record structs (faithful to the 132/16/24/12 byte layouts).
//
// Record *bytes* live in the decompressed payload; the pool-relative offsets
// stored inside records resolve strings (and the manufacturer int32 section-name
// array) against the text arena. All pool-offset fields are resolved eagerly
// into owned `Option<String>`; a zero offset means "absent".
// ---------------------------------------------------------------------------

/// One per INF file in the pack (132 bytes raw).
#[derive(Clone, Debug)]
pub struct DataInfFile {
    pub inf_path: String,
    pub inf_filename: String,
    pub fields: [Option<String>; 10],
    pub cats: [Option<String>; 10],
    pub date: Option<(u16, u8, u8)>,
    pub version: Option<(u16, u16, u16, u16)>,
    pub infsize: Option<u32>,
    pub infcrc: Option<u32>,
    pub reserved_a: i32,
    pub reserved_b: i32,
}

/// One per `[Manufacturer]` group (16 bytes raw).
#[derive(Clone, Debug)]
pub struct DataManuf {
    pub inffile_index: u32,
    pub manufacturer: String,
    pub sections: Vec<String>,
    pub sections_n: u32,
}

/// One per installable model row (24 bytes raw).
#[derive(Clone, Debug)]
pub struct DataDesc {
    pub manufacturer_index: u32,
    pub sect_pos: i32,
    pub desc: String,
    pub install: String,
    pub install_picked: String,
    pub feature: u32,
}

/// One per (ID string, model row) pairing (12 bytes raw).
#[derive(Clone, Debug)]
pub struct DataHwid {
    pub desc_index: u32,
    pub inf_pos: i32,
    pub hwid: String,
}

/// A candidate surfaced to later slices. `inf_pos` is 0 for hardware-ID matches
/// and >0 for compatible-ID matches (per SDIO semantics); Cove relies on Windows
/// ranking rather than this heuristic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub inf_path: String,
    pub inf_filename: String,
    pub provider: Option<String>,
    pub class: Option<String>,
    pub class_guid: Option<String>,
    pub catalog_file: Option<String>,
    pub version: Option<CandidateVersion>,
    pub date: Option<(u16, u8, u8)>,
    pub install_section: String,
    pub picked_section: String,
    pub inf_pos: i32,
}

/// Resolved driver version (major.minor.build.private) and date (y, m, d).
pub type CandidateVersion = (u16, u16, u16, u16);

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

/// A parsed SDIO index catalog for a single pack.
pub struct SdioCatalog {
    /// Pack name derived from the index file stem.
    pub pack_name: String,
    pub inf_records: Vec<DataInfFile>,
    pub manuf_records: Vec<DataManuf>,
    pub desc_records: Vec<DataDesc>,
    pub hwid_records: Vec<DataHwid>,
    /// The raw text arena (NUL-separated strings + embedded int32 arrays).
    pub text_pool: Vec<u8>,
    /// `hwid_uppercase -> indices into hwid_records`.
    pub hash_map: HashMap<String, Vec<usize>>,
}

impl SdioCatalog {
    /// Load and parse an SDW index file from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            SdioError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "index path has no file stem",
            ))
        })?;
        if stem.len() > MAX_PACK_FILENAME_LEN {
            return Err(SdioError::StringTooLong(0, MAX_PACK_FILENAME_LEN));
        }
        // Enforce the compressed-size cap before pulling bytes into memory.
        match fs::metadata(path) {
            Ok(meta) if meta.len() > MAX_COMPRESSED_BYTES as u64 => {
                return Err(SdioError::TooLarge(meta.len() as usize));
            }
            Ok(_) => {}
            Err(e) => return Err(SdioError::Io(e)),
        }
        let data = fs::read(path).map_err(SdioError::Io)?;
        Self::parse_inner(&data, stem.to_string())
    }

    /// Parse an in-memory SDW index buffer. `pack_name` is metadata only.
    pub fn parse_bytes(data: &[u8], pack_name: String) -> Result<Self> {
        if pack_name.len() > MAX_PACK_FILENAME_LEN {
            return Err(SdioError::StringTooLong(0, MAX_PACK_FILENAME_LEN));
        }
        Self::parse_inner(data, pack_name)
    }

    fn parse_inner(data: &[u8], pack_name: String) -> Result<Self> {
        // --- size cap (before touching content) ---
        if data.len() > MAX_COMPRESSED_BYTES {
            return Err(SdioError::TooLarge(data.len()));
        }

        // --- container header: "SDW" + version(LE u32) + flag(1) ---
        if data.len() < CONTAINER_PREFIX_LEN + LZMA_ALONE_HEADER_LEN {
            return Err(SdioError::BadBlockHeader(0));
        }
        if &data[0..3] != MAGIC.as_slice() {
            return Err(SdioError::BadMagic);
        }
        let version = r32(data, 3)?;
        if version != FORMAT_VERSION {
            return Err(SdioError::BadVersion(version));
        }
        // byte 7 (flag): opaque, ignored per spec.

        // --- LZMA-alone decompression into a capped buffer ---
        let payload = decompress_alone(&data[8..])?;

        // --- six logical blocks ---
        // blocks 0..4 are vector blocks `[byte_count:u32][count:u32][data]`;
        // block 5 is the hashtable `[capacity:u32][used:u32][count:u32][count*16]`.
        let mut p = 0usize;
        let (inf_off, inf_cnt) =
            read_vector_header(&payload, &mut p, ELEM_INF, MAX_INF_RECORDS, 0)?;
        let (man_off, man_cnt) =
            read_vector_header(&payload, &mut p, ELEM_MANUF, MAX_MANUF_RECORDS, 1)?;
        let (desc_off, desc_cnt) =
            read_vector_header(&payload, &mut p, ELEM_DESC, MAX_DESC_RECORDS, 2)?;
        let (hwid_off, hwid_cnt) =
            read_vector_header(&payload, &mut p, ELEM_HWID, MAX_HWID_RECORDS, 3)?;
        let (txt_start, txt_len) = read_vector_header(&payload, &mut p, 1, MAX_TEXT_POOL_BYTES, 4)?;
        let txt: &[u8] = payload
            .get(txt_start..txt_start + txt_len)
            .ok_or(SdioError::BadBlockHeader(txt_start))?;

        // --- decode record arrays (strings resolve against the text arena) ---
        let mut inf_records = Vec::with_capacity(inf_cnt);
        for i in 0..inf_cnt {
            inf_records.push(decode_inf(&payload, txt, inf_off + i * ELEM_INF)?);
        }
        let mut manuf_records = Vec::with_capacity(man_cnt);
        for i in 0..man_cnt {
            manuf_records.push(decode_manuf(&payload, txt, man_off + i * ELEM_MANUF)?);
        }
        let mut desc_records = Vec::with_capacity(desc_cnt);
        for i in 0..desc_cnt {
            desc_records.push(decode_desc(&payload, txt, desc_off + i * ELEM_DESC)?);
        }
        let mut hwid_records = Vec::with_capacity(hwid_cnt);
        for i in 0..hwid_cnt {
            hwid_records.push(decode_hwid(&payload, txt, hwid_off + i * ELEM_HWID)?);
        }

        // --- cross-reference validation (fail closed) ---
        for m in &manuf_records {
            if m.inffile_index as usize >= inf_cnt {
                return Err(SdioError::CrossRefInvalid {
                    kind: "inffile_index",
                    index: m.inffile_index as u64,
                    count: inf_cnt as u64,
                });
            }
        }
        for d in &desc_records {
            if d.manufacturer_index as usize >= man_cnt {
                return Err(SdioError::CrossRefInvalid {
                    kind: "manufacturer_index",
                    index: d.manufacturer_index as u64,
                    count: man_cnt as u64,
                });
            }
        }
        for h in &hwid_records {
            if h.desc_index as usize >= desc_cnt {
                return Err(SdioError::CrossRefInvalid {
                    kind: "desc_index",
                    index: h.desc_index as u64,
                    count: desc_cnt as u64,
                });
            }
        }

        // --- hashtable (block 5): structurally validated, unused for lookup ---
        let (cap, used, cnt) = read_hashtable_header(&payload, p)?;
        p += 4 + 8 + (cnt as usize) * ELEM_HASHITEM;
        if cap == 0 && cnt != 0 {
            return Err(SdioError::BadBlockHeader(p));
        }
        if cnt as u64 * ELEM_HASHITEM as u64 != used as u64 {
            return Err(SdioError::BlockSizeMismatch {
                block: 5,
                count: cnt as u64,
                elem_size: ELEM_HASHITEM,
                byte_count: used as u64,
            });
        }

        // --- no trailing garbage ---
        if p != payload.len() {
            return Err(SdioError::BadBlockHeader(p));
        }

        // --- build HWID lookup map (uppercased) ---
        let mut hash_map: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, h) in hwid_records.iter().enumerate() {
            hash_map.entry(h.hwid.to_uppercase()).or_default().push(i);
        }

        Ok(SdioCatalog {
            pack_name,
            inf_records,
            manuf_records,
            desc_records,
            hwid_records,
            text_pool: txt.to_vec(),
            hash_map,
        })
    }

    pub fn pack_name(&self) -> &str {
        &self.pack_name
    }
    pub fn hwid_count(&self) -> u32 {
        self.hwid_records.len() as u32
    }
    pub fn inf_count(&self) -> u32 {
        self.inf_records.len() as u32
    }
    pub fn manuf_count(&self) -> u32 {
        self.manuf_records.len() as u32
    }
    pub fn desc_count(&self) -> u32 {
        self.desc_records.len() as u32
    }

    /// Resolve every candidate whose (uppercased) stored HWID equals `id`.
    /// Unknown IDs return an empty `Vec` (not an error). Matching is an exact
    /// string post-check: the HashMap key already IS the uppercased string.
    pub fn find_by_hwid(&self, id: &str) -> Vec<Candidate> {
        let key = id.to_uppercase();
        let Some(indices) = self.hash_map.get(&key) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(indices.len());
        for &idx in indices {
            if let Some(hwid) = self.hwid_records.get(idx)
                && let Some(c) = self.resolve_candidate(hwid)
            {
                out.push(c);
            }
        }
        out
    }

    /// Bounded variant of [`SdioCatalog::find_by_hwid`] used by the matcher.
    ///
    /// The indexed bucket size for the exact match is inspected **first**; if it
    /// exceeds `max`, the lookup fails closed with
    /// [`SdioError::LookupBucketTooLarge`] *before* any result `Vec` is
    /// allocated. This lets an untrusted catalog never turn one device ID into an
    /// unexpectedly huge allocation during matching. When within budget the
    /// result is identical to [`SdioCatalog::find_by_hwid`].
    pub fn find_by_hwid_bounded(&self, id: &str, max: usize) -> Result<Vec<Candidate>> {
        let key = id.to_uppercase();
        let Some(indices) = self.hash_map.get(&key) else {
            return Ok(Vec::new());
        };
        if indices.len() > max {
            return Err(SdioError::LookupBucketTooLarge {
                id: id.to_string(),
                bucket: indices.len(),
                max,
            });
        }
        let mut out = Vec::with_capacity(indices.len());
        for &idx in indices {
            if let Some(hwid) = self.hwid_records.get(idx)
                && let Some(c) = self.resolve_candidate(hwid)
            {
                out.push(c);
            }
        }
        Ok(out)
    }

    fn resolve_candidate(&self, hwid: &DataHwid) -> Option<Candidate> {
        let desc = self.desc_records.get(hwid.desc_index as usize)?;
        let manuf = self.manuf_records.get(desc.manufacturer_index as usize)?;
        let inf = self.inf_records.get(manuf.inffile_index as usize)?;
        Some(Candidate {
            inf_path: inf.inf_path.clone(),
            inf_filename: inf.inf_filename.clone(),
            provider: inf.fields[FIELD_PROVIDER].clone(),
            class: inf.fields[FIELD_CLASS].clone(),
            class_guid: inf.fields[FIELD_CLASS_GUID].clone(),
            catalog_file: inf.fields[FIELD_CATALOG_FILE].clone(),
            version: inf.version,
            date: inf.date,
            install_section: desc.install.clone(),
            picked_section: desc.install_picked.clone(),
            inf_pos: hwid.inf_pos,
        })
    }
}

// ---------------------------------------------------------------------------
// Decompression + low-level helpers
// ---------------------------------------------------------------------------

fn decompress_alone(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < LZMA_ALONE_HEADER_LEN {
        return Err(SdioError::BadBlockHeader(0));
    }
    // LZMA-alone header: props(1) + dict_size(4) + declared_unpacked_size(8).
    // Props byte and dict size are consumed by lzma-rs; we only sanity-check the
    // declared unpacked size before decoding.
    let declared = {
        let a: [u8; 8] = input
            .get(5..13)
            .ok_or(SdioError::BadBlockHeader(0))?
            .try_into()
            .map_err(|_| SdioError::BadBlockHeader(0))?;
        u64::from_le_bytes(a)
    };
    if declared != 0xFFFF_FFFF_FFFF_FFFF && declared > MAX_UNCOMPRESSED_BYTES as u64 {
        return Err(SdioError::UncompressedTooLarge(declared as usize));
    }
    let mut reader = Cursor::new(input);
    let mut cap = CappedWriter::new(MAX_UNCOMPRESSED_BYTES);
    lzma_rs::lzma_decompress(&mut reader, &mut cap)
        .map_err(|e| SdioError::Decompress(format!("lzma-rs: {e}")))?;
    let written = cap.written();
    if written > MAX_UNCOMPRESSED_BYTES {
        return Err(SdioError::UncompressedTooLarge(written));
    }
    Ok(cap.into_inner())
}

/// Writer that refuses to let the decompressor emit more than `max` bytes.
struct CappedWriter {
    buf: Vec<u8>,
    max: usize,
}
impl CappedWriter {
    fn new(max: usize) -> Self {
        Self {
            buf: Vec::with_capacity(8 * 1024),
            max,
        }
    }
    fn written(&self) -> usize {
        self.buf.len()
    }
    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}
impl Write for CappedWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() + b.len() > self.max {
            return Err(std::io::Error::other("uncompressed cap exceeded"));
        }
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Read a little-endian `u32` guarded against truncation.
fn r32(buf: &[u8], off: usize) -> Result<u32> {
    let end = off.checked_add(4).ok_or(SdioError::BadBlockHeader(off))?;
    let a: [u8; 4] = buf
        .get(off..end)
        .ok_or(SdioError::BadBlockHeader(off))?
        .try_into()
        .map_err(|_| SdioError::BadBlockHeader(off))?;
    Ok(u32::from_le_bytes(a))
}

/// Read a little-endian `i32` guarded against truncation.
fn ri32(buf: &[u8], off: usize) -> Result<i32> {
    let end = off.checked_add(4).ok_or(SdioError::BadBlockHeader(off))?;
    let a: [u8; 4] = buf
        .get(off..end)
        .ok_or(SdioError::BadBlockHeader(off))?
        .try_into()
        .map_err(|_| SdioError::BadBlockHeader(off))?;
    Ok(i32::from_le_bytes(a))
}

/// A NUL-terminated string at `off` within the text `pool`; `off == 0` -> `None`.
fn pool_str(pool: &[u8], off: u32) -> Result<Option<String>> {
    if off == 0 {
        return Ok(None);
    }
    let base = off as usize;
    if base >= pool.len() {
        return Err(SdioError::PoolOffsetOutOfRange {
            offset: off,
            pool: pool.len() as u32,
        });
    }
    let rest = &pool[base..];
    let len = match rest.iter().position(|&c| c == 0) {
        Some(l) => l,
        None => return Err(SdioError::UnterminatedString(off)),
    };
    if len > MAX_STRING_LEN {
        return Err(SdioError::StringTooLong(off, MAX_STRING_LEN));
    }
    let s =
        std::str::from_utf8(&rest[..len]).map_err(|_| SdioError::BadBlockHeader(off as usize))?;
    Ok(Some(s.to_string()))
}

/// Read a `vector_save` block header `[byte_count:u32][count:u32]` + advance `p`.
fn read_vector_header(
    payload: &[u8],
    p: &mut usize,
    elem_size: usize,
    max_count: usize,
    block: usize,
) -> Result<(usize, usize)> {
    let byte_count = r32(payload, *p)? as usize;
    let count = r32(payload, *p + 4)? as usize;
    let expected = count
        .checked_mul(elem_size)
        .ok_or(SdioError::BlockSizeMismatch {
            block,
            count: count as u64,
            elem_size,
            byte_count: byte_count as u64,
        })?;
    if expected != byte_count {
        return Err(SdioError::BlockSizeMismatch {
            block,
            count: count as u64,
            elem_size,
            byte_count: byte_count as u64,
        });
    }
    if count > max_count {
        return Err(SdioError::RecordCountExceeded {
            block,
            count: count as u64,
            bound: max_count as u64,
        });
    }
    let data_start = *p + 8;
    let end = data_start
        .checked_add(byte_count)
        .ok_or(SdioError::BadBlockHeader(*p))?;
    if end > payload.len() {
        return Err(SdioError::BadBlockHeader(*p));
    }
    *p = end;
    Ok((data_start, count))
}

/// Read the hashtable header `[capacity:u32][used:u32][count:u32]` (no advance).
fn read_hashtable_header(payload: &[u8], p: usize) -> Result<(u32, u32, u32)> {
    let cap = r32(payload, p)?;
    let used = r32(payload, p + 4)?;
    let count = r32(payload, p + 8)?;
    let expected =
        (count as usize)
            .checked_mul(ELEM_HASHITEM)
            .ok_or(SdioError::BlockSizeMismatch {
                block: 5,
                count: count as u64,
                elem_size: ELEM_HASHITEM,
                byte_count: used as u64,
            })?;
    if expected != used as usize {
        return Err(SdioError::BlockSizeMismatch {
            block: 5,
            count: count as u64,
            elem_size: ELEM_HASHITEM,
            byte_count: used as u64,
        });
    }
    Ok((cap, used, count))
}

// ---------------------------------------------------------------------------
// Record decoders.
// `payload` holds the raw record bytes; `pool` is the text arena. Record-owned
// integer fields are read from `payload`; string offsets (and the manufacturer
// section-name int32 array) are read from `pool` at pool-relative offsets.
// ---------------------------------------------------------------------------

fn decode_inf(payload: &[u8], pool: &[u8], o: usize) -> Result<DataInfFile> {
    let inf_path = pool_str(pool, r32(payload, o)?)?.unwrap_or_default();
    let inf_filename = pool_str(pool, r32(payload, o + 4)?)?.unwrap_or_default();
    let mut fields: [Option<String>; 10] = Default::default();
    for (j, slot) in fields.iter_mut().enumerate() {
        *slot = pool_str(pool, r32(payload, o + 8 + 4 * j)?)?;
    }
    let mut cats: [Option<String>; 10] = Default::default();
    for (j, slot) in cats.iter_mut().enumerate() {
        *slot = pool_str(pool, r32(payload, o + 48 + 4 * j)?)?;
    }
    let reserved_a = ri32(payload, o + 88)?;
    let reserved_b = ri32(payload, o + 92)?;
    let day = ri32(payload, o + 96)?;
    let month = ri32(payload, o + 100)?;
    let year = ri32(payload, o + 104)?;
    let ver_v1 = ri32(payload, o + 108)?;
    let ver_v2 = ri32(payload, o + 112)?;
    let ver_v3 = ri32(payload, o + 116)?;
    let ver_v4 = ri32(payload, o + 120)?;
    let infsize = ri32(payload, o + 124)?;
    let infcrc = r32(payload, o + 128)?;
    if infsize < 0 {
        return Err(SdioError::OutOfRange {
            field: "infsize",
            value: infsize as i64,
        });
    }
    let infsize = infsize as u32;

    // Fail closed on values that cannot be represented, never truncate them.
    for (field, value) in [
        ("ver_v1", ver_v1),
        ("ver_v2", ver_v2),
        ("ver_v3", ver_v3),
        ("ver_v4", ver_v4),
    ] {
        if !(0..=u16::MAX as i32).contains(&value) {
            return Err(SdioError::OutOfRange {
                field,
                value: value as i64,
            });
        }
    }
    let ver_v1 = ver_v1 as u16;
    let ver_v2 = ver_v2 as u16;
    let ver_v3 = ver_v3 as u16;
    let ver_v4 = ver_v4 as u16;

    // An all-zero date means "absent"; any other out-of-range component is
    // rejected rather than clamped.
    let date = if year == 0 && month == 0 && day == 0 {
        None
    } else {
        if !(1..=u16::MAX as i32).contains(&year)
            || !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
        {
            return Err(SdioError::OutOfRange {
                field: "driver_date",
                value: year as i64,
            });
        }
        Some((year as u16, month as u8, day as u8))
    };
    let version = if ver_v1 | ver_v2 | ver_v3 | ver_v4 != 0 {
        Some((ver_v1, ver_v2, ver_v3, ver_v4))
    } else {
        None
    };

    Ok(DataInfFile {
        inf_path,
        inf_filename,
        fields,
        cats,
        date,
        version,
        infsize: Some(infsize),
        infcrc: Some(infcrc),
        reserved_a,
        reserved_b,
    })
}

fn decode_manuf(payload: &[u8], pool: &[u8], o: usize) -> Result<DataManuf> {
    let inffile_index = r32(payload, o)?;
    let manufacturer = pool_str(pool, r32(payload, o + 4)?)?.unwrap_or_default();
    let sections_off = r32(payload, o + 8)? as usize;
    let sections_n_raw = ri32(payload, o + 12)?;
    if sections_n_raw < 0 {
        return Err(SdioError::ReservedFieldInvalid);
    }
    let sections_n = sections_n_raw as usize;
    if sections_n > MAX_SECTIONS_PER_MANUF {
        return Err(SdioError::RecordCountExceeded {
            block: 1,
            count: sections_n as u64,
            bound: MAX_SECTIONS_PER_MANUF as u64,
        });
    }

    let ints_len = sections_n
        .checked_mul(4)
        .ok_or(SdioError::BadBlockHeader(o))?;
    let sec_end = sections_off
        .checked_add(ints_len)
        .ok_or(SdioError::BadBlockHeader(o))?;
    if sec_end > pool.len() {
        return Err(SdioError::BadBlockHeader(o));
    }

    let mut sections = Vec::with_capacity(sections_n);
    for j in 0..sections_n {
        let off = r32(pool, sections_off + j * 4)? as u32;
        sections.push(pool_str(pool, off)?.unwrap_or_default());
    }

    Ok(DataManuf {
        inffile_index,
        manufacturer,
        sections,
        sections_n: sections_n as u32,
    })
}

fn decode_desc(payload: &[u8], pool: &[u8], o: usize) -> Result<DataDesc> {
    let manufacturer_index = r32(payload, o)?;
    let sect_pos = ri32(payload, o + 4)?;
    let desc = pool_str(pool, r32(payload, o + 8)?)?.unwrap_or_default();
    let install = pool_str(pool, r32(payload, o + 12)?)?.unwrap_or_default();
    let install_picked = pool_str(pool, r32(payload, o + 16)?)?.unwrap_or_default();
    let feature = r32(payload, o + 20)?;
    Ok(DataDesc {
        manufacturer_index,
        sect_pos,
        desc,
        install,
        install_picked,
        feature,
    })
}

fn decode_hwid(payload: &[u8], pool: &[u8], o: usize) -> Result<DataHwid> {
    let desc_index = r32(payload, o)?;
    let inf_pos = ri32(payload, o + 4)?;
    let hwid = pool_str(pool, r32(payload, o + 8)?)?.unwrap_or_default();
    Ok(DataHwid {
        desc_index,
        inf_pos,
        hwid,
    })
}
