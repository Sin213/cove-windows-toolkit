// Integration tests for the SDIO index catalog parser (Tab 2a-2, Option C slice).
//
// Fixtures: real SDIO r886 index bytes (`DP_Display_SDIO01_26082.bin`) plus
// mechanical corruptions. See `fixtures/sdio/README.md` for provenance.

use std::io::Cursor;
use std::path::PathBuf;

use mod_drivers::sdio::{
    Candidate, DataInfFile, FIELD_CATALOG_FILE, FIELD_CLASS, FIELD_CLASS_GUID, FIELD_PROVIDER,
    FORMAT_VERSION, MAX_COMPRESSED_BYTES, SdioCatalog, SdioError,
};

const VALID_BYTES: &[u8] = include_bytes!("../fixtures/sdio/valid_small.bin");

/// Unwrap parse errors without requiring `SdioCatalog: Debug`.
fn err_of(res: Result<SdioCatalog, SdioError>) -> SdioError {
    match res {
        Err(e) => e,
        Ok(_) => panic!("expected parse error"),
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("sdio")
        .join(name)
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("fixture {name} missing: {e}"))
}

/// Decode the valid fixture's compressed payload into its decompressed bytes.
fn decode_valid_payload() -> Vec<u8> {
    let mut input = Cursor::new(&VALID_BYTES[8..]);
    let mut out = Vec::new();
    lzma_rs::lzma_decompress(&mut input, &mut out).expect("valid fixture must decode");
    out
}

/// Re-wrap a patched decompressed payload as a full SDW/0x205 file.
fn rewrap(patched: &[u8]) -> Vec<u8> {
    let mut enc = Cursor::new(Vec::new());
    lzma_rs::lzma_compress(&mut Cursor::new(patched), &mut enc).expect("re-encode");
    let stream = enc.into_inner();
    let mut out = Vec::with_capacity(8 + stream.len());
    out.extend_from_slice(b"SDW");
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.push(0u8); // opaque flag byte
    out.extend_from_slice(&stream);
    out
}

// ===========================================================================
// RED-1 — container acceptance
// ===========================================================================
#[test]
fn red1_valid_fixture_loads() {
    let cat = SdioCatalog::open(&fixture_path("valid_small.bin")).expect("should parse");
    assert_eq!(cat.pack_name(), "valid_small");
    assert_eq!(cat.inf_count(), 4);
    assert_eq!(cat.manuf_count(), 4);
    assert_eq!(cat.desc_count(), 272);
    assert_eq!(cat.hwid_count(), 272);
    assert!(!cat.text_pool.is_empty());
    assert!(!cat.hash_map.is_empty());
}

// ===========================================================================
// RED-2 — magic rejection
// ===========================================================================
#[test]
fn red2_bad_magic_rejected() {
    let bytes = fixture_bytes("bad_magic.bin");
    let err = err_of(SdioCatalog::parse_bytes(
        &bytes,
        "DP_Display_SDIO01_26082".into(),
    ));
    assert!(matches!(err, SdioError::BadMagic), "got {err:?}");
}

// ===========================================================================
// RED-3 — version rejection
// ===========================================================================
#[test]
fn red3_bad_version_rejected() {
    let mut bytes = VALID_BYTES.to_vec();
    bytes[3..7].copy_from_slice(&0x0206u32.to_le_bytes());
    let err = err_of(SdioCatalog::parse_bytes(
        &bytes,
        "DP_Display_SDIO01_26082".into(),
    ));
    assert!(matches!(err, SdioError::BadVersion(0x206)), "got {err:?}");
}

// ===========================================================================
// RED-4 — truncation rejection
// ===========================================================================
#[test]
fn red4_truncated_header_rejected() {
    let bytes = fixture_bytes("truncated_header.bin");
    assert!(bytes.len() < 21);
    let res = SdioCatalog::parse_bytes(&bytes, "truncated".into());
    assert!(res.is_err(), "truncated header must fail closed");
    assert!(!err_of(res).to_string().is_empty());
}

// ===========================================================================
// RED-5 — corrupt LZMA stream rejection
// ===========================================================================
#[test]
fn red5_corrupt_lzma_rejected() {
    let bytes = fixture_bytes("corrupt_lzma.bin");
    let err = err_of(SdioCatalog::parse_bytes(
        &bytes,
        "DP_Display_SDIO01_26082".into(),
    ));
    assert!(
        matches!(err, SdioError::Decompress(_)),
        "expected Decompress, got {err:?}"
    );
}

// ===========================================================================
// RED-6 — block walk correctness + cross-reference integrity
// ===========================================================================
#[test]
fn red6_block_walk_and_crossrefs_hold() {
    let cat = SdioCatalog::open(&fixture_path("valid_small.bin")).unwrap();
    // Structural sizes (proves the six-block walk consumed exact bytes).
    assert_eq!(cat.text_pool.len(), 11833);
    // Every hwid desc_index < desc_count, every desc manufacturer_index < manuf_count
    // and every manuf inffile_index < inf_count — success implies all held.
    assert!(
        cat.hwid_records
            .iter()
            .all(|h| (h.desc_index as usize) < cat.desc_records.len())
    );
    assert!(
        cat.desc_records
            .iter()
            .all(|d| (d.manufacturer_index as usize) < cat.manuf_records.len())
    );
    assert!(
        cat.manuf_records
            .iter()
            .all(|m| (m.inffile_index as usize) < cat.inf_records.len())
    );
    // hash_map covers exactly the hwid record set.
    let mapped: usize = cat.hash_map.values().map(|v| v.len()).sum();
    assert_eq!(mapped, cat.hwid_records.len());
}

// ===========================================================================
// RED-7 — record decode correctness
// ===========================================================================
#[test]
fn red7_inf_record_decoded_correctly() {
    let cat = SdioCatalog::open(&fixture_path("valid_small.bin")).unwrap();
    let inf: &DataInfFile = &cat.inf_records[0];

    assert!(
        inf.inf_path
            .starts_with("amd\\10x64\\ati2mtag_StrixHalo_32.0.23033.5002\\")
    );
    assert_eq!(inf.inf_filename, "u0202099.inf");
    assert_eq!(
        inf.fields[FIELD_CLASS_GUID].as_deref(),
        Some("{4D36E968-E325-11CE-BFC1-08002BE10318}")
    );
    assert_eq!(inf.fields[FIELD_CLASS].as_deref(), Some("Display"));
    assert_eq!(
        inf.fields[FIELD_PROVIDER].as_deref(),
        Some("Advanced Micro Devices, Inc.")
    );
    assert_eq!(
        inf.fields[FIELD_CATALOG_FILE].as_deref(),
        Some("u0202099.cat")
    );
    // nt/ia64/amd64 display and DriverVer slots are absent.
    for i in 4..=9 {
        assert!(inf.fields[i].is_none(), "fields[{i}] should be absent");
    }
    assert_eq!(inf.cats[4].as_deref(), Some("2:10.0"));
    assert_eq!(inf.date, Some((2026, 6, 29)));
    assert_eq!(inf.version, Some((32, 0, 23033, 5002)));
    assert_eq!(inf.infsize, Some(139_910));
    assert_eq!(inf.infcrc, Some(0x00922611));
    // Reserved slots are read (0) and explicitly ignored, not inferred.
    assert_eq!(inf.reserved_a, 0);
    assert_eq!(inf.reserved_b, 0);
}

// ===========================================================================
// RED-8 — HWID lookup round-trip
// ===========================================================================
#[test]
fn red8_known_hwid_resolves_to_candidate() {
    let cat = SdioCatalog::open(&fixture_path("valid_small.bin")).unwrap();
    let target = "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1";

    let upper = cat.find_by_hwid(target);
    assert!(!upper.is_empty(), "uppercase HWID must resolve");

    let lower = cat.find_by_hwid(&target.to_lowercase());
    assert_eq!(
        upper.len(),
        lower.len(),
        "case-insensitive lookup must match"
    );

    let c: &Candidate = &upper[0];
    assert_eq!(c.inf_filename, "u0202099.inf");
    assert!(
        c.inf_path
            .starts_with("amd\\10x64\\ati2mtag_StrixHalo_32.0.23033.5002\\")
    );
    assert_eq!(c.provider.as_deref(), Some("Advanced Micro Devices, Inc."));
    assert_eq!(c.class.as_deref(), Some("Display"));
    assert_eq!(
        c.class_guid.as_deref(),
        Some("{4D36E968-E325-11CE-BFC1-08002BE10318}")
    );
    assert_eq!(c.catalog_file.as_deref(), Some("u0202099.cat"));
    assert_eq!(c.version, Some((32, 0, 23033, 5002)));
    assert_eq!(c.date, Some((2026, 6, 29)));
    assert_eq!(c.install_section, "ati2mtag_StrixHalo");
    assert_eq!(c.picked_section, "ati2mtag_strixhalo");
    assert_eq!(c.inf_pos, 0);
}

// ===========================================================================
// RED-9 — unknown HWID yields no candidates
// ===========================================================================
#[test]
fn red9_unknown_hwid_empty() {
    let cat = SdioCatalog::open(&fixture_path("valid_small.bin")).unwrap();
    let res = cat.find_by_hwid("PCI\\VEN_FFFF&DEV_FFFF");
    assert!(res.is_empty());
    // Also the lowercase variant must be empty.
    assert!(cat.find_by_hwid("pci\\ven_ffff&dev_ffff").is_empty());
}

// ===========================================================================
// RED-10 — oversized compressed file rejected
// ===========================================================================
#[test]
fn red10_oversized_rejected() {
    // > MAX_COMPRESSED_BYTES. The bytes are never paged in; only the length is
    // inspected before rejection.
    let big = vec![0u8; MAX_COMPRESSED_BYTES + 1];
    let err = err_of(SdioCatalog::parse_bytes(&big, "oversized".into()));
    assert!(matches!(err, SdioError::TooLarge(_)), "got {err:?}");
}

// ===========================================================================
// RED-11 — count/size mismatch / bound rejection (patched count too large)
// ===========================================================================
#[test]
fn red11_record_count_bound_enforced() {
    // (a) Pure size mismatch: corrupt byte_count so count*132 != byte_count.
    let mut pay = decode_valid_payload();
    let bc = u32::from_le_bytes(pay[0..4].try_into().unwrap());
    pay[0..4].copy_from_slice(&(bc + 132).to_le_bytes()); // count unpatched
    let err = err_of(SdioCatalog::parse_bytes(&rewrap(&pay), "patched".into()));
    assert!(
        matches!(err, SdioError::BlockSizeMismatch { block: 0, .. }),
        "got {err:?}"
    );

    // (b) Count above MAX_INF_RECORDS (200_000) with a consistent byte_count.
    let mut pay = decode_valid_payload();
    // block 0 = inffile vector; header is [byte_count:u32 @0][count:u32 @4].
    let new_count: u32 = 1_000_000;
    let new_bc: u32 = new_count * 132;
    pay[0..4].copy_from_slice(&new_bc.to_le_bytes());
    pay[4..8].copy_from_slice(&new_count.to_le_bytes());

    let err = err_of(SdioCatalog::parse_bytes(&rewrap(&pay), "patched".into()));
    assert!(
        matches!(
            err,
            SdioError::RecordCountExceeded {
                block: 0,
                count: 1_000_000,
                ..
            }
        ),
        "got {err:?}"
    );
}

// ===========================================================================
// RED-12 — cross-reference rejection (desc_index out of range)
// ===========================================================================
#[test]
fn red12_crossref_rejected() {
    let mut pay = decode_valid_payload();
    // hwid record 0 begins at payload offset 7152; desc_index is the first u32.
    // desc_count == 272, so 272 is out of range.
    let rec0 = 7152usize;
    pay[rec0..rec0 + 4].copy_from_slice(&272u32.to_le_bytes());

    let err = err_of(SdioCatalog::parse_bytes(&rewrap(&pay), "patched".into()));
    assert!(
        matches!(
            err,
            SdioError::CrossRefInvalid {
                kind: "desc_index",
                index: 272,
                ..
            }
        ),
        "got {err:?}"
    );
}

// ===========================================================================
// RED-13 — pool offset out of range rejected
// ===========================================================================
#[test]
fn red13_pool_offset_rejected() {
    let pay_len = decode_valid_payload().len();
    let mut pay = decode_valid_payload();
    // HWID record 0's string offset is at payload offset 7160; pool length is 11833.
    let str_off_field = 7160usize;
    let bad_off: u32 = 12_833; // > 11833
    pay[str_off_field..str_off_field + 4].copy_from_slice(&bad_off.to_le_bytes());
    // sanity: payload still the expected size
    assert_eq!(pay.len(), pay_len);

    let err = err_of(SdioCatalog::parse_bytes(&rewrap(&pay), "patched".into()));
    assert!(
        matches!(err, SdioError::PoolOffsetOutOfRange { offset: 12_833, .. }),
        "got {err:?}"
    );
}

// ===========================================================================
// RED-14 — fuzz robustness (no panics on random mutations)
// ===========================================================================
#[test]
fn red14_random_mutations_never_panic() {
    let base = VALID_BYTES.to_vec();
    let len = base.len();
    // tiny deterministic splitmix64 PRNG — no extra crate dependency.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15; // fixed seed (golden-ratio constant)
    let mut next = || {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF584E6281EC4A27);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        (z % len as u64) as usize
    };
    for seed in 0..200u32 {
        let mut copy = base.clone();
        for _ in 0..3 {
            let i = (next() + seed as usize) % len;
            copy[i] ^= 0xFF;
        }
        let outcome = std::panic::catch_unwind(|| SdioCatalog::parse_bytes(&copy, "fuzz".into()));
        assert!(
            outcome.is_ok(),
            "parser panicked on fuzz seed {seed} (mutation at byte {})",
            next() % len
        );
    }
}
