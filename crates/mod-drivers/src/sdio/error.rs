use thiserror::Error;

/// All failures that can occur while loading/validating an SDIO index catalog.
///
/// Every variant here represents a *detected, controlled rejection* of untrusted
/// bytes. The parser must never panic, never `unwrap`, and never silently coerce
/// malformed input into a plausible-looking result.
#[derive(Debug, Error)]
pub enum SdioError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file exceeds maximum compressed size of {0} bytes")]
    TooLarge(usize),

    #[error("not an SDW index (bad magic)")]
    BadMagic,

    #[error("unsupported SDW index version 0x{0:X} (expected 0x205)")]
    BadVersion(u32),

    #[error("decompression failed: {0}")]
    Decompress(String),

    #[error("uncompressed payload exceeds cap of {0} bytes")]
    UncompressedTooLarge(usize),

    #[error("malformed block header at offset {0}")]
    BadBlockHeader(usize),

    #[error("count/size mismatch in block {block}: count * {elem_size} != {byte_count}")]
    BlockSizeMismatch {
        block: usize,
        count: u64,
        elem_size: usize,
        byte_count: u64,
    },

    #[error("record count {count} exceeds bound {bound} in block {block}")]
    RecordCountExceeded {
        block: usize,
        count: u64,
        bound: u64,
    },

    #[error("pool offset {offset} is out of range (pool size {pool})")]
    PoolOffsetOutOfRange { offset: u32, pool: u32 },

    #[error("unterminated string at pool offset {0}")]
    UnterminatedString(u32),

    #[error("string at pool offset {0} exceeds max length {1}")]
    StringTooLong(u32, usize),

    #[error("cross-reference invalid: {kind} index {index} >= count {count}")]
    CrossRefInvalid {
        kind: &'static str,
        index: u64,
        count: u64,
    },

    #[error("unknown field / reserved byte out of expected range")]
    ReservedFieldInvalid,

    #[error("value {value} out of expected range in field {field}")]
    OutOfRange { field: &'static str, value: i64 },

    /// A bounded catalog lookup was refused because the exact-ID bucket would
    /// exceed the caller-supplied allocation/result cap. The bucket size is
    /// always checked **before** any result `Vec` is allocated.
    #[error("hwid lookup bucket for {id:?} has {bucket} records, cap is {max}")]
    LookupBucketTooLarge {
        id: String,
        bucket: usize,
        max: usize,
    },
}
