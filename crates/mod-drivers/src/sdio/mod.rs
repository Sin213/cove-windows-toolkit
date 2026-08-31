//! `sdio` — clean-room, offline-only parser for SDIO (Snappy Driver Installer
//! Origin) index catalogs under Option C.
//!
//! This module parses the SDW/0x205 binary index format produced by SDIO r886.
//! It performs **no networking** and never transmits data: it only reads index
//! files that the user placed on disk via their own copy of SDIO. Matching and
//! applicability ranking against live Windows devices live in later slices
//! (Tab 2a-3+); this slice exposes a typed, fail-closed catalog + lookup API.
//!
//! Format reference: see `catalog.rs` doc comments and the Tab 2a-2
//! specification in `crates/mod-drivers/fixtures/sdio/README.md`.

pub mod applicability;
mod catalog;
pub mod error;
pub mod extraction;
pub mod local_pack;
pub mod matching;

pub use applicability::{
    ApplicabilityError, ApplicabilityReason, AssessedCatalogCandidate, AssessedDeviceMatches,
    CatalogApplicabilityEvidence, CatalogOsApplicability, ParsedMachineContext, TargetArch,
    TargetOsDecoration, TargetParseError, assess_device_matches, assess_matches, evaluate_target,
    normalize_host_arch, parse_machine_context, parse_target_os_version,
};
pub use catalog::{
    Candidate, CandidateVersion, DataDesc, DataHwid, DataInfFile, DataManuf, FIELD_CATALOG_FILE,
    FIELD_CATALOG_FILE_NT, FIELD_CATALOG_FILE_NTAMD64, FIELD_CATALOG_FILE_NTIA64,
    FIELD_CATALOG_FILE_NTX86, FIELD_CLASS, FIELD_CLASS_GUID, FIELD_DRIVER_PACKAGE_DISPLAY_NAME,
    FIELD_DRIVER_VER, FIELD_PROVIDER, FORMAT_VERSION, MAX_COMPRESSED_BYTES, SdioCatalog,
};
pub use error::SdioError;

pub use extraction::{
    ExtractionError, ExtractionResult, MAX_ARCHIVE_BLOCKS, MAX_ARCHIVE_DECLARED_UNPACKED_BYTES,
    MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_TOTAL_NAME_BYTES, MAX_CODERS_PER_BLOCK,
    MAX_TARGET_BLOCK_EXPANSION_RATIO, MAX_TARGET_DECODE_BYTES, MAX_TARGET_INF_BYTES,
    StagedInfArtifact, materialize_inf,
};

pub use local_pack::{
    ExpectedArchiveMember, LocalPackAvailability, LocalPackError, LocalPackRef,
    MAX_ARCHIVE_COMPONENT_LEN, MAX_ARCHIVE_MEMBER_COMPONENTS, MAX_ARCHIVE_MEMBER_LEN,
    MAX_LOCAL_PACK_BYTES, MAX_PACKS_PER_BATCH, PackageMaterializationRequest, expected_inf_member,
    expected_pack_filename, resolve_assessed_pack, resolve_local_pack, resolve_local_packs,
    validate_pack_size,
};

pub use matching::{
    CatalogCandidateMatch, DeviceCatalogMatches, DeviceIdKind, MAX_CANDIDATES_PER_DEVICE,
    MAX_CATALOGS_PER_MATCH, MAX_DEVICES_PER_MATCH, MAX_EVIDENCE_PER_CANDIDATE, MAX_IDS_PER_DEVICE,
    MAX_TOTAL_CANDIDATES, MatchError, MatchEvidence, match_device_to_catalogs,
    match_devices_to_catalogs,
};

/// Convenience alias used by callers.
pub type Result<T> = std::result::Result<T, SdioError>;
