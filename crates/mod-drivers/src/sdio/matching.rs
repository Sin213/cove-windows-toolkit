//! Pure candidate-discovery join between ordered Windows `DeviceIdentity` values
//! and already-parsed local/offline `SdioCatalog` indexes (Tab 2a-3, Option C).
//!
//! This layer performs **candidate discovery only**. It never classifies a
//! candidate as newer / better / recommended / an update, and it never derives a
//! Windows rank. Windows rank remains authoritative and is captured only where
//! Windows itself reports it (in the identity layer); a catalog `inf_pos` is SDIO
//! metadata, preserved verbatim, and is explicitly **not** a Windows rank.
//!
//! Matching is exact: the uppercase-keyed catalog lookup is a post-check for
//! string equality after the catalog's own case normalization. No prefix, suffix,
//! glob, wildcard, `REV_`/`SUBSYS_` stripping, or generic-ID synthesis ever
//! happens here.
//!
//! The matcher is pure: callers supply already-parsed objects. No device
//! enumeration, no index/directory/`.7z` access, no downloads, no writes, and no
//! networking.

use crate::identity::DeviceIdentity;
use crate::sdio::catalog::{Candidate, SdioCatalog};
use crate::sdio::error::SdioError;

// ---------------------------------------------------------------------------
// Matching bounds (finite — untrusted local metadata must not leak unbounded
// allocations or unbounded iteration). These are fail-closed caps; crossing one
// returns an explicit [`MatchError`], never silent truncation.
// ---------------------------------------------------------------------------

/// Maximum number of input devices in one batch. Aligns with the established
/// `identity::MAX_DEVICES` (4_096) bound so a single `DeviceIdentity` scan can
/// always be matched whole.
pub const MAX_DEVICES_PER_MATCH: usize = 4_096;

/// Maximum number of input catalogs in one match. Generous headroom above the
/// current real SDIO set (~104 indexes) with no practical downside.
pub const MAX_CATALOGS_PER_MATCH: usize = 256;

/// Maximum device IDs (hardware + compatible) considered per device. Sum of the
/// established identity bounds `MAX_HARDWARE_IDS_PER_DEVICE` (64) and
/// `MAX_COMPATIBLE_IDS_PER_DEVICE` (256).
pub const MAX_IDS_PER_DEVICE: usize =
    crate::identity::MAX_HARDWARE_IDS_PER_DEVICE + crate::identity::MAX_COMPATIBLE_IDS_PER_DEVICE;

/// Maximum unique logical candidates surfaced for a single device instance.
/// Sized comfortably above real per-device candidate totals across ~104 packs.
pub const MAX_CANDIDATES_PER_DEVICE: usize = 512;

/// Maximum candidate rows across an entire batch (the union over all devices).
pub const MAX_TOTAL_CANDIDATES: usize = 65_536;

/// Maximum evidence records retained for a single logical candidate. A malicious
/// catalog can funnel many device IDs onto one model row, so this stays bounded
/// and is enforced before a candidate's evidence is allowed to grow.
pub const MAX_EVIDENCE_PER_CANDIDATE: usize = 64;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Which device-ID list surfaced an evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceIdKind {
    /// The ID came from `DeviceIdentity::hardware_ids`.
    Hardware,
    /// The ID came from `DeviceIdentity::compatible_ids`.
    Compatible,
}

/// One ordered path explaining why a candidate was discovered.
///
/// `ordinal` indexes the original `DeviceIdentity` list it came from: the
/// `hardware_ids` list when `kind == Hardware`, the `compatible_ids` list when
/// `kind == Compatible`.
///
/// [`Self::device_id`] retains the device-side original casing verbatim; it is a
/// display/preservation value and is never normalized or lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchEvidence {
    pub kind: DeviceIdKind,
    /// Original (device-side) casing of the matched ID. Preserved, not normalized.
    pub device_id: String,
    /// Position of `device_id` in the matching `DeviceIdentity` ID list.
    pub ordinal: usize,
    /// Resolved from the matched SDIO `DataHwid::inf_pos`. **SDIO metadata, not a
    /// Windows rank.** 0 typically means a hardware-ID match; >0 a compatible-ID
    /// match per SDIO semantics. Cove never turns this into a ranking.
    pub inf_pos: i32,
}

/// One logical candidate surfaced from one pack, with the ordered evidence that
/// explains its discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogCandidateMatch {
    /// Pack provenance. Two packs are always distinct candidates, even if they
    /// share INF filename / provider / version / install section.
    pub pack_name: String,
    /// The original parsed candidate (first deterministic discovery wins).
    pub candidate: Candidate,
    /// Ordered evidence paths that discovered this candidate.
    pub evidence: Vec<MatchEvidence>,
}

/// The per-device matching result. One result per input device instance, in input
/// order. A device whose IDs found no candidate gets `candidates: []`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCatalogMatches {
    pub instance_id: String,
    pub candidates: Vec<CatalogCandidateMatch>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed reasons the matcher refuses to produce output.
#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("too many devices: {0} provided, limit is {MAX_DEVICES_PER_MATCH}")]
    TooManyDevices(usize),
    #[error("too many catalogs: {0} provided, limit is {MAX_CATALOGS_PER_MATCH}")]
    TooManyCatalogs(usize),
    #[error("too many IDs on device: {0} (hardware + compatible), limit is {MAX_IDS_PER_DEVICE}")]
    TooManyDeviceIds(usize),
    #[error(
        "candidate budget exceeded for device: would exceed limit of {MAX_CANDIDATES_PER_DEVICE}"
    )]
    TooManyCandidates,
    #[error("total candidate budget exceeded across batch: limit is {MAX_TOTAL_CANDIDATES}")]
    TooManyTotalCandidates,
    #[error("evidence budget exceeded for a candidate: limit is {MAX_EVIDENCE_PER_CANDIDATE}")]
    TooMuchEvidence,
    /// A catalog lookup rejected the request (e.g. an untrusted bucket exceeded
    /// its allocation budget before any result was allocated).
    #[error("catalog lookup rejected: {0}")]
    Catalog(#[from] SdioError),
}

/// Convenience result alias for the matching layer.
pub type MatchResult<T> = std::result::Result<T, MatchError>;

// ---------------------------------------------------------------------------
// Matchers (pure)
// ---------------------------------------------------------------------------

/// Match one device's ordered IDs against the supplied catalogs, in order.
///
/// Hardware IDs are queried first (in source order), then compatible IDs (in
/// source order). Discovery is exact; candidates deduplicate per device per pack
/// while retaining all ordered evidence.
pub fn match_device_to_catalogs(
    device: &DeviceIdentity,
    catalogs: &[SdioCatalog],
) -> MatchResult<DeviceCatalogMatches> {
    if catalogs.len() > MAX_CATALOGS_PER_MATCH {
        return Err(MatchError::TooManyCatalogs(catalogs.len()));
    }
    let mut total_candidates = 0usize;
    match_one(&mut total_candidates, device, catalogs)
}

/// Match many devices and return one result per input device, in input order.
///
/// Never reorders devices by candidate count and never parallelizes; correctness
/// and determinism come first.
pub fn match_devices_to_catalogs(
    devices: &[DeviceIdentity],
    catalogs: &[SdioCatalog],
) -> MatchResult<Vec<DeviceCatalogMatches>> {
    if devices.len() > MAX_DEVICES_PER_MATCH {
        return Err(MatchError::TooManyDevices(devices.len()));
    }
    if catalogs.len() > MAX_CATALOGS_PER_MATCH {
        return Err(MatchError::TooManyCatalogs(catalogs.len()));
    }
    let mut out = Vec::with_capacity(devices.len());
    let mut total_candidates = 0usize;
    for device in devices {
        let matched = match_one(&mut total_candidates, device, catalogs)?;
        out.push(matched);
    }
    Ok(out)
}

/// Internal single-device matcher. Owns the per-device candidate/evidence budgets
/// and the deterministic discovery order.
fn match_one(
    total_candidates: &mut usize,
    device: &DeviceIdentity,
    catalogs: &[SdioCatalog],
) -> MatchResult<DeviceCatalogMatches> {
    let id_count = device
        .hardware_ids
        .len()
        .saturating_add(device.compatible_ids.len());
    if id_count > MAX_IDS_PER_DEVICE {
        return Err(MatchError::TooManyDeviceIds(id_count));
    }

    // Deterministic candidate accumulator. Discovery order (device ID order ->
    // catalog order -> bucket order) defines candidate position; dedupe merges
    // repeated logical candidates while appending ordered evidence.
    let mut candidates: Vec<CatalogCandidateMatch> = Vec::new();
    let mut key_to_index: std::collections::HashMap<CandidateKey, usize> =
        std::collections::HashMap::new();

    // Hardware IDs first (source order), then compatible IDs (source order).
    for (kind, ordinal, id) in device
        .hardware_ids
        .iter()
        .enumerate()
        .map(|(ordinal, id)| (DeviceIdKind::Hardware, ordinal, id))
        .chain(
            device
                .compatible_ids
                .iter()
                .enumerate()
                .map(|(ordinal, id)| (DeviceIdKind::Compatible, ordinal, id)),
        )
    {
        for catalog in catalogs {
            // The remaining per-device candidate budget is checked BEFORE the
            // lookup allocates: an untrusted bucket larger than the remainder
            // must fail closed instead of allocating a huge result `Vec`. The
            // seam's `max` IS the remaining budget, so its rejection is exactly
            // a candidate-budget breach and surfaces as `TooManyCandidates`.
            let remaining = MAX_CANDIDATES_PER_DEVICE.saturating_sub(candidates.len());
            match catalog.find_by_hwid_bounded(id, remaining) {
                Ok(found) => {
                    for candidate in found {
                        let key = CandidateKey {
                            pack_name: catalog.pack_name.clone(),
                            inf_path: candidate.inf_path.clone(),
                            inf_filename: candidate.inf_filename.clone(),
                            install_section: candidate.install_section.clone(),
                            picked_section: candidate.picked_section.clone(),
                            sect_pos: candidate.sect_pos,
                            models_section: candidate.models_section.clone(),
                        };
                        let evidence = MatchEvidence {
                            kind,
                            device_id: id.clone(),
                            ordinal,
                            inf_pos: candidate.inf_pos,
                        };

                        match key_to_index.get(&key) {
                            Some(&idx) => {
                                let slot = &mut candidates[idx];
                                if slot.evidence.len() >= MAX_EVIDENCE_PER_CANDIDATE {
                                    return Err(MatchError::TooMuchEvidence);
                                }
                                slot.evidence.push(evidence);
                            }
                            None => {
                                if candidates.len() >= MAX_CANDIDATES_PER_DEVICE {
                                    return Err(MatchError::TooManyCandidates);
                                }
                                if *total_candidates >= MAX_TOTAL_CANDIDATES {
                                    return Err(MatchError::TooManyTotalCandidates);
                                }
                                key_to_index.insert(key, candidates.len());
                                candidates.push(CatalogCandidateMatch {
                                    pack_name: catalog.pack_name.clone(),
                                    candidate,
                                    evidence: vec![evidence],
                                });
                                *total_candidates += 1;
                            }
                        }
                    }
                }
                Err(SdioError::LookupBucketTooLarge { .. }) => {
                    return Err(MatchError::TooManyCandidates);
                }
                Err(e) => return Err(MatchError::Catalog(e)),
            }
        }
    }

    Ok(DeviceCatalogMatches {
        instance_id: device.instance_id.clone(),
        candidates,
    })
}

/// Deterministic identity of one logical candidate within one pack. `inf_pos` is
/// deliberately excluded: it is per-HWID SDIO metadata that belongs in evidence,
/// not part of the installable model identity.
///
/// `sect_pos` + `models_section` are included (Gate A4): SDIO indexes can carry
/// otherwise-identical rows — same INF, install section, picked section — that
/// differ only by the Models-section target decoration (`sect_pos`), and an
/// undecorated base name (`sect_pos == 0`) must never collapse with a
/// decorated entry that happens to share identical text. Without them those
/// rows would collapse and lose OS-applicability provenance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CandidateKey {
    pack_name: String,
    inf_path: String,
    inf_filename: String,
    install_section: String,
    picked_section: String,
    sect_pos: i32,
    models_section: Option<String>,
}
