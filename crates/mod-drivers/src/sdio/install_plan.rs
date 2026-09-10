//! Read-only install-plan builder (Tab 2a-7, Option C).
//!
//! A plan is a typed description of what a future privileged install
//! lifecycle (Tab 2a-8) would be permitted to attempt *if* it re-verifies
//! the exact staged package immediately before mutation. The plan is
//!
//! - **not** a command string (no `pnputil /add-driver …` argv anywhere);
//! - **not** an execution object (no process invocation, no driver-store
//!   mutation, no restore point, no device mutation);
//! - **not** persisted (no JSON cache, no database row, no registry entry);
//! - **not** a success claim (the plan can only say "Ready" or "Blocked",
//!   never "Installed" / "Succeeded" / "Applied").
//!
//! A plan entry is produced only when the candidate was assessed
//! `HostCompatible` by the 2a-4 applicability layer AND the Windows
//! trust gate produced a [`VerifiedDriverPackage`]. Any other
//! combination yields no ready entry, and a [`PlanBlockReason`] is
//! returned so the caller can audit why.
//!
//! # Classification preservation
//!
//! The plan never re-implements ranking, date, version, or OEM-vs-generic
//! logic. It preserves the exact [`CatalogApplicabilityEvidence`]
//! supplied by the 2a-4 layer. Existing assessment is authoritative;
//! 2a-7 only attaches its trust gate.

use std::path::{Path, PathBuf};

use crate::sdio::applicability::{
    AssessedCatalogCandidate, AssessedDeviceMatches, CatalogOsApplicability,
};
use crate::sdio::local_pack::{LocalPackAvailability, resolve_local_pack};
use crate::sdio::matching::CatalogCandidateMatch;
use crate::sdio::signature::VerifiedDriverPackage;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Why a candidate did not produce a ready install entry.
///
/// Anything here means the caller must not attempt to install the
/// candidate. There is no "force", "trust-once", or warning-only mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanBlockReason {
    /// 2a-4 said the candidate is excluded from this host.
    #[error("candidate is not applicable to this host: {0}")]
    HostIncompatible(&'static str),
    /// 2a-4 could not prove applicability (Indeterminate). The plan
    /// builder never silently promotes Indeterminate to installable.
    #[error("candidate applicability is indeterminate: {0}")]
    Indeterminate(&'static str),
    /// The Windows-native trust gate did not return a verified package.
    /// Detailed reason is on the [`VerifiedDriverPackage`] attempt itself
    /// (in [`InstallPlanBuilder::build`]); this variant only records the
    /// fact that the gate failed at the plan layer.
    #[error("Windows trust gate did not verify the package")]
    Unverified,
    /// The candidate identity and the verified package identity disagree
    /// (different pack, different INF, or different staging root). This
    /// is a hard invariant: `verified A / plan B` is never allowed.
    #[error("verified package identity does not match the candidate")]
    IdentityMismatch,
    /// The builder received inconsistent inputs (e.g. verified package
    /// not for this candidate's device).
    #[error("install-plan builder received inconsistent inputs")]
    InconsistentInputs,
}

// ---------------------------------------------------------------------------
// Install plan
// ---------------------------------------------------------------------------

/// One ready install entry, BORROWING the live verified package.
///
/// The entry does not own the trust token and cannot copy it. The `'v`
/// lifetime is the hard invariant: an entry cannot outlive the
/// [`VerifiedDriverPackage`] whose live filesystem lease (retained handles +
/// namespace pins) is what authorizes it. The compiler enforces that, not a
/// runtime check — a plan built from a token that is later dropped simply
/// does not compile.
///
/// `PartialEq`/`Eq` are deliberately absent: the token is a capability, not a
/// value, and comparing entries by value would invite substitution reasoning.
#[derive(Debug, Clone)]
pub struct InstallPlanEntry<'v> {
    /// Target device identity (the `DeviceIdentity` the plan was built
    /// for). The plan is per-device; no cross-device substitution.
    target_device: TargetDeviceRef,
    /// Candidate provenance, exactly as 2a-3 / 2a-4 produced it. The
    /// plan never recomputes rank/date/version/OEM-vs-generic.
    candidate: CatalogCandidateMatch,
    /// Applicability evidence from 2a-4, preserved verbatim.
    applicability: CatalogApplicabilityEvidenceRef,
    /// The live verified package, BORROWED. Never owned, never cloned.
    verified: &'v VerifiedDriverPackage,
}

/// Reference to the target device. Only the fields the install lifecycle
/// needs; the full `DeviceIdentity` is not duplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDeviceRef {
    /// The Windows device-instance primary key. Never derived from
    /// hardware IDs.
    pub instance_id: String,
}

/// Reference to 2a-4's applicability evidence, narrowed to the fields
/// the plan carries. The plan is not a copy; the values are owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogApplicabilityEvidenceRef {
    /// The resolved status, preserved verbatim from 2a-4.
    pub status: CatalogOsApplicability,
    /// The reason code, preserved verbatim.
    pub reason_code: String,
    /// Optional Models-section target provenance.
    pub models_section: Option<String>,
    /// Optional parsed TargetOSVersion decoration.
    pub target: Option<String>,
}

impl CatalogApplicabilityEvidenceRef {
    /// Build the plan-side reference from the 2a-4 evidence. Pure copy;
    /// no re-evaluation.
    pub(crate) fn from_assessed(c: &AssessedCatalogCandidate) -> Self {
        let target = c.os.target.as_ref().map(|t| format!("{:?}", t));
        Self {
            status: c.os.status,
            reason_code: format!("{:?}", c.os.reason),
            models_section: c.os.models_section.clone(),
            target,
        }
    }
}

impl<'v> InstallPlanEntry<'v> {
    /// The target device-instance ID.
    pub fn target_device_instance_id(&self) -> &str {
        &self.target_device.instance_id
    }
    /// The candidate pack name (provenance, also used for logging).
    pub fn candidate_pack_name(&self) -> &str {
        &self.candidate.pack_name
    }
    /// The candidate INF filename (the leaf 2a-7 verified).
    pub fn candidate_inf_filename(&self) -> &str {
        &self.candidate.candidate.inf_filename
    }
    /// The exact verified INF path on disk.
    pub fn verified_inf_path(&self) -> &std::path::Path {
        self.verified.inf_path()
    }
    /// The catalog Windows chose for the verified package.
    pub fn catalog_name(&self) -> &str {
        self.verified.catalog_name()
    }
    /// The safe signer display string, if Windows supplied one.
    pub fn signer(&self) -> Option<&str> {
        self.verified.signer()
    }
    /// The applicability status (verbatim from 2a-4).
    pub fn applicability_status(&self) -> CatalogOsApplicability {
        self.applicability.status
    }
    /// The live [`VerifiedDriverPackage`] this entry borrows.
    ///
    /// Safe to expose: the plan already borrows the live token, and the token
    /// itself exposes no artifact, evidence, handle, or identity escape
    /// hatch. Reaching the staged artifact still requires consuming the token
    /// via `into_artifact`, which ends the trust guarantee.
    pub fn verified_package(&self) -> &'v VerifiedDriverPackage {
        self.verified
    }
}

/// The aggregate install plan for one target device. The plan is the
/// set of `ready` entries (one per verified candidate). A device with
/// no ready candidate produces an empty `ready` Vec; the device
/// identity is still in the plan so the consumer can show "no
/// installable plan" per device.
/// CF3 — a plan cannot outlive the token it borrows. Compiler RED: the
/// snippet fails only because `'a` cannot be extended to `'static`, which is
/// exactly the property that stops a plan from surviving its trust lease.
///
/// ```compile_fail
/// use mod_drivers::sdio::install_plan::InstallPlan;
/// fn escape<'a>(p: InstallPlan<'a>) -> InstallPlan<'static> { p }
/// ```
///
/// The companion positive case compiles, confirming the failure above is the
/// lifetime and not a typo in the path:
///
/// ```
/// use mod_drivers::sdio::install_plan::InstallPlan;
/// fn keep<'a>(p: InstallPlan<'a>) -> InstallPlan<'a> { p }
/// ```
#[derive(Debug, Clone)]
pub struct InstallPlan<'v> {
    target_device: TargetDeviceRef,
    /// Ready install entries in input order. The plan builder never
    /// re-sorts, re-ranks, or re-filters these.
    ready: Vec<InstallPlanEntry<'v>>,
}

impl<'v> InstallPlan<'v> {
    /// All ready install entries (input order).
    pub fn ready(&self) -> &[InstallPlanEntry<'v>] {
        &self.ready
    }
    /// The target device-instance ID.
    pub fn target_device_instance_id(&self) -> &str {
        &self.target_device.instance_id
    }
}

// ---------------------------------------------------------------------------
// Plan builder
// ---------------------------------------------------------------------------

/// Pure, non-mutating install-plan builder.
///
/// Construct with a device-bound assessment ([`AssessedDeviceMatches`]); call
/// [`build`] for each (candidate, verified package) pair. The builder
/// preserves candidate classification, never promotes/demotes, and only emits
/// a ready entry when every gate passes. The plan's target-device identity is
/// always the device the assessment was computed for — it can never be an
/// arbitrary caller-supplied string stamped onto a foreign candidate.
pub struct InstallPlanBuilder<'a> {
    device: &'a AssessedDeviceMatches,
    /// The operator's explicit SDIO drivers root — the SAME root the 2a-5
    /// resolver used to produce the materialization request that the staged,
    /// verified artifact came from. It is required, not optional: without it
    /// the builder has no authoritative way to turn an assessed candidate
    /// back into the package OBJECT it describes, and would be reduced to
    /// comparing labels.
    drivers_root: PathBuf,
}

impl<'a> InstallPlanBuilder<'a> {
    /// Construct a builder bound to one device's assessed matches and to the
    /// explicit drivers root those candidates resolve against. The
    /// target-device instance ID is taken from the assessment itself; the
    /// plan is per-device and cross-device reuse is a hard error.
    pub fn new(device: &'a AssessedDeviceMatches, drivers_root: &Path) -> Self {
        Self {
            device,
            drivers_root: drivers_root.to_path_buf(),
        }
    }

    /// The device-instance ID this builder is bound to (from the assessment).
    pub fn device_instance_id(&self) -> &str {
        &self.device.instance_id
    }

    /// Build the plan for one (candidate, verified-package) pair.
    ///
    /// The candidate must be one of this device's assessed candidates; a
    /// candidate from another device is rejected with
    /// [`PlanBlockReason::InconsistentInputs`] before any entry is emitted.
    ///
    /// Returns:
    /// - `Ok(Some(entry))` — the only branch that may produce a ready
    ///   install entry, and only when the 2a-4 status is
    ///   [`CatalogOsApplicability::HostCompatible`] AND the package
    ///   was [`VerifiedDriverPackage`] AND the identities match.
    /// - `Ok(None)` — the candidate was assessed but did not qualify
    ///   (e.g. Indeterminate, or no verified package was supplied).
    /// - `Err(PlanBlockReason::IdentityMismatch)` — the verified
    ///   package's pack/member identity does not match the candidate.
    ///   This is a hard invariant: verify A but plan B is forbidden.
    /// - `Err(PlanBlockReason::InconsistentInputs)` — the candidate is
    ///   not one of this device's assessed candidates.
    pub fn build<'v>(
        &self,
        candidate: &AssessedCatalogCandidate,
        verified: Option<&'v VerifiedDriverPackage>,
    ) -> Result<Option<InstallPlanEntry<'v>>, PlanBlockReason> {
        if self.device.instance_id.is_empty() {
            return Err(PlanBlockReason::InconsistentInputs);
        }

        // Gate 0: the candidate must be one of THIS device's assessed
        // candidates — by identity, not by value. Value equality cannot
        // distinguish an identical candidate assessed for another device;
        // only the actual assessed instance (pointer identity within the
        // device's candidate list) is accepted. A foreign candidate is a
        // hard error, never a re-stamping.
        if !self
            .device
            .candidates
            .iter()
            .any(|c| std::ptr::eq(c, candidate))
        {
            return Err(PlanBlockReason::InconsistentInputs);
        }

        // Gate 1: applicability must be HostCompatible. Anything else
        // (HostIncompatible, Indeterminate) is non-installable.
        match candidate.os.status {
            CatalogOsApplicability::HostCompatible => {}
            CatalogOsApplicability::HostIncompatible => {
                return Ok(None);
            }
            CatalogOsApplicability::Indeterminate => {
                return Ok(None);
            }
        }

        // Gate 2: a verified package is required.
        let verified = match verified {
            Some(v) => v,
            None => return Ok(None),
        };

        // Gate 3: PACKAGE-OBJECT binding between candidate and verified token.
        //
        // Verify A / plan B is the most common mutation class, and comparing
        // labels does not close it. `pack_name` and the archive-member string
        // are names: two different archives under two different roots can
        // carry the same pack name and the same member and still be different
        // packages with different bytes. Comparing only those authorizes a
        // downgrade or a mirror substitution.
        //
        // So resolve the candidate back into a package OBJECT through the same
        // authoritative 2a-5 resolver that produced the request the artifact
        // was staged from, and require that object to be the one the token
        // owns. `resolve_local_pack` canonicalizes `<root>\<pack_name>.7z` and
        // validates the INF/catalog members, so its output is the resolver's
        // identity, not a string this layer invented.
        //
        // A candidate whose pack cannot be resolved at plan time is NOT
        // installable: the token cannot be shown to describe it.
        let resolved = match resolve_local_pack(&self.drivers_root, &candidate.matched) {
            Ok(LocalPackAvailability::Present(request)) => request,
            // Missing pack or a rejected root/member: fail closed. Never fall
            // back to a label comparison.
            Ok(LocalPackAvailability::Missing { .. }) | Err(_) => {
                return Err(PlanBlockReason::IdentityMismatch);
            }
        };

        // 3a — the exact package object (canonical `.7z` path). This is the
        // check that distinguishes archive A from archive B.
        if resolved.pack().archive_path() != verified.pack_archive_path() {
            return Err(PlanBlockReason::IdentityMismatch);
        }
        // 3b — the pack name, from the resolved object rather than the raw
        // label, so the two can never disagree silently.
        if resolved.pack().pack_name() != verified.pack_name() {
            return Err(PlanBlockReason::IdentityMismatch);
        }
        // 3c — the COMPLETE expected member path, not the leaf: a leaf-only
        // comparison would let `dirA/driver.inf` pass for a `dirB/driver.inf`
        // plan entry.
        if resolved.inf().relative_path() != verified.expected_archive_member() {
            return Err(PlanBlockReason::IdentityMismatch);
        }
        // 3d — catalog provenance. The catalog is what Windows checks the INF
        // against, so a candidate naming a different catalog (or naming one
        // where the verified package had none, or vice versa) describes a
        // different package contract. Compared case-insensitively because the
        // staged leaf preserves the ARCHIVE spelling, which may differ from
        // the INF's spelling only by ASCII case.
        let candidate_catalog_leaf = resolved
            .catalog()
            .map(|c| leaf_of_member(c.relative_path()));
        match (candidate_catalog_leaf, verified.expected_catalog_leaf()) {
            (None, None) => {}
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            _ => return Err(PlanBlockReason::IdentityMismatch),
        }

        Ok(Some(InstallPlanEntry {
            target_device: TargetDeviceRef {
                instance_id: self.device.instance_id.clone(),
            },
            candidate: candidate.matched.clone(),
            applicability: CatalogApplicabilityEvidenceRef::from_assessed(candidate),
            // BORROWED, never cloned: the entry's lifetime is tied to the
            // live token, so it cannot outlive the lease that authorizes it.
            verified,
        }))
    }

    /// Convenience: build a plan with no candidate yet (always empty).
    pub fn empty_plan<'v>(&self) -> InstallPlan<'v> {
        InstallPlan {
            target_device: TargetDeviceRef {
                instance_id: self.device.instance_id.clone(),
            },
            ready: Vec::new(),
        }
    }

    /// Convenience: build the aggregate plan from an iteration of
    /// `(assessed, verified_opt)` pairs, preserving input order.
    pub fn build_plan<'b, I>(&self, candidates: I) -> InstallPlan<'b>
    where
        I: IntoIterator<
            Item = (
                &'b AssessedCatalogCandidate,
                Option<&'b VerifiedDriverPackage>,
            ),
        >,
    {
        let mut ready = Vec::new();
        for (c, v) in candidates {
            if let Ok(Some(entry)) = self.build(c, v) {
                ready.push(entry);
            }
        }
        InstallPlan {
            target_device: TargetDeviceRef {
                instance_id: self.device.instance_id.clone(),
            },
            ready,
        }
    }
}

/// The bare leaf of a validated archive member path (`/`-separated). The
/// staged artifact records the catalog by leaf, so the comparison happens at
/// the same granularity; the member's DIRECTORY is already pinned by the INF
/// member comparison in gate 3c, which shares that directory.
fn leaf_of_member(member: &str) -> &str {
    member.rsplit('/').next().unwrap_or(member)
}
