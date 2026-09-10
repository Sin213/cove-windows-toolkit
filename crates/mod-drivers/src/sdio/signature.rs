//! Windows-native driver-package trust verification (Tab 2a-7, Option C).
//!
//! Validates the extracted driver package through Windows' own trust facility
//! for INF + catalog-signed driver packages. The trust anchor is the exact
//! staged INF produced by the 2a-6 layer, bound to its INF->catalog->catalog-
//! signature chain. No other trust source is consulted; no network access
//! occurs; no shell, no certutil, no signtool.
//!
//! # Trust boundary
//!
//! [`DriverPackageVerifier::verify`] is the security boundary. Anything that
//! has not come out of this function with [`TrustResult::Trusted`] is
//! non-installable in the install-plan gate.
//!
//! Archive SHA-256 (acquisition integrity) is *not* driver authenticity. It
//! proves downloaded bytes match expected metadata, not that the publisher is
//! trustworthy. Windows signature/catalog verification is the distinct
//! required gate.
//!
//! # Offline / no-network policy
//!
//! `SetupVerifyInfFileW` evaluates locally available catalog and embedded
//! signature state. It does not intentionally fetch certificate chains, CRLs,
//! or OCSP over the network in its standard form. The slice does not enable
//! any network-touching revocation policy.
//!
//! # No general INF parsing
//!
//! This slice never reads the INF's content itself. Windows resolves the
//! `[Version]` CatalogFile internally; the slice only asks Windows whether
//! the resulting package is trusted, and reads back the catalog filename
//! Windows chose. If Windows' internal resolver can't bind the INF to a
//! catalog, the result is `Untrusted` / `CatalogMissing` / `Unknown`, never
//! "the first .cat we found".

use std::fs;
use std::path::{Path, PathBuf};

use crate::sdio::extraction::StagedInfArtifact;

// The `test-inject` feature exposes `DriverPackageVerifier::with_check_fn`,
// which can manufacture a `Trusted` result and therefore a
// `VerifiedDriverPackage` without consulting Windows at all. Being absent from
// the default feature set is only a *policy*: `--all-features`, explicit
// feature forwarding, or Cargo's feature unification across a dependency graph
// can all switch it on in a shipped build.
//
// This turns that policy into ENFORCEMENT. A build with optimizations and
// without debug assertions is a release/production build, and the seam must
// not exist in one. Compilation fails loudly instead of silently shipping a
// trust bypass.
#[cfg(all(feature = "test-inject", not(debug_assertions), not(test)))]
compile_error!(
    "the `test-inject` feature exposes a trust-injection seam that can fabricate a \
     VerifiedDriverPackage without Windows verification; it must never be enabled in a \
     release build. Build tests with debug assertions enabled, or drop the feature."
);

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Fail-closed reasons the native Windows trust contract rejected a package.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TrustError {
    /// The resolved INF path escaped its staging root. Rejecting before
    /// any trust call is the hard invariant: no path traversal can ever
    /// reach `SetupVerifyInfFileW`.
    #[error("candidate INF path escapes its staging root")]
    InfEscapesStaging,
    /// The candidate's relative identity could not be safely rejoined
    /// (absolute path, drive prefix, UNC, reparse-point, parent traversal,
    /// reserved DOS name, trailing dot/space, NUL byte, non-ASCII, or
    /// overlong component).
    #[error("candidate INF relative identity is unsafe: {0}")]
    UnsafeInfIdentity(String),
    /// The INF was not a regular file under the staging root (symlink,
    /// reparse point, directory, or absent after extraction).
    #[error("staged INF is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    /// The staged INF is empty.
    #[error("staged INF is empty")]
    EmptyInf,
    /// The INF file exceeded the absolute size cap.
    #[error("staged INF exceeds size cap of {MAX_STAGED_INF_BYTES} bytes")]
    InfTooLarge,
    /// Windows reported the package is unsigned (no catalog, no embedded
    /// signature, or no trust anchor found). `Trusted` is the only state
    /// that produces a ready install entry.
    #[error("unsigned driver package")]
    Unsigned,
    /// Windows reported the signature is present but not trusted.
    #[error("untrusted driver package signature")]
    Untrusted,
    /// Windows could not find a catalog for the INF.
    #[error("no driver catalog resolved for the staged INF")]
    CatalogMissing,
    /// The INF references a catalog that is not staged beside it.
    #[error("catalog for the staged INF is not staged beside it")]
    CatalogNotStaged,
    /// The staged bytes are not the bytes extraction produced.
    ///
    /// Object identity alone cannot detect this: an in-place overwrite keeps
    /// the FileId, and a write through a memory-mapped view can happen even
    /// after every handle that created the mapping has been closed — share
    /// modes govern opens, not existing mapped views. The verifier therefore
    /// re-fingerprints the staged content before AND after the native trust
    /// call, and on every re-attestation. Any difference fails closed.
    #[error("staged driver package bytes changed after extraction")]
    StagedBytesChanged,
    /// Windows reported a malformed package.
    #[error("malformed driver package")]
    Malformed,
    /// Windows reported an API error that the verifier cannot safely map
    /// to a more specific state. Fail closed: this is never treated as a
    /// pass.
    #[error("native trust API error (win32={0})")]
    NativeApiError(u32),
    /// Trust verification is not available on the current platform (Linux
    /// CI host, etc.). The install-plan gate must classify this as
    /// non-installable, same as Unsigned.
    #[error("Windows trust verification is unavailable on this platform")]
    Unavailable,
    /// An attempt to fabricate a [`VerifiedDriverPackage`] outside the
    /// verifier was rejected. This variant is not produced by the verifier
    /// itself; it is the rejection of an attempt to construct the verified
    /// type by other means.
    #[error("VerifiedDriverPackage construction is controlled; this attempt was rejected")]
    ConstructionControlled,
}

/// Maximum bytes the staged INF may be. INF files are tiny; this is a hard
/// ceiling well above any legitimate driver package's primary INF.
pub const MAX_STAGED_INF_BYTES: u64 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Trust result
// ---------------------------------------------------------------------------

/// The Windows-native driver-package trust result.
///
/// A `bool` cannot distinguish unsigned from invalid-signature from unknown-
/// trust, so the install-plan gate requires [`TrustResult::Trusted`]
/// explicitly. Every other variant is non-installable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustResult {
    /// Windows resolved the exact INF, located the catalog it points to,
    /// and verified the catalog signature against the local trust store.
    /// `catalog_name` is the catalog Windows associated with the package
    /// (a bare filename, never an attacker-controlled path).
    ///
    /// `reported_catalog_path` (Windows production only) is the FULL path
    /// SetupAPI reported in `SP_INF_SIGNER_INFO_V2_W.CatalogFile`. The
    /// verifier binds THAT object's identity to the extraction-time staged
    /// catalog identity (F2) — never a leaf-reduced self-comparison. The
    /// fake-test seam leaves it `None` and uses the leaf form.
    Trusted {
        catalog_name: String,
        signer: Option<String>,
        #[cfg(windows)]
        reported_catalog_path: Option<String>,
    },
    /// Rejected (see [`TrustError`]). The install-plan gate must produce
    /// no ready entry for any value of `Untrusted`.
    Untrusted(TrustError),
}

impl TrustResult {
    /// True only for `Trusted`. The single gate condition.
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustResult::Trusted { .. })
    }
}

// ---------------------------------------------------------------------------
// VerifyRejected (failure carries the artifact back)
// ---------------------------------------------------------------------------

/// A rejected verification attempt, carrying the staged artifact back.
///
/// Because [`DriverPackageVerifier::verify`] consumes the
/// [`StagedInfArtifact`], a failure would otherwise strand it — the artifact
/// is not `Clone`, and re-extracting it would produce different bytes with a
/// different object identity, weakening provenance. So the failure path
/// returns the ORIGINAL artifact, untouched, and a transient rejection can be
/// retried against exactly the same staged objects.
///
/// This is not `Clone` (it owns the artifact's live lease) and it is not a
/// trust claim: no [`VerifiedDriverPackage`] exists for any value of this
/// type.
#[derive(Debug)]
pub struct VerifyRejected {
    /// Why the package was rejected.
    pub error: TrustError,
    /// The original staged artifact, returned so the caller may retry.
    pub artifact: StagedInfArtifact,
}

impl VerifyRejected {
    /// The rejection reason.
    pub fn error(&self) -> &TrustError {
        &self.error
    }
    /// Consume the rejection and take the staged artifact back.
    pub fn into_artifact(self) -> StagedInfArtifact {
        self.artifact
    }
}

impl std::fmt::Display for VerifyRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for VerifyRejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

// ---------------------------------------------------------------------------
// RetainedEvidence (live guards, not a snapshot)
// ---------------------------------------------------------------------------

/// The live security evidence that justifies a `Trusted` result.
///
/// Every field is either an RAII guard whose *continued existence* is the
/// guarantee, or the identity that guard was bound to. This is **not** a
/// snapshot: dropping this struct releases the namespace pins and the file
/// locks, and at that instant the staged bytes are no longer protected.
///
/// It is private and non-`Clone` by construction (its guard fields are not
/// `Clone`), so it cannot be duplicated or fabricated outside `verify`.
///
/// In Tab 2a-7R this value is what [`VerifiedDriverPackage`] will own, so that
/// a trust token cannot outlive the evidence that justified it. The guards
/// were previously function-local bindings in `verify` and dropped when it
/// returned; aggregating them here does not change when they drop.
struct RetainedEvidence {
    // The three guards below are never *read*, and that is correct: their
    // security value is their LIFETIME, not their value. Each holds an OS
    // handle whose continued existence is what blocks rename, delete, and
    // write of the staged namespace; they do their work by existing and by
    // being dropped, never by being inspected. The allowance is scoped to
    // exactly these fields — do not widen it, and do not silence the lint by
    // renaming them with `_` prefixes (they are live ownership state, and a
    // `_` prefix would falsely mark them unused).
    /// Pins on EVERY directory above the staging root, up to (but excluding)
    /// the volume root. The volume-GUID prefix stabilizes which volume the
    /// trust path names; it does NOT turn the directory components below it
    /// into object references, so each of those components is pinned too or
    /// an attacker could rename an unpinned ancestor and rebuild the same
    /// pathname over a different INF between deriving the path and SetupAPI
    /// opening it. A volume root has no parent directory entry and cannot be
    /// renamed, so it needs no pin.
    #[allow(dead_code)]
    ancestor_pins: Vec<DirPinGuard>,
    /// Pin on the canonical staging root (the child's parent). Blocks
    /// rename/delete of the ancestor directory.
    #[allow(dead_code)]
    root_pin: DirPinGuard,
    /// Pin on the staging child directory itself. Blocks rename/delete of
    /// the directory the INF and catalog live in.
    #[allow(dead_code)]
    child_pin: DirPinGuard,
    /// Lock on the exact staged INF object, opened relative to `child_pin`.
    /// Withholds write + delete sharing.
    #[allow(dead_code)]
    inf_lock: FileLockGuard,
    /// Lock on the staged catalog object, when the package named one.
    catalog_lock: Option<FileLockGuard>,
    /// Object identity captured from the held INF lock. Bound to the
    /// artifact's extraction-time identity before this struct is built.
    inf_identity: Option<FileObjectIdentity>,
    /// Object identity captured from the held catalog lock, when present.
    catalog_identity: Option<FileObjectIdentity>,
    /// Content fingerprint of the staged INF, bound to the extraction-time
    /// fingerprint. Re-checked after the native call and on re-attestation,
    /// because identity cannot see an in-place or mapped-view overwrite.
    #[cfg(windows)]
    inf_digest: crate::sdio::extraction::StagedContentDigest,
    /// Content fingerprint of the staged catalog, when the package named one.
    #[cfg(windows)]
    catalog_digest: Option<crate::sdio::extraction::StagedContentDigest>,
    /// The stable volume-GUID path that authorized the trust call. This is
    /// the only path form a consumer may use; the drive-letter form is
    /// deliberately not retained.
    stable_inf_path: PathBuf,
}

/// Redacted `Debug`. The guards wrap raw OS handles; formatting them would
/// leak handle values into logs and error messages. Only presence and the
/// stable path are reported.
impl std::fmt::Debug for RetainedEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedEvidence")
            .field("root_pin", &"<pinned>")
            .field("child_pin", &"<pinned>")
            .field("inf_lock", &"<locked>")
            .field(
                "catalog_lock",
                &self.catalog_lock.as_ref().map(|_| "<locked>"),
            )
            .field("inf_identity", &self.inf_identity.is_some())
            .field("catalog_identity", &self.catalog_identity.is_some())
            .field("stable_inf_path", &self.stable_inf_path)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Catalog evidence consistency (pure classification)
// ---------------------------------------------------------------------------

/// How the retained catalog evidence classifies, once proven self-consistent.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatalogEvidenceState {
    /// No catalog was staged — the legitimate embedded-signature case. There
    /// is nothing to re-check.
    NoCatalog,
    /// A retained catalog lock AND its recorded identity are both present, so
    /// the live handle identity comparison must run.
    CatalogBacked,
}

/// Classify the retained catalog evidence from PRESENCE ALONE.
///
/// Deliberately pure and capability-free: it takes two booleans and no handle,
/// guard, identity value, artifact, or token. That is what makes the two
/// impossible states directly testable — they cannot be produced through
/// normal construction, because `verify` always records a catalog lock and its
/// identity together.
///
/// A half-present state is never normalized into success.
#[cfg(windows)]
fn catalog_evidence_state(
    has_catalog_lock: bool,
    catalog_identity_present: bool,
) -> Result<CatalogEvidenceState, TrustError> {
    match (has_catalog_lock, catalog_identity_present) {
        (false, false) => Ok(CatalogEvidenceState::NoCatalog),
        (true, true) => Ok(CatalogEvidenceState::CatalogBacked),
        // Lock without identity, or identity without lock: impossible, fail closed.
        (true, false) | (false, true) => Err(TrustError::CatalogNotStaged),
    }
}

// ---------------------------------------------------------------------------
// VerifiedDriverPackage (controlled construction)
// ---------------------------------------------------------------------------

/// A driver package whose Windows-native trust result was `Trusted`.
///
/// Construction is controlled: only [`DriverPackageVerifier::verify`] can
/// produce one. The struct's fields are private; downstream code cannot
/// fabricate a verified package with an arbitrary path or a fake
/// `Trusted` classification. The type system is the gate.
/// # Non-`Clone` is load-bearing
///
/// Neither this type nor [`StagedInfArtifact`] is `Clone`, `Copy`, or wrapped
/// in a cloning container, and that is a security property rather than an
/// oversight. Ownership of this token *is* the live filesystem trust lease:
/// it owns the retained extraction handles and the namespace pins/locks that
/// keep the staged bytes from being substituted. A second copy of the token
/// would be a second claim of trust backed by only one set of guards, and
/// dropping either copy would release guards the other still relies on. Do
/// not add `Clone`/`Copy`, and do not reintroduce copying indirectly through
/// `Arc` or a wrapper type.
///
/// CF1 — the token is not `Clone`. This is a compiler RED: the only reason the
/// snippet fails is the missing `Clone` bound.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<mod_drivers::sdio::signature::VerifiedDriverPackage>();
/// ```
#[derive(Debug)]
pub struct VerifiedDriverPackage {
    /// The staged artifact, **owned**. Holding it keeps the 2a-6 F3 lease
    /// handles open. Deliberately not exposed by reference: see
    /// [`VerifiedDriverPackage::into_artifact`].
    artifact: StagedInfArtifact,
    /// The live guards that justify the `Trusted` result, **owned**. While
    /// this token is alive the staging namespace stays pinned.
    evidence: RetainedEvidence,
    /// Catalog Windows chose (bare filename, not a path).
    catalog_name: String,
    /// Safe signer display string, when Windows supplied one.
    signer: Option<String>,
}

impl VerifiedDriverPackage {
    /// The stable verification path that authorized the trust result.
    ///
    /// This is the path form carried in the retained evidence — the same one
    /// the native trust call was made against. The staged artifact's ordinary
    /// drive-letter path is deliberately NOT reachable while this token is
    /// alive; recovering it requires consuming the token via
    /// [`VerifiedDriverPackage::into_artifact`], which ends the guarantee.
    pub fn inf_path(&self) -> &Path {
        &self.evidence.stable_inf_path
    }
    /// The catalog Windows associated with the package (bare filename).
    pub fn catalog_name(&self) -> &str {
        &self.catalog_name
    }
    /// Safe signer display string, if any.
    pub fn signer(&self) -> Option<&str> {
        self.signer.as_deref()
    }
    /// 2a-5 pack name (derived from the owned artifact).
    pub fn pack_name(&self) -> &str {
        self.artifact.pack_name()
    }
    /// The exact archive member the 2a-6 layer materialized (derived from
    /// the owned artifact).
    pub fn expected_archive_member(&self) -> &str {
        self.artifact.expected_archive_member()
    }
    /// The canonical 2a-5 pack archive path (derived from the owned
    /// artifact).
    pub fn pack_archive_path(&self) -> &Path {
        self.artifact.pack_archive_path()
    }
    /// The catalog leaf this package was STAGED with — the 2a-5 catalog
    /// provenance, not the catalog string Windows reported back
    /// ([`VerifiedDriverPackage::catalog_name`]). The plan gate compares this
    /// against the candidate's own resolved catalog member, so a candidate
    /// naming a different catalog cannot be authorized by this token.
    pub fn expected_catalog_leaf(&self) -> Option<&str> {
        self.artifact.catalog_leaf()
    }

    /// Re-prove, from the RETAINED HANDLES, that this token still refers to
    /// the same objects it was verified against.
    ///
    /// This is the enforced replacement for the prose obligation that a
    /// privileged install lifecycle must "re-verify the exact staged package
    /// immediately before mutation". Call it immediately before any mutation.
    ///
    /// It is a check on the existing live ownership lease, NOT a second
    /// verification constructor: it produces no new token, clones nothing,
    /// releases no pin or lock, and never reopens the INF or catalog by
    /// pathname. `stable_inf_path` is deliberately not consulted as an
    /// authority — a pathname can be redirected, an open handle cannot. The
    /// retained object identities are the only evidence used.
    ///
    /// Fails closed on mismatch, on inability to prove identity, and on any
    /// internally inconsistent catalog evidence.
    pub fn reattest(&self) -> Result<(), TrustError> {
        #[cfg(windows)]
        {
            // INF: re-read identity from the handle the evidence already
            // holds, and require it to equal the identity captured when this
            // token was verified.
            let expected_inf = self
                .evidence
                .inf_identity
                .ok_or_else(|| TrustError::NotRegularFile(self.evidence.stable_inf_path.clone()))?;
            let current_inf = identity_of_lock_guard(&self.evidence.inf_lock)
                .ok_or_else(|| TrustError::NotRegularFile(self.evidence.stable_inf_path.clone()))?;
            if current_inf != expected_inf {
                return Err(TrustError::InfEscapesStaging);
            }
            // Identity is not sufficient on its own. A writable memory-mapped
            // view survives the close of every handle that created it, and no
            // share mode revokes it, so an attacker holding one can rewrite
            // the staged file in place at any time — leaving the FileId, and
            // therefore the check above, completely undisturbed. Re-read the
            // content through the retained lock and require it to be the bytes
            // that were verified.
            let current_inf_digest = digest_of_lock_guard(&self.evidence.inf_lock)
                .ok_or(TrustError::StagedBytesChanged)?;
            if current_inf_digest != self.evidence.inf_digest {
                return Err(TrustError::StagedBytesChanged);
            }

            // Catalog: the handle and the identity must agree about whether a
            // catalog exists at all. A half-present state is not normalized
            // into success — it is an impossible state and fails closed.
            // Step 2: classify the retained catalog evidence for
            // self-consistency. Presence only — no handle or identity value
            // crosses into the classifier.
            match catalog_evidence_state(
                self.evidence.catalog_lock.is_some(),
                self.evidence.catalog_identity.is_some(),
            )? {
                // Step 3: catalog-backed, so re-read the identity from the
                // retained catalog handle and compare. The handle read, the
                // FileId comparison, and the error mapping all stay here.
                CatalogEvidenceState::CatalogBacked => {
                    let catalog_lock = self
                        .evidence
                        .catalog_lock
                        .as_ref()
                        .ok_or(TrustError::CatalogNotStaged)?;
                    let expected_catalog = self
                        .evidence
                        .catalog_identity
                        .ok_or(TrustError::CatalogNotStaged)?;
                    let current_catalog =
                        identity_of_lock_guard(catalog_lock).ok_or(TrustError::CatalogNotStaged)?;
                    if current_catalog != expected_catalog {
                        return Err(TrustError::CatalogNotStaged);
                    }
                    // And the catalog content, for the same reason as the INF.
                    let expected_catalog_digest = self
                        .evidence
                        .catalog_digest
                        .ok_or(TrustError::StagedBytesChanged)?;
                    let current_catalog_digest =
                        digest_of_lock_guard(catalog_lock).ok_or(TrustError::StagedBytesChanged)?;
                    if current_catalog_digest != expected_catalog_digest {
                        return Err(TrustError::StagedBytesChanged);
                    }
                }
                // Legitimate absence: the package carried no staged catalog
                // (embedded-signature semantics). Nothing to re-check.
                CatalogEvidenceState::NoCatalog => {}
            }

            Ok(())
        }
        // No token can be constructed off Windows (the pins fail closed
        // first), so this arm is unreachable; it stays fail-closed rather
        // than asserting a guarantee the platform cannot provide.
        #[cfg(not(windows))]
        {
            Err(TrustError::Unavailable)
        }
    }

    /// Consume the token and hand the staged artifact back to the caller.
    ///
    /// This is the ONLY route from a verified token to the underlying
    /// [`StagedInfArtifact`], and it is deliberately consuming: the retained
    /// evidence is dropped first, releasing the namespace pins and file
    /// locks, so the trust guarantee ends at exactly the moment the artifact
    /// (and its ordinary drive-letter path) becomes reachable again. There is
    /// no borrowing accessor — a live token never lets a caller reach the
    /// artifact's own `inf_path()`.
    ///
    /// Ordinary destructuring; no `unsafe`, `ManuallyDrop`, or `mem::forget`.
    pub fn into_artifact(self) -> StagedInfArtifact {
        let VerifiedDriverPackage {
            artifact,
            evidence,
            catalog_name: _,
            signer: _,
        } = self;
        // Explicit: guards close BEFORE the artifact is returned.
        drop(evidence);
        artifact
    }
}

// ---------------------------------------------------------------------------
// Windows-native verifier
// ---------------------------------------------------------------------------

/// Windows-native driver-package verifier.
///
/// The only public way to produce a [`VerifiedDriverPackage`]. The verifier
/// is stateless; tests inject a custom verifier function via
/// [`DriverPackageVerifier::with_check_fn`] to exercise non-Windows paths
/// and to model the real Windows result enum without live certificates.
///
/// The injection seam is compiled only when the `test-inject` feature is
/// enabled (never in production builds), so downstream crates cannot
/// substitute an always-trusted check.
pub struct DriverPackageVerifier {
    check: CheckFn,
}

type CheckFn = fn(&Path) -> TrustResult;

impl DriverPackageVerifier {
    /// Construct the production verifier. It calls `SetupVerifyInfFileW`
    /// on Windows; on non-Windows platforms it returns `Unavailable` for
    /// every input (so tests can model the same result type and a future
    /// CI run on Linux classifies everything as non-installable).
    pub fn new() -> Self {
        Self {
            check: native_check,
        }
    }

    /// Test-only injection of a custom verifier function. Available only
    /// when the `test-inject` feature is enabled (dev/test builds). The
    /// custom function returns the same [`TrustResult`] enum as production,
    /// so fakes model production shapes.
    #[cfg(feature = "test-inject")]
    pub fn with_check_fn(check: CheckFn) -> Self {
        Self { check }
    }

    /// Verify the exact staged INF produced by the 2a-6 layer.
    ///
    /// Order of checks (every check is fail-closed):
    /// 1. Re-resolve the candidate's relative identity against the staging
    ///    root, refusing any path that escapes, traverses, contains a
    ///    drive/UNC prefix, NUL, reparse point, reserved DOS name, or
    ///    non-ASCII. **No `SetupVerifyInfFileW` call is reachable from a
    ///    path that fails this gate.**
    /// 2. `symlink_metadata` on the leaf (BEFORE canonicalization) to
    ///    reject symlinks/reparse points without following them.
    /// 3. `is_file` + non-zero size + size cap on the leaf.
    /// 4. Canonicalize the staging root and the resolved INF; require
    ///    the canonical INF's parent to equal the canonical staging root.
    /// 5. If the package carries a catalog, require the catalog to be
    ///    staged beside the INF (SetupAPI contract) and validate it the
    ///    same way (leaf symlink gate first).
    /// 6. The Windows-native trust call. Any `Untrusted(_)` outcome is
    ///    passed through; a `Trusted` outcome produces a
    ///    [`VerifiedDriverPackage`].
    // The `Err` variant is large (~304 bytes) because it deliberately carries
    // the whole `StagedInfArtifact` back to the caller — that IS the failure
    // contract, so a transient rejection can be retried against exactly the
    // same staged objects. Boxing it would add an allocation on every failure
    // path and hide the ownership transfer that is the point of the type.
    // Scoped to this function only.
    #[allow(clippy::result_large_err)]
    pub fn verify(
        &self,
        artifact: StagedInfArtifact,
    ) -> Result<VerifiedDriverPackage, VerifyRejected> {
        // Phase 3.5 ownership bridge. The verification body below is unchanged:
        // it still operates on `&artifact` with the same `?` / early-return
        // fail-closed control flow and the same gate ordering. Only the
        // ownership envelope is new — the body yields the retained evidence
        // plus the trust metadata, and this outer function decides where the
        // artifact goes (into the token on success, back to the caller on
        // failure). The full Phase 4 `verify_inner` extraction is deliberately
        // NOT performed here.
        let outcome = (|| -> Result<(RetainedEvidence, String, Option<String>), TrustError> {
            // Shadow with a borrow so every existing check below compiles
            // untouched. The closure therefore captures `artifact` by
            // reference, leaving it owned and movable once the call returns.
            let artifact = &artifact;
            let (staging, leaf) = self.resolve_under_staging(artifact)?;
            // Object-bound namespace guard (F1/F2): pin the canonical staging root
            // (the child's parent) and the staging child itself with DELETE-access
            // handles and FILE_SHARE_READ only. Empirically verified (design gate):
            // this combination makes `MoveFileEx` rename and `RemoveDirectory` of
            // the pinned directory FAIL with ERROR_SHARING_VIOLATION while the
            // guard is held. The namespace that `SetupVerifyInfFileW` resolves is
            // therefore genuinely STABLE for the whole native call — substitution
            // is prevented, not merely detected afterward.
            //
            // Pinning the child and its immediate parent is NOT enough. The
            // path handed to SetupAPI still contains every directory component
            // below the volume root, and any unpinned one can be renamed so the
            // same pathname is rebuilt over a different INF. Pin the whole
            // chain, top-down, then bind the child object.
            let staging_root = staging.parent().ok_or(TrustError::InfEscapesStaging)?;
            // Everything strictly ABOVE the staging root. The staging root
            // itself is `root_pin` below — pinning it twice would collide with
            // our own pin, because these pins withhold delete sharing and
            // `root_pin` asks for DELETE access.
            let ancestor_pins = pin_ancestors_above(staging_root)?;
            let root_pin = DirPinGuard::open_pinned(staging_root)?;
            let child_pin = DirPinGuard::open_pinned(&staging)?;

            // The chain is now immovable, but it was built one component at a
            // time. Prove the directory we ended up pinning is the exact
            // directory extraction created: if any component was swapped while
            // the chain was being taken, this pathname now resolves to a
            // different object and the identities differ.
            #[cfg(windows)]
            {
                let expected = artifact
                    .staging_dir_identity()
                    .ok_or(TrustError::InfEscapesStaging)?;
                let actual =
                    identity_of_dir_pin(&child_pin).ok_or(TrustError::InfEscapesStaging)?;
                if actual != expected {
                    return Err(TrustError::InfEscapesStaging);
                }
            }

            // Lock the exact INF object RELATIVE to the pinned child handle
            // (handle-relative open: RootDirectory = pinned child). The lock
            // withholds write+delete share; the object identity is captured from
            // the held handle. F1: that identity must EQUAL the extraction-time
            // INF identity recorded in the artifact — if the staged object was
            // replaced between materialization and verification, the FileId
            // differs and we fail closed here.
            let (inf_lock, inf_identity) = self.lock_inf_relative(&child_pin, &leaf)?;
            #[cfg(windows)]
            {
                let expected = artifact
                    .inf_identity()
                    .ok_or(TrustError::NotRegularFile(staging.join(&leaf)))?;
                let actual = inf_identity.ok_or(TrustError::NotRegularFile(staging.join(&leaf)))?;
                if actual != expected {
                    return Err(TrustError::InfEscapesStaging);
                }
            }
            let _ = &inf_identity;

            // Bind the staged CONTENT, not just the object. The identity check
            // above cannot see an in-place overwrite performed between
            // materialization and here — an overwrite leaves the FileId
            // untouched — so the fingerprint taken through the extraction-time
            // creation handle must still describe what this lock holds.
            #[cfg(windows)]
            let inf_digest = {
                let expected = artifact
                    .inf_digest()
                    .ok_or(TrustError::StagedBytesChanged)?;
                let actual =
                    digest_of_lock_guard(&inf_lock).ok_or(TrustError::StagedBytesChanged)?;
                if actual != expected {
                    return Err(TrustError::StagedBytesChanged);
                }
                actual
            };

            // Lock the expected catalog RELATIVE to the pinned child handle (when
            // the artifact derived one). Its object identity is captured. F1: it
            // must equal the artifact's extraction-time catalog identity.
            let catalog_lock = match artifact.catalog_leaf() {
                Some(cat) => {
                    let norm = cat.trim();
                    validate_single_component(norm).map_err(|e| {
                        TrustError::UnsafeInfIdentity(format!("catalog {norm}: {e}"))
                    })?;
                    // The catalog must be present and lockable, else fail closed.
                    match open_relative_locked(child_pin.handle(), norm) {
                        Ok((guard, identity)) => {
                            #[cfg(windows)]
                            {
                                let expected = artifact
                                    .catalog_identity()
                                    .ok_or(TrustError::CatalogNotStaged)?;
                                // F3: the artifact must RETAIN the catalog creation
                                // handle (the write-open denial that preserves the
                                // staged bytes across the boundary). A catalog with
                                // no retained handle cannot be byte-stable.
                                if artifact.retained_catalog_handle().is_none() {
                                    return Err(TrustError::CatalogNotStaged);
                                }
                                let actual = identity.ok_or(TrustError::CatalogNotStaged)?;
                                if actual != expected {
                                    return Err(TrustError::CatalogNotStaged);
                                }
                                // And the catalog CONTENT, for the same reason
                                // as the INF: identity survives an overwrite.
                                let expected_digest = artifact
                                    .catalog_digest()
                                    .ok_or(TrustError::StagedBytesChanged)?;
                                let actual_digest = digest_of_lock_guard(&guard)
                                    .ok_or(TrustError::StagedBytesChanged)?;
                                if actual_digest != expected_digest {
                                    return Err(TrustError::StagedBytesChanged);
                                }
                            }
                            Some((guard, identity))
                        }
                        Err(TrustError::NotRegularFile(_)) => {
                            return Err(TrustError::CatalogNotStaged);
                        }
                        Err(e) => return Err(e),
                    }
                }
                None => None,
            };
            // The catalog lock on Windows always carries the object identity of
            // the locked file; on non-Windows (fake-check tests only) identity is
            // absent and the filename gate below remains the portable check.

            // Invariant checks run AFTER the locks are held (identity-bound).
            self.check_invariants(&staging.join(&leaf))?;
            if let Some(cat) = artifact.catalog_leaf() {
                self.check_catalog_staged(&staging, cat)?;
            }

            // Re-verify containment identity under the held pins, immediately
            // before the native call. With DELETE-access pins this is belt-and-
            // suspenders (the namespace cannot be substituted), but it catches
            // any pre-existing inconsistency.
            let re_checked = self.resolve_under_staging(artifact)?;
            if re_checked.0 != staging || re_checked.1 != leaf {
                return Err(TrustError::InfEscapesStaging);
            }
            self.check_invariants(&staging.join(&leaf))?;

            // F1: the trust-authorizing path is the STABLE volume-GUID path
            // derived from the retained extraction-time INF handle — never the
            // caller/drive-letter path form. SetupAPI resolves the volume-GUID
            // form against the volume object, so an ancestor rename/recreate of
            // the staging directory cannot redirect the pathname to a different
            // INF object. On non-Windows (or if the retained handle is absent)
            // the verifier fails closed rather than falling back to the ordinary
            // path form for production; the fake-test seam still receives the
            // ordinary path (it models results, it does not authorize trust).
            let stable_inf_path: PathBuf = {
                #[cfg(windows)]
                {
                    match artifact.retained_inf_handle().and_then(volume_guid_path_of) {
                        Some(vg) => vg,
                        None => return Err(TrustError::InfEscapesStaging),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = artifact;
                    staging.join(&leaf)
                }
            };

            let result = (self.check)(&stable_inf_path);
            match result {
                TrustResult::Trusted {
                    catalog_name,
                    signer,
                    #[cfg(windows)]
                    reported_catalog_path,
                } => {
                    // F3: a Windows-reported catalog REQUIRES a locked expected
                    // catalog. If none was derived/staged/locked, any nonempty
                    // reported catalog fails closed (never trust a catalog that
                    // was never extracted and locked).
                    let reported = catalog_name.trim();
                    if !reported.is_empty() {
                        // The expected catalog must have been staged + locked.
                        // `expected_identity` is consumed only by the Windows
                        // object-binding branch below; on non-Windows the
                        // filename gate is the portable check.
                        let (expected_guard, expected_identity) = match &catalog_lock {
                            Some((g, id)) => (g, *id),
                            None => return Err(TrustError::CatalogNotStaged),
                        };
                        #[cfg(not(windows))]
                        let _ = expected_identity;
                        // Normalize the reported leaf with the approved bare-leaf
                        // rules.
                        let reported_leaf = reported.rsplit(['\\', '/']).next().unwrap_or(reported);
                        validate_single_component(reported_leaf).map_err(|e| {
                            TrustError::UnsafeInfIdentity(format!(
                                "reported catalog {reported_leaf}: {e}"
                            ))
                        })?;
                        if !names_equal_for_host(reported_leaf, expected_leaf_of(artifact)) {
                            return Err(TrustError::CatalogNotStaged);
                        }
                        #[cfg(windows)]
                        {
                            let expected_id =
                                expected_identity.ok_or(TrustError::CatalogNotStaged)?;
                            // F2: bind the object SetupAPI ACTUALLY verified. When
                            // production reported a FULL catalog path, open that
                            // exact object (reparse-safe) and require its identity
                            // to equal the extraction-time staged catalog identity.
                            // Never compare the staged catalog to itself via the
                            // leaf alone: leaf-reduction would accept a DIFFERENT
                            // reported catalog object that merely shares the leaf.
                            match &reported_catalog_path {
                                Some(full) if !full.trim().is_empty() => {
                                    let full = full.trim();
                                    // Bind the object SetupAPI ACTUALLY verified.
                                    // Only the exact staged catalog object carries
                                    // the extraction-time FileId; a reported
                                    // catalog resolved from any other directory
                                    // fails the equality below.
                                    match open_reported_catalog_full(full) {
                                        Ok(Some(reported_id)) if reported_id == expected_id => {}
                                        _ => return Err(TrustError::CatalogNotStaged),
                                    }
                                }
                                // Fake-test seam (no reported full path): bind the
                                // leaf under the pinned child as before.
                                _ => {
                                    match open_relative_locked(child_pin.handle(), reported_leaf) {
                                        Ok((_reported_guard, Some(reported_id))) => {
                                            if reported_id != expected_id {
                                                return Err(TrustError::CatalogNotStaged);
                                            }
                                        }
                                        _ => return Err(TrustError::CatalogNotStaged),
                                    }
                                }
                            }
                        }
                        // `reported_catalog_path` is a cfg(windows)-only field of
                        // `TrustResult::Trusted`, so on non-Windows it is not
                        // bound by the pattern above and there is nothing to
                        // consume here.
                        // Keep the expected-catalog guard alive through the
                        // comparison (it is dropped at scope end).
                        let _keep = expected_guard;
                    }
                    // Aggregate the live guards into the single evidence value the
                    // 2a-7R token will own. The guards are MOVED, never copied:
                    // these are the same handles, still held, and they still drop
                    // at the end of this function. Phase 3 moves this value into
                    // the returned token so the guarantee outlives `verify`.
                    let (catalog_lock, catalog_identity) = match catalog_lock {
                        Some((guard, identity)) => (Some(guard), identity),
                        None => (None, None),
                    };

                    // Re-fingerprint AFTER the native call. Everything above
                    // proves what SetupAPI was pointed at; this proves the
                    // bytes did not change while it was looking.
                    //
                    // Share modes cannot carry that guarantee on their own: a
                    // writable mapped view survives the close of every handle
                    // that created it, so an attacker who obtained one before
                    // the lease existed can still write through it afterwards,
                    // and no open-time denial revokes it. Only re-reading the
                    // content detects that, so a token is issued exclusively
                    // for bytes that are still the extracted bytes.
                    #[cfg(windows)]
                    {
                        let now = digest_of_lock_guard(&inf_lock)
                            .ok_or(TrustError::StagedBytesChanged)?;
                        if now != inf_digest {
                            return Err(TrustError::StagedBytesChanged);
                        }
                        if let Some(guard) = catalog_lock.as_ref() {
                            let expected = artifact
                                .catalog_digest()
                                .ok_or(TrustError::StagedBytesChanged)?;
                            let now = digest_of_lock_guard(guard)
                                .ok_or(TrustError::StagedBytesChanged)?;
                            if now != expected {
                                return Err(TrustError::StagedBytesChanged);
                            }
                        }
                    }

                    let evidence = RetainedEvidence {
                        ancestor_pins,
                        root_pin,
                        child_pin,
                        inf_lock,
                        catalog_lock,
                        inf_identity,
                        catalog_identity,
                        #[cfg(windows)]
                        inf_digest,
                        #[cfg(windows)]
                        catalog_digest: artifact.catalog_digest(),
                        stable_inf_path,
                    };
                    Ok((evidence, catalog_name, signer))
                }
                TrustResult::Untrusted(e) => Err(e),
            }
        })();

        match outcome {
            // SUCCESS: the artifact and the live evidence both MOVE into the
            // token, so the trust guarantee cannot outlive its guards.
            Ok((evidence, catalog_name, signer)) => Ok(VerifiedDriverPackage {
                artifact,
                evidence,
                catalog_name,
                signer,
            }),
            // FAILURE: no token exists. The ORIGINAL artifact is handed back
            // untouched (never cloned, never rebuilt) so a transient failure
            // can be retried without re-extracting or weakening provenance.
            Err(error) => Err(VerifyRejected { error, artifact }),
        }
    }

    /// Lock the exact staged INF object relative to the pinned child handle.
    #[cfg(windows)]
    fn lock_inf_relative(
        &self,
        child_pin: &DirPinGuard,
        leaf: &str,
    ) -> Result<(FileLockGuard, Option<FileObjectIdentity>), TrustError> {
        validate_single_component(leaf).map_err(TrustError::UnsafeInfIdentity)?;
        open_relative_locked(child_pin.handle(), leaf)
    }

    #[cfg(not(windows))]
    fn lock_inf_relative(
        &self,
        _child_pin: &DirPinGuard,
        _leaf: &str,
    ) -> Result<(FileLockGuard, Option<FileObjectIdentity>), TrustError> {
        // No-op guard on non-Windows: production `native_check` returns
        // `Unavailable` before any `Trusted` can emerge; only the fake-check
        // test seam reaches this path, and it must stay portable.
        Ok((FileLockGuard(None), None))
    }

    /// Re-validate the candidate's relative identity under the staging
    /// root. Mirrors the established 2a-6 component rules so we don't
    /// depend on the production `validate_archive_member` (which is
    /// file-private) and so this gate is independent of any specific
    /// archive format.
    ///
    /// Returns `(staging_root, leaf)` — the containment-validated pair
    /// used for every later check and for the native call. The leaf is
    /// inspected with `symlink_metadata` BEFORE canonicalization, so a
    /// symlink substituted into the staging dir is rejected as itself,
    /// never followed to its target.
    fn resolve_under_staging(
        &self,
        artifact: &StagedInfArtifact,
    ) -> Result<(PathBuf, String), TrustError> {
        let staging = artifact.staging_dir().to_path_buf();
        let leaf = extract_inf_leaf(artifact.inf_path())?;

        // Re-validate the leaf as a single component (this is the same
        // contract `validate_component` enforces, restated so this gate
        // does not depend on a private helper).
        validate_single_component(&leaf).map_err(TrustError::UnsafeInfIdentity)?;

        // Symlink/reparse gate BEFORE canonicalization: `canonicalize`
        // follows links, so a staged leaf replaced by a symlink (or a file
        // carrying FILE_ATTRIBUTE_REPARSE_POINT without a symlink tag) must
        // be rejected here, not after the link has been resolved.
        let joined = staging.join(&leaf);
        let meta = fs::symlink_metadata(&joined)
            .map_err(|_| TrustError::NotRegularFile(joined.clone()))?;
        if meta.file_type().is_symlink() {
            return Err(TrustError::NotRegularFile(joined));
        }
        if is_reparse_point(&meta) {
            return Err(TrustError::NotRegularFile(joined));
        }
        if !meta.is_file() {
            return Err(TrustError::NotRegularFile(joined));
        }

        // No absolute, no drive, no UNC, no traversal: the leaf is a bare
        // name by construction (we just split it off the artifact path).
        // Joining onto the staging root is the actual containment check.
        //
        // The staging root carried by the artifact is the canonical identity
        // captured at extraction time. Re-canonicalizing now and requiring an
        // exact match binds the verification to that original directory: a
        // staging child replaced by a directory junction, or a changed CWD
        // re-rooting a relative path, makes the identities differ and fails
        // closed here.
        let canonical_staging =
            fs::canonicalize(&staging).map_err(|_| TrustError::InfEscapesStaging)?;
        if canonical_staging != staging {
            return Err(TrustError::InfEscapesStaging);
        }
        // Reparse-point gate: the staging root and every component below it
        // up to the artifact must not be a reparse point (junction/symlink).
        // `canonicalize` follows links, so a junction substituted in place of
        // the extraction-time directory must be rejected as itself, before
        // any link target is trusted. The leaf is checked separately in
        // `check_invariants` / `check_catalog_staged`; here we cover the
        // directory chain.
        self.check_no_reparse_components(&canonical_staging, &joined)?;
        let canonical_joined =
            fs::canonicalize(&joined).map_err(|_| TrustError::InfEscapesStaging)?;
        if canonical_joined.parent() != Some(canonical_staging.as_path()) {
            return Err(TrustError::InfEscapesStaging);
        }
        Ok((canonical_staging, leaf))
    }

    /// Reject any reparse point (junction/symlink) in the directory chain
    /// from the staging root down to (and including) the leaf's parent.
    /// Canonicalization follows links, so this gate inspects each component
    /// with `symlink_metadata` (which does not follow) before any link target
    /// can be accepted.
    fn check_no_reparse_components(&self, staging: &Path, joined: &Path) -> Result<(), TrustError> {
        let mut cur = joined.parent().unwrap_or(joined).to_path_buf();
        loop {
            let meta = fs::symlink_metadata(&cur).map_err(|_| TrustError::InfEscapesStaging)?;
            // A reparse point is a link; reject it as itself.
            if meta.file_type().is_symlink() || is_reparse_point(&meta) {
                return Err(TrustError::InfEscapesStaging);
            }
            if cur == *staging {
                break;
            }
            match cur.parent() {
                Some(p) => {
                    if p == cur {
                        break;
                    }
                    cur = p.to_path_buf();
                }
                None => break,
            }
        }
        Ok(())
    }

    /// Require the catalog referenced by the package to be staged beside
    /// the INF (the Windows SetupAPI contract: a third-party INF's catalog
    /// must reside in the same directory as the INF). The catalog leaf is
    /// validated with the same symlink-first/reparse gate as the INF.
    fn check_catalog_staged(&self, staging: &Path, catalog: &str) -> Result<(), TrustError> {
        validate_single_component(catalog)
            .map_err(|e| TrustError::UnsafeInfIdentity(format!("catalog {catalog}: {e}")))?;
        let catalog_path = staging.join(catalog);
        let meta = fs::symlink_metadata(&catalog_path).map_err(|_| TrustError::CatalogNotStaged)?;
        if meta.file_type().is_symlink() {
            return Err(TrustError::CatalogNotStaged);
        }
        if is_reparse_point(&meta) {
            return Err(TrustError::CatalogNotStaged);
        }
        if !meta.is_file() {
            return Err(TrustError::CatalogNotStaged);
        }
        let len = meta.len();
        if len == 0 {
            return Err(TrustError::CatalogNotStaged);
        }
        if len > MAX_STAGED_INF_BYTES {
            return Err(TrustError::CatalogNotStaged);
        }
        Ok(())
    }

    fn check_invariants(&self, path: &Path) -> Result<(), TrustError> {
        let meta = fs::symlink_metadata(path)
            .map_err(|_| TrustError::NotRegularFile(path.to_path_buf()))?;
        if meta.file_type().is_symlink() {
            return Err(TrustError::NotRegularFile(path.to_path_buf()));
        }
        if !meta.is_file() {
            return Err(TrustError::NotRegularFile(path.to_path_buf()));
        }
        let len = meta.len();
        if len == 0 {
            return Err(TrustError::EmptyInf);
        }
        if len > MAX_STAGED_INF_BYTES {
            return Err(TrustError::InfTooLarge);
        }
        Ok(())
    }
}

impl Default for DriverPackageVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract a single bare filename (the INF leaf) from a staged-INF path.
/// The 2a-6 layer places the staged INF as a flat leaf under the staging
/// child, so the leaf is the last component of `inf_path()`.
fn extract_inf_leaf(inf_path: &Path) -> Result<String, TrustError> {
    let leaf = inf_path
        .file_name()
        .ok_or_else(|| TrustError::UnsafeInfIdentity("not a leaf".into()))?
        .to_str()
        .ok_or_else(|| TrustError::UnsafeInfIdentity("non-utf8 leaf".into()))?
        .to_string();
    Ok(leaf)
}

/// Validate a single path component. Same rules as 2a-6
/// `validate_component` restated here so this gate is independent.
fn validate_single_component(comp: &str) -> Result<(), String> {
    if comp.is_empty() {
        return Err("empty component".into());
    }
    if comp.len() > 255 {
        return Err("component exceeds 255 bytes".into());
    }
    if comp == "." || comp == ".." {
        return Err("dot or dotdot component".into());
    }
    if comp.contains('\0') {
        return Err("NUL byte in component".into());
    }
    if !comp.is_ascii() {
        return Err("non-ASCII component".into());
    }
    let bytes = comp.as_bytes();
    let last = bytes[bytes.len() - 1];
    if last == b'.' || last.is_ascii_whitespace() {
        return Err("trailing dot or whitespace".into());
    }
    if is_reserved_dos_name(comp) {
        return Err("reserved DOS name".into());
    }
    if comp.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*']) {
        return Err("Windows-forbidden character".into());
    }
    Ok(())
}

/// True when the metadata carries `FILE_ATTRIBUTE_REPARSE_POINT` (0x400) on
/// Windows. A file can be a reparse point without being a symlink tag (e.g.
/// a mount point); `is_symlink()` alone would miss it. Always false on
/// non-Windows (no reparse-point semantics there).
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

/// RAII guard holding a verification file handle on Windows; a no-op on
/// other platforms. The inner handle is intentionally never read — its sole
/// purpose is to stay open (withholding write + delete sharing) until the
/// guard drops. The type is public only so the `test-inject` seams can
/// return it; production code never constructs it directly.
#[allow(dead_code)]
pub struct FileLockGuard(Option<FileLockInner>);

/// RAII guard pinning a DIRECTORY object (staging root / child) against
/// rename and delete on Windows, by holding a handle opened with `DELETE`
/// access and `FILE_SHARE_READ` only for the lifetime of the guard. A no-op
/// on non-Windows.
///
/// Empirically verified on the Windows host (design gate): with this access
/// and share combination, `MoveFileEx` rename and `RemoveDirectory` of the
/// pinned directory BOTH fail with ERROR_SHARING_VIOLATION while the handle
/// is held, so the namespace CANNOT be substituted for the whole native
/// verification interval. A `FILE_READ_ATTRIBUTES`-only handle does NOT block
/// rename or delete; `DELETE` access is required.
#[allow(dead_code)]
pub struct DirPinGuard {
    #[cfg(windows)]
    handle: std::ptr::NonNull<std::ffi::c_void>,
}

#[cfg(windows)]
impl Drop for DirPinGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.handle.as_ptr());
        }
    }
}

#[cfg(windows)]
impl DirPinGuard {
    fn open_pinned(path: &Path) -> Result<Self, TrustError> {
        const DELETE: u32 = 0x0001_0000;
        Self::open_with_access(path, DELETE)
    }

    /// Pin an ANCESTOR directory that Cove does not own.
    ///
    /// The pin's job is to deny others a rename/delete, and that comes from
    /// withholding `FILE_SHARE_DELETE`, not from the access WE request. Asking
    /// for `DELETE` on a directory like `C:\Users` is refused for an ordinary
    /// user, which would make the whole chain unpinnable; asking for
    /// `FILE_LIST_DIRECTORY` succeeds wherever the path is traversable.
    ///
    /// The access must still be one of the share-checked rights
    /// (read/write/execute/delete). A handle opened for `FILE_READ_ATTRIBUTES`
    /// alone does not participate in share accounting at all and would deny
    /// nothing — an easy and silent mistake to make here.
    fn open_ancestor_pinned(path: &Path) -> Result<Self, TrustError> {
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        Self::open_with_access(path, FILE_LIST_DIRECTORY)
    }

    fn open_with_access(path: &Path, desired_access: u32) -> Result<Self, TrustError> {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
        };

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000): open the reparse object
        // ITSELF, never its target. A raced junction is opened as the
        // junction, and the caller's reparse-attribute check rejects it —
        // the pin can never silently follow a substituted link.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        // What blocks a rename/delete is the share-mode EXCLUSION of
        // FILE_SHARE_DELETE below, not `desired_access` — but the access must
        // be one of the share-checked rights or the handle is excluded from
        // share accounting entirely and denies nothing. Callers pass DELETE
        // for directories Cove owns and FILE_LIST_DIRECTORY for ancestors it
        // merely needs to hold still.
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(TrustError::InfEscapesStaging);
        }
        // F5: prove the OPENED object is a real non-reparse directory before
        // it may serve as a pin / RootDirectory. Because the open used
        // FILE_FLAG_OPEN_REPARSE_POINT, a raced junction is opened as the
        // junction object itself; querying the handle attributes now rejects
        // it rather than silently following to its target.
        {
            use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
            let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
                unsafe { std::mem::zeroed() };
            let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            let attrs_ok = ok != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
            if !attrs_ok {
                unsafe {
                    let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                return Err(TrustError::InfEscapesStaging);
            }
        }
        // SAFETY: handle is valid and proven to be a non-reparse directory;
        // the guard owns and closes it.
        Ok(DirPinGuard {
            handle: unsafe { std::ptr::NonNull::new_unchecked(handle.cast()) },
        })
    }

    /// The pinned directory handle (private; used as the RootDirectory for
    /// handle-relative opens of the INF/catalog under the pinned child).
    fn handle(&self) -> *mut core::ffi::c_void {
        self.handle.as_ptr()
    }
}

#[cfg(not(windows))]
impl DirPinGuard {
    fn open_pinned(_path: &Path) -> Result<Self, TrustError> {
        Ok(DirPinGuard {})
    }

    /// No-op off Windows, matching `open_pinned`: there is no share-mode
    /// namespace lease to take, and no native verification surface that could
    /// consume one — the portable path gates are the whole defence there.
    fn open_ancestor_pinned(_path: &Path) -> Result<Self, TrustError> {
        Ok(DirPinGuard {})
    }

    fn handle(&self) -> *mut core::ffi::c_void {
        std::ptr::null_mut()
    }
}

/// Authoritative Windows file-object identity type, shared with the
/// extraction layer (`StagedInfArtifact` records the extraction-time identity
/// of this same type). Volume serial number + file ID from
/// `GetFileInformationByHandle`; distinguishes objects across volumes; two
/// handles to the same object yield equal identities; a same-named
/// replacement yields a different identity.
pub type FileObjectIdentity = crate::sdio::extraction::FileObjectId;

/// The expected catalog leaf of the artifact (bare filename), used to bind
/// the Windows-reported catalog name to the locked expected catalog.
fn expected_leaf_of(artifact: &StagedInfArtifact) -> &str {
    artifact.catalog_leaf().unwrap_or_default()
}

/// Case-insensitive filename equality on Windows (filesystem semantics);
/// exact equality elsewhere. Used to bind the catalog Windows reports to the
/// catalog Cove locked.
fn names_equal_for_host(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

#[cfg(windows)]
pub struct FileLockInner(std::ptr::NonNull<std::ffi::c_void>);

#[cfg(not(windows))]
#[allow(dead_code)]
pub struct FileLockInner;

impl std::fmt::Debug for FileLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileLockGuard(..)")
    }
}

#[cfg(windows)]
impl Drop for FileLockInner {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0.as_ptr());
        }
    }
}

/// Open a file RELATIVE to an already-pinned directory handle (the staging
/// child), and lock it with write- and delete-sharing withheld. The opened
/// object is the authoritative file object; its identity is returned so the
/// caller can bind the Windows-reported catalog to the exact locked catalog.
///
/// On non-Windows there is no native verification surface; the helper is a
/// no-op guard with no identity (production `native_check` returns
/// `Unavailable` before any `Trusted` can emerge; only the fake-check test
/// seam reaches this path).
#[cfg(not(windows))]
fn open_relative_locked(
    _parent_handle: *mut core::ffi::c_void,
    _leaf: &str,
) -> Result<(FileLockGuard, Option<FileObjectIdentity>), TrustError> {
    Ok((FileLockGuard(None), None))
}

#[cfg(windows)]
fn open_relative_locked(
    parent_handle: *mut core::ffi::c_void,
    leaf: &str,
) -> Result<(FileLockGuard, Option<FileObjectIdentity>), TrustError> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    // The leaf must be a bare single component (validated by callers with
    // validate_single_component). Reject any separator/path form here too —
    // the relative name must be a single component under the pinned root.
    if leaf.is_empty()
        || leaf.contains(['/', '\\', ':', '\0'])
        || leaf == "."
        || leaf == ".."
        || leaf.len() > 255
    {
        return Err(TrustError::UnsafeInfIdentity("invalid leaf".into()));
    }

    // Access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE.
    // Share: FILE_SHARE_READ only (no write, no delete).
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;

    // Build the relative name. NtCreateFile's ObjectName is relative to
    // RootDirectory when RootDirectory is set; no leading backslash.
    let mut name_buf: Vec<u16> = leaf.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent_handle,
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    // SAFETY: oa is a valid, fully-initialized OBJECT_ATTRIBUTES pointing at
    // a live UNICODE_STRING (name_buf outlives the call); parent_handle is a
    // valid open directory handle from the caller's pin; handle/io_status are
    // valid out-params.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0, // file attributes
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(TrustError::NotRegularFile(leaf.into()));
    }

    // The locked object must not be a reparse point.
    let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
        unsafe { std::mem::zeroed() };
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(handle, &mut info)
    };
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if ok == 0 || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        return Err(TrustError::NotRegularFile(leaf.into()));
    }
    // Authoritative 128-bit object identity from the held handle. An identity
    // that cannot be proven is fail-closed at the caller, never a match.
    let identity = match crate::sdio::extraction::object_id_of_raw_handle(handle.cast()) {
        Some(id) => id,
        None => {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(TrustError::NotRegularFile(leaf.into()));
        }
    };

    // SAFETY: handle valid; guard owns it.
    let inner = unsafe { FileLockInner(std::ptr::NonNull::new_unchecked(handle.cast())) };
    Ok((FileLockGuard(Some(inner)), Some(identity)))
}

/// F2 binding helper (Windows production): SetupAPI reported a FULL catalog
/// path. The verifier must bind the object Windows ACTUALLY verified — not
/// re-derive the staged leaf and compare the staged catalog to itself. The
/// reported full path is opened REPARSE-SAFE (`FILE_OPEN_REPARSE_POINT`, so a
/// final reparse is opened as the link object and rejected below) and its
/// FileObjectIdentity is returned. The caller requires that identity to equal
/// the extraction-time STAGED catalog identity: only the exact staged catalog
/// object carries that FileId, so a reported catalog resolved from ANY other
/// directory (driver store, system CatRoot, a colliding filename elsewhere)
/// fails the equality and the package is rejected.
///
/// Returns `Ok(None)` when the reported path is hostile, unopenable, or names
/// a reparse object (the caller maps that to `CatalogNotStaged`).
#[cfg(windows)]
fn open_reported_catalog_full(
    reported_full_path: &str,
) -> Result<Option<FileObjectIdentity>, TrustError> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    // Reject any hostile form (NUL, empty, overlong).
    if reported_full_path.is_empty()
        || reported_full_path.contains('\0')
        || reported_full_path.len() > 32767
    {
        return Ok(None);
    }

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let wide: Vec<u16> = OsStr::new(reported_full_path)
        .encode_wide()
        .chain(once(0))
        .collect();
    // Reparse-safe open of the reported object itself. FILE_SHARE_READ |
    // FILE_SHARE_DELETE keeps the read compatible with the verifier's own
    // locks; FILE_FLAG_OPEN_REPARSE_POINT opens a final reparse point as the
    // link object (never its target), and the attribute check below rejects
    // it.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Ok(None);
    }
    let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
        unsafe { std::mem::zeroed() };
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(handle, &mut info)
    };
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let identity = if ok != 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
    {
        crate::sdio::extraction::object_id_of_raw_handle(handle.cast())
    } else {
        None
    };
    unsafe {
        let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    Ok(identity)
}

/// Open the file with write- and delete-sharing withheld, then BIND the
/// checked identity to the acquired object: the handle's final canonical
/// path must equal the expected verified path, and the locked object must
/// not be a reparse point. Only after both proofs is the lock returned, so
/// the file object whose identity Cove validated is exactly the object held
/// against replacement and mutation during `SetupVerifyInfFileW`.
///
/// On Windows this is `CreateFileW` with `GENERIC_READ` access and
/// `FILE_SHARE_READ` ONLY — NO `FILE_SHARE_WRITE` (a concurrent writer cannot
/// open or mutate the trusted bytes while the lock is held) and NO
/// `FILE_SHARE_DELETE` (the file cannot be renamed or deleted/replaced while
/// the lock is held). The share mode MIRRORS [`open_relative_locked`]. On
/// non-Windows the path gates already cover the available substitution
/// primitives and the guard is a no-op.
#[cfg_attr(not(feature = "test-inject"), allow(dead_code))]
fn lock_file_verified(path: &Path) -> Result<FileLockGuard, TrustError> {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, GetFileInformationByHandle, GetFinalPathNameByHandleW,
            OPEN_EXISTING,
        };

        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        // FILE_FLAG_OPEN_REPARSE_POINT: never follow a reparse to its target;
        // a raced link is opened as the link and rejected below.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        // VOLUME_NAME_DOS returns the `C:\...` path form that matches the
        // input path (VOLUME_NAME_NONE drops the drive letter).
        const VOLUME_NAME_DOS: u32 = 0x0;

        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ, // no FILE_SHARE_WRITE, no FILE_SHARE_DELETE
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(TrustError::NotRegularFile(path.to_path_buf()));
        }

        // Bind identity: the final path of the LOCKED object must equal the
        // expected verified path (the same file object that passed the path
        // gates — a rename/replace between gate and lock now fails closed).
        let mut buf = [0u16; 1024];
        let len = unsafe {
            GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_DOS)
        };
        if len == 0 || len as usize >= buf.len() {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(TrustError::NotRegularFile(path.to_path_buf()));
        }
        let locked_path = String::from_utf16_lossy(&buf[..len as usize]);
        // Compare case-insensitively (Windows paths are case-insensitive)
        // after stripping any `\\?\` extended-length prefix.
        let locked_path = locked_path.strip_prefix(r"\\?\").unwrap_or(&locked_path);
        let expected = path.to_string_lossy();
        let expected = expected.strip_prefix(r"\\?\").unwrap_or(&expected);
        if !locked_path.eq_ignore_ascii_case(expected) {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(TrustError::InfEscapesStaging);
        }

        // The locked object must not be a reparse point.
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            return Err(TrustError::NotRegularFile(path.to_path_buf()));
        }

        // SAFETY: handle is valid (checked above) and identity-bound; the
        // guard owns it and closes it on drop.
        let inner = unsafe { FileLockInner(std::ptr::NonNull::new_unchecked(handle.cast())) };
        Ok(FileLockGuard(Some(inner)))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(FileLockGuard(None))
    }
}

/// Test-only seam: expose the reparse-attribute predicate so the integration
/// suite can prove a real junction reaches the exact
/// `FILE_ATTRIBUTE_REPARSE_POINT` branch. Compiled only when the `test-inject`
/// feature is enabled (never in production builds).
#[cfg(feature = "test-inject")]
pub fn test_is_reparse_point(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink() || is_reparse_point(&meta),
        Err(_) => false,
    }
}

/// Test-only seam: acquire the verification lock on a path and return the
/// guard (or the fail-closed error). Exposes `lock_file_verified` so the
/// integration suite can prove the write-share withholding (F4) and the
/// identity binding (F3) behavior against real Windows handles. Compiled only
/// when the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_lock_file(path: &Path) -> Result<FileLockGuard, TrustError> {
    lock_file_verified(path)
}

/// Test-only seam: pin a directory with the production `DirPinGuard` so the
/// integration suite can prove a pinned parent/child cannot be renamed or
/// replaced during verification. Compiled only when the `test-inject` feature
/// is enabled.
#[cfg(feature = "test-inject")]
pub fn test_pin_dir(path: &Path) -> Result<DirPinGuard, TrustError> {
    DirPinGuard::open_pinned(path)
}

/// Production-internal: the authoritative Windows object identity of the
/// object a held [`FileLockGuard`] refers to, read from the RETAINED HANDLE.
///
/// This is the single implementation of the handle->identity operation. It
/// reads `VolumeSerialNumber + FileId` via `GetFileInformationByHandle` on the
/// handle the guard already owns — it never opens anything by pathname, so it
/// cannot be redirected by a rename or a substituted directory entry. The
/// `test-inject` seam below delegates here, so the test and production reads
/// can never disagree.
///
/// `None` means the identity could not be proven (no handle, or the native
/// call failed). Callers must treat that as fail-closed, never as a pass.
///
/// Private: no public raw-handle API is introduced.
#[cfg(windows)]
fn identity_of_lock_guard(guard: &FileLockGuard) -> Option<FileObjectIdentity> {
    let inner = guard.0.as_ref()?;
    crate::sdio::extraction::object_id_of_raw_handle(inner.0.as_ptr().cast())
}

/// True when `path` is a volume root — a prefix plus a root component and
/// nothing else (`\\?\C:\`, `C:\`, or `/`). A volume root has no parent
/// directory entry, so it cannot be renamed and needs no pin.
fn is_volume_root(path: &Path) -> bool {
    use std::path::Component;
    let mut components = path.components();
    let first = components.next();
    let second = components.next();
    let rest = components.next();
    if rest.is_some() {
        return false;
    }
    matches!(
        (first, second),
        (Some(Component::Prefix(_)), Some(Component::RootDir)) | (Some(Component::RootDir), None)
    )
}

/// Pin every directory strictly ABOVE `dir`, stopping at the volume root.
///
/// `SetupVerifyInfFileW` is handed `\\?\Volume{GUID}\a\b\...\child\driver.inf`.
/// The volume-GUID prefix fixes which volume that resolves against, but every
/// component after it is still an ordinary directory entry that a sufficiently
/// privileged attacker can rename. Renaming one and rebuilding the same suffix
/// elsewhere lets SetupAPI open a DIFFERENT INF than the one whose identity and
/// bytes were just checked — the checks bind Cove's retained handles, not the
/// object SetupAPI resolves for itself.
///
/// Pinning holds every one of those components open with delete/rename sharing
/// withheld, so the pathname cannot be re-pointed for the duration of the call.
/// Pins are taken TOP-DOWN, and the caller then binds the child's object
/// identity, which is what proves no component moved while the chain was being
/// built.
fn pin_ancestors_above(dir: &Path) -> Result<Vec<DirPinGuard>, TrustError> {
    let mut chain: Vec<&Path> = Vec::new();
    let mut cursor = dir.parent();
    while let Some(p) = cursor {
        if is_volume_root(p) {
            break;
        }
        chain.push(p);
        cursor = p.parent();
    }
    // `chain` is bottom-up; pin from the top down.
    chain.reverse();
    let mut pins = Vec::with_capacity(chain.len());
    for p in chain {
        pins.push(DirPinGuard::open_ancestor_pinned(p)?);
    }
    Ok(pins)
}

/// Production-internal: the identity of the directory object a held
/// [`DirPinGuard`] refers to, read from the pinned handle itself.
#[cfg(windows)]
fn identity_of_dir_pin(guard: &DirPinGuard) -> Option<FileObjectIdentity> {
    crate::sdio::extraction::object_id_of_raw_handle(guard.handle().cast())
}

/// Production-internal: the CONTENT fingerprint of the object a held
/// [`FileLockGuard`] refers to, read through the handle the guard already owns.
///
/// Identity answers "is this the same object"; this answers "does it still
/// hold the same bytes". Both are required, because the two most dangerous
/// mutations leave identity untouched: an in-place overwrite, and a write
/// through a memory-mapped view (which survives the close of every handle that
/// created it, and which no share mode can revoke).
///
/// `None` means the fingerprint could not be taken; callers fail closed.
///
/// Private: no public raw-handle API is introduced.
#[cfg(windows)]
fn digest_of_lock_guard(
    guard: &FileLockGuard,
) -> Option<crate::sdio::extraction::StagedContentDigest> {
    let inner = guard.0.as_ref()?;
    crate::sdio::extraction::digest_of_raw_handle(inner.0.as_ptr().cast()).ok()
}

/// Test-only seam: the Windows object identity of a locked file. Compiled
/// only when the `test-inject` feature is enabled. Delegates to the
/// production helper so there is exactly one implementation.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_identity_of(guard: &FileLockGuard) -> Option<FileObjectIdentity> {
    identity_of_lock_guard(guard)
}

/// Test-only seam: invoke `SetupVerifyInfFileW` RAW and return the raw
/// `(BOOL result, GetLastError DWORD)` WITHOUT any TrustError translation.
/// Used by R49 to prove the volume-GUID path reaches the SAME native parsing
/// as the ordinary path and that a path-rejection control fails distinctly.
/// Compiled only when the `test-inject` feature is enabled.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_probe_native_raw(path: &Path) -> (i32, u32) {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;

    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
    let mut signer_info: SP_INF_SIGNER_INFO_V2_W = unsafe { std::mem::zeroed() };
    signer_info.cbSize = std::mem::size_of::<SP_INF_SIGNER_INFO_V2_W>() as u32;
    let ok = unsafe { SetupVerifyInfFileW(wide.as_ptr(), std::ptr::null(), &mut signer_info) };
    let err: u32 = unsafe { GetLastError() };
    (ok, err)
}

/// Test-only seam: the raw SetupAPI error-domain translation. Exposes
/// `translate_win32_error` so tests can prove `0xE0000241` (raw
/// ERROR_AUTHENTICODE_TRUSTED_PUBLISHER) is NOT treated as a generic
/// untrusted error and that the HRESULT form `0x800F0241` is NOT accepted as
/// the raw value. Compiled only when the `test-inject` feature is enabled.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_translate_raw_error(err: u32) -> TrustError {
    translate_win32_error(err)
}

/// Test-only seam: whether a second WRITE-capable open of the path currently
/// succeeds. With the verification lock held (write-sharing withheld), a
/// write-capable open must FAIL; after the lock is released it must succeed.
/// Compiled only when the `test-inject` feature is enabled.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_write_open_succeeds(path: &Path) -> bool {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return false;
    }
    unsafe {
        let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    true
}

#[cfg(all(not(windows), feature = "test-inject"))]
pub fn test_write_open_succeeds(_path: &Path) -> bool {
    true
}

fn is_reserved_dos_name(s: &str) -> bool {
    let base = s.split('.').next().unwrap_or(s);
    if base.len() > 4 {
        return false;
    }
    matches!(
        base.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

// ---------------------------------------------------------------------------
// Native Windows trust call
// ---------------------------------------------------------------------------

/// `ERROR_AUTHENTICODE_TRUSTED_PUBLISHER` (0xE0000241): the raw SetupAPI
/// GetLastError value when `SetupVerifyInfFileW` returns FALSE for a VALID
/// package signed by a certificate in the Trusted Publishers store (the
/// signer structure is populated). Authoritative from setupapi.h:
/// `APPLICATION_ERROR_MASK(0x20000000) | ERROR_SEVERITY_ERROR(0xC0000000) |
/// 0x241`. The HRESULT-converted `SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER`
/// (0x800F0241) is a DIFFERENT value and must NOT be compared against raw
/// GetLastError.
#[cfg(windows)]
const ERROR_AUTHENTICODE_TRUSTED_PUBLISHER: u32 = 0xE000_0241;

/// The production trust call. On Windows, calls `SetupVerifyInfFileW` and
/// maps its return + `GetLastError()` to [`TrustResult`]. On non-Windows,
/// returns `Untrusted(Unavailable)` so the install-plan gate fails closed
/// (the install plan builder can be exercised on Linux CI but never
/// produces a ready plan there).
#[cfg(windows)]
fn native_check(inf_path: &Path) -> TrustResult {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;

    // Wide-stringify the INF path (null-terminated).
    let wide: Vec<u16> = OsStr::new(inf_path).encode_wide().chain(once(0)).collect();

    // Zero-initialize the output struct; cbSize must be set by caller.
    // The struct layout is fixed by the Win32 SDK and is the V2 wide
    // version (UTF-16 catalog/signer name fields).
    let mut signer_info: SP_INF_SIGNER_INFO_V2_W = unsafe { std::mem::zeroed() };
    signer_info.cbSize = std::mem::size_of::<SP_INF_SIGNER_INFO_V2_W>() as u32;

    let ok = unsafe { SetupVerifyInfFileW(wide.as_ptr(), std::ptr::null(), &mut signer_info) };
    if ok != 0 {
        let catalog = trim_wide(&signer_info.CatalogFile);
        let signer = trim_wide(&signer_info.DigitalSigner);
        return TrustResult::Trusted {
            catalog_name: catalog_leaf_from_path(&catalog),
            signer: if signer.is_empty() {
                None
            } else {
                Some(signer)
            },
            reported_catalog_path: if catalog.is_empty() {
                None
            } else {
                Some(catalog)
            },
        };
    }

    // Map the error code to the narrowest category we can recognize. The
    // value is the RAW GetLastError domain: SetupAPI's Authenticode errors
    // are application errors (0xE0000xxx), NOT their HRESULT-converted
    // SPAPI_E_* forms (0x800F0xxx).
    let err: u32 = unsafe { GetLastError() };
    match err {
        // A valid Authenticode signature from a Trusted Publishers store
        // certificate is a locally-trusted package. Microsoft's SetupAPI
        // guidance: SetupVerifyInfFileW returns FALSE with
        // ERROR_AUTHENTICODE_TRUSTED_PUBLISHER for this case and fills
        // the signer structure.
        ERROR_AUTHENTICODE_TRUSTED_PUBLISHER => {
            let catalog = trim_wide(&signer_info.CatalogFile);
            let signer = trim_wide(&signer_info.DigitalSigner);
            TrustResult::Trusted {
                catalog_name: catalog_leaf_from_path(&catalog),
                signer: if signer.is_empty() {
                    None
                } else {
                    Some(signer)
                },
                reported_catalog_path: if catalog.is_empty() {
                    None
                } else {
                    Some(catalog)
                },
            }
        }
        _ => TrustResult::Untrusted(translate_win32_error(err)),
    }
}

#[cfg(not(windows))]
fn native_check(_inf_path: &Path) -> TrustResult {
    TrustResult::Untrusted(TrustError::Unavailable)
}

/// Derive the stable volume-GUID path (`\\?\Volume{...}\...`) of an open file
/// object on Windows via `GetFinalPathNameByHandleW(VOLUME_NAME_GUID)`.
/// SetupAPI resolves this form against the VOLUME object rather than any
/// drive-letter / directory namespace chain, so the trust-authorizing path
/// cannot be redirected by an ancestor rename/recreate of the staging
/// directory. Returns `None` if the handle is absent or the API fails (the
/// caller fails closed).
#[cfg(windows)]
fn volume_guid_path_of(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    const VOLUME_NAME_GUID: u32 = 0x1;
    let mut buf = vec![0u16; 4096];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            VOLUME_NAME_GUID,
        )
    };
    if len == 0 || (len as usize) >= buf.len() {
        return None;
    }
    let wide = &buf[..len as usize];
    // The COMPLETE returned path is the trust-authorizing value. The `\\?\`
    // prefix is not decoration: `\\?\Volume{GUID}\...` is a namespace-
    // qualified path that SetupAPI resolves against the VOLUME object, while
    // the prefix-stripped `Volume{GUID}\...` is an ordinary RELATIVE path
    // with no volume semantics at all. Never strip it, and never re-normalize
    // it back to a drive-letter form (that would reintroduce the mutable
    // directory-namespace chain the design exists to avoid).
    Some(PathBuf::from(String::from_utf16_lossy(wide)))
}

#[cfg(windows)]
fn trim_wide(buf: &[u16; 260]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end]).trim_end().to_string()
}

/// Extract the bare catalog filename from a `CatalogFile` value returned by
/// SetupAPI. The API documents `SP_INF_SIGNER_INFO.CatalogFile` as the FULL
/// path of the signed catalog; the plan contract carries a bare filename, so
/// the leaf is extracted. If the value is empty or has no leaf, the value is
/// passed through unchanged (the caller's plan-gate validation rejects
/// anything that is not a bare filename).
#[cfg(windows)]
fn catalog_leaf_from_path(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

/// Translate a SetupVerifyInfFileW failure code to the narrowest
/// [`TrustError`] category. Values are authoritative from the Windows SDK:
///
/// - Generic Win32 errors (ERROR_FILE_NOT_FOUND etc.) are raw values.
/// - SetupAPI-specific Authenticode/catalog errors appear in the RAW
///   GetLastError application-error domain (0xE0000xxx) — the values below
///   are `APPLICATION_ERROR_MASK(0x20000000) | ERROR_SEVERITY_ERROR
///   (0xC0000000) | code` per setupapi.h. Their HRESULT-converted
///   `SPAPI_E_*` forms (0x800F0xxx) are a DIFFERENT domain and are NOT what
///   GetLastError returns for this call.
/// - `TRUST_E_*` values (0x800Bxxxx) are HRESULTs the WinVerifyTrust
///   provider surfaces through SetLastError unchanged; they are matched
///   verbatim.
#[cfg(windows)]
fn translate_win32_error(err: u32) -> TrustError {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
    const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
    const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
    // Raw SetupAPI application-error forms (setupapi.h):
    const ERROR_NO_CATALOG_FOR_OEM_INF: u32 = 0xE000_022F;
    const ERROR_NO_AUTHENTICODE_CATALOG: u32 = 0xE000_023F;
    const ERROR_AUTHENTICODE_DISALLOWED: u32 = 0xE000_0240;
    const ERROR_AUTHENTICODE_TRUST_NOT_ESTABLISHED: u32 = 0xE000_0242;
    const ERROR_AUTHENTICODE_PUBLISHER_NOT_TRUSTED: u32 = 0xE000_0243;
    match err {
        ERROR_FILE_NOT_FOUND => TrustError::CatalogMissing,
        ERROR_PATH_NOT_FOUND => TrustError::CatalogMissing,
        ERROR_INVALID_PARAMETER => TrustError::Malformed,
        TRUST_E_PROVIDER_UNKNOWN => TrustError::Untrusted,
        TRUST_E_SUBJECT_NOT_TRUSTED => TrustError::Untrusted,
        TRUST_E_NOSIGNATURE => TrustError::Unsigned,
        ERROR_NO_CATALOG_FOR_OEM_INF => TrustError::CatalogMissing,
        ERROR_NO_AUTHENTICODE_CATALOG => TrustError::CatalogMissing,
        // A valid Authenticode signature from a Trusted Publishers cert is
        // a trusted package; handled in native_check before this is reached.
        ERROR_AUTHENTICODE_TRUSTED_PUBLISHER => TrustError::Untrusted,
        ERROR_AUTHENTICODE_DISALLOWED => TrustError::Untrusted,
        ERROR_AUTHENTICODE_TRUST_NOT_ESTABLISHED => TrustError::Untrusted,
        ERROR_AUTHENTICODE_PUBLISHER_NOT_TRUSTED => TrustError::Untrusted,
        // Any other non-zero code means Windows did not certify the
        // package. Treat all as Untrusted to keep semantics clear (and
        // so the install-plan gate sees one well-defined non-installable
        // state).
        _ => TrustError::Untrusted,
    }
}

// ---------------------------------------------------------------------------
// Direct FFI declaration for SetupVerifyInfFileW
// ---------------------------------------------------------------------------
//
// `windows-sys 0.59` exposes the SetupAPI `SP_INF_SIGNER_INFO_V2_W` struct
// and most of the Setup* functions, but `SetupVerifyInfFileW` itself is
// not yet bound by that version. Declaring the FFI here is the standard
// `windows-sys` extension pattern (it is the same approach the crate uses
// internally: a one-line `windows_targets::link!` equivalent pulled into
// the user's crate). This is a narrow, recorded FFI surface — no new
// dependency, no new crypto, no shell.

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct SP_INF_SIGNER_INFO_V2_W {
    cbSize: u32,
    CatalogFile: [u16; 260],
    DigitalSigner: [u16; 260],
    DigitalSignerVersion: [u16; 260],
    SignerScore: u32,
}

#[cfg(windows)]
windows_targets::link!("setupapi.dll" "system" fn SetupVerifyInfFileW(
    infname : windows_sys::core::PCWSTR,
    altplatforminfo : *const core::ffi::c_void,
    infsignerinfo : *mut SP_INF_SIGNER_INFO_V2_W,
) -> windows_sys::Win32::Foundation::BOOL);

// ---------------------------------------------------------------------------
// Private unit coverage: catalog evidence-consistency classification
//
// The two INCONSISTENT states are unreachable through production construction
// (verify always sets the catalog lock and its identity together), which is
// exactly why they cannot be reached from an integration test. The decision is
// therefore classified by a pure helper that takes only presence booleans — no
// handle, no guard, no identity value, no capability of any kind — so the
// defensive fail-closed branches can be exercised directly.
// ---------------------------------------------------------------------------
#[cfg(all(test, windows))]
mod catalog_evidence_tests {
    use super::{CatalogEvidenceState, TrustError, catalog_evidence_state};

    #[test]
    fn none_none_is_the_legitimate_no_catalog_state() {
        assert_eq!(
            catalog_evidence_state(false, false),
            Ok(CatalogEvidenceState::NoCatalog),
            "a package with neither a staged catalog nor a catalog identity is \
             the legitimate embedded-signature case"
        );
    }

    #[test]
    fn some_some_is_the_catalog_backed_state() {
        assert_eq!(
            catalog_evidence_state(true, true),
            Ok(CatalogEvidenceState::CatalogBacked),
            "a lock plus its identity is the normal catalog-backed case and must \
             proceed to the live handle identity comparison"
        );
    }

    #[test]
    fn some_none_fails_closed() {
        assert_eq!(
            catalog_evidence_state(true, false),
            Err(TrustError::CatalogNotStaged),
            "a retained catalog lock with NO recorded identity is an impossible \
             state and must never be normalized into success"
        );
    }

    #[test]
    fn none_some_fails_closed() {
        assert_eq!(
            catalog_evidence_state(false, true),
            Err(TrustError::CatalogNotStaged),
            "a recorded catalog identity with NO retained lock is an impossible \
             state and must never be normalized into success"
        );
    }
}
