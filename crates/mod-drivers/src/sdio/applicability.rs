//! Catalog-level OS applicability (Tab 2a-4).
//!
//! This slice derives **catalog OS applicability only** from already-parsed
//! local/offline SDIO index metadata plus the machine context. It deliberately
//! does NOT claim a candidate is an update, recommended, installable, signed,
//! or better, and it never fabricates a Windows rank. Windows remains
//! authoritative.
//!
//! The dominant concern: reject candidates that catalog metadata can PROVE are
//! incompatible with the current Windows architecture / TargetOSVersion, while
//! preserving an explicit `Indeterminate` state whenever the SDIO index alone
//! cannot prove applicability. `Indeterminate` is fail-open: it must continue
//! to package-level validation and is never silently dropped.
//!
//! Pure: no I/O, no process invocation, no filesystem, no networking, no
//! Windows APIs.

use crate::identity::MachineContext;
use crate::sdio::matching::{CatalogCandidateMatch, DeviceCatalogMatches};

// ---------------------------------------------------------------------------
// Bounds (finite, fail closed)
// ---------------------------------------------------------------------------

/// Maximum length of a `TargetOSVersion` decoration string we will parse.
/// Real decorations are far shorter; the bound exists so untrusted catalog
/// metadata can never drive an unbounded parse.
pub const MAX_TARGET_OS_LEN: usize = 256;

/// Maximum number of dotted components after the `NT` prefix
/// (`[arch][.major][.minor][.pt][.suite][.build]` = 6 slots).
pub const MAX_TARGET_COMPONENTS: usize = 6;

// ---------------------------------------------------------------------------
// Host architecture
// ---------------------------------------------------------------------------

/// Windows target architectures recognized by the evaluator. Cove need not run
/// on all of them; the evaluator merely interprets the target decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArch {
    X86,
    Ia64,
    Amd64,
    Arm,
    Arm64,
}

/// Normalize a host `MachineContext::arch` string to a [`TargetArch`].
///
/// Only spellings actually produced by Cove are mapped, plus the canonical
/// `amd64` equivalent. No fuzzy matching. Unknown spellings return `None`.
pub fn normalize_host_arch(arch: &str) -> Option<TargetArch> {
    match arch {
        "x64" | "amd64" => Some(TargetArch::Amd64),
        "x86" => Some(TargetArch::X86),
        "arm64" => Some(TargetArch::Arm64),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// TargetOSVersion decoration
// ---------------------------------------------------------------------------

/// A parsed `TargetOSVersion` decoration.
///
/// Conceptual grammar (Microsoft, INF Manufacturer section):
/// `NT[Architecture][.[OSMajorVersion][.[OSMinorVersion]
///    [.[ProductType][.[SuiteMask][.[BuildNumber]]]]]]`
///
/// ASCII case-insensitive keywords; integer-exact numeric fields (decimal, or
/// `0x`-prefixed hex for product/suite); intentional empty components are
/// preserved positionally (`NTamd64.10.0...22000` == build 22000 with empty
/// product type and suite mask slots).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetOsDecoration {
    pub architecture: Option<TargetArch>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub product_type: Option<u32>,
    pub suite_mask: Option<u32>,
    pub build: Option<u32>,
}

/// Explicit, non-panicking rejection reasons from [`parse_target_os_version`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetParseError {
    #[error("target string exceeds max length {0}")]
    TooLong(usize),
    #[error("target string does not begin with NT")]
    NotNtDecoration,
    #[error("unsupported TargetOSVersion syntax")]
    UnsupportedSyntax,
    #[error("too many dotted components in TargetOSVersion")]
    TooManyComponents,
    #[error("invalid integer in TargetOSVersion component {0}")]
    InvalidNumber(usize),
}

/// Parse a `TargetOSVersion` decoration string strictly.
///
/// - ASCII case-insensitive for `NT` and the architecture keywords.
/// - Integer-exact numeric fields (no floats, no locale parsing, no junk
///   suffixes, u32-bounded).
/// - Dotted slots are strictly positional:
///   `[major][.minor][.product][.suite][.build]` after the optional
///   architecture; `NTamd64.10.0...22000` has five slots (product and suite
///   empty, build 22000). No right-alignment, no "skip to build" heuristics.
/// - Hex (`0x`) is accepted only for the ProductType and SuiteMask slots.
/// - Microsoft build floor: a build decoration requires OS 10.0 context and a
///   build >= 14310 (the Windows 10 build where build decorations were
///   introduced); anything else is rejected.
/// - A decoration must not end in a dot (trailing empty component).
/// - No recursion, no regex.
pub fn parse_target_os_version(s: &str) -> Result<TargetOsDecoration, TargetParseError> {
    if s.len() > MAX_TARGET_OS_LEN {
        return Err(TargetParseError::TooLong(s.len()));
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 || !bytes[0..2].eq_ignore_ascii_case(b"nt") {
        return Err(TargetParseError::NotNtDecoration);
    }

    let rest = &s[2..];
    let components: Vec<&str> = rest.split('.').collect();
    if components.len() > MAX_TARGET_COMPONENTS {
        return Err(TargetParseError::TooManyComponents);
    }

    // Architecture slot: components[0] is a known arch token, empty (arch
    // absent), or unsupported. A lone empty component (`NT` with no dots) means
    // "no architecture, no version".
    let (architecture, fields): (Option<TargetArch>, &[&str]) = match components.as_slice() {
        [] => (None, &[][..]),
        [""] => (None, &[][..]),
        [first, rest @ ..] => match arch_from_token(first) {
            Some(a) => (Some(a), rest),
            None if first.is_empty() => (None, rest),
            None => return Err(TargetParseError::UnsupportedSyntax),
        },
    };

    // Strictly positional slots. A decoration must not end in a dot: each slot
    // is either present or omitted, so a trailing empty component is unsupported
    // syntax rather than a silently-ignored suffix.
    if fields.last().is_some_and(|f| f.is_empty()) {
        return Err(TargetParseError::UnsupportedSyntax);
    }
    if fields.len() > 5 {
        return Err(TargetParseError::TooManyComponents);
    }

    let mut deco = TargetOsDecoration {
        architecture,
        ..Default::default()
    };
    let slots = [
        &mut deco.major,
        &mut deco.minor,
        &mut deco.product_type,
        &mut deco.suite_mask,
        &mut deco.build,
    ];
    for (i, component) in fields.iter().enumerate() {
        if component.is_empty() {
            continue;
        }
        // major/minor/build are decimal-only; product/suite also allow 0x hex.
        let value = match i {
            2 | 3 => parse_product_or_suite(component),
            _ => parse_decimal(component),
        }
        .ok_or(TargetParseError::InvalidNumber(i))?;
        *slots[i] = Some(value);
    }

    // Microsoft build floor: a build decoration targets Windows 10 (10.0) and
    // build >= 14310. Anything else is malformed for the current grammar.
    if let Some(b) = deco.build
        && (deco.major != Some(10) || deco.minor != Some(0) || b < 14310)
    {
        return Err(TargetParseError::UnsupportedSyntax);
    }

    // A minor version without a major version is not a valid OS-version pair:
    // the grammar is positional and a bare minor cannot express a threshold.
    if deco.minor.is_some() && deco.major.is_none() {
        return Err(TargetParseError::UnsupportedSyntax);
    }

    Ok(deco)
}

fn arch_from_token(tok: &str) -> Option<TargetArch> {
    if tok.eq_ignore_ascii_case("x86") {
        Some(TargetArch::X86)
    } else if tok.eq_ignore_ascii_case("ia64") {
        Some(TargetArch::Ia64)
    } else if tok.eq_ignore_ascii_case("amd64") {
        Some(TargetArch::Amd64)
    } else if tok.eq_ignore_ascii_case("arm") {
        Some(TargetArch::Arm)
    } else if tok.eq_ignore_ascii_case("arm64") {
        Some(TargetArch::Arm64)
    } else {
        None
    }
}

/// Decimal-only integer component (major/minor/build). u32-bounded, no floats.
fn parse_decimal(component: &str) -> Option<u32> {
    component.parse::<u32>().ok()
}

/// ProductType / SuiteMask component: decimal or `0x`-prefixed hex.
fn parse_product_or_suite(component: &str) -> Option<u32> {
    if let Some(hex) = component
        .strip_prefix("0x")
        .or_else(|| component.strip_prefix("0X"))
    {
        if hex.is_empty() {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else {
        component.parse::<u32>().ok()
    }
}

// ---------------------------------------------------------------------------
// Machine context
// ---------------------------------------------------------------------------

/// A strictly parsed `MachineContext`. `major`/`minor` are decimal integers
/// separated by exactly one `.`; `build` is an integer. No floats, no locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMachineContext {
    pub arch: TargetArch,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

/// Fail-closed reasons the assessment refuses to run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicabilityError {
    #[error("machine context is malformed (arch/os_version/os_build)")]
    InvalidMachineContext,
    #[error("unknown host architecture: {0}")]
    UnknownHostArchitecture(String),
}

/// Strictly parse the host machine context. Malformed trusted-host fields
/// return an explicit error; never a panic, never a permissive fallback.
pub fn parse_machine_context(machine: &MachineContext) -> Result<ParsedMachineContext, ApplicabilityError> {
    let arch = normalize_host_arch(&machine.arch).ok_or_else(|| {
        ApplicabilityError::UnknownHostArchitecture(machine.arch.clone())
    })?;

    // os_version must be exactly "major.minor" with decimal integers.
    let mut parts = machine.os_version.split('.');
    let (major_s, minor_s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(maj), Some(min), None) => (maj, min),
        _ => return Err(ApplicabilityError::InvalidMachineContext),
    };
    if major_s.is_empty() || minor_s.is_empty() {
        return Err(ApplicabilityError::InvalidMachineContext);
    }
    let major = major_s.parse::<u32>().map_err(|_| ApplicabilityError::InvalidMachineContext)?;
    let minor = minor_s.parse::<u32>().map_err(|_| ApplicabilityError::InvalidMachineContext)?;
    let build = machine
        .os_build
        .parse::<u32>()
        .map_err(|_| ApplicabilityError::InvalidMachineContext)?;

    Ok(ParsedMachineContext {
        arch,
        major,
        minor,
        build,
    })
}

// ---------------------------------------------------------------------------
// Catalog OS applicability domain
// ---------------------------------------------------------------------------

/// Tri-state catalog OS applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogOsApplicability {
    /// Catalog metadata PROVES the Models target permits the host architecture
    /// and OS version/build. Not "Windows will choose this package", "signed",
    /// "installable", "an update", or "recommended".
    HostCompatible,
    /// Catalog metadata PROVES the target excludes this host. A safe negative.
    HostIncompatible,
    /// The index alone cannot prove applicability. MUST NOT be converted to
    /// HostCompatible merely because the hardware ID matched.
    Indeterminate,
}

/// Why a candidate landed in its status. Evidence, not a rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicabilityReason {
    TargetSatisfied,
    ArchitectureMismatch,
    OsVersionTooOld,
    BuildTooOld,
    ProductTypeUnavailable,
    SuiteMaskUnavailable,
    MissingTargetMetadata,
    UnsupportedTargetSyntax,
    UnknownHostArchitecture,
}

/// The OS-applicability evidence for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogApplicabilityEvidence {
    /// Resolved Models-section target provenance (the SDIO
    /// `DataManuf.sections[sect_pos]` value), verbatim.
    pub models_section: Option<String>,
    /// The parsed TargetOSVersion decoration, when deterministically present.
    pub target: Option<TargetOsDecoration>,
    pub status: CatalogOsApplicability,
    pub reason: ApplicabilityReason,
}

/// One matched candidate annotated with its catalog OS applicability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessedCatalogCandidate {
    pub matched: CatalogCandidateMatch,
    pub os: CatalogApplicabilityEvidence,
}

/// Per-device assessment output. Device order, candidate order and evidence
/// order are preserved; nothing is reordered by status/date/version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessedDeviceMatches {
    pub instance_id: String,
    pub candidates: Vec<AssessedCatalogCandidate>,
}

/// Evaluate a parsed target decoration against a host machine.
///
/// Errors only for an invalid/unknown host machine; the tri-state itself is
/// returned inside the evidence.
pub fn evaluate_target(
    target: &TargetOsDecoration,
    machine: &MachineContext,
) -> Result<CatalogApplicabilityEvidence, ApplicabilityError> {
    let parsed = parse_machine_context(machine)?;
    Ok(evaluate_parsed_target(target, &parsed))
}

/// The pure evaluation core against an already-parsed machine context.
///
/// Order of evaluation:
/// 1. Architecture — explicit mismatch is an immediately provable negative.
/// 2. OS version — host older than the target's major/minor is a provable
///    negative; host newer satisfies the version threshold (build is relative
///    to its major/minor pair).
/// 3. BuildNumber (same major/minor) — host build below the target build is a
///    provable negative.
/// 4. Architecture absent — a satisfied threshold cannot prove compatibility
///    on a non-x86 host (architecture is only genuinely optional for x86
///    targets since Windows Server 2003 SP1), so the result is Indeterminate
///    rather than HostCompatible. A NEGATIVE version verdict stays final.
/// 5. ProductType / SuiteMask — only reached after all provable negatives have
///    passed; MachineContext lacks them, so the result is Indeterminate rather
///    than guessed.
fn evaluate_parsed_target(
    target: &TargetOsDecoration,
    machine: &ParsedMachineContext,
) -> CatalogApplicabilityEvidence {
    // The version/build threshold is independently provable without architecture:
    // a target whose OS minimum exceeds the host excludes it on every platform.
    // A NEGATIVE version verdict is final; a satisfied version threshold only
    // clears the version question and still requires architecture/product/suite
    // resolution.
    let has_version_threshold = target.major.is_some();
    let version_negative = match target.major {
        None => None,
        Some(t_major) => {
            let t_minor = target.minor.unwrap_or(0);
            if machine.major < t_major || (machine.major == t_major && machine.minor < t_minor)
            {
                Some(ApplicabilityReason::OsVersionTooOld)
            } else if machine.major > t_major || machine.minor > t_minor {
                // Microsoft: build is relative to the target's major/minor pair; a
                // newer OS version satisfies the threshold regardless of build.
                None
            } else if let Some(t_build) = target.build
                && machine.build < t_build
            {
                Some(ApplicabilityReason::BuildTooOld)
            } else {
                None
            }
        }
    };

    let (status, reason) = match (target.architecture, version_negative) {
        // Explicit incompatible architecture is a provable negative on its own.
        (Some(a), _) if a != machine.arch => {
            (CatalogOsApplicability::HostIncompatible, ApplicabilityReason::ArchitectureMismatch)
        }
        // Version/build alone proved a negative, independent of architecture
        // (an absent architecture never overrides a provable version negative;
        // per Microsoft the version threshold applies on any supported platform).
        (_, Some(reason)) => (CatalogOsApplicability::HostIncompatible, reason),
        // Explicit compatible architecture + satisfied version threshold: the
        // version/arch questions are settled; only product/suite remains.
        (Some(_), None) if has_version_threshold => product_suite_verdict(target),
        // Architecture-absent decoration whose version threshold is satisfied
        // AND which carries ProductType/SuiteMask: the version question is
        // settled, and the product/suite unknown is the more specific evidence
        // (MachineContext lacks both) — Indeterminate, not a bare no-target.
        (None, None) if has_version_threshold && (target.product_type.is_some() || target.suite_mask.is_some()) => {
            product_suite_verdict(target)
        }
        // Architecture-absent decoration with a satisfied version threshold.
        // Since Windows Server 2003 SP1, architecture is optional in
        // Models-section names only for x86-based target OS versions; on any
        // other host an arch-less decoration is not a deterministic
        // compatibility proof, so it cannot yield HostCompatible.
        (None, None) if has_version_threshold && machine.arch != TargetArch::X86 => {
            (CatalogOsApplicability::Indeterminate, ApplicabilityReason::MissingTargetMetadata)
        }
        // Architecture-absent decoration, satisfied threshold, x86 host:
        // arch-less is the documented x86 form and the threshold passes.
        (None, None) if has_version_threshold => product_suite_verdict(target),
        // Architecture absent AND no version threshold: the target carries no
        // deterministic OS evidence at all.
        (None, None) => {
            (CatalogOsApplicability::Indeterminate, ApplicabilityReason::MissingTargetMetadata)
        }
        // Architecture-only target (`NTamd64`): any <arch> version satisfies.
        (Some(_), None) => product_suite_verdict(target),
    };

    CatalogApplicabilityEvidence {
        models_section: None,
        target: Some(target.clone()),
        status,
        reason,
    }
}

/// Final verdict once architecture + OS version/build thresholds are satisfied:
/// an unknown ProductType / SuiteMask on the target makes the index unable to
/// prove applicability (never guessed as workstation or zero mask).
fn product_suite_verdict(target: &TargetOsDecoration) -> (CatalogOsApplicability, ApplicabilityReason) {
    if target.product_type.is_some() {
        (CatalogOsApplicability::Indeterminate, ApplicabilityReason::ProductTypeUnavailable)
    } else if target.suite_mask.is_some() {
        (CatalogOsApplicability::Indeterminate, ApplicabilityReason::SuiteMaskUnavailable)
    } else {
        (CatalogOsApplicability::HostCompatible, ApplicabilityReason::TargetSatisfied)
    }
}

// ---------------------------------------------------------------------------
// Assessment (pure)
// ---------------------------------------------------------------------------

/// Assess every candidate for one device. Preserves device order, candidate
/// order and match-evidence order. Returns every candidate; nothing is dropped.
pub fn assess_device_matches(
    matches: &DeviceCatalogMatches,
    machine: &MachineContext,
) -> Result<AssessedDeviceMatches, ApplicabilityError> {
    let parsed = parse_machine_context(machine)?;
    let candidates = matches
        .candidates
        .iter()
        .map(|m| assess_one(m, &parsed))
        .collect();
    Ok(AssessedDeviceMatches {
        instance_id: matches.instance_id.clone(),
        candidates,
    })
}

/// Assess every device in a batch. One result per input device, in input order.
pub fn assess_matches(
    matches: &[DeviceCatalogMatches],
    machine: &MachineContext,
) -> Result<Vec<AssessedDeviceMatches>, ApplicabilityError> {
    let parsed = parse_machine_context(machine)?;
    matches
        .iter()
        .map(|m| {
            Ok(AssessedDeviceMatches {
                instance_id: m.instance_id.clone(),
                candidates: m.candidates.iter().map(|c| assess_one(c, &parsed)).collect(),
            })
        })
        .collect()
}

fn assess_one(matched: &CatalogCandidateMatch, machine: &ParsedMachineContext) -> AssessedCatalogCandidate {
    let models_section = matched.candidate.models_section.clone();
    // Gate A4: `sect_pos > 0` means the entry IS a TargetOSVersion decoration
    // position; `sect_pos == 0` is the undecorated Models-section base name and
    // carries no OS evidence. Provenance is positional, never guessed from text.
    if matched.candidate.sect_pos > 0 {
        match models_section.as_deref() {
            Some(s) => match parse_target_os_version(s) {
                Ok(t) => {
                    let ev = evaluate_parsed_target(&t, machine);
                    return AssessedCatalogCandidate {
                        matched: matched.clone(),
                        os: CatalogApplicabilityEvidence {
                            models_section,
                            target: Some(t),
                            status: ev.status,
                            reason: ev.reason,
                        },
                    };
                }
                Err(_) => {
                    return AssessedCatalogCandidate {
                        matched: matched.clone(),
                        os: CatalogApplicabilityEvidence {
                            models_section,
                            target: None,
                            status: CatalogOsApplicability::Indeterminate,
                            reason: ApplicabilityReason::UnsupportedTargetSyntax,
                        },
                    };
                }
            },
            // A decoration position with no text is malformed metadata.
            None => {
                return AssessedCatalogCandidate {
                    matched: matched.clone(),
                    os: CatalogApplicabilityEvidence {
                        models_section,
                        target: None,
                        status: CatalogOsApplicability::Indeterminate,
                        reason: ApplicabilityReason::UnsupportedTargetSyntax,
                    },
                };
            }
        }
    }

    // Undecorated base name (sect_pos == 0): no TargetOSVersion evidence.
    AssessedCatalogCandidate {
        matched: matched.clone(),
        os: CatalogApplicabilityEvidence {
            models_section,
            target: None,
            status: CatalogOsApplicability::Indeterminate,
            reason: ApplicabilityReason::MissingTargetMetadata,
        },
    }
}
