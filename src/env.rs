//! The phase-environment contract surface (ADR-0003; `dev-docs/RazelV4PhaseEnvLockdown.md`, RATIFIED
//! 2026-07-06). Razel-owned and seam-insulated: NO `starlark::*` type appears here (plan §4.6), so every
//! key/value built from these types survives the earn-or-replace engine choice. The §1 matrix's decided
//! artifacts:
//!
//! * [`LoadKind`] — the CLOSED four-variant key discriminant (REQ-BZLLOAD-002). Env selection is a function
//!   of the LoadKind alone, never of key contents (key fact A): [`LoadKind::env_tag`] is the ONE kind→env
//!   mapping, and [`LoadKind::key_for_load`] is Bazel's `getKeyForLoad` kind propagation (REQ-BZLLOAD-005).
//! * [`Dialect`] — `.bzl` vs `.scl`, keyed from the label suffix, never defaulted (REQ-BZLCOMPILE-007).
//!   Orthogonal to LoadKind: a `.scl` key KEEPS the requesting kind (the double-load quirk, R3).
//! * [`PredeclaredEnvId`] + [`derive_predeclared_env_id`] — R1: a blake3-style digest over the razel codec
//!   framing of `env_tag(u8)` ⊕ the byte-sorted `(name, identity, version)` enumeration ⊕ (EnvBuildBzl ONLY)
//!   the injected-builtins slot. NEVER starlark heap bytes (`Globals::iter()` is not a cross-build encoding).
//! * [`StarlarkSemanticsId`] + [`StarlarkFlagRegistry`] — R2: a fingerprint over sorted `(flag, value)`
//!   pairs of NON-DEFAULT flags of a razel-owned CLOSED registry (canonical-map equality, mirroring
//!   `StarlarkSemantics.java:61-67` — equivalent flag sets are EQUAL). A KEY dimension; NEVER folded into
//!   any `transitive_digest` (Bazel parity: semantics is in no bzl digest).
//! * [`TypeOptions`] — R4: declared at compile (a `BzlCompileKey` dimension), enforced at load (Bazel's
//!   split kept; `BzlLoadFunction.java:883-892`).
//! * [`EvalEnv`] — the seam's environment handle (§3): `{load_kind, dialect, semantics, type_options}`.

use crate::BzlError;

// ──────────────── the razel-owned 32-byte identity digest ────────────────

/// Content digest for the phase-environment identities. SKELETON hash (same discipline as `razel-core`'s
/// `Digest` — the real impl is blake3): FNV-1a accumulation + length, splitmix64 expansion to 32 bytes.
/// Local to this crate BY DESIGN: the eval seam stays dependency-free, and `core::Digest` (frozen) exposes
/// no byte accessor for key encoding. These ids are their own identity domain (domain-prefixed below).
fn digest32(bytes: &[u8]) -> [u8; 32] {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h ^= bytes.len() as u64;
    h = h.wrapping_mul(PRIME);
    let mut out = [0u8; 32];
    let mut x = h;
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    out
}

fn framed(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s);
}

// ──────────────── LoadKind: the closed key discriminant (rows 1-5) ────────────────

/// The load kinds — a CLOSED set (REQ-BZLLOAD-002): a new variant is an ADR amendment, never an open
/// string. Mirrors Bazel's sealed `BzlLoadValue.Key` hierarchy (`KeyForBuild`/`KeyForBuiltins`/
/// `KeyForBzlmod`/`KeyForBzlmodBootstrap`). Wire codes are pinned in [`LoadKind::code`] — the ONE encoder
/// mapping; `from_code` is fail-closed. v1 exercises only `Build{is_prelude:false}`; the other variants are
/// representable-but-unsupported (the node fails closed on them, never absorbs).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum LoadKind {
    /// Rows 1-2: loaded on behalf of a BUILD file. `is_prelude` marks the BUILD prelude — a compile/key
    /// bit, NOT an environment (both prelude values share `EnvBuildBzl`, R1).
    Build { is_prelude: bool },
    /// Row 3: `@_builtins` pseudo-repo evaluation.
    Builtins,
    /// Row 4: repo rules / module extensions for Bzlmod-generated repositories.
    Bzlmod,
    /// Row 5: the `@bazel_tools` bzlmod bootstrap.
    BzlmodBootstrap,
}
impl LoadKind {
    /// The stable wire/key code (pinned here; the prelude bit gets its own code so the byte is total).
    pub fn code(self) -> u8 {
        match self {
            LoadKind::Build { is_prelude: false } => 0,
            LoadKind::Build { is_prelude: true } => 1,
            LoadKind::Builtins => 2,
            LoadKind::Bzlmod => 3,
            LoadKind::BzlmodBootstrap => 4,
        }
    }
    /// Inverse of `code` — fail-closed on an unknown code (never a silent default).
    pub fn from_code(c: u8) -> Option<LoadKind> {
        Some(match c {
            0 => LoadKind::Build { is_prelude: false },
            1 => LoadKind::Build { is_prelude: true },
            2 => LoadKind::Builtins,
            3 => LoadKind::Bzlmod,
            4 => LoadKind::BzlmodBootstrap,
            _ => return None,
        })
    }
    /// Bazel's `getKeyForLoad` kind propagation (REQ-BZLLOAD-005): the kind a DEPENDENCY load is requested
    /// under. A prelude's loads are ordinary `Build{is_prelude:false}` (no prelude re-export propagation);
    /// every other kind propagates itself.
    pub fn key_for_load(self) -> LoadKind {
        match self {
            LoadKind::Build { .. } => LoadKind::Build { is_prelude: false },
            other => other,
        }
    }
    /// The env tag this kind selects (key fact A — a function of the kind alone). `.scl` overrides to
    /// `EnvScl` for EVERY kind (row 6: env selection ignores the kind; the KEY still keeps it — R3).
    pub fn env_tag(self, dialect: Dialect) -> EnvTag {
        if dialect == Dialect::Scl {
            return EnvTag::EnvScl;
        }
        match self {
            LoadKind::Build { .. } => EnvTag::EnvBuildBzl, // prelude SHARES EnvBuildBzl (R1)
            LoadKind::Builtins => EnvTag::EnvBuiltinsBzl,
            LoadKind::Bzlmod => EnvTag::EnvBzlmodBzl,
            LoadKind::BzlmodBootstrap => EnvTag::EnvBzlmodBootstrapBzl,
        }
    }
}

// ──────────────── Dialect: keyed from the label suffix, never defaulted ────────────────

/// `.bzl` vs `.scl` — a key dimension resolved from the label suffix (REQ-BZLCOMPILE-007), orthogonal to
/// [`LoadKind`] (R3: a `.scl` reached from two kinds is two keys/two copies — Bazel's documented quirk).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Dialect {
    Bzl = 0,
    Scl = 1,
}
impl Dialect {
    /// The stable wire/key code (pinned by the explicit discriminants).
    pub fn code(self) -> u8 {
        self as u8
    }
    /// Inverse of `code` — fail-closed on an unknown code.
    pub fn from_code(c: u8) -> Option<Dialect> {
        Some(match c {
            0 => Dialect::Bzl,
            1 => Dialect::Scl,
            _ => return None,
        })
    }
    /// Key the dialect from the label/path suffix — the ONE derivation (never inferred to a permissive
    /// default): anything not `.bzl`/`.scl` is `None`, a fail-closed condition at the caller.
    pub fn from_label_suffix(label: &str) -> Option<Dialect> {
        if label.ends_with(".bzl") {
            Some(Dialect::Bzl)
        } else if label.ends_with(".scl") {
            Some(Dialect::Scl)
        } else {
            None
        }
    }
}

// ──────────────── PredeclaredEnvId (R1) ────────────────

/// The six environment tags (§2). `EnvBuildFile` is the package-node row (7) — an env tag but NOT a
/// LoadKind; `Build{is_prelude:*}` SHARES `EnvBuildBzl` (prelude-ness lives in the LoadKind, R1).
/// Discriminants are EXPLICIT + `#[repr(u8)]` (the [`AttrType`](crate::AttrType) discipline).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum EnvTag {
    EnvBuildBzl = 1,
    EnvBuiltinsBzl = 2,
    EnvBzlmodBzl = 3,
    EnvBzlmodBootstrapBzl = 4,
    EnvScl = 5,
    EnvBuildFile = 6,
}
impl EnvTag {
    /// The stable digest code (pinned by the explicit discriminants).
    pub fn code(self) -> u8 {
        self as u8
    }
    /// Inverse of `code` — fail-closed on an unknown code.
    pub fn from_code(c: u8) -> Option<EnvTag> {
        Some(match c {
            1 => EnvTag::EnvBuildBzl,
            2 => EnvTag::EnvBuiltinsBzl,
            3 => EnvTag::EnvBzlmodBzl,
            4 => EnvTag::EnvBzlmodBootstrapBzl,
            5 => EnvTag::EnvScl,
            6 => EnvTag::EnvBuildFile,
            _ => return None,
        })
    }
}

/// One registered builtin in an environment's declared enumeration: its bound `name`, the builtin's
/// `identity` (WHICH razel builtin serves the name — the dimension a builtins injection overrides), and its
/// `version` (bumped when the builtin's observable behavior changes). The impl crate DECLARES these tables;
/// the id is derived from the declaration, never from a live heap.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EnvEntry {
    pub name: String,
    pub identity: String,
    pub version: String,
}

/// The `STARLARK_BUILTINS` node's value digest — razel's analogue of Bazel's `exports.bzl` transitive
/// digest (`StarlarkBuiltinsFunction.java:191-192`). v1 has NO live builtins node yet; the fold SLOT is
/// pinned now (option-tag framing: absent = tag `0`) so the v1 id is stable and a future injected value is
/// a DIFFERENT id, never a re-key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct BuiltinsDigest(pub [u8; 32]);

/// A predeclared environment's identity — a `BzlLoadKey` dimension (REQ-BZLLOAD-001/018). Derived ONLY by
/// [`derive_predeclared_env_id`] (the canonical funnel).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PredeclaredEnvId(pub [u8; 32]);

/// THE canonical derivation (R1): blake3-style digest over
/// `domain ⊕ env_tag(u8) ⊕ [byte-sorted] (name, identity, version) triples ⊕ [fold column] builtins slot`.
///
/// The §1 FOLD COLUMN is applied HERE, per frozen row: the injected-builtins slot is encoded for
/// `EnvBuildBzl` ONLY (rows 1-2 — `BzlLoadFunction.java:1365-1370`), and deliberately NOT for
/// `EnvBzlmodBzl` (row 4 — the repo-refetch-storm rationale, `:1377-1386`) or any other tag. A uniform
/// fold-always/fold-never is a parity bug either way (key fact B); the two mutants below each restore one.
///
/// Deterministic by construction: the enumeration is sorted by the full `(name, identity, version)` triple
/// (derived `Ord` — byte order), so insertion order can never leak into the id.
pub fn derive_predeclared_env_id(
    tag: EnvTag,
    entries: &[EnvEntry],
    injected_builtins: Option<&BuiltinsDigest>,
) -> PredeclaredEnvId {
    let mut sorted: Vec<&EnvEntry> = entries.iter().collect();
    sorted.sort();
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"razel:predeclared-env:v1"); // domain separation from every other digest family
    b.push(tag.code());
    b.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
    for e in sorted {
        framed(&mut b, e.name.as_bytes());
        framed(&mut b, e.identity.as_bytes());
        framed(&mut b, e.version.as_bytes());
    }
    // The fold column (frozen per §1 row). MUTANTS: `mutant_builtins_digest_dropped_for_build` restores
    // fold-never (a builtins change leaves BUILD-loaded ids stale — under-invalidation);
    // `mutant_builtins_digest_folded_for_bzlmod` restores fold-always for row 4 (a builtins change
    // re-fingerprints Bzlmod modules — repo-refetch over-invalidation). Each turns its headline gate red.
    let folds = match tag {
        EnvTag::EnvBuildBzl => !cfg!(feature = "mutant_builtins_digest_dropped_for_build"),
        EnvTag::EnvBzlmodBzl => cfg!(feature = "mutant_builtins_digest_folded_for_bzlmod"),
        _ => false,
    };
    if folds {
        match injected_builtins {
            None => b.push(0), // the v1 sentinel: no builtins value yet; a future Some is a DIFFERENT id
            Some(d) => {
                b.push(1);
                b.extend_from_slice(&d.0);
            }
        }
    }
    PredeclaredEnvId(digest32(&b))
}

/// Apply a builtins injection over a registered enumeration — key fact C: injection may only *override* a
/// registered name, never add or remove one (`validateSymbolIsInjectable`,
/// `BazelStarlarkEnvironment.java:349-360`). That invariant is what keeps ONE compile serving BUILD-loaded
/// and Bzlmod-loaded uses (the name-set is injection-invariant). Fail-closed: an injected name that
/// overrides nothing is a typed error — under `mutant_injection_adds_new_name` it is silently ADDED
/// instead, the exact unsoundness the `builtins_injection_override_only` gate kills.
pub fn apply_builtins_injection(
    registered: &[EnvEntry],
    overrides: &[EnvEntry],
) -> Result<Vec<EnvEntry>, BzlError> {
    let mut out = registered.to_vec();
    for o in overrides {
        match out.iter_mut().find(|e| e.name == o.name) {
            Some(slot) => *slot = o.clone(),
            None if cfg!(feature = "mutant_injection_adds_new_name") => out.push(o.clone()),
            None => {
                return Err(BzlError::Eval {
                    detail: format!(
                        "cannot inject '{}': builtins injection may only override a registered name, never add one",
                        o.name
                    ),
                })
            }
        }
    }
    Ok(out)
}

// ──────────────── StarlarkSemanticsId (R2) + TypeOptions (R4) ────────────────

/// UTF-8 enforcement mode for Starlark source bytes — one closed flag of the registry. The razel v1
/// default is `Error` (the load node already fail-closes on non-UTF-8 source — the default DESCRIBES the
/// shipped behavior; Bazel-parity of the softer modes is deferred to a parity vector).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Utf8Enforcement {
    Off = 0,
    Warning = 1,
    Error = 2,
}

/// Static/dynamic type-check options (Bazel `TypeOptions`) — R4: DECLARED at compile (a `BzlCompileKey`
/// dimension, carried in the compile VALUE), ENFORCED at load (`BzlLoadFunction.java:883-892` parity).
/// v1 sentinel: all-off (`Default`); the load path fails closed on any non-default value until the
/// type-check pass exists — a future value is new keyed behavior, never silently ignored.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct TypeOptions {
    pub use_type_syntax: bool,
    pub static_checks: bool,
    pub dynamic_checks: bool,
}
impl TypeOptions {
    /// Canonical 3-byte encoding (one bool byte per option, declaration order).
    pub fn encode_into(&self, b: &mut Vec<u8>) {
        b.push(self.use_type_syntax as u8);
        b.push(self.static_checks as u8);
        b.push(self.dynamic_checks as u8);
    }
}

/// The razel-owned CLOSED Starlark flag registry (R2) — the compile-relevant configuration that changes
/// module *meaning*. starlark-rust has no semantics object, so there is nothing engine-side to hash: this
/// struct IS the registry, by construction (seam clause, plan §4.6). CLOSED: adding a flag is an ADR-0003
/// amendment. Defaults below are the razel v1 row; a new flag lands AT its default, so the fingerprint of
/// existing configurations is unchanged (the non-default canonical map — nothing re-keys).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StarlarkFlagRegistry {
    /// `.scl` dialect availability (Bazel `--experimental_enable_scl_dialect`). v1 default: DISABLED —
    /// a `.scl` load under the v1 row fails closed (REQ-BZLLOAD-015).
    pub scl_enabled: bool,
    /// `.bzl` `visibility()` machinery availability. v1 default: enabled (default-PUBLIC data, R5).
    pub bzl_visibility_enabled: bool,
    /// Enforce visibility at the caller's load edge (Bazel `--check_bzl_visibility`). v1 default: enabled.
    pub check_bzl_visibility: bool,
    /// Source-bytes UTF-8 enforcement. v1 default: `Error` (the shipped fail-closed read).
    pub utf8_enforcement: Utf8Enforcement,
    /// The type-syntax trio (R4). v1 default: all-off.
    pub type_options: TypeOptions,
    /// Label prefixes allowed to use type syntax. Canonicalized (sorted + deduped) in the fingerprint.
    pub type_syntax_allowlist: Vec<String>,
}
impl Default for StarlarkFlagRegistry {
    fn default() -> StarlarkFlagRegistry {
        StarlarkFlagRegistry {
            scl_enabled: false,
            bzl_visibility_enabled: true,
            check_bzl_visibility: true,
            utf8_enforcement: Utf8Enforcement::Error,
            type_options: TypeOptions::default(),
            type_syntax_allowlist: Vec::new(),
        }
    }
}
impl StarlarkFlagRegistry {
    /// The R2 fingerprint: blake3-style digest over the name-sorted `(flag, value)` pairs of NON-DEFAULT
    /// flags only — the exact canonical-map equality Bazel uses (`StarlarkSemantics.java:61-67`), so an
    /// explicit-at-default configuration and an omitted one are EQUAL (no spurious cache splits), and a
    /// flag added later at its default re-keys nothing.
    pub fn fingerprint(&self) -> StarlarkSemanticsId {
        let d = StarlarkFlagRegistry::default();
        let mut pairs: Vec<(&'static str, Vec<u8>)> = Vec::new();
        if self.scl_enabled != d.scl_enabled {
            pairs.push(("scl_enabled", vec![self.scl_enabled as u8]));
        }
        if self.bzl_visibility_enabled != d.bzl_visibility_enabled {
            pairs.push(("bzl_visibility_enabled", vec![self.bzl_visibility_enabled as u8]));
        }
        if self.check_bzl_visibility != d.check_bzl_visibility {
            pairs.push(("check_bzl_visibility", vec![self.check_bzl_visibility as u8]));
        }
        if self.utf8_enforcement != d.utf8_enforcement {
            pairs.push(("utf8_enforcement", vec![self.utf8_enforcement as u8]));
        }
        if self.type_options != d.type_options {
            let mut v = Vec::new();
            self.type_options.encode_into(&mut v);
            pairs.push(("type_options", v));
        }
        // Canonical SET semantics for the allowlist: sorted + deduped before comparison and encoding.
        let mut allow = self.type_syntax_allowlist.clone();
        allow.sort();
        allow.dedup();
        if allow != d.type_syntax_allowlist {
            let mut v = Vec::new();
            v.extend_from_slice(&(allow.len() as u64).to_be_bytes());
            for a in &allow {
                framed(&mut v, a.as_bytes());
            }
            pairs.push(("type_syntax_allowlist", v));
        }
        pairs.sort_by(|a, z| a.0.cmp(z.0));
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(b"razel:starlark-semantics:v1"); // domain separation
        b.extend_from_slice(&(pairs.len() as u64).to_be_bytes());
        for (name, value) in &pairs {
            framed(&mut b, name.as_bytes());
            framed(&mut b, value);
        }
        StarlarkSemanticsId(digest32(&b))
    }
}

/// The Starlark-semantics fingerprint — a `BzlLoadKey` dimension (slot already reserved,
/// REQ-BZLLOAD-001/018), NEVER folded into `transitive_digest` (R2; Bazel parity: semantics propagates via
/// the key/edge only). v1 registers a single row — keyed selection with one entry ([`Self::v1`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct StarlarkSemanticsId(pub [u8; 32]);
impl StarlarkSemanticsId {
    /// The single v1 semantics row: the all-default registry's fingerprint. Any other id observed by the
    /// v1 node/evaluator is fail-closed "unknown semantics row", never a silently-different behavior.
    pub fn v1() -> StarlarkSemanticsId {
        StarlarkFlagRegistry::default().fingerprint()
    }
}

// ──────────────── EvalEnv: the seam's environment handle (§3) ────────────────

/// The environment a `.bzl` evaluation runs under — the `BzlEvaluator` seam's parameter (§3). The trait
/// was parameterless w.r.t. environment and thus structurally incapable of the §1 rows; this handle names
/// them. BUILD-file eval (row 7) is NOT represented here: it is not a LoadKind — `evaluate_build` itself
/// is that phase's discriminant and uses `EnvBuildFile` internally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvalEnv {
    pub load_kind: LoadKind,
    pub dialect: Dialect,
    pub semantics: StarlarkSemanticsId,
    pub type_options: TypeOptions,
}
impl EvalEnv {
    /// The row-1 env (`.bzl` for BUILD) under the single v1 semantics row + v1 TypeOptions sentinel — the
    /// environment every current call site evaluates in (behavior-preserving for the current corpus).
    pub fn build_bzl_v1() -> EvalEnv {
        EvalEnv {
            load_kind: LoadKind::Build { is_prelude: false },
            dialect: Dialect::Bzl,
            semantics: StarlarkSemanticsId::v1(),
            type_options: TypeOptions::default(),
        }
    }
}
impl Default for EvalEnv {
    fn default() -> EvalEnv {
        EvalEnv::build_bzl_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: &str, i: &str, v: &str) -> EnvEntry {
        EnvEntry { name: n.into(), identity: i.into(), version: v.into() }
    }
    fn table() -> Vec<EnvEntry> {
        vec![entry("provider", "razel.provider", "1"), entry("rule", "razel.rule", "1")]
    }

    /// Lockdown gate `predeclared_env_id_is_canonical` (§4, NEW; unit-gated): same env twice / different
    /// insertion order ⇒ identical id; ids differ across env tags and across every enumeration dimension.
    #[test]
    fn predeclared_env_id_is_canonical() {
        let fwd = table();
        let mut rev = table();
        rev.reverse();
        let a = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &fwd, None);
        let b = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &rev, None);
        assert_eq!(a, b, "insertion order must never leak into the id (byte-sorted enumeration)");
        assert_eq!(
            a,
            derive_predeclared_env_id(EnvTag::EnvBuildBzl, &fwd, None),
            "deterministic across derivations"
        );
        // ids partition by tag: every pair of tags over one enumeration is distinct.
        let tags = [
            EnvTag::EnvBuildBzl,
            EnvTag::EnvBuiltinsBzl,
            EnvTag::EnvBzlmodBzl,
            EnvTag::EnvBzlmodBootstrapBzl,
            EnvTag::EnvScl,
            EnvTag::EnvBuildFile,
        ];
        for (i, x) in tags.iter().enumerate() {
            for y in &tags[i + 1..] {
                assert_ne!(
                    derive_predeclared_env_id(*x, &fwd, None),
                    derive_predeclared_env_id(*y, &fwd, None),
                    "env tags {x:?} vs {y:?} must yield distinct ids"
                );
            }
        }
        // every triple dimension is identity: name / identity / version each distinguish.
        let base = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &table(), None);
        let mut t = table();
        t[0].identity = "razel.other".into();
        assert_ne!(base, derive_predeclared_env_id(EnvTag::EnvBuildBzl, &t, None), "identity distinguishes");
        let mut t = table();
        t[0].version = "2".into();
        assert_ne!(base, derive_predeclared_env_id(EnvTag::EnvBuildBzl, &t, None), "version distinguishes");
        let mut t = table();
        t.push(entry("aspect", "razel.aspect", "1"));
        assert_ne!(base, derive_predeclared_env_id(EnvTag::EnvBuildBzl, &t, None), "the name-set distinguishes");
    }

    /// Headline matrix gate `build_bzl_digest_includes_injected_builtins` (§1 fold column, rows 1-2).
    /// RED under `mutant_builtins_digest_dropped_for_build` (fold-never = under-invalidation).
    #[test]
    fn build_bzl_digest_includes_injected_builtins() {
        let e = table();
        let none = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &e, None);
        let d1 = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &e, Some(&BuiltinsDigest([1; 32])));
        let d2 = derive_predeclared_env_id(EnvTag::EnvBuildBzl, &e, Some(&BuiltinsDigest([2; 32])));
        assert_ne!(none, d1, "the v1 no-builtins sentinel and an injected value must be DIFFERENT ids");
        assert_ne!(d1, d2, "an injected-builtins change must re-fingerprint the EnvBuildBzl id (the fold)");
    }

    /// Headline matrix gate `bzlmod_bzl_digest_excludes_injected_builtins` (§1 fold column, row 4 — the
    /// repo-refetch-storm rationale). RED under `mutant_builtins_digest_folded_for_bzlmod` (fold-always =
    /// over-invalidation).
    #[test]
    fn bzlmod_bzl_digest_excludes_injected_builtins() {
        let e = table();
        let none = derive_predeclared_env_id(EnvTag::EnvBzlmodBzl, &e, None);
        let d1 = derive_predeclared_env_id(EnvTag::EnvBzlmodBzl, &e, Some(&BuiltinsDigest([1; 32])));
        let d2 = derive_predeclared_env_id(EnvTag::EnvBzlmodBzl, &e, Some(&BuiltinsDigest([2; 32])));
        assert_eq!(none, d1, "row 4 deliberately EXCLUDES the builtins digest (no refetch storm on upgrades)");
        assert_eq!(d1, d2, "an injected-builtins change must NOT re-fingerprint the EnvBzlmodBzl id");
    }

    /// Lockdown gate `builtins_injection_override_only` (§4, NEW; key fact C): an injection that does not
    /// override a registered name fails closed; an override changes the id but never the name-set.
    /// RED under `mutant_injection_adds_new_name`.
    #[test]
    fn builtins_injection_override_only() {
        let reg = table();
        // (a) adding a new name is fail-closed — the one-compile-serves-two-kinds collapse depends on it.
        assert!(
            apply_builtins_injection(&reg, &[entry("smuggled", "razel.smuggled", "1")]).is_err(),
            "injecting a symbol that overrides no registered name must fail closed, never be added"
        );
        // (b) overriding a registered name is legal, changes the id, and keeps the name-set identical.
        let injected = apply_builtins_injection(&reg, &[entry("rule", "builtins.rule", "7")])
            .expect("overriding a registered name is a legal injection");
        assert_eq!(injected.len(), reg.len(), "injection must never change the name-set size");
        let names = |v: &[EnvEntry]| {
            let mut n: Vec<String> = v.iter().map(|e| e.name.clone()).collect();
            n.sort();
            n
        };
        assert_eq!(names(&injected), names(&reg), "injection is override-only: the NAME-SET is invariant");
        assert_ne!(
            derive_predeclared_env_id(EnvTag::EnvBuildBzl, &reg, None),
            derive_predeclared_env_id(EnvTag::EnvBuildBzl, &injected, None),
            "an override changes the builtin's identity/version ⇒ the env id must change"
        );
    }

    /// Contract gate `load_kind_is_closed_set` (REQ-BZLLOAD-002): the exhaustive match compiles over
    /// exactly the four Bazel kinds; wire codes are pinned + fail-closed round-trips.
    #[test]
    fn load_kind_is_closed_set() {
        // Exhaustive match — a new variant is a compile error here (the ADR-amendment tripwire).
        fn class(k: LoadKind) -> &'static str {
            match k {
                LoadKind::Build { .. } => "build",
                LoadKind::Builtins => "builtins",
                LoadKind::Bzlmod => "bzlmod",
                LoadKind::BzlmodBootstrap => "bzlmod_bootstrap",
            }
        }
        let all = [
            LoadKind::Build { is_prelude: false },
            LoadKind::Build { is_prelude: true },
            LoadKind::Builtins,
            LoadKind::Bzlmod,
            LoadKind::BzlmodBootstrap,
        ];
        for (i, k) in all.iter().enumerate() {
            assert_eq!(k.code(), i as u8, "wire code pinned for {}", class(*k));
            assert_eq!(LoadKind::from_code(i as u8), Some(*k), "code {i} round-trips");
        }
        for c in 5..=255u8 {
            assert_eq!(LoadKind::from_code(c), None, "unknown kind code {c} must fail closed");
        }
    }

    /// Contract gate `dependency_load_kind_is_contextual` (REQ-BZLLOAD-005, the `getKeyForLoad` table):
    /// a prelude's loads are ordinary `Build{false}`; every other kind propagates itself.
    #[test]
    fn dependency_load_kind_is_contextual() {
        assert_eq!(
            LoadKind::Build { is_prelude: true }.key_for_load(),
            LoadKind::Build { is_prelude: false },
            "a prelude file's loads are loaded as ordinary Build (no prelude re-export propagation)"
        );
        assert_eq!(LoadKind::Build { is_prelude: false }.key_for_load(), LoadKind::Build { is_prelude: false });
        assert_eq!(LoadKind::Builtins.key_for_load(), LoadKind::Builtins);
        assert_eq!(LoadKind::Bzlmod.key_for_load(), LoadKind::Bzlmod);
        assert_eq!(LoadKind::BzlmodBootstrap.key_for_load(), LoadKind::BzlmodBootstrap);
    }

    /// Key facts A + R1/R3 of the kind→env mapping: env selection is a function of the LoadKind alone;
    /// prelude SHARES EnvBuildBzl; `.scl` overrides EVERY kind to EnvScl (the key keeps the kind — R3).
    #[test]
    fn env_selection_is_a_function_of_loadkind() {
        assert_eq!(LoadKind::Build { is_prelude: false }.env_tag(Dialect::Bzl), EnvTag::EnvBuildBzl);
        assert_eq!(
            LoadKind::Build { is_prelude: true }.env_tag(Dialect::Bzl),
            EnvTag::EnvBuildBzl,
            "prelude-ness is a LoadKind bit, not an environment (R1: shares EnvBuildBzl)"
        );
        assert_eq!(LoadKind::Builtins.env_tag(Dialect::Bzl), EnvTag::EnvBuiltinsBzl);
        assert_eq!(LoadKind::Bzlmod.env_tag(Dialect::Bzl), EnvTag::EnvBzlmodBzl);
        assert_eq!(LoadKind::BzlmodBootstrap.env_tag(Dialect::Bzl), EnvTag::EnvBzlmodBootstrapBzl);
        for k in [LoadKind::Build { is_prelude: false }, LoadKind::Builtins, LoadKind::Bzlmod] {
            assert_eq!(k.env_tag(Dialect::Scl), EnvTag::EnvScl, ".scl env selection ignores the kind (row 6)");
        }
    }

    /// R2: the semantics fingerprint is the non-default canonical map — the default registry IS the v1
    /// row; a flag flip re-keys; an allowlist is canonicalized as a set.
    #[test]
    fn semantics_fingerprint_is_nondefault_canonical_map() {
        let v1 = StarlarkSemanticsId::v1();
        assert_eq!(StarlarkFlagRegistry::default().fingerprint(), v1, "the all-default registry is the v1 row");
        let scl = StarlarkFlagRegistry { scl_enabled: true, ..Default::default() };
        assert_ne!(scl.fingerprint(), v1, "a non-default flag must produce a different semantics id");
        let a = StarlarkFlagRegistry {
            type_syntax_allowlist: vec!["//b".into(), "//a".into(), "//a".into()],
            ..Default::default()
        };
        let b = StarlarkFlagRegistry {
            type_syntax_allowlist: vec!["//a".into(), "//b".into()],
            ..Default::default()
        };
        assert_eq!(a.fingerprint(), b.fingerprint(), "the allowlist is canonicalized (sorted + deduped set)");
        assert_ne!(a.fingerprint(), v1, "a non-empty allowlist is a non-default flag");
    }

    /// REQ-BZLCOMPILE-007: the dialect is keyed from the label suffix and NEVER defaulted — an unknown
    /// suffix is `None` (fail-closed at the caller), and the wire codes fail closed.
    #[test]
    fn dialect_is_keyed_from_suffix_not_defaulted() {
        assert_eq!(Dialect::from_label_suffix("pkg/rules.bzl"), Some(Dialect::Bzl));
        assert_eq!(Dialect::from_label_suffix("pkg/opts.scl"), Some(Dialect::Scl));
        assert_eq!(Dialect::from_label_suffix("pkg/BUILD.bazel"), None, "not a load dialect — never defaulted");
        assert_eq!(Dialect::from_label_suffix("rules.bzl.bak"), None);
        for c in 2..=255u8 {
            assert_eq!(Dialect::from_code(c), None, "unknown dialect code {c} must fail closed");
        }
    }
}
