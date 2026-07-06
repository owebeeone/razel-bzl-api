use crate::{Depset, ProviderDef};

/// The declared type of a rule attribute (Bazel's `attr.*`). Minimal set; grows additively. The point for
/// analysis is distinguishing LABEL-typed attrs (which resolve to dependency targets) from scalars.
///
/// Discriminants are EXPLICIT + `#[repr(u8)]`: the stable wire/digest code is `self as u8`, the ONE source of
/// truth used by every encoder. Reordering variants can't silently change the code (the byte is pinned here).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AttrType {
    Int = 0,
    String = 1,
    Bool = 2,
    Label = 3,
    LabelList = 4,
    StringList = 5,
}
impl AttrType {
    /// Is this attribute a dependency edge (a label or list of labels)? Analysis resolves these to targets.
    pub fn is_label(self) -> bool {
        matches!(self, AttrType::Label | AttrType::LabelList)
    }
    /// The stable code for this type (pinned by the explicit discriminants). The one encoder mapping.
    pub fn code(self) -> u8 {
        self as u8
    }
    /// Inverse of `code` — fail-closed on an unknown code (never a silent default).
    pub fn from_code(c: u8) -> Option<AttrType> {
        Some(match c {
            0 => AttrType::Int,
            1 => AttrType::String,
            2 => AttrType::Bool,
            3 => AttrType::Label,
            4 => AttrType::LabelList,
            5 => AttrType::StringList,
            _ => return None,
        })
    }
}

/// A rule definition's codec-neutral identity, produced by `rule(...)` in a `.bzl` and carried as a value:
/// WHERE it is defined (`bzl` = the defining `.bzl`, `name` = the exported symbol) + its attribute schema.
/// Deliberately carries NO live implementation function (a heap-bound Starlark value is not codec-neutral) —
/// the analysis phase re-obtains the live impl by re-evaluating `bzl`. `attrs` is name-sorted (deterministic).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuleDef {
    pub bzl: String,
    pub name: String,
    pub attrs: Vec<(String, AttrType)>,
    /// The toolchain TYPE ids this rule requires (`rule(toolchains=[…])`). Analysis resolves each to a
    /// `ctx.toolchains[type]` for the target's configuration (phase #4). Empty = no toolchains required.
    pub toolchains: Vec<String>,
}

/// A codec-neutral value a `.bzl` can export at module scope. EXHAUSTIVE by ratified decision (R3): a new
/// variant is compile-driven match growth in every consumer — never a wildcard arm absorbing it. Digest tags
/// 0-7 are pinned in [`encode_bzl_value`]; a variant's tag is immutable once landed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BzlValue {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<BzlValue>),
    /// A rule defined by `rule(...)` — its identity + attr schema (see `RuleDef`).
    Rule(RuleDef),
    /// A provider type defined by `provider(...)` — its identity + field schema (see `ProviderDef`).
    Provider(ProviderDef),
    /// A depset — the ordered-DAG value (see `Depset`). VALUE-MODEL-ONLY in v1: the tag + order-code table
    /// are pinned NOW (`RazelV4ProviderIdentityLockdown.md` rows C/D, R6) so no unpinned byte can enter
    /// frozen digest content when the live depset machinery lands; nothing constructs one yet.
    Depset(Depset),
}

/// The exported global bindings of an evaluated `.bzl`, sorted by name (deterministic).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BzlModule {
    pub bindings: Vec<(String, BzlValue)>,
}
impl BzlModule {
    pub fn get(&self, name: &str) -> Option<&BzlValue> {
        self.bindings.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

/// Where a target's rule is defined — the link the analysis phase follows to find + run the rule's impl. A
/// target instantiated by a `rule()`-defined callable carries `Some`; the generic `target(kind=…)` spike
/// placeholder carries `None` (so analysis fails closed on it — there is no impl to run).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuleOrigin {
    pub bzl: String,
    pub name: String,
}

/// A target instantiated by a rule call in a BUILD file: its rule `kind`, its `name`, its attribute values
/// (sorted by attr name, deterministic), and its rule `origin` (where the rule is defined, for analysis).
/// Instantiation records DATA — the rule's `_impl` is NOT run here; running rules to produce providers/actions
/// is the analysis phase (ADR-0004). `name` is lifted out of the attrs because a package is keyed by target
/// name (uniqueness is enforced fail-closed at instantiation).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TargetDecl {
    pub kind: String,
    pub name: String,
    pub attrs: Vec<(String, BzlValue)>,
    pub origin: Option<RuleOrigin>,
}

