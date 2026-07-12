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
    /// A `label_list(allow_files = …)` attribute: a list of labels naming SOURCE FILES (not dependency
    /// targets). Distinct from `LabelList` because analysis must NOT resolve these to `CONFIGURED_TARGET`
    /// deps — razel models a source as a `FILE` node, so `is_label()` is FALSE and the rule impl reads them
    /// through `ctx.files.<attr>` (C3). Additive code 6 (existing codes are pinned; nothing iterates 0..=5).
    FileList = 6,
    /// A `string_dict()` attribute: a `{string: string}` map (T20 R-load, row 5 — rules_rust's
    /// `debug_info`/`opt_level`/`strip_level` toolchain attrs). NOT a dep edge (`is_label()` = FALSE). Additive
    /// code 7 (existing codes 0..=6 pinned). Analysis-time `ctx.attr.<name>` = dict is deferred (no probe uses it).
    StringDict = 7,
    /// A `string_list_dict()` attribute: a `{string: [string]}` map (T20 R-load, row 5). NOT a dep edge.
    /// Additive code 8. Analysis-time surfacing deferred (no probe uses it).
    StringListDict = 8,
    /// A `label_keyed_string_dict()` attribute: a `{label: string}` map whose KEYS are dep labels (T20 R-load,
    /// row 5). Additive code 9. In Bazel its keys ARE dependency edges; razel does NOT yet resolve dict-keyed
    /// deps (`is_label()` = FALSE for now, so analysis skips it — DEFERRED to R-analyze, documented, never a
    /// silent product need this wave: no probe-path rule uses it). A rule that reads one at analysis sees an
    /// unresolved attr, not a wrong dep set.
    LabelKeyedStringDict = 9,
}
impl AttrType {
    /// Is this attribute a dependency EDGE (a label or list of labels resolved to configured targets)?
    /// `FileList` is deliberately NOT a dep edge — its entries are source files (`ctx.files.<attr>`), so
    /// analysis skips them and never tries `resolve_dep("src/lib.rs")`.
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
            6 => AttrType::FileList,
            7 => AttrType::StringDict,
            8 => AttrType::StringListDict,
            9 => AttrType::LabelKeyedStringDict,
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
/// 0-10 are pinned in [`encode_bzl_value`]; a variant's tag is immutable once landed.
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
    /// A `File` value — carried by its exec-root-relative path string (the ONE load-bearing field; `dirname`/
    /// `basename` are derived from it on the live side). Added at T17-C5: provider fields now carry Files
    /// (`RustInfo.rlib`, `DefaultInfo.files` elements), so a File must survive the codec across node
    /// boundaries with `.path` intact — a `Str` would decode back to a string and lose `.path`. File has NO
    /// reserved tag (unlike depset's tag 7), so per the additive-growth discipline (ratified R3: the enum is
    /// EXHAUSTIVE, a new variant is compile-driven match growth) it takes the next FREE digest tag 8. Tags
    /// 0-7 stay byte-frozen; nothing about this reshapes them.
    File(String),
    /// A `struct(...)` value (T20 R-load-codec) — a bag of named fields, each itself a `BzlValue` (a nested
    /// struct, a `FunctionRef`, a provider, data …). rules_rust's `rust_common = struct(create_crate_info =
    /// _create_crate_info, crate_info = CrateInfo, default_version = "1.96.0", …)` is one: a struct whose
    /// fields mix functions, providers and strings, `load()`ed by sibling modules. CANONICAL: `fields` are
    /// SORTED by name (deterministic → digest-stable regardless of `struct()` kwargs order). Takes the next
    /// FREE digest tag 9; tags 0-8 stay byte-frozen (additive R3 growth, `RazelV4ProviderIdentityLockdown.md`).
    Struct(Vec<(String, BzlValue)>),
    /// A reference to a `.bzl`-defined FUNCTION (T20 R-load-codec) — the codec-neutral identity of a Starlark
    /// function that crosses the `BZL_LOAD` node boundary (`triple.bzl` → `triple`/`get_host_triple`;
    /// `common.bzl` → `_create_crate_info` inside `rust_common`). NEVER the closure/body: Bazel itself never
    /// serializes Starlark functions (Skyframe holds live modules; the digest basis is transitive source
    /// content). The evaluator re-materializes the live callable from the defining module (see the live-module
    /// bridge in `razel-bzl-starlark`). Takes the next FREE digest tag 10; tags 0-9 stay byte-frozen.
    FunctionRef(FunctionRef),
    /// A `Label(...)` value carried by its canonical label string (`@repo//pkg:name` / `//pkg:name`). The
    /// load-time `Label()` builtin (rules_cc's `CC_TOOLCHAIN_TYPE = Label("@bazel_tools//tools/cpp:toolchain_
    /// type")`) constructs one; it is often EXPORTED and `load()`ed, so it must cross the node boundary with
    /// its label text intact (the honest `.package`/`.name`/`.repo_name` fields are re-derived from it on the
    /// live side). Takes the next FREE digest tag 11; tags 0-10 stay byte-frozen (additive R3 growth).
    Label(String),
    /// A `dict` value (T20 R-load-codec) — INSERTION-ordered `(key, value)` pairs, each itself a `BzlValue`.
    /// `.bzl` modules export dict constants and structs carry dict fields; a `load()`ed dict must cross the
    /// node boundary intact. Order is PRESERVED (not sorted): Starlark dict iteration is insertion-ordered and
    /// observable, so the digest is order-sensitive (two same-entry dicts in different insertion order iterate
    /// differently ⇒ distinct values). Takes the next FREE digest tag 12; tags 0-11 stay byte-frozen.
    Dict(Vec<(BzlValue, BzlValue)>),
    /// An `attr.<type>(...)` schema MARKER (T20 R-load-codec) — the descriptor `attr.label_list(allow_files =
    /// True, providers = [...])` produces. Real rulesets build shared attribute dicts (`_common_attrs = {...}`)
    /// in one `.bzl` and `load()` them into others to compose rule schemas, so the marker must cross the node
    /// boundary with its schema fields intact. Carries the same fields the live marker does (the `AttrType`
    /// code + the live-channel schema: allow_files / required providers / mandatory / string default). Takes
    /// the next FREE digest tag 13; tags 0-12 stay byte-frozen.
    AttrDecl(AttrDecl),
    /// A `tuple(...)` value (T20 R-load-codec) — an IMMUTABLE ordered sequence. Same payload as
    /// [`BzlValue::List`] but a DISTINCT Starlark type (so `type(x) == "tuple"` and a tuple never aliases a
    /// list in the digest). `.bzl` modules carry tuple constants (and tuple dict keys). Takes the next FREE
    /// digest tag 14; tags 0-13 stay byte-frozen.
    Tuple(Vec<BzlValue>),
    /// An UNRESOLVED `select(...)` / SelectorList (T20 select) — a FIRST-CLASS load-time value that is NEVER
    /// resolved during BUILD/.bzl evaluation. It crosses the PACKAGE node boundary inside a `TargetDecl.attrs`
    /// value (`deps = select({...})`) and is resolved at ANALYSIS against the target's configuration (the
    /// resolution locus that OWNS matching). Modeled as Bazel's SelectorList: an ordered list of [`SelectArm`]s
    /// concatenated (`["//a"] + select({...})` → a Concrete arm then a Branch arm). A bare `select({...})` is a
    /// single Branch arm. CANONICAL: each Branch's conditions are CONDITION-LABEL-SORTED (a select dict is
    /// order-independent for matching, so sorting is safe and makes the digest declaration-order-independent).
    /// This is the ONLY BzlValue variant whose crossing was ratified with a STOP-and-justify (R3): resolution
    /// is owned by analysis and the raw selector MUST cross unresolved (the configuration is unknown at load),
    /// so a resolve-before-boundary shape is impossible — the additive tag 15 is the honest form. Tags 0-14
    /// stay byte-frozen.
    Select(Vec<SelectArm>),
}

/// One arm of a [`BzlValue::Select`] SelectorList (Bazel's model): either a concrete operand in a `+` chain or
/// a `select({...})` branch. Arms are resolved independently and CONCATENATED at analysis.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SelectArm {
    /// A plain value operand in a `+` chain (`["//a"] + select(...)` → the `["//a"]` Concrete arm). Resolves
    /// to itself.
    Concrete(BzlValue),
    /// A `select({condition: value, ...}, no_match_error = "...")` branch. `conditions` are CANONICALLY SORTED
    /// by condition label (order-independent for matching → digest-stable). `//conditions:default` sorts as a
    /// normal string but is treated specially at resolution (matches least-specifically, only when no real
    /// condition matches). `no_match_error` carries Bazel's `select(no_match_error=)` message ("" = default).
    Branch { conditions: Vec<(String, BzlValue)>, no_match_error: String },
}

/// The codec-neutral form of an `attr.<type>(...)` schema marker (T20 R-load-codec, digest tag 13). Mirrors
/// the live `AttrTypeValue`'s fields so a shared attribute dict round-trips across a `load()`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttrDecl {
    /// The [`AttrType`] discriminant (`AttrType::code()`).
    pub code: u8,
    /// `label_list(allow_files = …)`: `None` = not a files attr, `Some([])` = any file, `Some([".rs"])` = only
    /// those extensions.
    pub allow_files: Option<Vec<String>>,
    /// `providers = [P, …]` required-provider NAMES on a label attr.
    pub providers: Vec<String>,
    /// `mandatory = True`.
    pub mandatory: bool,
    /// `attr.string(default = "…")` — the string default (only strings carry a codec-neutral default).
    pub default: Option<String>,
}

/// The codec-neutral identity of a `.bzl`-defined function (T20 R-load-codec, digest tag 10).
///
/// Identity = the PAIR `(module, name)` (so two same-named functions from DIFFERENT modules never alias —
/// exactly like a provider's `(bzl, name)` pair). `defining_digest` is the content digest of the defining
/// MODULE (its source + the digests of the modules it loads), NOT the function body: a body change
/// re-fingerprints the whole defining module, which re-fingerprints this ref, which changes every dependent's
/// `BZL_LOAD` value — module-content-level early cutoff, the SAME granularity as Bazel (whose `BzlLoadValue`
/// digest is the transitive source content). It is ALSO the live-module bridge's cache key dimension: the
/// evaluator materializes the callable from `(module, defining_digest)`'s cached live module (see
/// `razel-bzl-starlark`). The body is never carried, in any form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FunctionRef {
    /// The defining module's path — root-relative, or the `external/<repo>/…` exec form for a function
    /// defined in an external repo. The FIRST identity component (drop it and same-named functions alias).
    pub module: String,
    /// The exported symbol name in `module` (the name the live-module bridge looks up — a top-level `def`
    /// name, INCLUDING a private `_`-prefixed one when the function rides a struct field). The SECOND
    /// identity component.
    pub name: String,
    /// The defining module's content digest (source ⊕ transitive load-dep digests). Makes this ref — and
    /// thus every dependent's module value — source-sensitive, so a body change propagates (module-content
    /// cutoff). NOT the body; a fixed 32 bytes so the tag-10 frame is self-delimiting without a length prefix.
    pub defining_digest: [u8; 32],
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

