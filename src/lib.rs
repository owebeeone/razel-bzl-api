//! `razel-bzl-api` — the Starlark-evaluation seam. A `.bzl` file is evaluated by a `BzlEvaluator`; the result
//! is a `BzlModule` (its exported global bindings) in a codec-neutral value model. The concrete evaluator
//! (`starlark-rust`) lives behind this trait in `razel-bzl-starlark`, so the loading node-kinds depend on
//! THIS api, never on the Starlark crate — mock→real, wall-clean (same pattern as the `System` seam).
//!
//! SPIKE scope: enough of the value model to prove the integration (`x = 1 + 2`, strings, bools, lists).
//! Provider/struct/function values and `load()` resolution are deliberately out of this first cut.
//! When the model grows, `BzlValue`/`BzlError` extend and the conformance suite MUST extend in lockstep
//! (P9). Growth mechanism (ratified, `RazelV4ProviderIdentityLockdown.md` R3): `BzlValue` stays
//! **exhaustive** — a new variant is compile-driven match growth in every consumer, the fail-closed
//! discipline (`#[non_exhaustive]` would force downstream wildcard arms, which IS a coercion-to-default
//! path — anti-P3). Only `BzlError` carries `#[non_exhaustive]` (new error kinds are additive).

/// The phase-environment contract surface (ADR-0003 lockdown): LoadKind/Dialect/PredeclaredEnvId/
/// StarlarkSemanticsId/TypeOptions + the `EvalEnv` seam handle. Re-exported at the crate root.
mod env;
pub use env::*;

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

/// A provider TYPE declaration's codec-neutral form (`provider(name, fields=[…])`), carried as a value so it
/// survives `load()` across `.bzl`s (a provider is first-class loadable, like a rule). Identity is `id` — a
/// full [`ProviderId`], so declaration identity and instance identity share the reserved `bzl` dim and cannot
/// drift (`RazelV4ProviderIdentityLockdown.md` §2); `fields` are the declared field names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderDef {
    pub id: ProviderId,
    pub fields: Vec<String>,
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

/// A depset's traversal-order kind — exactly FOUR, with FIXED digest codes mirroring Bazel's enum ordinals
/// (`Order.java:104-108`), written as a fixed byte (never a varint of a Rust enum layout). The deprecated
/// order names (stable/compile/link/naive_link) are not parseable in current Bazel and MUST NOT be added.
/// Discriminants are EXPLICIT + `#[repr(u8)]` — same discipline as [`AttrType`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum DepsetOrder {
    /// Bazel `STABLE_ORDER` — Starlark `"default"`.
    Default = 0,
    /// Bazel `COMPILE_ORDER` — Starlark `"postorder"`.
    Postorder = 1,
    /// Bazel `LINK_ORDER` — Starlark `"topological"`.
    Topological = 2,
    /// Bazel `NAIVE_LINK_ORDER` — Starlark `"preorder"`.
    Preorder = 3,
}
impl DepsetOrder {
    /// The stable digest code (pinned by the explicit discriminants). The one encoder mapping.
    pub fn code(self) -> u8 {
        if cfg!(feature = "mutant_depset_order_code_swap") {
            // MUTANT: swap the topological/preorder codes → the byte-golden order-code gate goes red.
            return match self {
                DepsetOrder::Topological => 3,
                DepsetOrder::Preorder => 2,
                o => o as u8,
            };
        }
        self as u8
    }
    /// Inverse of `code` — fail-closed on an unknown code (never a silent default).
    pub fn from_code(c: u8) -> Option<DepsetOrder> {
        Some(match c {
            0 => DepsetOrder::Default,
            1 => DepsetOrder::Postorder,
            2 => DepsetOrder::Topological,
            3 => DepsetOrder::Preorder,
            _ => return None,
        })
    }
    /// Parse a Starlark `order =` name. ONLY the four current names parse (`Order.java:171-177,192-201`);
    /// the deprecated aliases fail closed.
    pub fn parse(name: &str) -> Option<DepsetOrder> {
        Some(match name {
            "default" => DepsetOrder::Default,
            "postorder" => DepsetOrder::Postorder,
            "topological" => DepsetOrder::Topological,
            "preorder" => DepsetOrder::Preorder,
            _ => return None,
        })
    }
    /// The canonical Starlark name (the `to_proto`/display form).
    pub fn starlark_name(self) -> &'static str {
        match self {
            DepsetOrder::Default => "default",
            DepsetOrder::Postorder => "postorder",
            DepsetOrder::Topological => "topological",
            DepsetOrder::Preorder => "preorder",
        }
    }
}

/// A depset value: the ordered DAG (never pre-flattened — the digest is STRUCTURAL, per-node, injective on
/// the value; same `to_list()` with different nesting is a DIFFERENT digest, mirroring Bazel's per-node
/// fingerprint shape without chasing its exact bytes — ratified R6). `elem` is the canonical top-level
/// Starlark type symbol, a DERIVED cache of the content (`None` = empty, merges with anything) — it is NOT
/// independent digest content (the §2 frame pins tag/order/direct/transitive only). Merge/type-check/flatten
/// semantics (lockdown row D) land with the live machinery; v1 pins only the value + digest shape.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Depset {
    pub order: DepsetOrder,
    pub elem: Option<String>,
    pub direct: Vec<BzlValue>,
    pub transitive: Vec<Depset>,
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

// ──────────────── analysis: providers (the rule-evaluation output) ────────────────

/// A provider's identity — the key for `dep[Provider]` lookup and a CONTENT-KEY dimension (it feeds every
/// configured-target + toolchain digest). Ratified shape (`RazelV4ProviderIdentityLockdown.md` R1, mirroring
/// `RuleOrigin{bzl,name}` and Bazel's `StarlarkProvider.Key = (module key, exported name)`): the PAIR of the
/// defining `.bzl` and the exported name. v1 cut: `bzl` is the `None` SENTINEL under the hard single-module
/// corpus cap — a future `Some(label)` is a *different* identity (a key change, never a re-key); `name` is
/// NEVER re-keyed out of digest scope (reserve-the-key).
///
/// ALL identity comparison/hash/order rides the derived `Eq`/`Ord`/`Hash` — raw field comparison outside
/// razel-bzl-api is BANNED (the lockdown §0.3 sweep). Same-name providers differing in `bzl` are distinct in
/// every consuming position.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ProviderId {
    /// The exported name — today's whole identity; NEVER re-keyed out of digest scope.
    pub name: String,
    /// The defining `.bzl` — `None` in v1 (the sentinel; digest tag 0). `Some(_)` is a DIFFERENT identity.
    pub bzl: Option<String>,
}
impl ProviderId {
    /// The v1 constructor: a name-only identity with the `bzl` dim at its `None` sentinel (the declared name
    /// IS the exported name under the single-module cap — lockdown R5).
    pub fn from_name(name: impl Into<String>) -> ProviderId {
        ProviderId { name: name.into(), bzl: None }
    }
    /// The exported name — for display/diagnostics; NEVER for identity comparison (use the derived impls).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The defining-`.bzl` dim (`None` = the v1 sentinel).
    pub fn bzl(&self) -> Option<&str> {
        self.bzl.as_deref()
    }
}

/// A provider INSTANCE — a typed, codec-neutral value a rule's impl publishes (`Provider(field = …)`). This is
/// the analysis phase's per-target output; it flows along dependency edges (`dep[Provider]`). `fields` are
/// name-sorted (deterministic → early-cutoff friendly). The rule's impl is NOT stored — only its plain result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderInstance {
    pub provider: ProviderId,
    pub fields: Vec<(String, BzlValue)>,
}
impl ProviderInstance {
    pub fn get(&self, field: &str) -> Option<&BzlValue> {
        self.fields.iter().find(|(n, _)| n == field).map(|(_, v)| v)
    }
}

fn framed(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s);
}

/// The provider IDENTITY frame — THE one digest rendering of a `ProviderId`, shared by
/// [`encode_provider_instance`] and the `encode_bzl_value` Provider arm (lockdown §2, decision B):
///
///   `[namespace: u8]`      `0x00` = Starlark-declared; `0x01` = builtin/native — RESERVED now (row G lands
///                          DefaultInfo & co under it later) so a builtin `FooInfo` can never collide with a
///                          Starlark `FooInfo` (Bazel's leading fingerprint bool, partitioned the same way).
///   `[bzl: u8 tag + run]`  tag `0x00` = `None` (the v1 sentinel); tag `0x01` + u64-framed label when it fills.
///   `[name: u64-framed]`   the exported name.
///
/// Two framed identity runs, exactly like the Rule arm (`rd.bzl` then `rd.name`). Private: the frame exists
/// ONLY inside the canonical codec funnel.
fn encode_provider_identity(id: &ProviderId, b: &mut Vec<u8>) {
    if cfg!(feature = "mutant_provider_digest_name_only") {
        // MUTANT: drop the namespace byte + the reserved bzl dim — the pre-lockdown name-only shape, under
        // which a same-name identity differing in `bzl` silently fuses in every digest.
        framed(b, id.name.as_bytes());
        return;
    }
    b.push(0x00); // namespace: Starlark-declared (0x01 = builtin, reserved for row G)
    match &id.bzl {
        None => b.push(0x00), // the v1 sentinel: a future Some(label) is a DIFFERENT key, not a re-key
        Some(l) => {
            b.push(0x01);
            framed(b, l.as_bytes());
        }
    }
    framed(b, id.name.as_bytes());
}

/// The depset digest frame (lockdown §2, R6 — STRUCTURAL, per-node, injective on the value):
/// `[tag 7][order code byte][u64 direct count + encoded values][u64 transitive count + recursion]`.
/// The order byte is `DepsetOrder::code()` (the pinned table, never a Rust enum layout); `elem` is a derived
/// cache and NOT digest content. Private: reachable only through [`encode_bzl_value`].
fn encode_depset(d: &Depset, b: &mut Vec<u8>) {
    b.push(7);
    b.push(d.order.code());
    b.extend_from_slice(&(d.direct.len() as u64).to_be_bytes());
    for v in &d.direct {
        encode_bzl_value(v, b);
    }
    b.extend_from_slice(&(d.transitive.len() as u64).to_be_bytes());
    for t in &d.transitive {
        encode_depset(t, b);
    }
}

/// THE canonical, lossless, injective encoding of a `BzlValue` — the single source of truth for every content
/// key / digest in the workspace (loading, package, analysis, toolchain all delegate here, so they cannot drift).
/// Tagged (one byte per variant); every byte run is u64-length-framed so no field can bleed into the next; the
/// `AttrType` discriminant uses its own `code()` (the one attr-type source of truth); Rule/Provider carry their
/// full identity (bzl/name/attrs/toolchains; the §2 identity frame + fields). Append-only into `b` so callers
/// can frame around it.
pub fn encode_bzl_value(v: &BzlValue, b: &mut Vec<u8>) {
    match v {
        BzlValue::None => b.push(0),
        BzlValue::Bool(x) => {
            b.push(1);
            b.push(*x as u8);
        }
        BzlValue::Int(i) => {
            b.push(2);
            b.extend_from_slice(&i.to_be_bytes());
        }
        BzlValue::Str(s) => {
            b.push(3);
            framed(b, s.as_bytes());
        }
        BzlValue::List(items) => {
            b.push(4);
            b.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for it in items {
                encode_bzl_value(it, b);
            }
        }
        BzlValue::Rule(rd) => {
            b.push(5);
            framed(b, rd.bzl.as_bytes());
            framed(b, rd.name.as_bytes());
            b.extend_from_slice(&(rd.attrs.len() as u64).to_be_bytes());
            for (n, t) in &rd.attrs {
                framed(b, n.as_bytes());
                b.push(t.code()); // stable AttrType code (the one source of truth)
            }
            b.extend_from_slice(&(rd.toolchains.len() as u64).to_be_bytes());
            for tc in &rd.toolchains {
                framed(b, tc.as_bytes());
            }
        }
        BzlValue::Provider(pd) => {
            b.push(6);
            encode_provider_identity(&pd.id, b);
            b.extend_from_slice(&(pd.fields.len() as u64).to_be_bytes());
            for f in &pd.fields {
                framed(b, f.as_bytes());
            }
        }
        BzlValue::Depset(d) => encode_depset(d, b),
    }
}

/// Canonical encoding of a `ProviderInstance` (the §2 identity frame, then length-framed `(name, value)`
/// fields via [`encode_bzl_value`]). The per-provider unit for content digests; callers prefix a provider
/// COUNT to make a run of providers self-delimiting (the framing after the identity is byte-identical to the
/// pre-lockdown shape — only the identity run changed, ratified R2 while zero goldens exist).
pub fn encode_provider_instance(p: &ProviderInstance, b: &mut Vec<u8>) {
    encode_provider_identity(&p.provider, b);
    b.extend_from_slice(&(p.fields.len() as u64).to_be_bytes());
    for (n, v) in &p.fields {
        b.extend_from_slice(&(n.len() as u64).to_be_bytes());
        b.extend_from_slice(n.as_bytes());
        encode_bzl_value(v, b);
    }
}

/// One dependency's analysis result as fed into a rule impl: the providers that dep published, keyed by its
/// label. The analysis node resolves a target's label-typed attrs to these (restart-driven); the impl reads
/// them via `dep[Provider]`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DepProviders {
    pub label: String,
    pub providers: Vec<ProviderInstance>,
}

/// A resolved toolchain fed into a rule impl: the toolchain TYPE (its identity) + the `toolchain_info` provider
/// it carries. The analysis node resolves required toolchain types to these (phase #4, `TOOLCHAIN_CONTEXT`);
/// the impl reads them via `ctx.toolchains[type]`. Empty until phase #4 lands — `ctx.toolchains` is an empty
/// map now (a missing type indexes to a fail-closed error).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedToolchain {
    pub toolchain_type: String,
    pub info: ProviderInstance,
}

/// An action a rule's impl declares via `ctx.actions.*` — codec-neutral, the unit the EXECUTION phase (#5) runs.
/// Plain data (deterministic for the action key + early cutoff). Empty until phase #5 wires `ctx.actions`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActionTemplate {
    pub mnemonic: String,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

/// The result of running a rule's implementation: the providers it published AND the actions it declared. A
/// struct (not a bare `Vec`) so the two analysis outputs grow independently — #5 fills `actions` without
/// touching the seam signature again (anti-corner: reserve the shape now).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RuleResult {
    pub providers: Vec<ProviderInstance>,
    pub actions: Vec<ActionTemplate>,
}

/// Fail-closed evaluation errors — never a panic, never a silent default.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum BzlError {
    /// Syntax error while parsing the `.bzl`.
    Parse { detail: String },
    /// Runtime/semantic error while evaluating it.
    Eval { detail: String },
    /// A construct the value model does not (yet) represent.
    Unsupported { what: String },
}

/// The seam: evaluate a `.bzl` to its exported module bindings. Pure w.r.t. the filesystem — the caller
/// supplies the source bytes AND the already-evaluated modules for each `load()` target, so the ENGINE owns
/// the dependency graph (it requests the loaded `.bzl`s as nodes and restarts) while the evaluator stays a
/// deterministic function of its inputs. `module_name` is a label/path used only for diagnostics.
///
/// ENVIRONMENT-PARAMETERIZED (the ADR-0003 lockdown §3): module/rule evaluation takes an [`EvalEnv`]
/// naming the phase — the trait was parameterless w.r.t. environment and thus structurally incapable of
/// the §1 matrix's distinctions. The impl selects a NAMED, precomputed, digested per-phase environment
/// from it (fail-closed on any row it has not built — never a shared default Globals). BUILD-file eval
/// (matrix row 7) is not a LoadKind: `evaluate_build` itself is that phase's discriminant.
pub trait BzlEvaluator: Send + Sync {
    /// Parse-only: the `load()` targets this source declares, in declaration order (the first string
    /// argument to each `load(...)`). Lets the caller resolve + build them BEFORE evaluation. No evaluation.
    fn load_targets(&self, source: &str) -> Result<Vec<String>, BzlError>;

    /// The [`PredeclaredEnvId`] this evaluator serves for `kind`/`dialect` — key fact A: env selection is
    /// a function of the LoadKind alone (plus the `.scl` row-6 override), never of key contents. This is
    /// how a requester obtains the env-id KEY DIMENSION (REQ-BZLLOAD-018) without reaching behind the
    /// seam. Fail-closed: a kind whose environment this evaluator has not built is a typed error, never a
    /// defaulted id.
    fn predeclared_env_id(&self, kind: &LoadKind, dialect: Dialect) -> Result<PredeclaredEnvId, BzlError>;

    /// Evaluate the source to its exports, in the environment `env` names. `loaded` supplies, per `load()`
    /// target string, the module that target evaluated to — so `load("t", "sym")` resolves `sym` from
    /// `loaded`'s entry for `"t"`.
    fn evaluate(
        &self,
        env: &EvalEnv,
        module_name: &str,
        source: &str,
        loaded: &[(String, BzlModule)],
    ) -> Result<BzlModule, BzlError>;

    /// Evaluate a BUILD file to the targets it instantiates, in declaration order. The BUILD-dialect globals
    /// expose `target(kind = ..., name = ..., **attrs)`, which RECORDS a target (data) rather than running any
    /// rule logic — so this is loading, not analysis. `loaded` supplies each `load()`ed module (e.g. for
    /// constants used in attrs); same seam contract as `evaluate`. Duplicate target names within the package
    /// are a fail-closed `Eval` error, never a silent last-wins.
    ///
    /// SPIKE: `target(kind=...)` is a generic instantiation placeholder — there is no `rule()` machinery yet
    /// (a rule-callable defined in a `.bzl`, surviving `load()` as a frozen value, is entangled with providers
    /// and is the ADR-0004 cut). Attr *schema* validation is likewise deferred: attrs are recorded as-passed.
    fn evaluate_build(
        &self,
        package_name: &str,
        source: &str,
        loaded: &[(String, BzlModule)],
    ) -> Result<Vec<TargetDecl>, BzlError>;

    /// Run a rule's implementation and return the providers it publishes — the analysis-phase seam. The rule
    /// is defined in `rule_source` (the evaluator re-evaluates it to obtain the live impl + provider/ctx
    /// machinery); `rule_name` selects which rule. `loaded` supplies the rule `.bzl`'s own `load()` deps;
    /// `attrs` are the target's attribute values (the evaluator validates label-typed attrs against `deps`);
    /// `deps` supplies each dependency's already-computed providers (keyed by label) for `ctx.attr.<labels>` +
    /// `dep[Provider]`. Pure w.r.t. the engine: the caller owns the dependency graph (resolves deps to nodes,
    /// restarts) while the evaluator is a deterministic function of these inputs.
    ///
    /// `ctx` exposes `ctx.label` + `ctx.attr.<name>` + dep providers + `ctx.toolchains[type]` (the resolved
    /// toolchains supplied in `toolchains`; an empty map until phase #4). The result carries the impl's
    /// providers AND its declared actions (`actions` empty until phase #5 wires `ctx.actions`). `ctx.actions`
    /// itself is a fail-closed absence today (reaching for it errors). The `toolchains` slot + the `RuleResult`
    /// shape are reserved here so #4/#5 fill them additively without re-touching this signature.
    ///
    /// `env` names the environment the rule's `.bzl` is re-evaluated in — the analysis re-eval of a
    /// BUILD-loaded module runs in the SAME row-1 env as its load (`EvalEnv::build_bzl_v1` today).
    fn evaluate_rule(
        &self,
        env: &EvalEnv,
        rule_source: &str,
        rule_module_name: &str,
        rule_name: &str,
        loaded: &[(String, BzlModule)],
        label: &str,
        attrs: &[(String, BzlValue)],
        deps: &[DepProviders],
        toolchains: &[ResolvedToolchain],
    ) -> Result<RuleResult, BzlError>;
}

pub mod conformance {
    use super::*;

    /// Minimal contract any evaluator must satisfy: a module of plain bindings evaluates to those bindings,
    /// arithmetic folds, and the result is name-sorted.
    pub fn supports_basic_bindings<E: BzlEvaluator>(e: &E) {
        let m = e
            .evaluate(&EvalEnv::default(), "m", "b = 2 + 3\na = \"hi\"\nc = True\nd = [1, 2]\ne = 5000000000\n", &[])
            .expect("a module of literal/arithmetic bindings must evaluate");
        assert_eq!(m.get("a"), Some(&BzlValue::Str("hi".into())));
        assert_eq!(m.get("b"), Some(&BzlValue::Int(5)), "arithmetic must fold");
        assert_eq!(m.get("c"), Some(&BzlValue::Bool(true)));
        assert_eq!(m.get("d"), Some(&BzlValue::List(vec![BzlValue::Int(1), BzlValue::Int(2)])));
        assert_eq!(m.get("e"), Some(&BzlValue::Int(5_000_000_000)), "ints beyond i32 round-trip (full i64)");
        let names: Vec<&str> = m.bindings.iter().map(|(n, _)| n.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "exported bindings must be name-sorted (deterministic)");
    }

    /// Fail-closed: a syntax error is a typed `Parse`, never a panic.
    pub fn parse_error_is_fail_closed<E: BzlEvaluator>(e: &E) {
        assert!(
            matches!(e.evaluate(&EvalEnv::default(), "m", "x = = 1\n", &[]), Err(BzlError::Parse { .. })),
            "a syntax error must be a typed BzlError::Parse"
        );
    }

    /// `load()` resolution: the source's load target is reported, and a symbol loaded from a supplied module
    /// is usable in evaluation.
    pub fn supports_load<E: BzlEvaluator>(e: &E) {
        let src = "load(\"dep\", \"y\")\nx = y + 1\n";
        assert_eq!(e.load_targets(src).expect("load_targets parses"), vec!["dep".to_string()]);
        let dep = BzlModule { bindings: vec![("y".to_string(), BzlValue::Int(10))] };
        let m = e
            .evaluate(&EvalEnv::default(), "m", src, &[("dep".to_string(), dep)])
            .expect("evaluation with a loaded module must succeed");
        assert_eq!(m.get("x"), Some(&BzlValue::Int(11)), "loaded symbol y=10 must be usable: x = y + 1 = 11");
    }

    /// A `load()`ed symbol is usable locally but is NOT re-exported by the loader (Bazel semantics) —
    /// otherwise a third file could wrongly `load()` it transitively, and the loader's value would couple
    /// to the loaded module's contents (defeating cutoff).
    pub fn loaded_symbols_not_reexported<E: BzlEvaluator>(e: &E) {
        let dep = BzlModule { bindings: vec![("y".to_string(), BzlValue::Int(7))] };
        let m = e
            .evaluate(&EvalEnv::default(), "m", "load(\"dep\", \"y\")\nx = y\n", &[("dep".to_string(), dep)])
            .expect("evaluation must succeed");
        assert_eq!(m.get("x"), Some(&BzlValue::Int(7)), "loaded y is usable: x = y = 7");
        assert_eq!(m.get("y"), None, "a load()ed symbol must NOT appear in the loader's exports");
    }

    /// A value kind the model does not represent (e.g. a function) is rejected fail-closed, not dropped.
    pub fn rejects_unsupported_types<E: BzlEvaluator>(e: &E) {
        assert!(
            matches!(e.evaluate(&EvalEnv::default(), "m", "def f():\n    pass\n", &[]), Err(BzlError::Unsupported { .. })),
            "an exported function must surface as a typed BzlError::Unsupported"
        );
    }

    /// Phase separation is ENVIRONMENTAL, not runtime-only (lockdown §3; the v1 cut of
    /// `build_loaded_and_bzlmod_loaded_not_conflated`): the BUILD-file env (row 7) and the `.bzl` env
    /// (row 1) are distinct predeclared name-sets. A BUILD file must not see `.bzl` toplevels
    /// (`provider`/`rule`), and a `.bzl` must not see the BUILD-file toplevel (`target`) — under the spike's
    /// one-Globals-for-everything shape (`mutant_one_globals_all_loadkinds`) both leak and this goes red.
    pub fn phase_envs_not_conflated<E: BzlEvaluator>(e: &E) {
        assert!(
            e.evaluate_build("pkg", "p = provider(\"P\", fields = [])\n", &[]).is_err(),
            "the BUILD-file env must NOT expose the .bzl toplevel 'provider' (environmental separation)"
        );
        assert!(
            e.evaluate_build("pkg", "r = rule\n", &[]).is_err(),
            "the BUILD-file env must NOT expose the .bzl toplevel 'rule'"
        );
        assert!(
            e.evaluate(&EvalEnv::default(), "m.bzl", "_t = [target]\n", &[]).is_err(),
            "the .bzl env must NOT expose the BUILD-file toplevel 'target'"
        );
    }

    // ──────────────── BUILD evaluation (`evaluate_build`) ────────────────

    /// A BUILD file instantiates targets via `target(...)`; each call yields a `TargetDecl` carrying its kind,
    /// name, and (name-sorted) attrs. The rule `_impl` is not run — this is pure data instantiation. Attrs are
    /// name-sorted regardless of call order, so the value is order-insensitive (early-cutoff friendly).
    pub fn supports_target_instantiation<E: BzlEvaluator>(e: &E) {
        let src = "target(kind = \"my_rule\", name = \"a\", srcs = [\"x.txt\"])\n\
                   target(kind = \"my_rule\", name = \"b\", zzz = 1, aaa = 2)\n";
        let ts = e.evaluate_build("pkg", src, &[]).expect("a BUILD of target() calls must evaluate");
        assert_eq!(ts.len(), 2, "two target() calls instantiate two targets");
        assert_eq!(ts[0].kind, "my_rule");
        assert_eq!(ts[0].name, "a");
        assert_eq!(
            ts[0].attrs,
            vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("x.txt".into())]))]
        );
        assert_eq!(ts[1].name, "b");
        assert_eq!(
            ts[1].attrs,
            vec![("aaa".to_string(), BzlValue::Int(2)), ("zzz".to_string(), BzlValue::Int(1))],
            "attrs must be name-sorted regardless of keyword order"
        );
    }

    /// Two targets with the same name is a fail-closed error (a package is keyed by name; never last-wins).
    pub fn build_dup_name_is_fail_closed<E: BzlEvaluator>(e: &E) {
        let src = "target(kind = \"r\", name = \"dup\")\ntarget(kind = \"r\", name = \"dup\")\n";
        assert!(
            matches!(e.evaluate_build("pkg", src, &[]), Err(BzlError::Eval { .. })),
            "a duplicate target name must be a typed Eval error, never a silent last-wins"
        );
    }

    /// A `load()`ed constant is usable as an attribute value in a BUILD (proves BUILD-level `load()`).
    pub fn build_uses_loaded_constant<E: BzlEvaluator>(e: &E) {
        let src = "load(\"consts\", \"SRCS\")\ntarget(kind = \"r\", name = \"a\", srcs = SRCS)\n";
        let consts = BzlModule {
            bindings: vec![("SRCS".to_string(), BzlValue::List(vec![BzlValue::Str("g.txt".into())]))],
        };
        let ts = e
            .evaluate_build("pkg", src, &[("consts".to_string(), consts)])
            .expect("a BUILD using a loaded constant must evaluate");
        assert_eq!(ts.len(), 1);
        assert_eq!(
            ts[0].attrs,
            vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("g.txt".into())]))],
            "the loaded constant SRCS must be usable as an attr value"
        );
    }

    /// An attribute whose value the model cannot represent (e.g. a function) fails closed, not silently dropped.
    pub fn build_rejects_unsupported_attr<E: BzlEvaluator>(e: &E) {
        let src = "def f():\n    pass\ntarget(kind = \"r\", name = \"a\", bad = f)\n";
        assert!(
            e.evaluate_build("pkg", src, &[]).is_err(),
            "an attr value of an unsupported kind must fail closed"
        );
    }

    // ──────────────── rule() machinery (analysis prerequisite) ────────────────

    /// `rule(implementation=…, attrs={…})` in a `.bzl` evaluates to a `BzlValue::Rule` carrying the attr
    /// schema (name-sorted), under the exported symbol's name + the defining `.bzl` path. The impl is NOT
    /// carried in the value (it is re-obtained at analysis).
    pub fn supports_rule_definition<E: BzlEvaluator>(e: &E) {
        let src = "def _impl(ctx):\n    pass\n\
                   my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list(), \"value\": attr.int()})\n";
        let m = e.evaluate(&EvalEnv::default(), "rules.bzl", src, &[]).expect("a .bzl defining a rule must evaluate");
        let r = match m.get("my_rule") {
            Some(BzlValue::Rule(rd)) => rd,
            other => panic!("my_rule must export as BzlValue::Rule, got {other:?}"),
        };
        assert_eq!(r.name, "my_rule", "the rule's identity name is its exported symbol");
        assert_eq!(r.bzl, "rules.bzl", "the rule's identity carries its defining .bzl");
        assert_eq!(
            r.attrs,
            vec![("deps".to_string(), AttrType::LabelList), ("value".to_string(), AttrType::Int)],
            "the attr schema is recorded name-sorted, with types"
        );
        assert_eq!(m.get("_impl"), None, "the private impl is not exported");
    }

    /// A BUILD that `load()`s a rule and calls it instantiates a target whose `kind` is the rule symbol and
    /// whose `origin` points at the rule's definition — the link analysis follows to run the impl.
    pub fn build_rule_call_records_origin<E: BzlEvaluator>(e: &E) {
        let rule_mod = BzlModule {
            bindings: vec![(
                "my_rule".to_string(),
                BzlValue::Rule(RuleDef {
                    bzl: "pkg/rules.bzl".to_string(),
                    name: "my_rule".to_string(),
                    attrs: vec![("deps".to_string(), AttrType::LabelList), ("value".to_string(), AttrType::Int)],
                    toolchains: vec![],
                }),
            )],
        };
        let src = "load(\"rules\", \"my_rule\")\nmy_rule(name = \"a\", value = 5, deps = [\":b\"])\n";
        let ts = e
            .evaluate_build("pkg", src, &[("rules".to_string(), rule_mod)])
            .expect("a BUILD calling a loaded rule must evaluate");
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].kind, "my_rule", "the target's kind is the rule symbol");
        assert_eq!(
            ts[0].origin,
            Some(RuleOrigin { bzl: "pkg/rules.bzl".to_string(), name: "my_rule".to_string() }),
            "the target records its rule origin (the analysis link)"
        );
        assert_eq!(
            ts[0].attrs,
            vec![
                ("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":b".into())])),
                ("value".to_string(), BzlValue::Int(5)),
            ],
            "attr values recorded, name-sorted"
        );
    }

    /// Calling a rule with an attribute not in its schema is a fail-closed error (never silently recorded).
    pub fn build_rule_rejects_unknown_attr<E: BzlEvaluator>(e: &E) {
        let rule_mod = BzlModule {
            bindings: vec![(
                "my_rule".to_string(),
                BzlValue::Rule(RuleDef {
                    bzl: "pkg/rules.bzl".to_string(),
                    name: "my_rule".to_string(),
                    attrs: vec![("value".to_string(), AttrType::Int)],
                    toolchains: vec![],
                }),
            )],
        };
        let src = "load(\"rules\", \"my_rule\")\nmy_rule(name = \"a\", bogus = 1)\n";
        assert!(
            e.evaluate_build("pkg", src, &[("rules".to_string(), rule_mod)]).is_err(),
            "an attribute not in the rule's schema must fail closed"
        );
    }

    /// An attribute VALUE whose shape doesn't match the declared type fails closed (so analysis never sees a
    /// wrong-typed attr — e.g. a string where a label list / dependency edge is expected).
    pub fn build_rule_rejects_wrong_attr_type<E: BzlEvaluator>(e: &E) {
        let rule_mod = BzlModule {
            bindings: vec![(
                "my_rule".to_string(),
                BzlValue::Rule(RuleDef {
                    bzl: "pkg/rules.bzl".to_string(),
                    name: "my_rule".to_string(),
                    attrs: vec![("deps".to_string(), AttrType::LabelList)],
                    toolchains: vec![],
                }),
            )],
        };
        // `deps` is a label_list, but a bare string is passed — a shape mismatch.
        let src = "load(\"rules\", \"my_rule\")\nmy_rule(name = \"a\", deps = \"not a list\")\n";
        assert!(
            e.evaluate_build("pkg", src, &[("rules".to_string(), rule_mod)]).is_err(),
            "an attr value whose type does not match the schema must fail closed"
        );
    }

    /// Calling a rule from a `.bzl` module (where there is no target registry) is a typed error — NOT a panic.
    /// Rules are instantiated in BUILD files; a rule call elsewhere must fail closed, loudly and recoverably.
    pub fn rule_call_outside_build_is_fail_closed<E: BzlEvaluator>(e: &E) {
        let rule_mod = BzlModule {
            bindings: vec![(
                "my_rule".to_string(),
                BzlValue::Rule(RuleDef { bzl: "pkg/rules.bzl".to_string(), name: "my_rule".to_string(), attrs: vec![], toolchains: vec![] }),
            )],
        };
        let src = "load(\"rules\", \"my_rule\")\nmy_rule(name = \"a\")\n";
        assert!(
            e.evaluate(&EvalEnv::default(), "m.bzl", src, &[("rules".to_string(), rule_mod)]).is_err(),
            "calling a rule from a .bzl (no target registry) must fail closed, not panic"
        );
    }

    // ──────────────── analysis: running a rule impl → providers (the A2 seam) ────────────────

    /// The headline A2 contract: a REAL `.bzl`-defined rule impl runs through the Starlark seam, reads an
    /// attribute AND a dependency's provider, and publishes a provider — proving providers flow along edges.
    /// (The sum-provider exam, evaluated directly here; A4 runs the same shape through the engine, granularly.)
    pub fn supports_rule_evaluation<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])

def _impl(ctx):
    t = ctx.attr.value
    for d in ctx.attr.deps:
        t += d[NumberInfo].total
    return [NumberInfo(total = t)]

my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int(), \"deps\": attr.label_list()})
";
        let attrs = vec![
            ("value".to_string(), BzlValue::Int(2)),
            ("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":a".into()), BzlValue::Str(":b".into())])),
        ];
        let pi = |n: i64| ProviderInstance {
            provider: ProviderId::from_name("NumberInfo"),
            fields: vec![("total".to_string(), BzlValue::Int(n))],
        };
        let deps = vec![
            DepProviders { label: ":a".to_string(), providers: vec![pi(10)] },
            DepProviders { label: ":b".to_string(), providers: vec![pi(20)] },
        ];
        let out = e
            .evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &deps, &[])
            .expect("the rule impl must run and publish a provider")
            .providers;
        assert_eq!(out.len(), 1, "the impl returns exactly one provider");
        assert_eq!(out[0].provider, ProviderId::from_name("NumberInfo"));
        assert_eq!(
            out[0].get("total"),
            Some(&BzlValue::Int(32)),
            "ctx.attr.value (2) + sum of deps' NumberInfo.total (10 + 20) = 32 — providers flow along edges"
        );
    }

    /// Fail-closed: reaching for an undeclared dep provider (`dep[Missing]`) is a loud error, never empty.
    pub fn rule_eval_missing_provider_is_fail_closed<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])
OtherInfo = provider(\"OtherInfo\", fields = [\"x\"])

def _impl(ctx):
    return [NumberInfo(total = ctx.attr.deps[0][OtherInfo].x)]

my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list()})
";
        let attrs = vec![("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":a".into())]))];
        let deps = vec![DepProviders {
            label: ":a".to_string(),
            // the dep publishes NumberInfo, NOT OtherInfo — so dep[OtherInfo] must fail closed.
            providers: vec![ProviderInstance {
                provider: ProviderId::from_name("NumberInfo"),
                fields: vec![("total".to_string(), BzlValue::Int(1))],
            }],
        }];
        assert!(
            e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &deps, &[]).is_err(),
            "indexing a dep by a provider it does not publish must fail closed"
        );
    }

    /// Fail-closed: constructing a provider with a field not in its declared schema is a loud error.
    pub fn provider_rejects_unknown_field<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])

def _impl(ctx):
    return [NumberInfo(bogus = 1)]

my_rule = rule(implementation = _impl, attrs = {})
";
        assert!(
            e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[]).is_err(),
            "constructing a provider with an undeclared field must fail closed"
        );
    }

    /// Provider identity is OPAQUE (lockdown gate `provider_identity_opaque_comparison`, the C2 sweep):
    /// `dep[Provider]` re-keying rides `ProviderId`'s derived impls, never a raw-name comparison. A dep
    /// provider named like the module's own but differing in the reserved `bzl` dim is a DIFFERENT identity —
    /// matching it by name would silently fuse two provider types (the §0.3 leak). Fail-closed instead.
    pub fn provider_identity_opaque_comparison<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])

def _impl(ctx):
    return [NumberInfo(total = ctx.attr.deps[0][NumberInfo].total)]

my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list()})
";
        let attrs = vec![("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":a".into())]))];
        // Same NAME, different identity: the dep's provider was defined in another .bzl (bzl = Some). Under
        // the single-module cap this cannot be this module's NumberInfo.
        let deps = vec![DepProviders {
            label: ":a".to_string(),
            providers: vec![ProviderInstance {
                provider: ProviderId { name: "NumberInfo".into(), bzl: Some("other/defs.bzl".into()) },
                fields: vec![("total".to_string(), BzlValue::Int(1))],
            }],
        }];
        assert!(
            e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &deps, &[]).is_err(),
            "a bzl-differing provider identity must NOT fuse with the module's provider by raw name"
        );
    }

    /// Fail-closed (lockdown decision H, gate `provider_dup_declaration_fail_closed`): a second same-name
    /// `provider()` declaration visible at module scope is a typed `Eval` error NAMING the provider — killing
    /// the silent last-wins. Aliasing (two names bound to the SAME declaration) stays legal.
    pub fn provider_dup_declaration_fail_closed<E: BzlEvaluator>(e: &E) {
        // (a) the rule-eval provider index path.
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])
Other = provider(\"NumberInfo\", fields = [\"x\"])

def _impl(ctx):
    return [NumberInfo(total = 1)]

my_rule = rule(implementation = _impl, attrs = {})
";
        match e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[]) {
            Err(BzlError::Eval { detail }) => {
                assert!(detail.contains("NumberInfo"), "the error must NAME the colliding provider: {detail}")
            }
            other => panic!("a duplicate provider declaration must be a typed Eval error, got {other:?}"),
        }
        // (b) the plain module path — the same collision reaching module scope via `evaluate`.
        let dup = "A = provider(\"P\", fields = [])\nB = provider(\"P\", fields = [])\n";
        match e.evaluate(&EvalEnv::default(), "m.bzl", dup, &[]) {
            Err(BzlError::Eval { detail }) => {
                assert!(detail.contains("'P'"), "the error must NAME the colliding provider: {detail}")
            }
            other => panic!("a duplicate provider declaration at module scope must fail closed, got {other:?}"),
        }
        // (c) aliasing is NOT a collision: one declaration, two names.
        let alias = "P = provider(\"P\", fields = [\"x\"])\nAlias = P\n";
        assert!(
            e.evaluate(&EvalEnv::default(), "m.bzl", alias, &[]).is_ok(),
            "aliasing one provider declaration under two names must stay legal (it is ONE identity)"
        );
    }

    /// Fail-closed (lockdown decision E, gate `rule_result_dup_provider_fail_closed`): an impl returning two
    /// instances of one provider is an analysis error with Bazel's exact shape
    /// (`StarlarkRuleConfiguredTargetUtil.java:273-275`) — never a silent last-wins merge.
    pub fn rule_result_dup_provider_fail_closed<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])

def _impl(ctx):
    return [NumberInfo(total = 1), NumberInfo(total = 2)]

my_rule = rule(implementation = _impl, attrs = {})
";
        match e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[]) {
            Err(BzlError::Eval { detail }) => assert!(
                detail.contains("Multiple conflicting returned providers with key NumberInfo"),
                "Bazel's duplicate-return error shape expected, got: {detail}"
            ),
            other => panic!("duplicate returned providers must fail closed, got {other:?}"),
        }
    }

    /// Fail-closed: a dep label referenced by an attr but NOT supplied in `deps` is a loud error, never an
    /// absorbed empty provider set (a declared dependency must not silently go unanalyzed). The impl here does
    /// NOT itself touch the dep, so only the seam's own check can catch the omission.
    pub fn rule_eval_missing_dep_label_is_fail_closed<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])

def _impl(ctx):
    return [NumberInfo(total = 0)]

my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list()})
";
        let attrs = vec![("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":a".into())]))];
        // The target declares dep :a, but the caller supplies NO providers for it.
        assert!(
            e.evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &[], &[]).is_err(),
            "a declared dep with no supplied providers must fail closed, not absorb to empty"
        );
    }

    /// A rule's impl declares an action (`declare_action`); it surfaces in `RuleResult.actions` (the analysis
    /// output the execution phase consumes) alongside the providers.
    pub fn supports_action_declaration<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])

def _impl(ctx):
    declare_action(mnemonic = \"Touch\", argv = [\"touch\", \"out\"], outputs = [\"out\"])
    return [NumberInfo(x = 1)]

my_rule = rule(implementation = _impl, attrs = {})
";
        let r = e
            .evaluate_rule(&EvalEnv::default(), src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[])
            .expect("a rule declaring an action must evaluate");
        assert_eq!(r.providers.len(), 1, "the provider is still published");
        assert_eq!(r.actions.len(), 1, "the declared action surfaces in the rule result");
        assert_eq!(r.actions[0].mnemonic, "Touch");
        assert_eq!(r.actions[0].argv, vec!["touch".to_string(), "out".to_string()]);
        assert_eq!(r.actions[0].outputs, vec!["out".to_string()]);
    }
}

#[cfg(test)]
mod canonical_codec_tests {
    use super::*;

    fn enc(v: &BzlValue) -> Vec<u8> {
        let mut b = Vec::new();
        encode_bzl_value(v, &mut b);
        b
    }

    #[test]
    fn distinct_scalars_encode_distinctly_and_deterministically() {
        assert_ne!(enc(&BzlValue::Int(1)), enc(&BzlValue::Int(2)));
        assert_ne!(enc(&BzlValue::Bool(true)), enc(&BzlValue::Bool(false)));
        // tags separate variants that could otherwise alias (None vs false vs 0 vs "").
        assert_ne!(enc(&BzlValue::None), enc(&BzlValue::Bool(false)));
        assert_ne!(enc(&BzlValue::Int(0)), enc(&BzlValue::Str(String::new())));
        assert_eq!(enc(&BzlValue::Str("x".into())), enc(&BzlValue::Str("x".into())), "deterministic");
    }

    #[test]
    fn length_framing_prevents_string_aliasing() {
        // ["ab","c"] vs ["a","bc"] would collide under naive concatenation; framing must separate them.
        let a = BzlValue::List(vec![BzlValue::Str("ab".into()), BzlValue::Str("c".into())]);
        let b = BzlValue::List(vec![BzlValue::Str("a".into()), BzlValue::Str("bc".into())]);
        assert_ne!(enc(&a), enc(&b));
        // a string "x" must not collide with a 1-element list ["x"] (tag separation).
        assert_ne!(enc(&BzlValue::Str("x".into())), enc(&BzlValue::List(vec![BzlValue::Str("x".into())])));
    }

    #[test]
    fn rule_identity_is_injective_across_bzl_name_attrs_toolchains() {
        let base = RuleDef { bzl: "a.bzl".into(), name: "r".into(), attrs: vec![], toolchains: vec![] };
        let diff_bzl = RuleDef { bzl: "b.bzl".into(), ..base.clone() };
        let diff_attr = RuleDef { attrs: vec![("x".into(), AttrType::Int)], ..base.clone() };
        let diff_tc = RuleDef { toolchains: vec!["//cc:t".into()], ..base.clone() };
        let mk = |rd: &RuleDef| enc(&BzlValue::Rule(rd.clone()));
        assert_ne!(mk(&base), mk(&diff_bzl), "bzl distinguishes");
        assert_ne!(mk(&base), mk(&diff_attr), "attrs distinguish");
        assert_ne!(mk(&base), mk(&diff_tc), "toolchains distinguish");
    }

    #[test]
    fn provider_instance_boundary_is_framed() {
        let mk = |n: &str, v: BzlValue| {
            let mut b = Vec::new();
            encode_provider_instance(&ProviderInstance { provider: ProviderId::from_name("P"), fields: vec![(n.to_string(), v)] }, &mut b);
            b
        };
        // (name="ab", "c") vs (name="a", "bc") must not alias.
        assert_ne!(mk("ab", BzlValue::Str("c".into())), mk("a", BzlValue::Str("bc".into())));
        // an Int field difference must change the encoding (the bug the toolchain digest had).
        assert_ne!(mk("v", BzlValue::Int(1)), mk("v", BzlValue::Int(2)));
    }

    /// Lockdown gate `provider_identity_reserved_bzl_dim` (§4): the reserved `bzl` dim is IN the identity —
    /// equal names differing in `bzl` digest differently AND compare unequal, and the v1 sentinel bytes are
    /// literally present in the frame. RED under `mutant_provider_digest_name_only` (the pre-lockdown shape).
    #[test]
    fn provider_identity_reserved_bzl_dim() {
        let mk = |bzl: Option<&str>| ProviderInstance {
            provider: ProviderId { name: "P".into(), bzl: bzl.map(|s| s.to_string()) },
            fields: vec![],
        };
        let enc_pi = |p: &ProviderInstance| {
            let mut b = Vec::new();
            encode_provider_instance(p, &mut b);
            b
        };
        let none = enc_pi(&mk(None));
        let a = enc_pi(&mk(Some("a.bzl")));
        let b = enc_pi(&mk(Some("b.bzl")));
        assert_ne!(none, a, "bzl None vs Some must digest differently (the reserved dim is live in the frame)");
        assert_ne!(a, b, "bzl Some(a) vs Some(b) must digest differently");
        assert_ne!(mk(None).provider, mk(Some("a.bzl")).provider, "the derived Eq must distinguish the bzl dim");
        // The v1 sentinel bytes, literally: [0x00 namespace = Starlark][0x00 bzl = None][u64 name frame]…
        assert_eq!(none[0], 0x00, "namespace byte: Starlark-declared (0x01 = builtin, reserved)");
        assert_eq!(none[1], 0x00, "bzl dim: the v1 None sentinel tag");
        assert_eq!(&none[2..10], &1u64.to_be_bytes(), "the exported name is u64-framed after the identity dims");
        // The SAME identity frame partitions the encode_bzl_value Provider arm (declaration identity).
        let pd = |bzl: Option<&str>| {
            BzlValue::Provider(ProviderDef {
                id: ProviderId { name: "P".into(), bzl: bzl.map(|s| s.to_string()) },
                fields: vec![],
            })
        };
        assert_ne!(enc(&pd(None)), enc(&pd(Some("a.bzl"))), "ProviderDef carries the same reserved dim (no drift)");
    }

    /// Lockdown gate `depset_order_codes_pinned` (§4, row C): the four order codes are byte-golden Bazel
    /// enum ordinals; `from_code` is fail-closed on 4..=255; ONLY the four Starlark names parse (deprecated
    /// aliases rejected). RED under `mutant_depset_order_code_swap`.
    #[test]
    fn depset_order_codes_pinned() {
        let table = [
            (DepsetOrder::Default, 0u8, "default"),
            (DepsetOrder::Postorder, 1, "postorder"),
            (DepsetOrder::Topological, 2, "topological"),
            (DepsetOrder::Preorder, 3, "preorder"),
        ];
        for (order, code, name) in table {
            assert_eq!(order.code(), code, "byte-golden digest code for {name} (Bazel Order.java ordinal)");
            assert_eq!(DepsetOrder::from_code(code), Some(order), "code {code} round-trips");
            assert_eq!(DepsetOrder::parse(name), Some(order), "Starlark name '{name}' parses");
            assert_eq!(order.starlark_name(), name);
        }
        for c in 4..=255u8 {
            assert_eq!(DepsetOrder::from_code(c), None, "unknown code {c} must fail closed, never default");
        }
        for stale in ["stable", "compile", "link", "naive_link", "STABLE_ORDER", ""] {
            assert_eq!(DepsetOrder::parse(stale), None, "deprecated/unknown order name '{stale}' must not parse");
        }
    }

    /// R6: the depset digest is STRUCTURAL (per-node DAG), injective on the value — same flattened elements
    /// with different nesting are different digests; the order code byte is digest content.
    #[test]
    fn depset_digest_is_structural() {
        let s = |x: &str| BzlValue::Str(x.into());
        let leafless = |direct: Vec<BzlValue>, transitive: Vec<Depset>| Depset {
            order: DepsetOrder::Default,
            elem: Some("string".into()),
            direct,
            transitive,
        };
        let flat = leafless(vec![s("a"), s("b")], vec![]);
        let nested = leafless(vec![s("a")], vec![leafless(vec![s("b")], vec![])]);
        assert_ne!(
            enc(&BzlValue::Depset(flat.clone())),
            enc(&BzlValue::Depset(nested)),
            "same to_list, different nesting ⇒ different digest (structural, never the flattened list)"
        );
        let mut post = flat.clone();
        post.order = DepsetOrder::Postorder;
        assert_ne!(enc(&BzlValue::Depset(flat)), enc(&BzlValue::Depset(post)), "the order code is digest content");
        // tag separation: an empty depset must not alias an empty list.
        let empty = Depset { order: DepsetOrder::Default, elem: None, direct: vec![], transitive: vec![] };
        assert_ne!(enc(&BzlValue::Depset(empty)), enc(&BzlValue::List(vec![])), "depset tag 7 ≠ list tag 4");
    }
}
