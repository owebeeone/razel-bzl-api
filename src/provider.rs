use crate::BzlValue;

/// A provider TYPE declaration's codec-neutral form (`provider(name, fields=[…])`), carried as a value so it
/// survives `load()` across `.bzl`s (a provider is first-class loadable, like a rule). Identity is `id` — a
/// full [`ProviderId`], so declaration identity and instance identity share the reserved `bzl` dim and cannot
/// drift (`RazelV4ProviderIdentityLockdown.md` §2); `fields` are the declared field names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderDef {
    pub id: ProviderId,
    pub fields: Vec<String>,
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

/// One `new_local_repository(...)` declaration from MODULE.bazel (D6, C6): an external source root. `name` is
/// the apparent repo name (`@taut-shape//…`), `path` its root relative to the workspace root. `build_file` is
/// OPTIONAL (T20 R1): `Some(label)` overlays a BUILD-less repo with a main-repo `//pkg:BUILD.bazel` (taut-shape);
/// `None` mounts a repo that ships its OWN BUILD/.bzl files, read AS-IS (a real Bazel module, e.g. rules_rust).
/// The composition root maps these into the `ExternalRepos` registry (resolving `path` against the workspace
/// root, and the `build_file` label — when present — to a main-root-relative path).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepoDecl {
    pub name: String,
    pub path: String,
    pub build_file: Option<String>,
}

/// The evaluated MODULE.bazel (D6, C6): the workspace's declaration surface both razel and real Bazel read.
/// Yielded by [`crate::BzlEvaluator::evaluate_module_file`], evaluated in a fail-closed module-dialect env
/// exposing ONLY `module()`, `register_toolchains()`, `use_repo_rule()` — an unknown name is a typed error.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ModuleFileValue {
    /// `module(name = …)`.
    pub module_name: String,
    /// The labels of `register_toolchains(…)` — the toolchains resolution may select from (each a
    /// `//pkg:name` label of a `toolchain()` target).
    pub registered_toolchains: Vec<String>,
    /// The `new_local_repository(…)` external-source-root declarations.
    pub repos: Vec<RepoDecl>,
}

