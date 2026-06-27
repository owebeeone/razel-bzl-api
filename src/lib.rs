//! `razel-bzl-api` — the Starlark-evaluation seam. A `.bzl` file is evaluated by a `BzlEvaluator`; the result
//! is a `BzlModule` (its exported global bindings) in a codec-neutral value model. The concrete evaluator
//! (`starlark-rust`) lives behind this trait in `razel-bzl-starlark`, so the loading node-kinds depend on
//! THIS api, never on the Starlark crate — mock→real, wall-clean (same pattern as the `System` seam).
//!
//! SPIKE scope: enough of the value model to prove the integration (`x = 1 + 2`, strings, bools, lists).
//! Provider/struct/function values and `load()` resolution are deliberately out of this first cut.
//! When the model grows, `BzlValue`/`BzlError` extend and the conformance suite MUST extend in lockstep
//! (P9): `#[non_exhaustive]` permits safe growth, but P3 forbids coercing a new kind to a default.

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
/// survives `load()` across `.bzl`s (a provider is first-class loadable, like a rule). Identity is `id` (the
/// declared name); `fields` are the declared field names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderDef {
    pub id: String,
    pub fields: Vec<String>,
}

/// A codec-neutral value a `.bzl` can export at module scope.
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

/// A provider's identity — the key for `dep[Provider]` lookup. SPIKE: the provider's declared name (a string).
/// Two providers sharing a name would collide; a future id can add the defining `.bzl` ADDITIVELY (anti-corner:
/// keep identity minimal + by-name now, no merge-algebra assumptions baked in — ADR-0004's later half).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ProviderId(pub String);

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

/// THE canonical, lossless, injective encoding of a `BzlValue` — the single source of truth for every content
/// key / digest in the workspace (loading, package, analysis, toolchain all delegate here, so they cannot drift).
/// Tagged (one byte per variant); every byte run is u64-length-framed so no field can bleed into the next; the
/// `AttrType` discriminant uses its own `code()` (the one attr-type source of truth); Rule/Provider carry their
/// full identity (bzl/name/attrs/toolchains; id/fields). Append-only into `b` so callers can frame around it.
pub fn encode_bzl_value(v: &BzlValue, b: &mut Vec<u8>) {
    fn framed(b: &mut Vec<u8>, s: &[u8]) {
        b.extend_from_slice(&(s.len() as u64).to_be_bytes());
        b.extend_from_slice(s);
    }
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
            framed(b, pd.id.as_bytes());
            b.extend_from_slice(&(pd.fields.len() as u64).to_be_bytes());
            for f in &pd.fields {
                framed(b, f.as_bytes());
            }
        }
    }
}

/// Canonical encoding of a `ProviderInstance` (id, then length-framed `(name, value)` fields via
/// [`encode_bzl_value`]). The per-provider unit for content digests; callers prefix a provider COUNT to make a
/// run of providers self-delimiting.
pub fn encode_provider_instance(p: &ProviderInstance, b: &mut Vec<u8>) {
    b.extend_from_slice(&(p.provider.0.len() as u64).to_be_bytes());
    b.extend_from_slice(p.provider.0.as_bytes());
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
pub trait BzlEvaluator: Send + Sync {
    /// Parse-only: the `load()` targets this source declares, in declaration order (the first string
    /// argument to each `load(...)`). Lets the caller resolve + build them BEFORE evaluation. No evaluation.
    fn load_targets(&self, source: &str) -> Result<Vec<String>, BzlError>;

    /// Evaluate the source to its exports. `loaded` supplies, per `load()` target string, the module that
    /// target evaluated to — so `load("t", "sym")` resolves `sym` from `loaded`'s entry for `"t"`.
    fn evaluate(
        &self,
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
    fn evaluate_rule(
        &self,
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
            .evaluate("m", "b = 2 + 3\na = \"hi\"\nc = True\nd = [1, 2]\ne = 5000000000\n", &[])
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
            matches!(e.evaluate("m", "x = = 1\n", &[]), Err(BzlError::Parse { .. })),
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
            .evaluate("m", src, &[("dep".to_string(), dep)])
            .expect("evaluation with a loaded module must succeed");
        assert_eq!(m.get("x"), Some(&BzlValue::Int(11)), "loaded symbol y=10 must be usable: x = y + 1 = 11");
    }

    /// A `load()`ed symbol is usable locally but is NOT re-exported by the loader (Bazel semantics) —
    /// otherwise a third file could wrongly `load()` it transitively, and the loader's value would couple
    /// to the loaded module's contents (defeating cutoff).
    pub fn loaded_symbols_not_reexported<E: BzlEvaluator>(e: &E) {
        let dep = BzlModule { bindings: vec![("y".to_string(), BzlValue::Int(7))] };
        let m = e
            .evaluate("m", "load(\"dep\", \"y\")\nx = y\n", &[("dep".to_string(), dep)])
            .expect("evaluation must succeed");
        assert_eq!(m.get("x"), Some(&BzlValue::Int(7)), "loaded y is usable: x = y = 7");
        assert_eq!(m.get("y"), None, "a load()ed symbol must NOT appear in the loader's exports");
    }

    /// A value kind the model does not represent (e.g. a function) is rejected fail-closed, not dropped.
    pub fn rejects_unsupported_types<E: BzlEvaluator>(e: &E) {
        assert!(
            matches!(e.evaluate("m", "def f():\n    pass\n", &[]), Err(BzlError::Unsupported { .. })),
            "an exported function must surface as a typed BzlError::Unsupported"
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
        let m = e.evaluate("rules.bzl", src, &[]).expect("a .bzl defining a rule must evaluate");
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
            e.evaluate("m.bzl", src, &[("rules".to_string(), rule_mod)]).is_err(),
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
            provider: ProviderId("NumberInfo".into()),
            fields: vec![("total".to_string(), BzlValue::Int(n))],
        };
        let deps = vec![
            DepProviders { label: ":a".to_string(), providers: vec![pi(10)] },
            DepProviders { label: ":b".to_string(), providers: vec![pi(20)] },
        ];
        let out = e
            .evaluate_rule(src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &deps, &[])
            .expect("the rule impl must run and publish a provider")
            .providers;
        assert_eq!(out.len(), 1, "the impl returns exactly one provider");
        assert_eq!(out[0].provider, ProviderId("NumberInfo".into()));
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
                provider: ProviderId("NumberInfo".into()),
                fields: vec![("total".to_string(), BzlValue::Int(1))],
            }],
        }];
        assert!(
            e.evaluate_rule(src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &deps, &[]).is_err(),
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
            e.evaluate_rule(src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[]).is_err(),
            "constructing a provider with an undeclared field must fail closed"
        );
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
            e.evaluate_rule(src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &attrs, &[], &[]).is_err(),
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
            .evaluate_rule(src, "pkg/rules.bzl", "my_rule", &[], "//pkg:t", &[], &[], &[])
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
            encode_provider_instance(&ProviderInstance { provider: ProviderId("P".into()), fields: vec![(n.to_string(), v)] }, &mut b);
            b
        };
        // (name="ab", "c") vs (name="a", "bc") must not alias.
        assert_ne!(mk("ab", BzlValue::Str("c".into())), mk("a", BzlValue::Str("bc".into())));
        // an Int field difference must change the encoding (the bug the toolchain digest had).
        assert_ne!(mk("v", BzlValue::Int(1)), mk("v", BzlValue::Int(2)));
    }
}
