use crate::{
    BzlModule, BzlValue, DepProviders, Dialect, EvalEnv, LoadKind, PredeclaredEnvId,
    ResolvedToolchain, RuleResult, TargetDecl,
};

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

