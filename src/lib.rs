//! `razel-bzl-api` — the Starlark-evaluation seam. A `.bzl` file is evaluated by a `BzlEvaluator`; the result
//! is a `BzlModule` (its exported global bindings) in a codec-neutral value model. The concrete evaluator
//! (`starlark-rust`) lives behind this trait in `razel-bzl-starlark`, so the loading node-kinds depend on
//! THIS api, never on the Starlark crate — mock→real, wall-clean (same pattern as the `System` seam).
//!
//! SPIKE scope: enough of the value model to prove the integration (`x = 1 + 2`, strings, bools, lists).
//! Provider/struct/function values and `load()` resolution are deliberately out of this first cut.
//! When the model grows, `BzlValue`/`BzlError` extend and the conformance suite MUST extend in lockstep
//! (P9): `#[non_exhaustive]` permits safe growth, but P3 forbids coercing a new kind to a default.

/// A codec-neutral value a `.bzl` can export at module scope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BzlValue {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<BzlValue>),
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
}
