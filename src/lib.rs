//! `razel-bzl-api` — the Starlark-evaluation seam. A `.bzl` file is evaluated by a `BzlEvaluator`; the result
//! is a `BzlModule` (its exported global bindings) in a codec-neutral value model. The concrete evaluator
//! (`starlark-rust`) lives behind this trait in `razel-bzl-starlark`, so the loading node-kinds depend on
//! THIS api, never on the Starlark crate — mock→real, wall-clean (same pattern as the `System` seam).
//!
//! SPIKE scope: enough of the value model to prove the integration (`x = 1 + 2`, strings, bools, lists).
//! Provider/struct/function values and `load()` resolution are deliberately out of this first cut.

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

/// The seam: evaluate a `.bzl`'s source to its exported module bindings. `module_name` is a label/path used
/// only for diagnostics. Pure w.r.t. the filesystem — the caller supplies the source bytes (so the engine
/// owns the dependency on the file, and the evaluator stays a deterministic function of its input).
pub trait BzlEvaluator: Send + Sync {
    fn evaluate(&self, module_name: &str, source: &str) -> Result<BzlModule, BzlError>;
}

pub mod conformance {
    use super::*;

    /// Minimal contract any evaluator must satisfy: a module of plain bindings evaluates to those bindings,
    /// arithmetic folds, and the result is name-sorted.
    pub fn supports_basic_bindings<E: BzlEvaluator>(e: &E) {
        let m = e
            .evaluate("m", "b = 2 + 3\na = \"hi\"\nc = True\nd = [1, 2]\n")
            .expect("a module of literal/arithmetic bindings must evaluate");
        assert_eq!(m.get("a"), Some(&BzlValue::Str("hi".into())));
        assert_eq!(m.get("b"), Some(&BzlValue::Int(5)), "arithmetic must fold");
        assert_eq!(m.get("c"), Some(&BzlValue::Bool(true)));
        assert_eq!(m.get("d"), Some(&BzlValue::List(vec![BzlValue::Int(1), BzlValue::Int(2)])));
        let names: Vec<&str> = m.bindings.iter().map(|(n, _)| n.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "exported bindings must be name-sorted (deterministic)");
    }

    /// Fail-closed: a syntax error is a typed `Parse`, never a panic.
    pub fn parse_error_is_fail_closed<E: BzlEvaluator>(e: &E) {
        assert!(
            matches!(e.evaluate("m", "x = = 1\n"), Err(BzlError::Parse { .. })),
            "a syntax error must be a typed BzlError::Parse"
        );
    }
}
