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

/// The codec-neutral value model: `AttrType`/`RuleDef`/`BzlValue`/`BzlModule`/`RuleOrigin`/`TargetDecl`.
mod values;
pub use values::*;

/// Providers + depsets + the analysis-output shapes (`ProviderId`/`ProviderInstance`/`Depset`/`RuleResult`…).
mod provider;
pub use provider::*;

/// THE canonical codec funnel (`encode_bzl_value` / `encode_provider_instance`).
mod codec;
pub use codec::*;

/// The `BzlEvaluator` seam trait + `BzlError`.
mod seam;
pub use seam::*;

/// The evaluator conformance suite (grows in lockstep with the value model — P9).
mod conformance_mod;
pub use conformance_mod::conformance;

#[cfg(test)]
mod canonical_codec_tests;
