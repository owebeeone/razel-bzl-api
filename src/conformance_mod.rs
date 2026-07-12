pub mod conformance {
    use crate::*;

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

    /// A value kind the model represents crosses the boundary; one it does not is rejected fail-closed.
    pub fn rejects_unsupported_types<E: BzlEvaluator>(e: &E) {
        // T20 R-load-codec: an exported FUNCTION now surfaces as a `FunctionRef` (its (module, name) identity
        // + the defining module's content digest — NEVER the body), so sibling modules can `load()` it. It
        // is no longer a typed-Unsupported hole.
        let m = e
            .evaluate(&EvalEnv::default(), "m", "def f():\n    pass\n", &[])
            .expect("an exported function must evaluate (it surfaces as a FunctionRef, not a rejection)");
        match m.get("f") {
            Some(BzlValue::FunctionRef(fr)) => {
                assert_eq!(fr.name, "f", "the FunctionRef carries the symbol name");
                assert_eq!(fr.module, "m", "the FunctionRef carries the DEFINING module (identity, not the body)");
            }
            other => panic!("an exported function must surface as a BzlValue::FunctionRef, got {other:?}"),
        }
        // A value kind the model still does NOT represent (a `range` object) stays fail-closed — rejected as
        // a typed error, never silently dropped.
        assert!(
            matches!(
                e.evaluate(&EvalEnv::default(), "m", "x = range(3)\n", &[]),
                Err(BzlError::Unsupported { .. })
            ),
            "an unrepresentable value (a module-scope range) must surface as a typed BzlError::Unsupported"
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

    /// A rule's impl declares an action (`ctx.actions.run`); it surfaces in `RuleResult.actions` (the analysis
    /// output the execution phase consumes) alongside the providers. Projection law: `argv = [executable] +
    /// flattened arguments`, outputs as declared.
    pub fn supports_action_declaration<E: BzlEvaluator>(e: &E) {
        let src = "\
NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])

def _impl(ctx):
    ctx.actions.run(mnemonic = \"Touch\", executable = \"touch\", arguments = [\"out\"], outputs = [\"out\"])
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

