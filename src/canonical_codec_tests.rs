#[cfg(test)]
mod canonical_codec_tests {
    use crate::*;

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

    /// C5: the `File` value takes the next FREE digest tag 8 (a minimal exec-path frame), and a `depset[File]`
    /// (RustInfo.transitive_rlibs) is DISTINCT from a same-pathed `depset[Str]` — the File-ness is carried, so
    /// the codec is injective on the value and the round-trip preserves `.path` on the consuming side.
    #[test]
    fn file_takes_tag8_and_is_distinct_from_str() {
        let enc_file = enc(&BzlValue::File("p/lib.rlib".into()));
        assert_eq!(enc_file[0], 8, "File encodes under the next free tag 8 (tags 0-7 stay frozen)");
        assert_ne!(
            enc(&BzlValue::File("p/lib.rlib".into())),
            enc(&BzlValue::Str("p/lib.rlib".into())),
            "a File and a same-pathed Str are DISTINCT values (File-ness is digest content, not dropped)"
        );
        // a depset[File] ≠ a depset[Str] with the same path (RustInfo.transitive_rlibs carries Files).
        let ds = |v: BzlValue| BzlValue::Depset(Depset { order: DepsetOrder::Default, elem: None, direct: vec![v], transitive: vec![] });
        assert_ne!(
            enc(&ds(BzlValue::File("p/lib.rlib".into()))),
            enc(&ds(BzlValue::Str("p/lib.rlib".into()))),
            "depset[File] ≠ depset[Str] — the reserved tag-7 frame recurses into the File tag 8"
        );
    }

    fn func(module: &str, name: &str, d: u8) -> BzlValue {
        BzlValue::FunctionRef(FunctionRef { module: module.into(), name: name.into(), defining_digest: [d; 32] })
    }

    /// T20 R-load-codec: the codec's TAG assignment is frozen — every existing variant keeps its byte, and
    /// the new variants take the next free tags 9 (Struct), 10 (FunctionRef), 11 (Label). This pins the whole
    /// table so a future variant cannot silently re-seat an existing tag.
    #[test]
    fn codec_tag_table_is_frozen_through_tag_11() {
        assert_eq!(enc(&BzlValue::None)[0], 0);
        assert_eq!(enc(&BzlValue::Bool(false))[0], 1);
        assert_eq!(enc(&BzlValue::Int(0))[0], 2);
        assert_eq!(enc(&BzlValue::Str(String::new()))[0], 3);
        assert_eq!(enc(&BzlValue::List(vec![]))[0], 4);
        assert_eq!(enc(&BzlValue::Rule(RuleDef { bzl: "a".into(), name: "r".into(), attrs: vec![], toolchains: vec![] }))[0], 5);
        assert_eq!(enc(&BzlValue::Provider(ProviderDef { id: ProviderId::from_name("P"), fields: vec![] }))[0], 6);
        assert_eq!(enc(&BzlValue::Depset(Depset { order: DepsetOrder::Default, elem: None, direct: vec![], transitive: vec![] }))[0], 7);
        assert_eq!(enc(&BzlValue::File("p".into()))[0], 8);
        assert_eq!(enc(&BzlValue::Struct(vec![]))[0], 9, "Struct takes the next FREE tag 9");
        assert_eq!(enc(&func("m", "f", 0))[0], 10, "FunctionRef takes the next FREE tag 10");
        assert_eq!(enc(&BzlValue::Label("//p:t".into()))[0], 11, "Label takes the next FREE tag 11");
        // a Label must not alias a Str of the same text (tag separation).
        assert_ne!(enc(&BzlValue::Label("//p:t".into())), enc(&BzlValue::Str("//p:t".into())), "Label tag 11 ≠ Str tag 3");
    }

    /// Tag 9 (Struct): CANONICAL name-sorted encoding — two structs with the SAME fields in DIFFERENT
    /// `struct()` kwargs order digest IDENTICALLY; different field values digest differently; the struct tag
    /// does not alias a list/dict. RED under `mutant_struct_fields_unsorted` (declaration-order emit).
    #[test]
    fn struct_fields_canonical_sorted() {
        let s = |x: &str| BzlValue::Str(x.into());
        let ab = BzlValue::Struct(vec![("a".into(), s("1")), ("b".into(), s("2"))]);
        let ba = BzlValue::Struct(vec![("b".into(), s("2")), ("a".into(), s("1"))]); // reversed declaration order
        assert_eq!(enc(&ab), enc(&ba), "struct field order must NOT affect the digest (canonical name-sorted)");
        // a different value under 'b' changes the digest (fields are real content).
        let ab2 = BzlValue::Struct(vec![("a".into(), s("1")), ("b".into(), s("X"))]);
        assert_ne!(enc(&ab), enc(&ab2), "a changed field value must change the digest");
        // framing: {"a":"b"} must not alias {"ab":""} etc. (length-framed names + tag separation).
        let one = BzlValue::Struct(vec![("a".into(), s("b"))]);
        let two = BzlValue::Struct(vec![("ab".into(), s(""))]);
        assert_ne!(enc(&one), enc(&two), "struct name/value framing must be self-delimiting");
        // a struct is NOT a list (tag separation).
        assert_ne!(enc(&BzlValue::Struct(vec![])), enc(&BzlValue::List(vec![])), "struct tag 9 ≠ list tag 4");
    }

    /// Tag 15 (Select): the arm/branch frame is injective + canonical. A `select({...})`'s condition dict is
    /// order-INDEPENDENT for matching, so two selects that differ ONLY in condition-declaration order digest
    /// IDENTICALLY (canonical label-sorted — unlike a runtime dict's tag-12 insertion-order frame); a changed
    /// branch value / a changed no_match_error / a Concrete-vs-Branch arm split all change the digest; a select
    /// is NOT a list. RED under `mutant_select_conditions_unsorted` (declaration-order emit).
    #[test]
    fn select_frame_canonical_and_injective() {
        let s = |x: &str| BzlValue::Str(x.into());
        let branch = |conds: Vec<(&str, BzlValue)>| {
            BzlValue::Select(vec![SelectArm::Branch {
                conditions: conds.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                no_match_error: String::new(),
            }])
        };
        // condition-declaration order must NOT affect the digest (canonical label-sorted).
        let ab = branch(vec![("//a", s("1")), ("//b", s("2"))]);
        let ba = branch(vec![("//b", s("2")), ("//a", s("1"))]);
        assert_eq!(enc(&ab), enc(&ba), "select condition order must NOT affect the digest (canonical label-sorted)");
        assert_eq!(enc(&ab)[0], 15, "Select takes tag 15");
        // a changed branch value changes the digest (conditions are real content).
        assert_ne!(enc(&ab), enc(&branch(vec![("//a", s("1")), ("//b", s("X"))])), "a changed branch value changes the digest");
        // no_match_error is digest content.
        let nme = BzlValue::Select(vec![SelectArm::Branch {
            conditions: vec![("//a".into(), s("1"))],
            no_match_error: "boom".into(),
        }]);
        let no_nme = branch(vec![("//a", s("1"))]);
        assert_ne!(enc(&nme), enc(&no_nme), "no_match_error is digest content");
        // a Concrete arm vs a Branch arm split is observable (SelectorList structure is content).
        let concat = BzlValue::Select(vec![
            SelectArm::Concrete(BzlValue::List(vec![s("//x")])),
            SelectArm::Branch { conditions: vec![("//a".into(), s("1"))], no_match_error: String::new() },
        ]);
        assert_ne!(enc(&concat), enc(&no_nme), "a `[..] + select(..)` concat digests differently from a bare select");
        assert_eq!(enc(&ab), enc(&ab), "deterministic");
        // a select is NOT a list (tag separation).
        assert_ne!(enc(&BzlValue::Select(vec![])), enc(&BzlValue::List(vec![])), "select tag 15 ≠ list tag 4");
    }

    /// Tag 10 (FunctionRef): identity is the PAIR (module, name) plus the defining_digest — NEVER name alone.
    /// Two same-named functions from DIFFERENT modules digest (and compare) differently; a defining_digest
    /// change (a body edit re-fingerprinting the module) changes the digest; the same triple is deterministic.
    /// RED under `mutant_function_ref_drops_module` (name-only collapse).
    #[test]
    fn function_ref_carries_module_identity() {
        // Same name, different module → distinct (the mutant fuses these).
        assert_ne!(enc(&func("m1", "f", 0)), enc(&func("m2", "f", 0)), "same name, different module must digest differently");
        // Same name+module, different defining_digest (a body change re-fingerprinting the module) → distinct.
        assert_ne!(enc(&func("m", "f", 0)), enc(&func("m", "f", 9)), "a defining_digest change must change the digest (module-content cutoff)");
        // Different name, same module → distinct.
        assert_ne!(enc(&func("m", "f", 0)), enc(&func("m", "g", 0)), "different symbol name must digest differently");
        // Deterministic + the derived identity Eq distinguishes the module dim.
        assert_eq!(enc(&func("m", "f", 0)), enc(&func("m", "f", 0)), "deterministic");
        let a = FunctionRef { module: "m1".into(), name: "f".into(), defining_digest: [0; 32] };
        let b = FunctionRef { module: "m2".into(), name: "f".into(), defining_digest: [0; 32] };
        assert_ne!(a, b, "the derived Eq distinguishes the module dim (never aliases by name)");
        // a FunctionRef must not alias a Str of its name (tag separation).
        assert_ne!(enc(&func("m", "f", 0)), enc(&BzlValue::Str("f".into())), "FunctionRef tag 10 ≠ Str tag 3");
    }

    /// Tags 9+10 compose recursively and losslessly: a struct carrying a FunctionRef field is DISTINCT from the
    /// same struct carrying a Str of the function's name (the function-ness is digest content, not dropped), and
    /// nested structs are structurally distinct — the codec is injective on the whole value.
    #[test]
    fn struct_recurses_into_function_ref_and_nesting() {
        let with_fn = BzlValue::Struct(vec![("create".into(), func("common.bzl", "_create_crate_info", 3))]);
        let with_str = BzlValue::Struct(vec![("create".into(), BzlValue::Str("_create_crate_info".into()))]);
        assert_ne!(enc(&with_fn), enc(&with_str), "a struct field FunctionRef ≠ a same-named Str field (function-ness carried)");
        // nesting is structural: {inner: {x:"1"}} ≠ {inner: "1"} ≠ {x:"1"}.
        let nested = BzlValue::Struct(vec![("inner".into(), BzlValue::Struct(vec![("x".into(), BzlValue::Str("1".into()))]))]);
        let flat = BzlValue::Struct(vec![("inner".into(), BzlValue::Str("1".into()))]);
        assert_ne!(enc(&nested), enc(&flat), "a nested struct field ≠ a scalar field (structural)");
    }

    /// The R-load ladder's demand-driven value fills (tags 12 Dict / 13 AttrDecl / 14 Tuple): each is
    /// injective + deterministic and distinct from its look-alikes. Dict order is digest content (Starlark
    /// dict iteration is observable); a Tuple is distinct from a List with the same elements.
    #[test]
    fn ladder_value_tags_are_injective_and_distinct() {
        let s = |x: &str| BzlValue::Str(x.into());
        // Dict (12): insertion order is digest content; keys+values recurse.
        let ab = BzlValue::Dict(vec![(s("a"), s("1")), (s("b"), s("2"))]);
        let ba = BzlValue::Dict(vec![(s("b"), s("2")), (s("a"), s("1"))]);
        assert_ne!(enc(&ab), enc(&ba), "dict INSERTION order is observable → digest content (never sorted)");
        assert_eq!(enc(&ab), enc(&ab), "deterministic");
        assert_ne!(enc(&BzlValue::Dict(vec![])), enc(&BzlValue::Struct(vec![])), "empty dict tag 12 ≠ empty struct tag 9");
        // Tuple (14): distinct from a same-element List (tags separate the two sequence types).
        let tup = BzlValue::Tuple(vec![s("a"), s("b")]);
        let lst = BzlValue::List(vec![s("a"), s("b")]);
        assert_ne!(enc(&tup), enc(&lst), "a tuple ≠ a list with the same elements (distinct Starlark types)");
        assert_eq!(enc(&tup)[0], 14, "Tuple takes tag 14");
        // AttrDecl (13): the schema fields are injective (code / allow_files / providers / mandatory / default).
        let base = AttrDecl { code: 3, allow_files: None, providers: vec![], mandatory: false, default: None };
        let mk = |a: &AttrDecl| enc(&BzlValue::AttrDecl(a.clone()));
        assert_eq!(mk(&base)[0], 13, "AttrDecl takes tag 13");
        assert_ne!(mk(&base), mk(&AttrDecl { code: 4, ..base.clone() }), "the attr code distinguishes");
        assert_ne!(mk(&base), mk(&AttrDecl { mandatory: true, ..base.clone() }), "mandatory distinguishes");
        assert_ne!(mk(&base), mk(&AttrDecl { providers: vec!["P".into()], ..base.clone() }), "required providers distinguish");
        assert_ne!(mk(&base), mk(&AttrDecl { allow_files: Some(vec![".rs".into()]), ..base.clone() }), "allow_files distinguishes");
        assert_ne!(mk(&base), mk(&AttrDecl { default: Some("2021".into()), ..base }), "the string default distinguishes");
    }
}
