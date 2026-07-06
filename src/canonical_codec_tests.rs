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
}
