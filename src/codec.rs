use crate::{AttrDecl, BzlValue, Depset, FunctionRef, ProviderId, ProviderInstance, SelectArm};

fn framed(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s);
}

/// Encode an optional string as `[0x00]` (None) or `[0x01][u64-framed bytes]`.
fn framed_opt(b: &mut Vec<u8>, s: &Option<String>) {
    match s {
        None => b.push(0),
        Some(v) => {
            b.push(1);
            framed(b, v.as_bytes());
        }
    }
}

/// Encode a list of strings as `[u64 count]` then each `[u64-framed bytes]`.
fn framed_list(b: &mut Vec<u8>, items: &[String]) {
    b.extend_from_slice(&(items.len() as u64).to_be_bytes());
    for s in items {
        framed(b, s.as_bytes());
    }
}

/// The attr-marker digest frame (T20 R-load-codec, tag 13): `[tag 13][code byte][allow_files: opt-tag + list |
/// 0x00 absent][providers list][mandatory byte][default: opt-string]`. Private: reachable only through
/// [`encode_bzl_value`].
fn encode_attr_decl(a: &AttrDecl, b: &mut Vec<u8>) {
    b.push(13);
    b.push(a.code);
    match &a.allow_files {
        None => b.push(0),
        Some(exts) => {
            b.push(1);
            framed_list(b, exts);
        }
    }
    framed_list(b, &a.providers);
    b.push(a.mandatory as u8);
    framed_opt(b, &a.default);
}

/// The select digest frame (T20 select, tag 15 — canonical, recursive): `[tag 15][u64 arm count]` then per
/// arm a discriminant byte + payload. `Concrete` → `[0x00][encoded value]`; `Branch` →
/// `[0x01][u64 cond count]` then per condition IN CANONICAL LABEL-SORTED ORDER `[u64-framed label][encoded
/// value]`, then `[u64-framed no_match_error]`. Sorting the conditions is what makes the digest independent of
/// the `select({...})` dict declaration order (a select dict is order-independent for matching, unlike a
/// runtime `dict` whose tag-12 frame preserves insertion order). Private: reachable only through
/// [`encode_bzl_value`].
fn encode_select(arms: &[SelectArm], b: &mut Vec<u8>) {
    b.push(15);
    b.extend_from_slice(&(arms.len() as u64).to_be_bytes());
    for arm in arms {
        match arm {
            SelectArm::Concrete(v) => {
                b.push(0x00);
                encode_bzl_value(v, b);
            }
            SelectArm::Branch { conditions, no_match_error } => {
                b.push(0x01);
                b.extend_from_slice(&(conditions.len() as u64).to_be_bytes());
                // Canonical: emit conditions in LABEL-SORTED order. `convert` already sorts, but the codec
                // re-sorts defensively so the ONE digest funnel cannot emit a declaration-ordered (unstable)
                // frame — the same belt-and-braces the tag-9 struct frame uses.
                let mut idx: Vec<usize> = (0..conditions.len()).collect();
                if !cfg!(feature = "mutant_select_conditions_unsorted") {
                    idx.sort_by(|&i, &j| conditions[i].0.cmp(&conditions[j].0));
                }
                for &i in &idx {
                    let (label, value) = &conditions[i];
                    framed(b, label.as_bytes());
                    encode_bzl_value(value, b);
                }
                framed(b, no_match_error.as_bytes());
            }
        }
    }
}

/// The struct digest frame (T20 R-load-codec, tag 9 — canonical, recursive): `[tag 9][u64 field count]` then,
/// per field in NAME-SORTED order, `[u64-framed name][encoded value]`. Sorting is what makes the digest
/// independent of `struct()` kwargs order (two structs with the same fields in different declaration orders
/// digest identically). Private: reachable only through [`encode_bzl_value`].
fn encode_struct(fields: &[(String, BzlValue)], b: &mut Vec<u8>) {
    b.push(9);
    b.extend_from_slice(&(fields.len() as u64).to_be_bytes());
    // Canonical: emit in NAME-SORTED order. The evaluator already sorts on convert, but the codec re-sorts
    // defensively so the ONE digest funnel cannot emit a declaration-ordered (unstable) frame.
    let mut idx: Vec<usize> = (0..fields.len()).collect();
    if cfg!(feature = "mutant_struct_fields_unsorted") {
        // MUTANT: emit fields in DECLARATION order → two structs equal-but-for-order digest differently
        // (digest instability); the canonical-order round-trip/equality gate goes red.
    } else {
        idx.sort_by(|&i, &j| fields[i].0.cmp(&fields[j].0));
    }
    for &i in &idx {
        let (name, value) = &fields[i];
        framed(b, name.as_bytes());
        encode_bzl_value(value, b);
    }
}

/// The function-reference digest frame (T20 R-load-codec, tag 10): `[tag 10][u64-framed module][u64-framed
/// name][32-byte defining_digest]`. Identity is the PAIR `(module, name)` plus the module content digest;
/// NO closure/body is ever encoded (Bazel never serializes Starlark functions — the digest basis is the
/// transitive module source, carried by `defining_digest`). Private: reachable only through [`encode_bzl_value`].
fn encode_function_ref(f: &FunctionRef, b: &mut Vec<u8>) {
    b.push(10);
    if cfg!(feature = "mutant_function_ref_drops_module") {
        // MUTANT: collapse the ref to NAME-ONLY (drop the module + defining_digest) → two same-named functions
        // from DIFFERENT modules alias, and a body change no longer re-fingerprints. The function-identity gate
        // goes red on a same-name/different-module pair.
        framed(b, f.name.as_bytes());
        return;
    }
    framed(b, f.module.as_bytes());
    framed(b, f.name.as_bytes());
    b.extend_from_slice(&f.defining_digest);
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
        // File (T17-C5): the next FREE tag after depset's 7. A minimal documented frame — its exec-path
        // string, u64-length-framed. That path is the SAME string the frozen ActionTemplate/dep_outputs
        // chaining map keys on, so a File surfaced to `.bzl` and a File carried in a provider round-trip to
        // the byte-identical exec path (the `dep[RustInfo].rlib.path` consuming side is lossless).
        BzlValue::File(p) => {
            b.push(8);
            framed(b, p.as_bytes());
        }
        // Struct (T20 R-load-codec): tag 9, canonical name-sorted recursive frame.
        BzlValue::Struct(fields) => encode_struct(fields, b),
        // FunctionRef (T20 R-load-codec): tag 10, (module, name, defining_digest) — never the body.
        BzlValue::FunctionRef(f) => encode_function_ref(f, b),
        // Label (T20 R-load-codec): tag 11, its canonical label string (u64-framed).
        BzlValue::Label(s) => {
            b.push(11);
            framed(b, s.as_bytes());
        }
        // Dict (T20 R-load-codec): tag 12, `[u64 pair count]` then per pair `[key][value]` in INSERTION
        // order (Starlark dict iteration order is observable → order is digest content, never sorted).
        BzlValue::Dict(pairs) => {
            b.push(12);
            b.extend_from_slice(&(pairs.len() as u64).to_be_bytes());
            for (k, v) in pairs {
                encode_bzl_value(k, b);
                encode_bzl_value(v, b);
            }
        }
        // AttrDecl (T20 R-load-codec): tag 13, the attr.* schema marker.
        BzlValue::AttrDecl(a) => encode_attr_decl(a, b),
        // Tuple (T20 R-load-codec): tag 14, `[u64 count]` then each element (a distinct tag from list's 4).
        BzlValue::Tuple(items) => {
            b.push(14);
            b.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for it in items {
                encode_bzl_value(it, b);
            }
        }
        // Select (T20 select): tag 15, the canonical arm/branch frame (conditions label-sorted).
        BzlValue::Select(arms) => encode_select(arms, b),
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

