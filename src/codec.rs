use crate::{BzlValue, Depset, ProviderId, ProviderInstance};

fn framed(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s);
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

