#!/usr/bin/env python3
"""Independent X25519 cross-verification against RFC 7748.

The decode functions are the RFC's OWN code (§5 <CODE BEGINS> blocks,
copied verbatim from the fetched https://www.rfc-editor.org/rfc/rfc7748.txt,
python-3-adapted only for the integer division in range()); the ladder is
a direct transcription of §4's pseudocode into python big-ints. Every
vector below is copied verbatim from the fetched RFC text. PASS lines
quote >=16 hex chars (A3-C9). This is the independent ground truth the
Rust implementation (engine/crates/holo-crypto::x25519) is diffed against.
"""
p = 2**255 - 19
A24 = 121665  # RFC §4: "(486662 - 2) / 4 = 121665 for curve25519/X25519"


def decodeLittleEndian(b, bits):
    return sum([b[i] << 8 * i for i in range((bits + 7) // 8)])


def decodeUCoordinate(u, bits):
    u_list = list(u)
    # RFC §5 verbatim: "implementations of X25519 (but not X448) MUST mask
    # the most significant bit in the final byte."
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)


def decodeScalar25519(k):
    k_list = list(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)


def cswap(swap, x2, x3):
    # RFC §4: dummy = mask(swap) AND (x_2 XOR x_3) — integer-domain
    # stand-in for the limb XOR; swap is per-iteration public k_t.
    return (x3, x2) if swap else (x2, x3)


def ladder(k_int, u):
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t
        A = (x2 + z2) % p
        AA = (A * A) % p
        B = (x2 - z2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = ((DA + CB) % p) ** 2 % p
        z3 = x1 * (((DA - CB) % p) ** 2 % p) % p
        x2 = (AA * BB) % p
        z2 = (E * ((AA + A24 * E) % p)) % p
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    return x2 * pow(z2, p - 2, p) % p


def X25519(k_bytes, u_bytes):
    k = decodeScalar25519(k_bytes)
    u = decodeUCoordinate(u_bytes, 255)
    return ladder(k, u)


def hexb(n):
    return bytes(n.to_bytes(32, "little")).hex()


def check(name, got, want):
    ok = got == want
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n       got  {got}\n       want {want}")
    return ok


def main():
    ok = True
    # RFC 7748 §5.2 vectors (verbatim from the fetched RFC)
    v1k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    v1u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    ok &= check("RFC 7748 §5.2 vector1", hexb(X25519(v1k, v1u)),
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    v2k = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    v2u = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    ok &= check("RFC 7748 §5.2 vector2 (u top bit set — non-canonical accepted)", hexb(X25519(v2k, v2u)),
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

    # RFC 7748 §6.1 DH vector (verbatim)
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    base = bytes([9]) + bytes(31)
    ka, kb = X25519(a, base), X25519(b, base)
    ka_b, kb_b = ka.to_bytes(32, "little"), kb.to_bytes(32, "little")
    ok &= check("§6.1 Alice public X25519(a,9)", hexb(ka),
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    ok &= check("§6.1 Bob public X25519(b,9)", hexb(kb),
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    ok &= check("§6.1 shared X25519(a, K_B)", hexb(X25519(a, kb_b)),
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    ok &= check("§6.1 shared X25519(b, K_A)", hexb(X25519(b, ka_b)),
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    # all-zero shared secret on small-order input (u = 0) — the recorded
    # policy rejects exactly this (A2, TLS 1.3-style)
    zero = X25519(bytes([1]) + bytes(31), bytes(32))
    ok &= check("u=0 → all-zero output (contributory rejection case)", hexb(zero),
                "00" * 32)

    # RFC 7748 §5.2 iterated test: k and u start at "0900…00";
    # (k, u) := (X25519(k, u), k) each iteration.
    k = bytes([9]) + bytes(31)
    u = bytes([9]) + bytes(31)
    k_int = X25519(k, u)
    k_b = k_int.to_bytes(32, "little")
    ok &= check("iterated after 1 iteration", hexb(k_int),
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    for _ in range(999):
        new_k_int = X25519(k_b, u)
        u = k_b  # RFC verbatim: "u to be the old value of k"
        k_b = new_k_int.to_bytes(32, "little")
        k_int = new_k_int
        # (no stray comments — ordering above is the RFC's own definition)
    ok &= check("iterated after 1,000 iterations", hexb(k_int),
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

    print("\nALL CHECKS " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
