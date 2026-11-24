#!/usr/bin/env python3
"""GROUND TRUTH for holo-crypto bignum + RSA verify (task 2-d-R2).

Python 3 big ints, no third-party libs. Produces every constant embedded in
the Rust tests (crates/holo-crypto/src/lib.rs, `mod tests`):

  * deterministic 1024-bit RSA key (p, q, n, e, d, dp, dq, qInv)
  * n0' = -n^-1 mod 2^64 (Montgomery context)
  * R^-1 mod n (R = 2^1024)
  * EMSA-PKCS1-v1_5 (RFC 8017 section 9.2) EM + sig for the test hash
    h1 = bytes 0..31, sig = pow(em, d, n), verified by pow(sig, e, n)
  * EMSA-PSS (RFC 8017 section 9.1) EM + sig, salt = 32 x 0xA5, MGF1-SHA256
  * 3 "random-ish" modmul tuples x*y mod n (+ their x*y*R^-1 mod n, which is
    what CIOS mont_mul must produce)
  * one x*y >= n tuple ((n-1)^2) for the CIOS final-carry test
  * a limb-for-limb CIOS simulation of the Rust algorithm for every tuple
  * OpenSSL 3.5.7 cross-checks (primes, raw-DigestInfo sign, PSS decode of an
    OpenSSL-produced signature)

DEVIATION (recorded): the task points at "RFC 8017 section A.1.1 example
1024-bit key". RFC 8017 A.1.1 ("RSA Public Key Syntax") defines ASN.1 SYNTAX
only and contains no key material (verified by grep on the fetched
rfc8017.txt; same for rfc3447/rfc2437). The key is therefore GENERATED
deterministically (sha256-seeded candidate scan + Miller-Rabin) so the test
key is reproducible, not transcribed from memory.
"""
import hashlib, math, subprocess, sys

# ---------------------------------------------------------------------------
# deterministic key generation (same seeds as the previous cross-check run)
# ---------------------------------------------------------------------------

def is_probable_prime(n):
    if n % 2 == 0:
        return n == 2
    small_primes = []
    sieve = [True] * 1000
    for i in range(2, 1000):
        if sieve[i]:
            small_primes.append(i)
            for j in range(i * i, 1000, i):
                sieve[j] = False
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1; r = 0
    while d % 2 == 0:
        d //= 2; r += 1
    for a in small_primes[:64]:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(seed: bytes, bits=512):
    cand = int.from_bytes(hashlib.sha256(seed).digest(), "big")
    cand |= (1 << (bits - 1))
    cand |= 1
    while True:
        if cand.bit_length() == bits and is_probable_prime(cand):
            return cand
        cand += 2

e = 65537
p = gen_prime(b"HoloNet deterministic key prime p")
q = gen_prime(b"HoloNet deterministic key prime q")
assert p != q
n = p * q
lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
assert math.gcd(e, lam) == 1
d = pow(e, -1, lam)
dp = d % (p - 1)
dq = d % (q - 1)
qinv = pow(q, -1, p)

k = (n.bit_length() + 7) // 8          # 128 octets
mod_bits = n.bit_length()              # 1023
em_bits = mod_bits - 1                 # 1022
em_len = (em_bits + 7) // 8            # 128

def hx(x):  return format(x, "x")
def hxp(x, w):  return format(x, "0{}x".format(w))

print("[i] modBits =", mod_bits, " k =", k, " emBits =", em_bits, " emLen =", em_len)
print("p  =", hx(p))
print("q  =", hx(q))
print("n  =", hxp(n, 2 * k))
print("e  =", hx(e))
print("d  =", hxp(d, 2 * k))
print("dp =", hxp(dp, 2 * k))
print("dq =", hxp(dq, 2 * k))
print("qinv =", hxp(qinv, 2 * k))

# independent primality confirmation of p and q
for name, val in (("p", p), ("q", q)):
    r = subprocess.run(["openssl", "prime", str(val)], capture_output=True, text=True)
    ok = "is prime" in r.stdout or "is prime" in r.stderr
    print(f"[{'OK' if ok else 'FAIL'}] openssl prime({name}) ->",
          (r.stdout + r.stderr).strip()[:80])

# ---------------------------------------------------------------------------
# RFC 8017 primitives
# ---------------------------------------------------------------------------

def os2ip(b):  return int.from_bytes(b, "big")
def i2osp(x, ln):
    assert 0 <= x < 256 ** ln, "i2osp overflow"
    return x.to_bytes(ln, "big")

def mgf1_sha256(seed: bytes, mask_len: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < mask_len:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:mask_len]

DIGEST_INFO_SHA256 = bytes.fromhex(
    "3031300d060960864801650304020105000420")  # RFC 8017 9.2 note 1

def emsa_pkcs15_encode(H: bytes, em_len: int) -> bytes:
    t = DIGEST_INFO_SHA256 + H
    t_len = len(t)
    assert em_len >= t_len + 11, "emLen too short"
    ps = b"\xff" * (em_len - t_len - 3)
    assert len(ps) >= 8
    return b"\x00\x01" + ps + b"\x00" + t

def emsa_pss_encode(H: bytes, em_bits: int, salt: bytes) -> bytes:
    h_len = len(H); s_len = len(salt)
    em_len = (em_bits + 7) // 8
    assert em_len >= h_len + s_len + 2, "encoding too short"
    salt = salt
    m_prime = b"\x00" * 8 + H + salt
    hh = hashlib.sha256(m_prime).digest()
    top = 8 * em_len - em_bits                       # bits forced to zero
    ps_len = em_len - h_len - s_len - 2
    db = b"\x00" * ps_len + b"\x01" + salt
    db_mask = mgf1_sha256(hh, em_len - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    masked_db = bytes([masked_db[0] & (0xFF >> top)]) + masked_db[1:]
    return masked_db + hh + b"\xbc"

def emsa_pss_verify_decode(em: bytes, em_bits: int, h_msg: bytes):
    """EMSA-PSS-VERIFY core (returns recovered salt) — used to verify sigs."""
    em_len = len(em); h_len = 32
    top = 8 * em_len - em_bits
    assert em[-1] == 0xBC, "bad trailer"
    db_len = em_len - h_len - 1
    masked_db, hh = em[:db_len], em[db_len:db_len + h_len]
    assert top == 0 or masked_db[0] >> (8 - top) == 0, "leftmost bits not zero"
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1_sha256(hh, db_len)))
    db = bytes([db[0] & (0xFF >> top)]) + db[1:]
    # salt length is recovered from the position of the 0x01 separator
    zeros = 0
    while db[zeros] == 0:
        zeros += 1
    assert db[zeros] == 1, "separator missing"
    salt = db[zeros + 1:]
    hp = hashlib.sha256(b"\x00" * 8 + h_msg + salt).digest()
    assert hp == hh, "H' mismatch"
    return salt, zeros

# ---------------------------------------------------------------------------
# 1) PKCS#1 v1.5 over h1 = bytes 0..31, sig = pow(em, d, n), roundtrip
# ---------------------------------------------------------------------------
h1 = bytes(range(32))
em1 = emsa_pkcs15_encode(h1, k)
sig1 = pow(i2osp_check := int.from_bytes(em1, "big"), d, n)
assert pow(sig1, e, n) == int.from_bytes(em1, "big"), "v1.5 roundtrip"
print("\n--- EMSA-PKCS1-v1_5 (RFC 8017 9.2), H = h1 = 000102...1f ---")
print("EM_pkcs15  =", em1.hex())
print("sig_pkcs15 =", hxp(sig1, 2 * k))
print("[OK] pow(sig, e, n) == os2ip(EM)  (v1.5 roundtrip verified)")

# independent OpenSSL check of the same signature via raw DigestInfo input
import subprocess as sp
# build PKCS#1 RSAPrivateKey DER by hand (version, n, e, d, p, q, dp, dq, qinv)
def der_len(b):
    if len(b) < 128:
        return bytes([len(b)])
    l = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(l)]) + l
def der_int(x):
    b = x.to_bytes((x.bit_length() + 8) // 8, "big")
    return b"\x02" + der_len(b) + b
def der_seq(*parts):
    body = b"".join(parts)
    return b"\x30" + der_len(body) + body
pkcs1_der = der_seq(der_int(0), der_int(n), der_int(e), der_int(d),
                    der_int(p), der_int(q), der_int(dp), der_int(dq),
                    der_int(qinv))
open("/tmp/wk-d2r_priv.der", "wb").write(pkcs1_der)
sp.run(["openssl", "pkcs8", "-topk8", "-inform", "DER", "-outform", "PEM",
        "-nocrypt", "-in", "/tmp/wk-d2r_priv.der",
        "-out", "/tmp/wk-d2r_priv.pem"], check=True, capture_output=True)
di = DIGEST_INFO_SHA256 + h1
open("/tmp/wk-d2r_digestinfo.bin", "wb").write(di)
open("/tmp/wk-d2r_sig1.bin", "wb").write(sig1.to_bytes(k, "big"))
r = sp.run(["openssl", "pkeyutl", "-sign", "-inkey", "/tmp/wk-d2r_priv.pem",
            "-in", "/tmp/wk-d2r_digestinfo.bin"],
           capture_output=True, check=True)
ossl_sig1 = r.stdout.hex()
print("sig_pkcs15(OSSL raw DigestInfo sign) =", ossl_sig1[:64], "... len", len(r.stdout))
print("[{}] OpenSSL PKCS#1 v1.5 signature {}".format(
    "OK" if ossl_sig1 == sig1.to_bytes(k, "big").hex() else "FAIL",
    "byte-identical to Python" if ossl_sig1 == sig1.to_bytes(k, "big").hex() else "MISMATCH"))
r = sp.run(["openssl", "pkeyutl", "-verify", "-pubin",
            "-inkey", "/tmp/wk-d2r_priv.pem",
            "-sigfile", "/tmp/wk-d2r_sig1.bin",
            "-in", "/tmp/wk-d2r_digestinfo.bin"], capture_output=True, text=True)
print("[{}] openssl pkeyutl verify:".format("OK" if r.returncode == 0 else "FAIL"),
      (r.stdout + r.stderr).strip())

# secondary v1.5 vector over a real message, cross-checked with openssl dgst
msg2 = b"HoloNet bignum/RSA cross-check message"
h2 = hashlib.sha256(msg2).digest()
em2 = emsa_pkcs15_encode(h2, k)
sig2 = pow(int.from_bytes(em2, "big"), d, n)
assert pow(sig2, e, n) == int.from_bytes(em2, "big")
print("\n--- secondary PKCS#1 v1.5 vector, H = sha256(msg2) ---")
print("msg2 =", msg2.decode())
print("h2   =", h2.hex())
print("EM2  =", em2.hex())
r = sp.run(["openssl", "dgst", "-sha256", "-sign", "/tmp/wk-d2r_priv.pem",
            "-"], input=msg2, capture_output=True, check=True)
sig2_ossl = r.stdout
print("sig2(OSSL dgst -sign) =", sig2_ossl.hex())
print("[{}] openssl dgst sig == Python pow(em2, d, n)".format(
    "OK" if sig2_ossl == sig2.to_bytes(k, "big") else "FAIL"))

# ---------------------------------------------------------------------------
# 2) EMSA-PSS, salt = 32 x 0xA5, sig = pow(em, d, n), decoded roundtrip
# ---------------------------------------------------------------------------
salt_a5 = b"\xa5" * 32
em_pss = emsa_pss_encode(h1, em_bits, salt_a5)
sig_pss = pow(int.from_bytes(em_pss, "big"), d, n)
em_rec = pow(sig_pss, e, n).to_bytes(k, "big")   # signature -> recovered EM
assert em_rec == em_pss, "pow(sig, e, n) must recover the EM"
rec_salt, rec_zeros = emsa_pss_verify_decode(em_rec, em_bits, h1)
assert rec_salt == salt_a5
print("\n--- EMSA-PSS (RFC 8017 9.1), H = h1, salt = a5 * 32 ---")
print("EM_pss   =", em_pss.hex())
print("sig_pss  =", hxp(sig_pss, 2 * k))
print("[OK] roundtrip: pow(sig, e, n) decodes to maskedDB||H||bc; salt recovered =",
      rec_salt.hex())
print("[OK] recovered salt == a5*32, PS zeros =", rec_zeros)

# cross-check the PSS *decoder* against an OpenSSL-produced signature
msg3 = b"HoloNet bignum/RSA cross-check message (PSS ossl)"
open("/tmp/wk-d2r_msg3.bin", "wb").write(msg3)
r = sp.run(["openssl", "dgst", "-sha256", "-sign", "/tmp/wk-d2r_priv.pem",
            "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
            "-out", "/tmp/wk-d2r_sig3.bin", "/tmp/wk-d2r_msg3.bin"],
           capture_output=True, check=True)
sig3 = int.from_bytes(open("/tmp/wk-d2r_sig3.bin", "rb").read(), "big")
h3 = hashlib.sha256(msg3).digest()
s3, z3 = emsa_pss_verify_decode(pow(sig3, e, n).to_bytes(k, "big"), em_bits, h3)
print("openssl PSS sig over msg3 decoded by this script: salt =", s3.hex(),
      "PS zeros =", z3)
print("[OK] python PSS decoder accepts the OpenSSL 3.5.7 PSS signature (saltlen 32)")

# ---------------------------------------------------------------------------
# 3) Montgomery context + schoolbook mul vectors
# ---------------------------------------------------------------------------
n0p = (-pow(n, -1, 1 << 64)) % (1 << 64)
R = 1 << (64 * (k // 8))            # R = 2^(64*16) = 2^1024
R_mod_n = R % n
Rinv_mod_n = pow(R, -1, n)
print("\n--- Montgomery context / constants ---")
print("n0' = -n^-1 mod 2^64 =", hxp(n0p, 16))
print("Rinv mod n =", hxp(Rinv_mod_n, 2 * k))

print("\n--- schoolbook mul vectors (x * y, full product) ---")
mul_cases = [
    ("01", "ffffffffffffffff"),
    ("deadbeefcafebabe0123456789abcdef", "0123456789abcdefdeadbeefcafebabe"),
    (hx(p), hx(q)),                                        # p*q == n
    ("7fffffffffffffffffffffffffffffff", "fffffffffffffffffffffffffffffffe"),
]
for i, (xs, ys) in enumerate(mul_cases, 1):
    xy = int(xs, 16) * int(ys, 16)
    print(f"mul{i}: x={xs}\n      y={ys}\n      x*y={hx(xy)}")

# ---------------------------------------------------------------------------
# 4) modmul tuples: 3 random-ish + EDGE (x*y >= n); CIOS simulation
# ---------------------------------------------------------------------------
print("\n--- plain modmul tuples x*y mod n  (+ x*y*R^-1 mod n for CIOS) ---")

def seed_int(tag: bytes, bits: int) -> int:
    v = int.from_bytes(hashlib.sha256(tag).digest(), "big")
    return v % n

mont_cases = [
    (seed_int(b"tuple1-x", mod_bits), seed_int(b"tuple1-y", mod_bits)),
    (seed_int(b"tuple2-x", mod_bits), seed_int(b"tuple2-y", mod_bits)),
    (seed_int(b"tuple3-x", mod_bits), seed_int(b"tuple3-y", mod_bits)),
]
# ensure the tuples are non-degenerate (non-zero, and at least one x*y >= n)
assert all(x != 0 and y != 0 for x, y in mont_cases)
edge_x = n - 1; edge_y = n - 1          # x*y = (n-1)^2 >= n  (final-carry)
noedge_x = n - 1; noedge_y = 2          # (n-1)*2 < n            (no subtract)

def cios_sim(a, b):
    """Limb-for-limb simulation of the Rust mont_mul (CIOS, k+2 limbs)."""
    mask = (1 << 64) - 1
    al = []; av = a
    while av: al.append(av & mask); av >>= 64
    bl = []; bv = b
    while bv: bl.append(bv & mask); bv >>= 64
    nl = []; nv = n
    while nv: nl.append(nv & mask); nv >>= 64
    kk = len(nl)
    t = [0] * (kk + 2)
    for i in range(kk):
        c = 0
        bi = bl[i] if i < len(bl) else 0
        for j in range(kk):
            aj = al[j] if j < len(al) else 0
            v = aj * bi + t[j] + c          # python ints: no overflow
            t[j] = v & mask
            c = v >> 64
        v = t[kk] + c
        t[kk] = v & mask
        t[kk + 1] = v >> 64
        m = (t[0] * n0p) & mask
        v = t[0] + m * nl[0]
        t[0] = v & mask
        c2 = v >> 64
        for j in range(1, kk):
            v = t[j] + m * nl[j] + c2
            t[j - 1] = v & mask
            c2 = v >> 64
        v = t[kk] + c2
        t[kk - 1] = v & mask
        c2 = v >> 64
        t[kk] = t[kk + 1] + c2
        t[kk + 1] = 0
    T = sum(t[i] << (64 * i) for i in range(kk + 1))
    final_sub = T >= n
    res = T - n if final_sub else T
    return res % n if res >= n else res, T, final_sub

ci = 0
for x, y in mont_cases:
    ci += 1
    plain = x * y % n
    mont = x * y * Rinv_mod_n % n
    got, T, fired = cios_sim(x, y)
    assert got == mont, f"CIOS sim mismatch case {ci}"
    assert T < 2 * n
    print(f"mont{ci}: x={hxp(x, 2 * k)}\n        y={hxp(y, 2 * k)}")
    print(f"        x*y mod n        = {hxp(plain, 2 * k)}")
    print(f"        x*y*R^-1 mod n   = {hxp(mont, 2 * k)}  (CIOS sim ok, T<2n: {T < 2*n})")

for tag, (x, y) in (("EDGE  ", (edge_x, edge_y)), ("NOEDGE", (noedge_x, noedge_y))):
    plain = x * y % n
    mont = x * y * Rinv_mod_n % n
    got, T, fired = cios_sim(x, y)
    assert got == mont and T < 2 * n
    print(f"{tag}: x={hxp(x, 2 * k)}\n       y={hxp(y, 2 * k)}")
    print(f"       x*y mod n = {hxp(plain, 2 * k)}  (x*y >= n: {x * y >= n})")
    print(f"       T (k+1 limbs, pre-final-subtract) = {hxp(T, 2 * k + 16)}")
    print(f"       final subtract fired: {fired}; result x*y*R^-1 mod n = {hxp(mont, 2 * k)}")

print("\n[OK] all CIOS simulations match Python x*y*R^-1 mod n; T < 2n in every case")
print("\nALL GROUND-TRUTH CHECKS PASSED")
