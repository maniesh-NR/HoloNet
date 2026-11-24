# Session journal — 2026-11-25: S1b completion sprint (items 3/4/5 via
# parallel agents; X25519 by the lead; owner-authorized autonomous run)

Owner instruction (scheduled session, job 546609): implement everything
on the roadmap that does not require owner input within this single
session; backup after each stage; parallelize across agents.

## Session-start ritual (runbook 0/0b, warm path)

- Remote reconciliation FIRST: `git ls-remote origin refs/heads/main` =
  c76844e == `git rev-parse HEAD`. MATCH (run-9 closure state).
- `git status --porcelain`: clean. No strays to triage.
- Toolchain: `cargo --version` → not found — the sandbox recycle wiped
  ~/.cargo a FIFTH time. Reinstalled per runbook step 2 (rustup-init
  minimal/stable) → cargo/rustc 1.100.0 (same as runs 6–9).
- Git identity already correct (maniesh-NR / 83553290+maniesh-NR@
  users.noreply.github.com); core.fileMode already false.
- Baseline re-verified BEFORE changes: `cargo test --workspace` →
  **97 green, 0 failed**; Cargo.lock `version = 3` held. Matches the
  CI-verified run-9 ledger (97 Linux / 96 macOS / 96 Windows @ e3c8304,
  run 44897540455).
- Memory loaded per D-0027/D-0028 + direct reads: PROJECT_MEMORY.md
  (full), WORKFLOW.md (§1.2/§2.6/§4), SANDBOX-RESTORE.md, the two
  newest journals (2026-11-21-memory-graph-rag.md, 2026-11-21b-blake2s.md),
  DECISIONS tail (next free = D-0030), LESSONS tail, BACKUPS tail,
  ROADMAP S1b verbatim, THREAT-MODEL §G/Windows sections.

## Scope verified against memory (owner-input-free remainder)

- Windows secret-at-rest ACL decision: **already recorded** (THREAT-MODEL
  §G lines 191-200: rely on per-user profile ACLs, admin/SYSTEM residual
  accepted, revisit-only clause) — D-0018 + A2-F4/C2, 2026-11-20. NO work
  needed; the task brief's over-inclusion corrected here.
- Server-path hardening backlog: all four items DONE (runs 4-5, CI
  44703200189 / 44700103379). NO work needed.
- Remaining: S1b items 2 (X25519), 3 (AES-CFB), 4 (ExpandLabel), 5
  (bignum/RSA); then record 0004 (S1→S2 gate) per WORKFLOW §2.6.
- Owner items (deferred, unchanged): D-0014 trojan confirmation; CVE
  id backfill when GitHub assigns; session PAT rotation.

## Stage batch 1: items 3+4+5 via parallel agents

Five agents launched in ONE message, each in an ISOLATED rsync copy of
engine/ (/tmp/wk-{x25519,cfb,hkdf,bignum}) with fully self-contained
briefs; deliverables = final lib.rs + report under
/home/z/my-project/scratch/; agents never touched the real repo, git,
or credentials.

- **2-b AES-CFB: DELIVERED.** SP 800-38A fetched + pdftotext-extracted
  (primary source), F.3.13-F.3.18 CFB128-AES128/192/256 verbatim;
  OpenSSL 3.5.7 cross-checked BOTH directions (prefix-stream technique
  — the naive per-block invocation mismatches because `openssl enc`
  streams from the IV); `pub(crate) mod cfb128` (raw fns not pub) +
  `cfb_usage_audit` (allowlist exactly [crates/holo-crypto/src/lib.rs],
  ≥15-file floor, file:line output); negative control proved in its
  workspace (probe file → FAIL → removed → green); its workspace:
  102-green (97+5), lock v3.
- **2-c TLS 1.3 schedule: DELIVERED.** `hkdf_sha256_expand` exposed
  (delegates to the private `expand`); `tls13::{encode_hkdf_label,
  hkdf_expand_label, derive_secret}`; RFC 8446 §7.1 pseudocode quoted;
  RFC 8448 §3 chain replayed with transcripts recomputed from raw
  published messages; 3 transcription/spec errors caught+fixed en route
  (dropped nibble in handshake secret; 12-vs-13-octet RFC 5869 salt;
  server-Finished HMAC covers CH..CertificateVerify per §4.4, not
  CH..SH); its workspace: 100-green (97+3), lock v3.
- **2-d bignum+RSA: DELIVERED (on second launch).** First launch died
  (context deadline) but had left partial code in its workspace; the
  relaunch agent AUDITED it line-by-line against the fetched RFC 8017,
  re-derived ALL ground truth independently (scratch/rsa_ground_truth.py:
  deterministic key, EMSA-PKCS1-v1_5 + EMSA-PSS encode in python,
  sigs = pow(em,d,n) + roundtrip, OpenSSL cross-sign v1.5 byte-identical,
  CIOS limb-level simulation with T < 2n asserted), replaced all vectors
  with fresh ones. HONEST DEVIATION, verified on the fetched RFC: §A.1.1
  defines ASN.1 SYNTAX ONLY — no example key exists — deterministic key
  generated instead. `bignum` (u64 limbs, CIOS, Newton n0', final-carry
  subtract exactly-once, edge-tested x·y ≥ n) + `rsa` verify-only
  (v1.5 + PSS SHA-256, MGF1, ct_eq, per-stage error strings, RSAVP1
  range check); its workspace: 106-green (97+9), lock v3.
- **2-a X25519: DIED TWICE** (empty response; relaunch also empty —
  heaviest scope). **Lead took over mid-session** (see Stage 2 below).
- **2-e python-KAT harness: DIED TWICE** (same). Its essential
  cross-checks were folded into the lead's own spot-checks + the
  2-d ground-truth script (which subsumes the RSA/KAT part).

## Merge surgery (three lib.rs deliverables → one file)

All three finals derive from the same 1730-line ancestor:
diff3(cfb, orig, hkdf) → clean, 2462 lines, exactly additive;
diff3(merged1, orig, bignum) → 2 conflicts, BOTH additive on both
sides (doc-header bullets; tail test region) → resolved by
concatenation (line-based parser; the ||||||| ancestor sections
dropped). rustc then caught three structural issues the textual merge
created — fixed in sequence:
1. stray `}` at the old mod-tests close (deleted);
2. `cfb_audit` module + bignum's nested `#[cfg(test)] mod tests`
   missing their interleaved closes (one `}` inserted before the
   nested `#[cfg(test)]` line — first attempt landed between the
   attribute and `mod`, caught by rustc and moved);
3. the merged tree's `mod tests` opening (orig 1238-1240) had been
   auto-resolved by diff3 to bignum's replaced region (banner + bignum
   + rsa modules), so cfb/tls13 helpers landed TOP-LEVEL non-cfg →
   lib-build dead-code warnings → `#[cfg(test)]` gates re-added to
   `SP800_38A_PT4` + `cfb128_kat`.
NOTE recorded honestly: in the merged tree the original `#[cfg(test)]
mod tests` wrapper is gone — the original inline test fns now sit
top-level (valid Rust; bare `sha256::` etc. resolve from crate root),
and only ONE `mod tests` block remains (bignum's). Compiles clean:
**114 passed, 0 failed** (97+5+3+9); lock v3 HELD; zero new warnings
(pre-existing holo-ss `SaltCache::len` warning only, recorded run-5).

## Verification evidence (A3-C9, lead-run, this host)

- CFB spot-check: `openssl enc -aes-128-cfb -K 2b7e1516…4f3c -iv
  000102…0e0f` over PT block 1 → `3b3fd92eb72dad20333449f8e83cfb4a` ==
  merged test constant (grep 2 hits: encrypt+decrypt tests).
- tls13 spot-check: python `hmac.new(0^32, 0^32, sha256)` →
  `33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a`
  == merged test constant (NOT quoted from memory — computed).
- RSA: `scratch/rsa_ground_truth.py` RERUN this run → "ALL GROUND-TRUTH
  CHECKS PASSED" (CIOS sims match Python x·y·R⁻¹ mod n; T < 2n every
  tuple; final-subtract fires exactly once on the edge tuple).
- cfb_usage_audit NEGATIVE DEMO in the REAL tree: planted
  crates/holo-socks/src/cfb_probe_scratch.rs (contains "cfb") →
  `test result: FAILED` with `cfb_probe_scratch.rs:1: matched "cfb"`
  (file:line); removed → `test result: ok. 1 passed`. Evidence quoted
  in D-0030.

## Memory updated (batch 1)

DECISIONS.md +2 (D-0030 CFB enforcement shape; D-0031 bignum/RSA CT
accepted-risk — the A3-C6/F13 criterion handed to A2 at the S1→S2 gate);
ROADMAP items 3/4/5 DONE-annotated with evidence; graph.json extended
via scripts/extend_graph_run10.py (SES-2026-11-25 + D-0030/D-0031 + 5
grouped T-nodes + 10 edges) → check OK 152 nodes/111 edges coverage
complete, RAG smoke OK 376 chunks; STATE.md run-10 header; this
journal. update_memory.py run pre-backup.

## Stage 2: X25519 (lead-implemented after two agent deaths)

Two 2-a launches died (empty response ×2 — the heaviest scope: full
field arithmetic + ladder + 1M-iter). The lead took over and shipped it
in-session:

- RFC 7748 fetched (rfc-editor.org, /tmp/rfc7748x.txt 1235 lines);
  §4 ladder pseudocode, §5 decodeScalar25519/decodeUCoordinate + the
  MUST-mask sentence, §5.2 vectors (both single-iteration pairs, the
  iterated definition + published 1/1,000/1M values), §6.1 DH vector,
  the cswap XOR-mask definition and §5.1 side-channel text — all
  quoted/extracted verbatim; a24 = 121665 quoted from §4.
- p−2 derived programmatically (python): LE bytes eb ff…7f; 2^64-radix
  limb 0 = 0xffffffffffffffeb (the roadmap's "0xffffffeb…" pin);
  51-bit limbs [0x7ffffffffffeb, 0x7ffffffffffff ×4].
- Implementation (scratch/x25519_module.rs → appended to lib.rs):
  5×51-bit u64 limbs + u128 intermediates (Poly1305 limb style); a
  shared fe_carry + fe_reduce (FOUR unconditional carry→fold rounds —
  termination proven by the geometric carry bounds: 2^54 → ≤2^8 → ≤1 →
  0; a first draft with ad-hoc rounds had a ping-pong fold bug, caught
  by self-review BEFORE compiling and rewritten); ladder = RFC §4
  verbatim (255 iterations, XOR-mask cswap); inversion = modpow p−2
  branching only on the public constant; all-zero shared secret → None
  via crate::ct_eq; BASEPOINT const; public_from_private with the
  order argument documented (clamped k = 2^254+8j ≢ 0 mod ℓ since 8ℓ >
  2^255 and ℓ odd).
- **FIRST-COMPILE GREEN: 48 passed (42+6), 2 ignored; workspace
  120-green (114+6), 0 failed; lock v3 held; zero new warnings.**
- Independent verification (scripts/verify_x25519_rfc7748.py): the
  RFC's OWN §5 python decode functions + a §4-pseudocode transcription
  → ALL 9 CHECKS PASSED (vector1, vector2, §6.1 both publics + both
  shared-secret directions, u=0 zero-output case, iterated 1 and
  1,000) — every PASS line quotes ≥16 hex chars.
- Release-mode iterated runs (D-0032): 1,000-iter PASSED in 0.12 s
  (`cargo test -p holo-crypto --release x25519_iterated_rfc7748_1000
  -- --ignored`); the 1M run executed in release in the background —
  result in the addendum below.
- Memory: D-0032 recorded (execution mode + CT checklist); ROADMAP
  item 2 DONE-annotated; graph extended (+D-0032, T-x25519-vectors,
  T-x25519-iterated).

## Addendum 1 (stage-1 CI + 1M iterated run)

- **STAGE 1 CI-VERIFIED: run 45488934917 @ d6c37a05 completed SUCCESS**
  (started 21:13:44Z, immediately after the push). The poll_ci.sh
  head_sha loop kept reporting "no run yet" for ~25 min (stale API
  filter response — first false negative of that script); the direct
  authenticated runs query is authoritative and shows completed/success.
  Poll script quirk recorded for a future LESSONS entry if it repeats.
- **1M-ITERATED RFC 7748 §5.2 VECTOR PASSED release-mode: 124.46 s**
  test time (`cargo test -p holo-crypto --release
  x25519_iterated_rfc7748_1m -- --ignored` → `1 passed; 0 failed`),
  matching the RFC-published
  7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424.
  Lock v3 held post-run. D-0032's execution-mode evidence complete.
  (The first nohup attempt died silently mid-compile when its parent
  shell closed — restarted synchronously; the log timestamps caught it.)

## Next

1. Stage 2 X25519 (lead): RFC 7748 fetch → vectors → field/ladder →
   tests (§5.2, §6.1, non-canonical, all-zero reject, iterated
   #[ignore]) → D-0032 execution-mode decision → backup.
2. Release-mode iterated runs (1000 + 1M) recorded.
3. Gate record 0004 (S1→S2) per WORKFLOW §2.6 + ADVERSARIAL.md — ONLY
   if S1 items all DONE + CI-verified and time allows; NO S2
   implementation without the gate passing.
4. Closure: README/ARCHITECTURE/STATE/PROJECT_MEMORY count citations to
   the CI-verified ledger (expected 114 Linux / 113 macOS / 113
   Windows visible 104/103/103 + socks 10 — reconcile per-OS).
5. Deferred owner items unchanged (D-0014; CVE backfill; PAT rotation).
