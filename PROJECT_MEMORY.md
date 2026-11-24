# PROJECT_MEMORY — HoloNet operational state (single compressed source of truth)

Owner protocol (2026-11-19, pstack principles, D-0016; hooks/gate D-0021): this file is the
TOKEN-EFFICIENT OPERATIONAL VIEW — tech-stack rules, active playbook,
verification contracts. The BINDING durable memory stays in
`harness/memory/*` (append-only DECISIONS/LESSONS/BACKUPS, STATE,
ROADMAP, session journals; gate records in `harness/adversarial/verdicts/`,
hash-chained). On any conflict: harness is authoritative; update both.
`update_memory.py` (repo root) appends the git-activity section below;
run at session start; `--check` gates structure/freshness and
`--install-hooks` installs the pre-/post-commit hooks (D-0021).
Zero-noise rule: no raw history dumps beyond that
section — summarize decisions/files/next-steps only.

## Tech Stack & Architecture Rules (invariants)

- GPL-3.0-or-later monorepo. Engine: pure-std Rust, edition 2021,
  **zero third-party crates (D-0002)**, MSRV **1.77.2** (Win7 SP1 /
  macOS 10.15 floor). 11 crates under `engine/crates/` (holo-util,
  -config, -theme, -proto, -engine, -net, -crypto, -ss, -socks,
  holonetctl, holonetd). Frontends: app_flutter (Android), app_kmp
  (macOS), app_qt (Win/Linux); NDJSON JSON-RPC to holonetd
  127.0.0.1:7977; Material You via one verified Rust color engine.
- **Cargo.lock stays `version = 3`** — modern cargo silently rewrites
  v3→v4 and breaks the 1.77.2 CI job; re-check after EVERY cargo run
  and journal it. (Violated by the 0003 run — the v4 rewrite rode to
  origin/main; found + restored to v3 on 2026-11-20 run 3.)
- `unsafe`: forbidden except the chartered S1 Windows entropy FFI in
  `holo-util/src/rand.rs` (D-0008), fail-closed entropy everywhere.
- Honesty rules: no fake success — non-live drivers return milestone
  errors; test counts only ever quoted from tree/CI evidence.
- Hash-anchored records: verify at BLOB level
  (`git show HEAD:<path> | sha256sum`); `harness/**` is LF-pinned.
- Host (owner Windows PC): no Rust/MSVC — verification = static +
  GitHub API (anonymous for conclusions; cached git credential for
  logs: `git credential fill`, GCM_INTERACTIVE=never, never echo
  token). Copilot cloud sandbox available for real Linux execution.
- AGENT MEMORY ACCESS (D-0027/D-0028): do NOT load whole memory files —
  retrieve first: `python harness/memory/graph/memory_rag.py ask
  "<query>" [--json]` (BM25 chunks + graph context); structured lookup:
  `python harness/memory/graph/memory_graph.py query <id|--type:T
  |--status:S> [--rel R]`; both validated in the harness-audit CI job.
  Graph/markdown stay authoritative; RAG is the read layer.

## Current objective

S1 server-path hardening RUN 5 (2026-11-20): ProbeGuard decay (N=1024)
+ CSPRNG-jittered slow-close (ceiling 2 s, D-0023) + A2-F6 auth read
deadline (10 s) SHIPPED, local 86-green; backup push LANDED
(ef19a6f..d9e137e) and CI run 44700103379 all-green (6/6) — per-OS
ledger 83 Linux / 82 macOS / 82 Windows recorded; README/ARCHITECTURE
counts now CI-verified. The 86-tree itself is CI-verified too:
run 44703200189 @ f433de4 all-green (6/6 jobs; 86 Linux / 85 macOS /
85 Windows).

S1 in progress: items 0, salt-cache, loopback-bind, ProbeGuard decay,
jittered slow-close, read-deadline AND rand-split enforcement (run 6,
D-0024) all DONE. **S1a is FULLY CLOSED as of 2026-11-21 (run 8):
the XChaCha wire fix — the last S1a item — landed (D-0029).**

RUN 7 (2026-11-20, owner decisions executed): **D-0025 = (a) advisory +
v0.3.1** and **D-0026 = S5 creds embedded-with-risk-acceptance**.
Executed: HoloNet-SA-0001 drafted (docs/advisories/) AND published as
GHSA-8h6m-w5qj-cq9g (CVE requested, pending); **v0.3.1 CUT** from the
CI-verified tree 6314da0 — 4 per-OS tags built all-green (runs
44758027482/44758056729/44758090961/44758125210), all 7 binaries
sha256-verified against their per-OS manifests, a signed master
SHA256SUMS.txt (Ed25519, python-crypto sign + stock-openssl verify,
roundtrip-proven) + the advisory attached to the main release; the 7
phantom v0.2.0/v0.3.0 DRAFTS deleted (2 vulnerable Windows builds
destroyed, 5 superseded unix builds de-footgunned; inventories quoted
in the journal); public v0.2.0-linux kept (unaffected). Signing key:
private in sandbox /home/z/my-project/keys/ (NOT in repo), pubkey
committed docs/release-signing.pub.pem; owner re-key at S7. Next dev:
XChaCha wire fix (unblocked) + BLAKE2s onward (S1b/S1c).

RUN 8 (2026-11-21, XChaCha wire fix — D-0029, binding condition 8,
record-0003 A3-C3): the xchacha20-ietf-poly1305 wire is NOW standard
XChaCha20-Poly1305-IETF (24-byte LE SIP004 counter → holo-crypto's
`aead_xchacha20poly1305_*`; `Direction` holds a method-sized N12/N24
nonce; the mislabeled zero-IV re-key + dead n24 store RETIRED, no
compat mode — it never interopped with any standard peer; chunk 0
coincidentally matches, divergence from the 2nd AEAD op). holo-crypto
now carries the official draft-irtf-cfrg-xchacha-03 vectors (§2.2.1 /
A.2.1 keystream / A.1 AEAD incl. the published intermediate Poly1305
key — fetched verbatim from the IETF archive); primitives were already
draft-correct, now PROVEN. Local 92-green (+5), static 94, lock v3
held; CI verification rides the run-8 push. Run-8 session-start
reconciliation: the run-7 push HAD landed at 17e5b8d (CI run
44759108489 SUCCESS) despite the BACKUPS.md FAILED tail — LANDED
reconciliation line appended; CVE still unassigned (cve_id None).
**CI-VERIFIED: run 44872078593 @ 676a58c all-green (6/6) — per-OS
ledger 92 Linux / 91 macOS / 91 Windows; README + ARCHITECTURE counts
updated. MID-RUN DIVERGENCE (third): the parallel graph/RAG session
pushed bcf8da1+05f9906 mid-run; reconciled via commit + rebase
(WORKFLOW §1.4) — my decision renumbered D-0027→D-0029 (theirs took
D-0027/D-0028), graph.json extended (D-0029 + SES-2026-11-21a + 3
test nodes; GAP-xchacha closed; graph check + RAG smoke green).**
RUN 9 (2026-11-21, S1b opens — BLAKE2s, RFC 7693, ROADMAP S1b item 1):
`holo-crypto::blake2s` shipped (hash/mac/digest one-shot, §3.3 counter
semantics keyed+unkeyed). D-0020 honored: the orphan's CODE unused;
its 16 KAT expectations each RE-verified against Python hashlib AND
OpenSSL 3.5.7 BEFORE reuse. SIGMA dual-sourced (§2.7 table == Appendix
D blake2s.c table). Layered mechanical guards, +5 tests: SIGMA row
permutation check; the FULL Appendix B "abc" round trace replayed
state-by-state THROUGH the production compression fn (Option trace
hook — no second code path); 16 KATs (8 unkeyed + 8 keyed); the
Appendix E self-test grand hash-of-hashes 6a411f08…4c1dfe over 48
digests (16/20/28/32-byte out × 0/3/64/65/255/1024-byte in ×
keyed+unkeyed — covers the ≥31-byte inputs that hid the orphan's
SIGMA[3][8] defect). Local 97-green (+5), static 99, lock v3 HELD.
**CI-VERIFIED in two rounds: push 6331952 failed ONLY the harness-audit
graph-coverage gate (new journal without a graph SES node — all 5 test
jobs green even there); graph.json extended (+1 SES +4 test nodes +6
edges, check/RAG-smoke green locally); fix push e3c8304 = run
44897540455 ALL-GREEN 6/6 — per-OS ledger 97 Linux / 96 macOS / 96
Windows (visible 87/86/86 + redirected socks 10); README/ARCHITECTURE
citations updated.**

RUN 10 (2026-11-25, owner-authorized autonomous session): S1b items
3/4/5 LANDED via a five-agent parallel batch into isolated scratch
workspaces (two agent deaths — X25519 taken over by the lead mid-session):
AES-CFB128 (SP 800-38A; `pub(crate) mod cfb128` + `cfb_usage_audit`
grep-test, negative demo LIVE — D-0030); tls13 HKDF-Expand-Label /
Derive-Secret (RFC 8446 §7.1; RFC 8448 §3 chain replayed with recomputed
transcripts); bignum (CIOS Montgomery, Newton n0', final-carry
exactly-once edge-tested) + rsa VERIFY-ONLY (PKCS#1 v1.5 + PSS SHA-256,
MGF1, ct_eq; ground truth = python big-int pow + OpenSSL 3.5.7 — RFC
8017 §A.1.1 defines syntax ONLY, no example key: deterministic key
generated + documented — D-0031 CT accepted-risk). Merge surgery:
3-way diff + 3 rustc-caught structural repairs (documented in the
journal). Local 114-green (97+5+3+9), static 116, lock v3 HELD; spot-
checks green (openssl CFB KAT, python HMAC early secret,
rsa_ground_truth.py rerun ALL PASSED). CI verification rides the run-10
push. X25519 (item 2) in progress by the lead — D-0032 execution-mode
decision pending.

Next dev: X25519 (execution-mode decision first; IN PROGRESS this
session), then S1→S2 gate record 0004. ~~AES-CFB, ExpandLabel,
bignum/RSA~~ DONE run 10.

## Verification contracts (how "done" is proven)

- Full matrix green on push: ubuntu/macos/1.77.2/cross-check/
  harness-audit green; windows REQUIRED-green since S1 item 0
  (D-0018 — the expected-red window is CLOSED). Verified green:
  run 44728988531 @ 937554f (2026-11-20; earlier 44703200189 @
  f433de4, 44700103379 @ d9e137e). Per-OS ledger for the CURRENT
  tree: 87 Linux / 86 macOS / 86 Windows (holo-socks redirected to
  socks-test.log in CI logs — reconcile before summing; 1 Linux-only
  integration test, cfg-gated util/config deltas).
- Memory regression budget: RSS growth < 8 MB over 64 MB relayed
  (D-0015; local reference +88–376 KB; runner variance absorbed).
- 89→99 `#[test]` countable: `grep -rn "#\[test\]" engine/crates
  --include="*.rs" | wc -l` → 116 (114 runnable on Linux after run
  10's +5 CFB +3 tls13 +9 bignum — no per-OS cfg gates on the new
  tests; macOS/Windows expected 113 each, socks reconciliation as
  always). Local 114-green; CI verification rides the run-10 push
  (previous CI-verified tree: 97 Linux / 96 macOS / 96 Windows @
  e3c8304, run 44897540455).
- Every run ends: `bash harness/scripts/backup.sh "<summary>"`
  (WORKFLOW §1.2; push = completion). Gate records quote SHA-256 in
  the BACKUPS.md line; next record number = 0004 (S1→S2 gate,
  sequence-numbered per WORKFLOW §2.6).

## Active playbook / todo

1. [owner] ~~D-0009/D-0013: advisory + signed v0.3.1~~ DECIDED run 7
   (D-0025, option (a)) AND EXECUTED (SA-0001 + GHSA-8h6m-w5qj-cq9g +
   v0.3.1 cut + drafts deleted).
2. [owner] ~~S5 credentials model~~ DECIDED run 7 (D-0026: embedded
   with recorded risk-acceptance; D-0001 amended for S5 operational
   creds; test fixtures stay synthetic).
3. [owner] Confirm D-0014 (trojan = named v1.0 second protocol).
4. [dev] ~~S1 item 0~~ DONE 2026-11-20 (D-0018; ledger 76/75/75;
   expected-red window closed).
5. [dev] ~~S1 rest per amended charter: salt-replay cache, off-loopback
   refusal~~ DONE 2026-11-20 run 4 (A2-C1 SaltCache cap-1024 FIFO +
   A3-C4 loopback-only bind w/ HOLONET_PROXY_LISTEN_ANY override; +7
   named tests, local 83-green); ~~ProbeGuard decay, CSPRNG slow-close,
   close-vs-hang uniformity~~ DONE 2026-11-20 run 5 (D-0023: cap 1024
   stalest-eviction + full-jitter ceiling 2 s + auth read deadline 10 s;
   +3 named tests, local 86-green; lock-across-sleep defect fixed);
   remaining: ~~XChaCha standard switch (waits on D-0009/D-0013)~~
   DONE 2026-11-21 run 8 (D-0029 — standard 24-byte-counter wire +
   draft vectors; the zero-IV mislabel retired),
   ~~BLAKE2s (BLAKE2b cut unless justified)~~ DONE 2026-11-21 run 9
   (RFC 7693; SIGMA dual-sourced; Appendix B trace + Appendix E
   self-test + 16 KATs; +5 tests, local 97-green),
   X25519 (1M-vector execution mode decided first), AES-CFB,
   ExpandLabel, bignum/RSA. Rand-split
   enforcement DONE 2026-11-20 run 6 (D-0024).
6. [dev] ~~A4-C2 harness-audit~~ DONE 2026-11-19 (full-tree integrity
   audit, D-0017); ~~A4-C3 backup.sh guards~~ DONE (rebase/unmerged
   refusal + WARN durability, negative-tested).
7. [research→charter] R-01..R-15 / C-01..C-15 backlog in ROADMAP.

## Key facts snapshot (2026-11-20, run 6)

- Run 6 (S1a closing: rand-split, D-0024): local suite **87 green**
  (rustc 1.100.0 reinstalled via rustup — the recycle wiped ~/.cargo
  again; baseline 86/86 re-verified BEFORE changes); static 89;
  Cargo.lock v3 HELD post-run. Weak PRNG behind rand::nosec
  (doc-hidden), ALL re-export paths closed (incl. the crate-root
  `pub use rand::{bytes, fill}` — found by the run's call-site map;
  leaving it would have defeated a module-only split), named audit
  test CI-enforces the two-entry allowlist (definition + holo-config
  profile IDs); both negative paths demonstrated live (planted scratch
  violation → audit FAIL with file:line; old root call → E0425).
  **CI-VERIFIED: run 44728988531 @ 937554f all-green (6/6 jobs) —
  per-OS ledger 87 Linux / 86 macOS / 86 Windows** (visible sums
  77/76/76 + the redirected holo-socks 10, reconciled; README +
  ARCHITECTURE citations updated).
- Run 5 (S1 hardening second pass): local suite **86 green**
  (baseline 83/83 re-verified before changes); push LANDED; CI
  44700103379 + 44703200189 all-green (ledger 86/85/85).
- Run 5 PUSH LANDED (owner PAT via env-var credential helper only):
  origin/main ef19a6f..f433de4; CI all-green 6/6 on BOTH pushes
  (44700103379 @ d9e137e = the 83-tree; 44703200189 @ f433de4 = the
  86-tree, ledger 86/85/85); the v4 lockfile regression's CI failure
  @ ef19a6f confirmed the canary logic.
- SHIPPED run 5: holo-net ProbeGuard cap (A1-F8) + holo-ss full-jitter
  slow-close w/ explicit ceiling (A3-C10) + holo-ss auth read deadline
  (A2-F6) — named tests green; ROADMAP + THREAT-MODEL §C annotated
  with honest residuals; D-0023 records all three decisions. serve_conn
  gained a ServePolicy param (all call sites updated). ProbeGuard-lock
  -across-sleep serialization defect found by inspection and fixed.
- Gate 0001 PASSED (S0→S1); progress review 0002 PASSED (4×
  PROCEED_WITH_CONDITIONS); cross-validation 0003 PASSED (4× PWC, 0
  BLOCK; A2-C1/A3-C4 closed run 4, the three remaining server-path
  items closed run 5). Next record: 0004 = the S1→S2 gate.
- Known shipped-plane gaps (chartered in S1, post-run-6): xchacha
  mislabel (owner decision first); crypto primitives
  BLAKE2s/X25519/AES-CFB/ExpandLabel/bignum-RSA not yet landed
  (S1b/S1c). Rand-split CLOSED run 6 (D-0024).
- Release surface (run 7): v0.3.1 family PUBLIC (4 per-OS + main with
  signed manifest + SA-0001), v0.3.0 (src), v0.2.0-linux (kept,
  unaffected), empty v0.2.0. All 7 phantom per-OS DRAFTS deleted
  (D-0025); GHSA-8h6m-w5qj-cq9g published, CVE requested.
- Hygiene: `SaltCache::len` unused outside tests (run-4 artifact,
  warning only, recorded in the run-5 journal).

## Recent Progress & Git Activity

```text
### Commit: c76844e - backup: run 9 closure: CI-VERIFIED 44897540455 @ e3c8304 all-green 6/6, per-OS ledger 97 Linux/96 macOS/96 Windows (visible 87/86/86 + socks 10 reconciled); README badge + Status block and ARCHITECTURE data p (maniesh-NR, 2026-11-21)
### Commit: e3c8304 - backup: run 9 fix: graph coverage — SES-2026-11-21b + 4 T-blake2s nodes + 6 edges (harness-audit had failed 44896588214 on the missing session node; all 5 test jobs were green); graph check + RAG smoke gree (maniesh-NR, 2026-11-21)
### Commit: 6331952 - backup: run 9: BLAKE2s RFC 7693 (S1b item 1): SIGMA dual-sourced, Appendix B trace + Appendix E self-test + 16 KATs (re-verified vs Python+OpenSSL); +5 tests, local 97-green, static 99, lock v3 held (maniesh-NR, 2026-11-21)
```
