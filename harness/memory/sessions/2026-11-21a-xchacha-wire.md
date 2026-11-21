# Session journal — 2026-11-21a: XChaCha20 wire fix (binding condition 8, D-0029) + run-7 reconciliation

## Session-start ritual (runbook 0/0b, warm path)

- Memory loaded in order (PROJECT_MEMORY, STATE, ROADMAP, DECISIONS
  tail, LESSONS, run-7 journal). fileMode=false already set; memory
  gate PASSED (lag 1 — the 17e5b8d STATE filename fix postdates the
  last update_memory.py run).
- **Remote reconciliation: MATCH — origin/main == 17e5b8d == local
  HEAD.** This resolves the run-7 backup question: the push DID land
  (carrying 6314da0..17e5b8d: the run-7 backup 19e0791, two honest
  FAILED markers, and the STATE pubkey-filename fix). The BACKUPS.md
  "FAILED 15:01:11Z" tail documented only backup.sh's in-script
  attempt — the retry landed after the session cut before the ledger
  could record it. Honest fix: LANDED reconciliation line appended to
  BACKUPS.md (labeled as a run-8 reconciliation, not a contemporaneous
  record). **CI of the 17e5b8d tree: run 44759108489 SUCCESS**
  (polled with poll_ci.sh via the env-var token) — the same 87/86/86
  engine tree as 937554f plus docs/harness-only commits.
- Toolchain: `cargo` ABSENT again (third wipe by recycle) — rustup
  reinstall per runbook step 2 (rustc 1.100.0). The first background
  nohup attempt died silently (empty log, no /tmp/rustup-init) — the
  synchronous runbook invocation is the reliable path.
- Baseline re-verified BEFORE any change: full workspace **87/87
  green** (sum over 21 suites), static 89 — matches the CI-verified
  ledger exactly.

## CVE backfill check (run-7 Next item 3)

- Repo-scoped advisory API: GHSA-8h6m-w5qj-cq9g state=published
  (2026-11-20T14:59:23Z), **cve_id = None — still not assigned**. No
  backfill possible; re-check next run. (The global /advisories
  endpoint 404s for unreviewed repo advisories — expected, not an
  error.)

## Investigation (before any code)

- The defect, precisely (record-0003 A2-F8, verified in-tree):
  `Direction` kept ONE 12-byte nonce for all methods; the
  `XChaCha20IetfPoly1305` branch of seal/open built a 24-byte `n24`
  **that it never used** (the dead store the ROADMAP named), then
  sealed with `hchacha20(subkey, 0^16)` as a FIXED re-key + plain
  `aead_chacha20poly1305_*` over the 12-byte counter. I.e. the cipher
  sold on the wire as xchacha20-ietf-poly1305 was re-keyed
  ChaCha20-Poly1305 — no 24-byte nonce ever influenced a keystream.
  Cryptographically still an AEAD (confidentiality/auth intact); the
  defect is interop/mislabeling vs every standard shadowsocks peer.
- holo-crypto's `hchacha20` and `aead_xchacha20poly1305_*` were
  ALREADY draft-correct (HChaCha20 no-final-add words 0..3/12..15; 4
  NUL bytes || nonce[16..24] inner nonce) but carried NO official
  vectors — standing criterion 1 ("no vector, no merge") was unmet.
- Standard target (record-0003 A3-C3): 24-byte SIP004 LE counter +
  XChaCha20-Poly1305-IETF; salt stays 32 bytes (= key length).
- Draft fetched verbatim:
  https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt
  (§2.2.1 HChaCha20 vector; A.1 AEAD vector with the published
  intermediate Poly1305 key; A.2.1 XChaCha20 keystream — note its IV
  ends 0x58, not 0x57). A.2.2 (counter=1) not needed: our AEAD path
  exercises counter 1 implicitly via the A.1 poly key + ct/tag.

## Implementation

- **holo-crypto tests (+3)**: `hchacha20_draft_xchacha_2_2_1`,
  `xchacha20_draft_a_2_1_keystream` (composed exactly as §2.3.1's
  pseudocode: hchacha20 → 4-NUL-prefixed inner nonce →
  chacha20::block from counter 0; asserts the draft's first 4
  keystream blocks), `aead_xchacha20poly1305_draft_a_1` (ct, tag, AND
  the published intermediate Poly1305 key, which pins every layer at
  once).
- **holo-ss wire**: `Direction.nonce` became a method-sized `Nonce`
  enum (N12/N24) with the same LE increment; the XChaCha branch of
  seal/open now calls `aead_xchacha20poly1305_*` directly with the
  24-byte counter. Dead n24 + zero-IV re-key REMOVED. Module docs
  updated (nonce semantics; also fixed the stale "close delay is
  deterministic today" comment — run 5 shipped jitter, D-0023).
- **holo-ss named tests (+2)**:
  `xchacha_wire_is_standard_aead_24byte_le_counter` — chunk k's bytes
  must EQUAL the standard AEAD at nonce=k (k=0,1,2), roundtripped via
  a second Direction; plus a tamper check;
  `xchacha_wire_differs_from_the_retired_zeroiv_construction` —
  divergence at chunk 1 (regression lock).

## Negative-path demonstrations (the invariant-over-prediction rule)

- The vector tests initially FAILED twice — both times MY
  hand-transcribed expected constants were wrong (a digit
  transposition "d4b3"→"d43b", then a digit dropped at a string
  line-continuation junction), while the implementation matched the
  fetched draft row-for-row. Recorded in LESSONS; the final constants
  were re-verified against the fetched text.
- The divergence test initially "failed" by NOT diverging: at chunk 0
  the retired and standard constructions COINCIDE (both nonces
  all-zero — the retired construction is the standard one at nonce
  0). Divergence starts at the second AEAD operation. The test now
  asserts at chunk 1; the chunk-0 coincidence is documented (it means
  v0.3.1↔run-8 sessions share their FIRST chunk's bytes, then split).
- The interop test initially mis-modeled seal/open on ONE Direction
  (open sees the post-increment nonce → tag mismatch). Fixed by
  modeling the two one-way directions like the real tunnel.

## Verification

- Local suites: holo-crypto 17→**20 green**; holo-ss 11→**13 green**
  (incl. `full_tunnel_roundtrip_all_ciphers` over the NEW wire);
  full workspace **92 green** (87 + 5). Static count **94** (89 + 5).
- Cargo.lock **v3 held** post-run (no Cargo.toml change).
- No new unsafe (grep clean); no third-party crates; MSRV untouched
  (no new language features beyond the existing floor — the Nonce enum
  uses core constructs only).

## Memory updated

ROADMAP (item 8 DONE annotation + the remaining-S1 list), THREAT-MODEL
§G (wire-standardization resolution bullet + revision history),
TECHNIQUES.md (XChaCha draft citation added), DECISIONS (D-0029, renumbered from D-0027 at rebase),
LESSONS (+2), STATE (run-8 header, run-7 preserved), PROJECT_MEMORY
(objective/playbook/snapshot/verification contracts), BACKUPS.md
(run-7 LANDED reconciliation line), this journal.

## Backup

- End-of-run backup.sh with the run summary; push via the env-var
  credential helper (retry pattern as runs 5–7; the token is
  re-loaded from the owner upload per tool call — env vars do not
  survive between calls in this sandbox). Outcome: BACKUPS.md tail.
- CI verification of the 92-tree rides this push; README/ARCHITECTURE
  counts update AFTER CI verifies (the established pattern), followed
  by the closure push.

## Next

1. Owner: confirm/override D-0014 (trojan default) — last open owner
   item; rotate the session PAT (transited chat again this run).
2. Dev: S1b starts — BLAKE2s (SIGMA re-derivation warning, D-0020;
   ROTR not ROTL), then X25519 (execution-mode decision first),
   AES-CFB (with its planned mechanical grep-audit).
3. CVE backfill when GitHub assigns the id (SA-0001 + GHSA).
4. After CI: README/ARCHITECTURE test-count citations → 92/91/91
   (pending the actual per-OS ledger parse, socks redirect
   reconciled).

## Addendum (post-divergence, written after the sections above)

- **MID-RUN DIVERGENCE (the project's third).** The first backup.sh
  REFUSED: origin/main had moved to 05f9906 — a PARALLEL SESSION had
  landed the agentic memory graph + RAG (bcf8da1: graph.json +
  memory_graph.py + memory_rag.py + CI integration; 05f9906: their own
  reconciliation curation, renumbering THEIR entries to D-0027(graph)
  / D-0028(RAG)). My run-8 work was uncommitted local at that point.
  Reconciled per WORKFLOW §1.4: committed the run-8 work (586603a),
  `git rebase origin/main`, ONE conflict (DECISIONS.md, both sides had
  appended at the tail) resolved keeping BOTH sides — with the
  numbering fixed honestly:
  - their D-0027 (graph) + D-0028 (RAG) entries stand as pushed;
  - MY XChaCha decision, drafted as D-0027 in this sandbox, is
    renumbered **D-0029** (a numbering note is recorded inside the
    entry);
  - their pushed file carried a stray pasted commit-message line
    ("dd6f4ba (…)") at the tail and a duplicated misplaced NUMBERING
    NOTE — both removed in the resolution, disposition recorded in the
    D-0029 numbering note.
  - D-0027 references in my ROADMAP/THREAT-MODEL/STATE/PROJECT_MEMORY/
    journal renumbered to D-0029 (their D-0027/D-0028 mentions in
    PROJECT_MEMORY's agent-guidance line left untouched).
- **Graph coverage extension (required by their D-0027: the
  harness-audit CI job fails on any source D-NNNN/session missing
  from graph.json).** Ran their check FIRST — it failed with exactly
  2 gaps (D-0029, session 2026-11-21a), proving the mechanism works on
  MY additions too. Then extended the graph (139 nodes/95 edges):
  +D-0029 decision node, +SES-2026-11-21a session node, +3 test nodes
  (the interop lock, the divergence lock, the draft vectors), GAP-xchacha
  flipped closed, holo-ss/holo-crypto/S1/A2-C4 summaries refreshed, two
  STALE nodes fixed (T-salt-replay-planned / T-loopback-refusal-planned
  were still "planned" though shipped runs 4-5 — flipped to passing
  with the shipped test names), edges added (D-0029 closes GAP-xchacha;
  authored/implements/tested_by/verified_by). Both dangling renamed-src
  edges fixed; `check` OK and `rag smoke` OK before the push.
- **backup.sh second refusal (found + cleared):** after the successful
  rebase, `REBASE_HEAD` lingers and the guard treats its existence as
  an in-progress rebase — cleared with `git update-ref -d REBASE_HEAD`
  (safe post-completion; disposition recorded in the backup summary).
- **Backup + push + CI:** backup.sh committed 84dbf83 (in-script push
  FAILED as usual — no terminal); manual retry via the env-var
  credential helper LANDED 05f9906..676a58c. **CI-VERIFIED: run
  44872078593 @ 676a58c all-green (6/6 jobs: ubuntu, macos, windows,
  1.77.2 canary, cross-compile, harness-audit incl. the graph coverage
  check + RAG smoke over the EXTENDED graph) — per-OS ledger 92 Linux
  / 91 macOS / 91 Windows** (job-log sums 82/81/81 visible + the
  redirected socks 10, reconciled — the log lines carry timestamp
  prefixes, so ledger greps must NOT anchor at line start; recorded as
  a mini-lesson here). Closure updates (README badge + Status block,
  ARCHITECTURE data-plane paragraph, STATE/PROJECT_MEMORY verified
  sentences, this addendum, BACKUPS LANDED line) ride the closure
  backup push.
- The suite was re-verified on the REBASED tree before pushing (92
  green, Cargo.lock v3 held) — the rebase brought harness/ci.yml/
  memory changes only, no engine deltas.
